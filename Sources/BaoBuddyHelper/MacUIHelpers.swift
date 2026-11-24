#if os(macOS)
import BaoBuddyCore
import Foundation

/// Pure, deterministic logic shared by `MacSettingsView` and `MacEditProfileSheet`.
enum MacSettingsLogic {
    /// Canonicalizes an OTLP endpoint URL for equality comparison:
    /// trims whitespace, lowercases scheme and host, omits default ports (`443` for https, `80` for http),
    /// and strips trailing slashes from the path.
    static func canonicalOTLPEndpoint(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased(),
              let host = components.host?.lowercased(), !host.isEmpty else { return "" }
        // The exporter appends a path to the configured string. Preserve an exact
        // match for nonstandard endpoints rather than equating different request URLs.
        if components.user != nil || components.password != nil || components.query != nil || components.fragment != nil {
            return trimmed
        }
        components.scheme = scheme
        components.host = host
        if (scheme == "https" && components.port == 443) || (scheme == "http" && components.port == 80) {
            components.port = nil
        }
        var path = components.percentEncodedPath
        while path.hasSuffix("/") { path.removeLast() }
        components.percentEncodedPath = path
        return components.string ?? ""
    }

    /// Preserves existing collector auth headers ONLY when the canonical OTLP endpoint is unchanged.
    /// Changing or clearing the endpoint clears saved headers so credentials for Collector A are
    /// never sent to Collector B.
    static func resolvedTelemetry(existing: BaoTelemetryConfig, newEndpoint: String) -> BaoTelemetryConfig {
        let trimmedNew = newEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        let existingCanonical = canonicalOTLPEndpoint(existing.otlpEndpoint)
        let newCanonical = canonicalOTLPEndpoint(trimmedNew)
        let keepHeaders = !newCanonical.isEmpty && existingCanonical == newCanonical
        return BaoTelemetryConfig(
            otlpEndpoint: trimmedNew,
            serviceName: existing.serviceName,
            headers: keepHeaders ? existing.headers : [:]
        )
    }

    /// Resolves the JWT audience on profile save.
    /// - Empty audience derives the canonical trust-domain-bound `baobuddy://` audience.
    /// - If editing an existing profile whose audience was the auto-derived `baobuddy://` value and
    ///   the user did not hand-edit it, re-derives from the updated deployment fields so rotating a
    ///   CA pin or changing URL/namespace/mTLS/mount saves cleanly.
    /// - Custom IdP audiences and explicitly edited `baobuddy://` values are preserved verbatim for validation.
    static func resolvedAudience(
        rawAudience: String,
        originalExpectedAudience: String?,
        derivedAudience: String
    ) -> String {
        let trimmed = rawAudience.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || (trimmed == originalExpectedAudience && trimmed.hasPrefix("baobuddy://")) {
            return derivedAudience
        }
        return trimmed
    }

    /// Loads the Secure Enclave public key PEM strictly scoped to `profile` (never reusing another
    /// server's key). Returns an empty string when `profile` is nil or has no scoped key enrolled.
    static func scopedPublicKeyPEM(
        for profile: BaoProfile?,
        deviceName: String = "mac",
        reader: (BaoProfile, String) -> String? = { profile, deviceName in
            try? SecureEnclaveKeyStore.scoped(for: profile, deviceName: deviceName).publicKeyPEM()
        }
    ) -> String {
        guard let profile else { return "" }
        return reader(profile, deviceName) ?? ""
    }
}

/// Explicit state of the local Mac Keychain grant for the currently selected server profile.
enum LocalGrantStatus: Equatable, Sendable {
    case inactive
    case active(TokenLookupInfo)
    case unknown(String)

    var isActive: Bool {
        if case let .active(info) = self { return info.ttlSeconds > 0 }
        return false
    }

    var activeInfo: TokenLookupInfo? {
        if case let .active(info) = self, info.ttlSeconds > 0 { return info }
        return nil
    }

    var isUnknown: Bool {
        if case .unknown = self { return true }
        return false
    }

    var unknownReason: String? {
        if case let .unknown(reason) = self { return reason }
        return nil
    }
}

/// Injectable platform and transport dependencies for `MenuBarState`, keeping live behavior
/// unchanged while allowing deterministic offline unit tests with zero Keychain/Touch ID prompts.
struct MenuBarDependencies {
    var loadManagedConfig: () -> ManagedAppConfig
    var loadProfileCollection: () -> ProfileCollection
    var saveProfileCollection: (ProfileCollection) throws -> Void
    var saveLegacyProfile: (BaoProfile) throws -> Void
    var readLocalGrant: (BaoProfile) throws -> String?
    var deleteRevokedLocalGrant: (BaoProfile, String) throws -> Void
    var lookupSelf: (BaoProfile, String) async throws -> TokenLookupInfo
    var revokeSelf: (BaoProfile, String) async throws -> Void
    var remoteStatus: (BaoProfile) async throws -> String
    var remoteRunningTasks: (BaoProfile) async -> RunningTasksResult
    var remoteRevokeHost: (BaoProfile) async throws -> String
    var recordedRemoteAccessors: (BaoProfile) throws -> [GrantAccessorStore.Entry]
    var revokeRemoteAccessor: (BaoProfile, String, ManagedAppConfig) async throws -> Void
    var removeRecordedRemoteAccessor: (BaoProfile, String) throws -> Void
    var executeGrant: (BaoProfile, GrantRequest, ManagedAppConfig) async throws -> GrantOutcome
    var recordActivity: (GrantActivityEntry) -> Void
    var emitTelemetry: (BaoProfile, GrantActivityEntry) -> Void
    var scheduleExpiryNotification: (String, String, String, Int) -> Void
    var cancelExpiryNotification: (String) -> Void
    var detectBiometry: () -> (label: String, symbol: String)

    @MainActor
    static var live: MenuBarDependencies {
        let multiStore = MultiProfileStore()
        let legacyStore = FileProfileStore()
        return MenuBarDependencies(
            loadManagedConfig: { ManagedAppConfig.load() },
            loadProfileCollection: { multiStore.load() },
            saveProfileCollection: { try multiStore.save($0) },
            saveLegacyProfile: { try legacyStore.save($0) },
            readLocalGrant: { profile in
                try MacKeychainGrantStore(profile: profile).readGrant()
            },
            deleteRevokedLocalGrant: { profile, token in
                try MacKeychainGrantStore(profile: profile).deleteRevokedGrant(matching: token)
            },
            lookupSelf: { profile, token in
                try await OpenBaoClient(profile: profile).lookupSelf(token: token, classifyingInactiveToken: true)
            },
            revokeSelf: { profile, token in
                try await OpenBaoClient(profile: profile).revokeSelf(token: token)
            },
            remoteStatus: { profile in
                try await BaoBuddyHelperCLI.remoteTransport(for: profile).status()
            },
            remoteRunningTasks: { profile in
                await BaoBuddyHelperCLI.remoteTransport(for: profile).runningTasks()
            },
            remoteRevokeHost: { profile in
                try await BaoBuddyHelperCLI.remoteTransport(for: profile).revoke()
            },
            recordedRemoteAccessors: { profile in
                try GrantAccessorStore().entries(for: profile)
            },
            revokeRemoteAccessor: { profile, accessor, orgPolicy in
                let orchestrator = GrantOrchestrator(
                    profile: profile,
                    signer: SecureEnclaveKeyStore.resolve(for: profile, deviceName: "mac"),
                    openbao: try OpenBaoClient(profile: profile),
                    via: "mac",
                    organizationPolicy: orgPolicy
                )
                try await orchestrator.revokeRemoteGrant(accessor: accessor)
            },
            removeRecordedRemoteAccessor: { profile, accessor in
                try GrantAccessorStore().remove(for: profile, accessor: accessor)
            },
            executeGrant: { profile, request, orgPolicy in
                let granter = profile.hasRemoteTarget ? BaoBuddyHelperCLI.remoteTransport(for: profile) : nil
                let accessorStore = GrantAccessorStore()
                let orchestrator = GrantOrchestrator(
                    profile: profile,
                    signer: SecureEnclaveKeyStore.resolve(for: profile, deviceName: "mac"),
                    openbao: try OpenBaoClient(profile: profile),
                    t3Granter: granter,
                    macStore: MacKeychainGrantStore(profile: profile),
                    via: "mac",
                    organizationPolicy: orgPolicy,
                    onRemoteGrantMinted: { accessor, expiresAt in
                        try accessorStore.record(for: profile, accessor: accessor, expiresAt: expiresAt)
                    },
                    onRemoteGrantRolledBack: { accessor in
                        try? accessorStore.remove(for: profile, accessor: accessor)
                    }
                )
                return try await orchestrator.execute(request)
            },
            recordActivity: { entry in
                GrantActivityStore().record(entry)
            },
            emitTelemetry: { profile, entry in
                guard profile.openbao.telemetry.isEnabled,
                      let exporter = try? BaoOTLPExporter(config: profile.openbao.telemetry) else {
                    return
                }
                let actor = profile.openbao.jwtAuth.subject
                Task.detached { await exporter.emit(entry: entry, actor: actor) }
            },
            scheduleExpiryNotification: { id, serverName, targetName, ttlSeconds in
                GrantExpiryNotifier.scheduleWarning(
                    identifier: id,
                    serverName: serverName,
                    targetName: targetName,
                    ttlSeconds: ttlSeconds
                )
            },
            cancelExpiryNotification: { id in
                GrantExpiryNotifier.cancel(identifier: id)
            },
            detectBiometry: {
                MenuBarState.detectSystemBiometry()
            }
        )
    }
}
#endif
