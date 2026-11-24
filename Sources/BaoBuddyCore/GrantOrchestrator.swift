import Foundation

public struct GrantOutcome: Equatable, Sendable {
    public let message: String
    public let replacedOldGrant: Bool
    /// Populated only for direct-token grants (when no remote SSH delivery target is configured).
    public let mintedToken: String?
    /// Accessor of the minted grant. It isn't a secret: it can only look up or revoke the token,
    /// and only with a token whose policy allows that. Keep it to revoke a remote grant later
    /// without trusting the remote host.
    public let accessor: String?
    /// Effective TTL in seconds confirmed by OpenBao (`min(requested, server lease_duration)`).
    public let effectiveTTLSeconds: Int?
    /// Conservative absolute deadline (`mintStartedAt + effectiveTTLSeconds`) shared by the grant,
    /// SSH certificate, credential artifacts, and remote accessor record.
    public let expiresAt: Date?
    /// Credential-extension artifacts. Returned only for direct-token grants; local and remote
    /// grants deliver them to the Keychain or the remote host instead.
    public let artifacts: [MintedExtensionArtifact]

    public init(
        message: String,
        replacedOldGrant: Bool = false,
        mintedToken: String? = nil,
        accessor: String? = nil,
        effectiveTTLSeconds: Int? = nil,
        expiresAt: Date? = nil,
        artifacts: [MintedExtensionArtifact] = []
    ) {
        self.message = message
        self.replacedOldGrant = replacedOldGrant
        self.mintedToken = mintedToken
        self.accessor = accessor
        self.effectiveTTLSeconds = effectiveTTLSeconds
        self.expiresAt = expiresAt
        self.artifacts = artifacts
    }
}

/// Orchestrates biometric JWT sign-in, scoped grant minting, SSH signing, push tokens, delivery
/// (local Keychain, direct token, or remote granter host), and cleanup of every temporary credential.
///
/// Trust boundary: OpenBao/Vault only sees "a registered device key signed a JWT". The 2-minute
/// `granter` token it returns can mint anything the token role allows, so the scope the user
/// approved is enforced by this code, not by the server. `verify` below closes the gap in the
/// other direction (a server minting more than was asked); see docs/THREAT_MODEL.md.
public struct GrantOrchestrator: Sendable {
    public let profile: BaoProfile
    public let jwtSigner: JWTSigner
    public let openbao: OpenBaoClient
    public let github: GitHubPushTokenClient
    public let t3Granter: (any T3GranterTransport)?
    public let macStore: (any MacGrantStore)?
    public let via: String
    /// Clock used to anchor conservative grant deadlines (injectable for deterministic tests).
    public let now: @Sendable () -> Date
    /// Called right after a remote grant token is minted and verified, BEFORE SSH delivery.
    /// Throwing fails closed: the minted token is revoked at OpenBao and SSH delivery never runs.
    public let onRemoteGrantMinted: (@Sendable (String, Date) throws -> Void)?
    /// Called only when a failed remote grant's rollback revocation is confirmed by OpenBao.
    public let onRemoteGrantRolledBack: (@Sendable (String) -> Void)?
    /// Set when the profile breaks organization (MDM) policy; every grant then fails with it.
    private let policyViolation: String?

    /// `organizationPolicy` defaults to the device's MDM configuration, so every grant path (app,
    /// menu bar, CLI, MCP) enforces it here rather than in each UI.
    public init(
        profile: BaoProfile,
        signer: any BiometricSigner,
        openbao: OpenBaoClient,
        github: GitHubPushTokenClient = GitHubPushTokenClient(),
        t3Granter: (any T3GranterTransport)? = nil,
        macStore: (any MacGrantStore)? = nil,
        via: String,
        organizationPolicy: ManagedAppConfig = .load(),
        now: @escaping @Sendable () -> Date = { Date() },
        onRemoteGrantMinted: (@Sendable (String, Date) throws -> Void)? = nil,
        onRemoteGrantRolledBack: (@Sendable (String) -> Void)? = nil
    ) {
        do {
            let allowDemo = profile.isDemoProfile && (openbao.transport is DemoOpenBaoTransport)
            self.profile = try organizationPolicy.enforce(on: profile, allowDemo: allowDemo)
            self.policyViolation = nil
        } catch {
            self.profile = profile
            self.policyViolation = error.localizedDescription
        }
        self.jwtSigner = JWTSigner(signer: signer)
        self.openbao = openbao
        self.github = github
        self.t3Granter = t3Granter
        self.macStore = macStore
        self.via = via
        self.now = now
        self.onRemoteGrantMinted = onRemoteGrantMinted
        self.onRemoteGrantRolledBack = onRemoteGrantRolledBack
    }

    /// Executes a validated grant request. Biometrics are prompted with the helper-computed scope.
    public func execute(_ request: GrantRequest) async throws -> GrantOutcome {
        if let policyViolation {
            throw GrantRequestError.organizationPolicy(policyViolation)
        }
        try request.validate(against: profile)
        let reason = request.summary(profile: profile)

        switch request.target {
        case .mac:
            return try await grantMac(request, reason: reason)
        case .t3:
            return try await grantT3(request, reason: reason)
        }
    }

    /// The request a 15-minute personal token covers: read and write plus every key, or the
    /// default-selected policies for a profile with a custom policy catalog.
    public func personalTokenRequest(why: String) -> GrantRequest {
        GrantRequest(
            target: .mac,
            hours: 1,
            write: true,
            keys: profile.openbao.keys.map(\.name),
            why: why
        )
    }

    /// Mints a 15-minute personal token printed to the calling terminal/program.
    /// Enforces the exact same audit reason & ticket validation as direct grants, identifies
    /// stdout/caller delivery and server identity in the biometric prompt, and records `DIRECT=1`.
    public func mintPersonalToken(why: String) async throws -> String {
        if let policyViolation {
            throw GrantRequestError.organizationPolicy(policyViolation)
        }
        let request = personalTokenRequest(why: why)
        try request.validate(against: profile)
        let policies = request.openBaoPolicies(profile: profile)
        var reason = "15-minute token — \(DirectTokenDestination.caller.label) on \(profile.promptServerDescription): \(request.scopeDescription(profile: profile))"
        if !request.why.isEmpty {
            reason += " — \(request.why)"
        }
        let scope = "DIRECT=1 MINUTES=15 \(request.auditScope(profile: profile).replacingOccurrences(of: "HOURS=1 ", with: ""))"
        let signIn = try await signIn(reason: reason, scope: scope)
        do {
            let minted = try await mint(signIn: signIn, ttlSeconds: 15 * 60, GrantTokenParameters(
                role: profile.openbao.tokenRoles.mac,
                policies: policies,
                ttl: "\(15 * 60)s",
                displayName: "\(profile.openbao.jwtAuth.subject)-15m",
                metadata: metadata(on: "direct", why: request.why.isEmpty ? "terminal" : request.why, scope: scope)
            ))
            try? await openbao.revokeSelf(token: signIn)
            return minted.token
        } catch {
            try? await openbao.revokeSelf(token: signIn)
            throw error
        }
    }

    private func grantMac(_ request: GrantRequest, reason: String) async throws -> GrantOutcome {
        guard let macStore else {
            throw GrantRequestError.invalidTarget("local (no Keychain grant store on this platform)")
        }
        let old: String?
        let auditScope = request.auditScope(profile: profile)
        let signIn = try await signIn(reason: reason, scope: auditScope)
        let mintStartedAt = now()
        let minted: MintedToken
        do {
            minted = try await mint(signIn: signIn, ttlSeconds: request.hours * 3600, GrantTokenParameters(
                role: profile.openbao.tokenRoles.mac,
                policies: request.openBaoPolicies(profile: profile),
                ttl: "\(request.hours * 3600)s",
                displayName: "grant-local",
                metadata: metadata(on: "local", why: request.why, scope: auditScope)
            ))
        } catch {
            try? await openbao.revokeSelf(token: signIn)
            throw error
        }

        let effectiveTTL = min(request.hours * 3600, minted.leaseDurationSeconds)
        let grantDeadline = mintStartedAt.addingTimeInterval(TimeInterval(effectiveTTL))
        let artifacts: [MintedExtensionArtifact]
        do {
            artifacts = try await mintArtifacts(request, grantToken: minted.token, grantDeadline: grantDeadline)
            old = try macStore.replaceGrant(minted.token, artifacts: artifacts)
        } catch {
            // Never leave a live token that nothing holds a copy of. Revoking the grant also
            // revokes any leases its extensions created.
            try? await openbao.revokeToken(authToken: signIn, targetToken: minted.token)
            try? await openbao.revokeSelf(token: signIn)
            throw error
        }
        try? await openbao.revokeSelf(token: signIn)

        var replaced = false
        if let old, !old.isEmpty, old != minted.token {
            // The old grant has often expired already, so a failed revoke doesn't fail the new grant.
            // Report a replacement only when the server confirmed it.
            replaced = (try? await openbao.revokeSelf(token: old)) != nil
        }
        let duration = request.hours == 1 ? "1 hour" : "\(request.hours) hours"
        let saved = artifacts.isEmpty ? "" : " Saved \(artifacts.map(\.name).joined(separator: ", ")) to the Keychain."
        return GrantOutcome(
            message: "Saved grant on this device (\(duration)).\(saved) \(reason)",
            replacedOldGrant: replaced,
            accessor: minted.accessor,
            effectiveTTLSeconds: effectiveTTL,
            expiresAt: grantDeadline
        )
    }

    /// Where a direct token goes, named in the biometric prompt so the user knows who receives it.
    public enum DirectTokenDestination: Sendable {
        /// Shown in the BaoBuddy app.
        case app
        /// Printed to the terminal (or program) that ran the command.
        case caller

        var label: String {
            switch self {
            case .app: return String(localized: "Show token in BaoBuddy", table: "BaoBuddyCore", comment: "Where a token goes, in the Face ID / Touch ID prompt: the token is shown in the app.")
            case .caller: return String(localized: "Print token to the program that asked", table: "BaoBuddyCore", comment: "Where a token goes, in the Face ID / Touch ID prompt: the token is printed for the command-line program that asked for it.")
            }
        }
    }

    /// Mints a direct OpenBao/Vault token and returns it to the caller. The biometric prompt says
    /// where the token goes, and the JWT scope carries `DIRECT=1`, because unlike a Keychain grant
    /// the bearer token leaves BaoBuddy's control.
    public func mintDirectToken(_ request: GrantRequest, destination: DirectTokenDestination = .app) async throws -> GrantOutcome {
        if let policyViolation {
            throw GrantRequestError.organizationPolicy(policyViolation)
        }
        try request.validate(against: profile)
        let duration = GrantDurationText.hours(request.hours)
        var reason = String(
            localized: "\(destination.label) on \(profile.promptServerDescription) (\(duration)): \(request.scopeDescription(profile: profile))",
            table: "BaoBuddyCore",
            comment: "Grant summary in the Face ID / Touch ID prompt. %1$@ is where the grant or token goes (for example: Grant to Build Host, or Show token in BaoBuddy); %2$@ is the server; %3$@ is the duration (for example: 2 hours); %4$@ is what it can access."
        )
        if !request.why.isEmpty {
            reason += " — \(request.why)"
        }
        let scope = "DIRECT=1 \(request.auditScope(profile: profile))"
        let signIn = try await signIn(reason: reason, scope: scope)
        do {
            let mintStartedAt = now()
            let minted = try await mint(signIn: signIn, ttlSeconds: request.hours * 3600, GrantTokenParameters(
                role: profile.openbao.tokenRoles.mac,
                policies: request.openBaoPolicies(profile: profile),
                ttl: "\(request.hours * 3600)s",
                displayName: "grant-\(via)",
                metadata: metadata(on: "direct", why: request.why, scope: scope)
            ))
            let effectiveTTL = min(request.hours * 3600, minted.leaseDurationSeconds)
            let grantDeadline = mintStartedAt.addingTimeInterval(TimeInterval(effectiveTTL))
            let artifacts: [MintedExtensionArtifact]
            do {
                artifacts = try await mintArtifacts(request, grantToken: minted.token, grantDeadline: grantDeadline)
            } catch {
                try? await openbao.revokeToken(authToken: signIn, targetToken: minted.token)
                throw error
            }
            try? await openbao.revokeSelf(token: signIn)
            return GrantOutcome(
                message: String(localized: "Minted scoped token (\(duration)).", table: "BaoBuddyCore", comment: "Banner after a token is created. %@ is its duration, for example: 2 hours."),
                mintedToken: minted.token,
                accessor: minted.accessor,
                effectiveTTLSeconds: effectiveTTL,
                expiresAt: grantDeadline,
                artifacts: artifacts
            )
        } catch {
            try? await openbao.revokeSelf(token: signIn)
            throw error
        }
    }

    /// Revokes a grant delivered to a remote host by its accessor, after a fresh biometric sign-in.
    /// This works even when the remote host is compromised or unreachable, because the request goes
    /// straight to OpenBao/Vault. Requires `auth/token/revoke-accessor` in the granter policy.
    public func revokeRemoteGrant(accessor: String) async throws {
        if let policyViolation {
            throw GrantRequestError.organizationPolicy(policyViolation)
        }
        let reason = String(
            localized: "Revoke the grant on \(profile.targetDisplayName) (\(profile.promptServerDescription))",
            table: "BaoBuddyCore",
            comment: "Face ID / Touch ID prompt. %1$@ is the remote host's name; %2$@ is the server."
        )
        let signIn = try await signIn(reason: reason, scope: "REVOKE")
        do {
            try await openbao.revokeAccessor(authToken: signIn, accessor: accessor)
            try? await openbao.revokeSelf(token: signIn)
        } catch {
            try? await openbao.revokeSelf(token: signIn)
            throw error
        }
    }

    private func grantT3(_ request: GrantRequest, reason: String) async throws -> GrantOutcome {
        guard let t3Granter else {
            throw T3GranterError.installRefused("No remote granter transport configured")
        }
        // Fail closed if a real remote delivery has no accessor persistence hook configured.
        // Only the in-memory DemoGranterTransport may run without a durable recorder.
        if onRemoteGrantMinted == nil && !(t3Granter is DemoGranterTransport) {
            throw T3GranterError.installRefused("Cannot deliver a remote grant without durable accessor persistence")
        }

        // Fetch the target's SSH public key before prompting biometrics if SSH is requested.
        let sshPubKey = request.sshHosts.isEmpty ? "" : try await t3Granter.fetchPublicKey()

        let auditScope = request.auditScope(profile: profile)
        let signIn = try await signIn(reason: reason, scope: auditScope)

        var mintedToken: String?
        var mintedAccessor: String?
        var persistedAccessor = false
        var pushToken = ""
        do {
            let mintStartedAt = now()
            let minted = try await mint(signIn: signIn, ttlSeconds: request.hours * 3600, GrantTokenParameters(
                role: profile.openbao.tokenRoles.t3,
                policies: request.openBaoPolicies(profile: profile),
                ttl: "\(request.hours * 3600)s",
                displayName: "grant-remote",
                metadata: metadata(on: "remote", why: request.why, scope: auditScope)
            ))
            mintedToken = minted.token

            // Every remote grant MUST carry a non-empty accessor and persist durably BEFORE
            // any credentials leave this device over SSH.
            guard !minted.accessor.isEmpty else {
                throw OpenBaoError.grantMismatch("OpenBao returned an empty accessor for the remote grant")
            }
            mintedAccessor = minted.accessor

            let effectiveTTL = min(request.hours * 3600, minted.leaseDurationSeconds)
            let grantDeadline = mintStartedAt.addingTimeInterval(TimeInterval(effectiveTTL))
            let grantDeadlineEpoch = UInt64(max(0, Int64(floor(grantDeadline.timeIntervalSince1970))))

            if let onRemoteGrantMinted {
                try onRemoteGrantMinted(minted.accessor, grantDeadline)
                persistedAccessor = true
            }

            // An SSH certificate can't be revoked once signed. Recompute remaining TTL against the
            // anchored mint deadline right before signing, and verify `valid_before <= grantDeadline`
            // with zero positive grace window.
            let sshCert: String
            if !sshPubKey.isEmpty {
                let principals = request.sshPrincipals(profile: profile)
                let keyID = "grant via \(via): \(request.why.isEmpty ? "no reason given" : request.why)"
                let signNowEpoch = Int64(ceil(now().timeIntervalSince1970))
                let remainingSeconds = Int(Int64(grantDeadlineEpoch) - signNowEpoch)
                guard remainingSeconds > 0 else {
                    throw OpenBaoError.grantMismatch("grant lifetime already elapsed before SSH signing")
                }
                let signed = try await openbao.signSSHKey(
                    authToken: signIn,
                    parameters: SSHSignParameters(
                        role: profile.openbao.ssh.role,
                        publicKey: sshPubKey,
                        validPrincipals: principals,
                        ttl: "\(remainingSeconds)s",
                        keyID: keyID
                    )
                )
                let parsedCert = try OpenSSHCertificate.parse(signed)
                try parsedCert.verify(expectedPrincipals: principals, maxValidBeforeEpoch: grantDeadlineEpoch)
                sshCert = signed
            } else {
                sshCert = ""
            }

            if request.push {
                pushToken = try await mintPushToken(signIn: signIn)
            }

            let artifacts = try await mintArtifacts(request, grantToken: minted.token, grantDeadline: grantDeadline)
            let response = try await t3Granter.install(GrantInstallPayload(
                token: minted.token,
                sshCert: sshCert,
                pushToken: pushToken,
                artifacts: artifacts
            ))
            mintedToken = nil
            mintedAccessor = nil
            pushToken = ""
            try? await openbao.revokeSelf(token: signIn)
            return GrantOutcome(
                message: response,
                accessor: minted.accessor,
                effectiveTTLSeconds: effectiveTTL,
                expiresAt: grantDeadline
            )
        } catch {
            if let pending = mintedToken {
                if (try? await openbao.revokeToken(authToken: signIn, targetToken: pending)) != nil,
                   persistedAccessor,
                   let accessor = mintedAccessor, !accessor.isEmpty {
                    onRemoteGrantRolledBack?(accessor)
                }
            }
            if !pushToken.isEmpty {
                try? await github.revokeInstallationToken(pushToken)
            }
            try? await openbao.revokeSelf(token: signIn)
            throw error
        }
    }

    // MARK: - Helpers

    /// Mints the selected credential extensions with the grant token, so the grant's policies
    /// govern them and their leases end with the grant. Expiry is capped at `grantDeadline`.
    /// Callers revoke the grant on failure, which also revokes any leases already created.
    private func mintArtifacts(_ request: GrantRequest, grantToken: String, grantDeadline: Date) async throws -> [MintedExtensionArtifact] {
        let grantExpiry = Int64(floor(grantDeadline.timeIntervalSince1970))
        var artifacts: [MintedExtensionArtifact] = []
        for ext in request.selectedExtensions(profile: profile) {
            let artifact: MintedExtensionArtifact
            do {
                artifact = try await openbao.invokeExtension(ext, authToken: grantToken, now: now())
            } catch let OpenBaoError.httpError(code, _) where code == 403 {
                throw OpenBaoError.unexpectedResponse(String(
                    localized: "credential extension '\(ext.id)': the grant's policies don't allow \(ext.endpoint). Set the extension's policy, or add the path to a policy the grant carries.",
                    table: "BaoBuddyCore",
                    comment: "Error detail. %1$@ is a credential extension ID; %2$@ is an OpenBao path."
                ))
            }
            artifacts.append(MintedExtensionArtifact(
                name: artifact.name,
                content: artifact.content,
                expiresAt: min(artifact.expiresAt ?? grantExpiry, grantExpiry)
            ))
        }
        return artifacts
    }

    private func signIn(reason: String, scope: String) async throws -> String {
        try JWTSigner.validateAudience(for: profile)
        let jwt = try await jwtSigner.makeLoginJWT(config: profile.openbao.jwtAuth, reason: reason, scope: scope)
        return try await openbao.loginJWT(
            mount: profile.openbao.jwtAuth.mount,
            role: profile.openbao.jwtAuth.role,
            jwt: jwt
        )
    }

    /// Creates a grant and checks it against what was approved. A token that doesn't match is
    /// revoked immediately and never returned.
    private func mint(signIn: String, ttlSeconds: Int, _ parameters: GrantTokenParameters) async throws -> MintedToken {
        let minted = try await openbao.createGrantToken(authToken: signIn, parameters: parameters)
        do {
            try minted.verify(requestedPolicies: parameters.policies, maxTTLSeconds: ttlSeconds)
        } catch {
            try? await openbao.revokeToken(authToken: signIn, targetToken: minted.token)
            throw error
        }
        return minted
    }

    private func metadata(on: String, why: String, scope: String) -> [String: String] {
        [
            "on": on,
            "by": profile.openbao.jwtAuth.subject,
            "via": via,
            "why": why.isEmpty ? "none given" : why,
            "scope": scope
        ]
    }

    /// Prefers a server-side token endpoint so the GitHub App key never reaches this device.
    private func mintPushToken(signIn: String) async throws -> String {
        let tokenPath = profile.openbao.githubTokenPath.trimmingCharacters(in: .whitespacesAndNewlines)
        if !tokenPath.isEmpty {
            return try await openbao.mintGitHubToken(authToken: signIn, path: tokenPath)
        }
        // Legacy mode: the App private key is read into this process. See docs/THREAT_MODEL.md.
        let app = try await openbao.readGitHubApp(authToken: signIn, itemPath: profile.openbao.githubAppItem)
        return try await github.mintPushToken(app: app)
    }
}
