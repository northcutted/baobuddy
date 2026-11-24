import BaoBuddyCore
import BaoBuddySSH
import Foundation

#if os(macOS)
import AppKit
@main
struct BaoBuddyHelperCLI {
    static func main() {
        // Filter out macOS LaunchServices `-psn_*` argument when opened from Finder / Spotlight / Login Items.
        let args = Array(CommandLine.arguments.dropFirst().filter { !$0.hasPrefix("-psn_") })
        guard let subcommand = args.first, subcommand != "menubar" else {
            // Run NSApplication directly on Thread 1 (never inside `MainActor.run`, which would
            // occupy DispatchQueue.main forever and deadlock every `@MainActor Task`).
            MainActor.assumeIsolated { MenuBarLauncher.run() }
            return
        }
        let rest = Array(args.dropFirst())
        Task {
            await runSubcommand(subcommand, rest: rest)
            exit(0)
        }
        dispatchMain()
    }

    private static func runSubcommand(_ subcommand: String, rest: [String]) async {
        do {
            switch subcommand {
            case "server-setup":
                try await ServerCommands.runServerSetup(args: rest)
            case "device":
                try await ServerCommands.runDevice(args: rest)
            case "export-profile":
                try await ServerCommands.runExportProfile(args: rest)
            case "tofu-init":
                try ServerCommands.runTofuInit(args: rest)
            case "mcp":
                try await MacMCPCommand.runMCP(args: rest)
            case "agent-prompt":
                try MacMCPCommand.runAgentPrompt(args: rest)
            case "init":
                try runInit(args: rest)
            case "pubkey":
                try runPubkey(args: rest)
            case "import-profile":
                try runImportProfile(args: rest)
            case "profile":
                try runProfileCommand(args: rest)
            case "profiles":
                runProfiles()
            case "use":
                try runUseProfile(args: rest)
            case "health":
                try await runHealth(args: rest)
            case "grant":
                try await runGrant(args: rest)
            case "personal-token":
                try await runPersonalToken(args: rest)
            case "status":
                try await runStatus(args: rest)
            case "revoke":
                try await runRevoke(args: rest)
            case "ssh-key":
                try runSSHKey(args: rest)
            case "-h", "--help", "help":
                printUsage()
            default:
                fputs("bao-buddy: unknown command '\(subcommand)'\n", stderr)
                printUsage()
                exit(2)
            }
        } catch {
            fputs("bao-buddy: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }

    static func keyStore(for profile: BaoProfile, deviceName: String = "mac") -> SecureEnclaveKeyStore {
        SecureEnclaveKeyStore.resolve(for: profile, deviceName: deviceName)
    }

    private struct ResolvedCLIKeyContext {
        let store: SecureEnclaveKeyStore
        let registerCommand: String
    }

    private static func resolveKeyStoreForCLI(args: [String]) throws -> ResolvedCLIKeyContext {
        let opts = parseFlags(args)
        if let addr = opts["addr"] ?? ProcessInfo.processInfo.environment["BAO_ADDR"] ?? ProcessInfo.processInfo.environment["VAULT_ADDR"],
           !addr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           opts["profile"] == nil,
           opts["profile-id"] == nil,
           opts["addr"] != nil || opts["mount"] != nil {
            let trimmedAddr = addr.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let url = URL(string: trimmedAddr) else {
                throw OpenBaoError.invalidBaseURL("invalid OpenBao address")
            }
            try OpenBaoClient.validateEndpointURL(url, allowDemo: false)
            let subject = opts["subject"] ?? ProcessInfo.processInfo.environment["USER"] ?? ""
            let mount = opts["mount"] ?? BaoServerAdmin.defaultMount(subject: subject)
            let ns = opts["namespace"] ?? ProcessInfo.processInfo.environment["BAO_NAMESPACE"] ?? ProcessInfo.processInfo.environment["VAULT_NAMESPACE"] ?? ""
            let caPath = (opts["cacert"] ?? ProcessInfo.processInfo.environment["BAO_CACERT"] ?? ProcessInfo.processInfo.environment["VAULT_CACERT"] ?? "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let caPEM = caPath.isEmpty
                ? ""
                : try String(contentsOfFile: caPath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
            let mtlsIdentity = opts["mtls-identity"] ?? ""
            let store = SecureEnclaveKeyStore.scoped(
                address: trimmedAddr,
                namespace: ns,
                mount: mount,
                caPEM: caPEM,
                mtlsClientIdentity: mtlsIdentity,
                deviceName: "mac"
            )
            let registerCmd = BaoServerAdmin.renderDeviceAddCommand(
                address: trimmedAddr,
                namespace: ns,
                caCertPath: caPath,
                mtlsClientIdentity: mtlsIdentity,
                mount: mount,
                selfKey: false
            )
            return ResolvedCLIKeyContext(store: store, registerCommand: registerCmd)
        }
        if let profile = try? loadActiveProfile(selector: opts["profile"], exactID: opts["profile-id"]) {
            let store = SecureEnclaveKeyStore.scoped(for: profile, deviceName: "mac")
            let registerCmd = BaoServerAdmin.renderDeviceAddCommand(
                address: profile.openbao.address,
                namespace: profile.openbao.namespace,
                caCertPath: profile.openbao.isTLSPinned ? "<ca.pem>" : "",
                mtlsClientIdentity: profile.openbao.mtlsClientIdentity,
                mount: profile.openbao.jwtAuth.mount,
                selfKey: false
            )
            return ResolvedCLIKeyContext(store: store, registerCommand: registerCmd)
        }
        throw ProfileError.notConfigured(
            "Keys are scoped per OpenBao server trust domain and JWT mount. Import/save a profile first, or pass --addr https://... --mount jwt-<user> (plus --namespace, --cacert, --mtls-identity if used)."
        )
    }

    private static func runInit(args: [String]) throws {
        let overwrite = args.contains("--force")
        let resolved = try resolveKeyStoreForCLI(args: args)
        let pem = try resolved.store.ensureKey(overwrite: overwrite)
        let fp = try resolved.store.publicKeyFingerprint()
        fputs("Secure Enclave P-256 key ready for \(resolved.store.scopeServer ?? "server") (sha256:\(fp)). Register the printed PEM on OpenBao by piping it into:\n", stderr)
        fputs("  \(resolved.registerCommand)\n", stderr)
        print(pem)
    }

    private static func runPubkey(args: [String]) throws {
        let resolved = try resolveKeyStoreForCLI(args: args)
        print(try resolved.store.publicKeyPEM())
    }

    struct EffectiveProfileState {
        let managed: ManagedAppConfig
        let profiles: [BaoProfile]
        let activeID: String?
    }

    static func effectiveProfiles() -> EffectiveProfileState {
        let managed = ManagedAppConfig.load()
        let collection = MultiProfileStore().load()
        let legacy = collection.profiles.isEmpty ? (try? FileProfileStore().load()) : nil
        let localList = collection.profiles.isEmpty ? (legacy.map { [$0] } ?? []) : collection.profiles
        let effective = managed.effectiveProfiles(local: localList)
        let activeID = collection.activeProfileID.flatMap { id in effective.contains(where: { $0.id == id }) ? id : nil }
            ?? effective.first?.id
        return EffectiveProfileState(managed: managed, profiles: effective, activeID: activeID)
    }

    static func loadActiveProfile(selector: String? = nil, exactID: String? = nil) throws -> BaoProfile {
        let managed = ManagedAppConfig.load()
        let collection = MultiProfileStore().load()
        let legacy = collection.profiles.isEmpty ? (try? FileProfileStore().load()) : nil
        if let exactID = exactID?.trimmingCharacters(in: .whitespacesAndNewlines), !exactID.isEmpty {
            if let selector = selector?.trimmingCharacters(in: .whitespacesAndNewlines), !selector.isEmpty,
               selector.lowercased() != exactID.lowercased() {
                throw ProfileError.invalidField("--profile-id", "cannot combine conflicting --profile and --profile-id")
            }
            return try managed.resolveProfileExact(id: exactID, localCollection: collection, legacyProfile: legacy)
        }
        return try managed.resolveProfile(selector: selector, localCollection: collection, legacyProfile: legacy)
    }

    static func resolveRemoteTargetFromCLI(opts: [String: String], profile: BaoProfile) throws -> BaoProfile {
        let exactID = opts["target-id"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let targetName = (opts["target"] ?? opts["remote-target"])?.trimmingCharacters(in: .whitespacesAndNewlines)
        let sshDest = opts["target-ssh"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        let hostKeyFP = opts["target-host-key-fp"]?.trimmingCharacters(in: .whitespacesAndNewlines)

        if let exactID, !exactID.isEmpty {
            if let targetName, !targetName.isEmpty, targetName.lowercased() != exactID.lowercased() {
                throw ProfileError.invalidRemoteTarget("cannot combine conflicting --target and --target-id")
            }
            let matched = try profile.resolveRemoteTargetExact(
                id: exactID,
                sshDestination: sshDest,
                hostKeyFingerprint: hostKeyFP
            )
            return profile.focusing(remoteTarget: matched)
        }
        if let targetName, !targetName.isEmpty {
            guard let matched = try profile.resolveRemoteTarget(named: targetName) else {
                let known = profile.configuredRemoteTargets.map { "\($0.displayName) [\($0.id)]" }.joined(separator: ", ")
                throw ProfileError.invalidRemoteTarget("unknown target '\(targetName)' (configured: \(known.isEmpty ? "none" : known))")
            }
            if let sshDest, !sshDest.isEmpty, matched.sshDestination != sshDest {
                throw ProfileError.invalidRemoteTarget("target '\(targetName)' does not match --target-ssh '\(sshDest)'")
            }
            if let hostKeyFP, !hostKeyFP.isEmpty,
               matched.hostKeyFingerprint.isEmpty || matched.hostKeyFingerprint != hostKeyFP.lowercased() {
                throw ProfileError.invalidRemoteTarget("target '\(targetName)' does not match --target-host-key-fp")
            }
            return profile.focusing(remoteTarget: matched)
        }
        return profile
    }

    /// Saves an imported or exported profile under the same rules as the apps: the MDM lock and
    /// pinning policy apply, the incoming `id` is never trusted, and managed profiles can't be
    /// replaced. A profile matching the same issuer binding (endpoint, namespace, TLS pin, mTLS
    /// identity), mount, and primary remote host updates the existing entry; distinct trust domains
    /// are saved side-by-side.
    static func upsertProfile(_ incoming: BaoProfile) throws -> BaoProfile {
        let managed = ManagedAppConfig.load()
        let multi = MultiProfileStore()
        var collection = multi.load()
        let plan = try ProfileImportPlan.make(
            importing: incoming,
            existing: collection.profiles,
            managedIDs: Set(managed.profiles.map(\.id)),
            organizationPolicy: managed
        )
        for notice in plan.notices {
            FileHandle.standardError.write(Data("Note: \(notice)\n".utf8))
        }
        if let replaced = plan.replaces {
            let changes = plan.changes.isEmpty ? "" : " Changed: \(plan.changes.joined(separator: ", "))."
            FileHandle.standardError.write(Data("Replacing profile '\(replaced.displayName)'.\(changes)\n".utf8))
        }
        let profile = plan.profile
        if let idx = collection.profiles.firstIndex(where: { $0.id == profile.id }) {
            collection.profiles[idx] = profile
        } else {
            collection.profiles.append(profile)
        }
        collection.activeProfileID = profile.id
        try multi.save(collection)
        try? FileProfileStore().save(profile)
        return profile
    }

    private static func runImportProfile(args: [String]) throws {
        let data: Data
        if let path = args.first, path != "-" {
            if path.hasPrefix("baobuddy://") || path.hasPrefix("baogrant://") || path.hasPrefix("baobuddy-profile:") {
                data = Data(path.utf8)
            } else {
                data = try Data(contentsOf: URL(fileURLWithPath: path))
            }
        } else {
            data = FileHandle.standardInput.readDataToEndOfFile()
        }
        let rawText = String(data: data, encoding: .utf8) ?? ""
        let decoded = try ProfileTransferCodec.decode(text: rawText)
        let saved = try upsertProfile(decoded)
        print("Saved BaoBuddy profile '\(saved.displayName)' (\(saved.openbao.address))")
    }

    private static func runProfileCommand(args: [String]) throws {
        guard let action = args.first else {
            fputs("usage: bao-buddy profile <list|use|show|remove> [name]\n", stderr)
            exit(2)
        }
        let rest = Array(args.dropFirst())
        switch action {
        case "list":
            runProfiles()
        case "use":
            try runUseProfile(args: rest)
        case "show":
            let opts = parseFlags(rest)
            let positional = rest.first(where: { !$0.hasPrefix("--") })
            let profile = try loadActiveProfile(selector: opts["profile"] ?? positional)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(profile.forSharing)
            guard let jsonText = String(data: data, encoding: .utf8) else {
                throw OpenBaoError.unexpectedResponse("failed to encode profile JSON")
            }
            if opts["copy"] != nil, ManagedAppConfig.load().disableClipboard {
                fputs("Clipboard copy is disabled by your organization's MDM policy.\n", stderr)
            } else if opts["copy"] != nil {
                let pb = NSPasteboard.general
                pb.clearContents()
                pb.setString(jsonText, forType: .string)
                fputs("Copied '\(profile.displayName)' profile JSON to clipboard.\n", stderr)
            }
            if opts["qr"] != nil {
                let uri = try ProfileTransferCodec.encodeURI(profile)
                if let ascii = MacQRCode.renderTerminalASCII(from: uri) {
                    print("Scan with BaoBuddy on your iPhone (or the iPhone Camera app):\n")
                    print(ascii)
                    return
                }
            }
            print(jsonText)
        case "remove", "delete":
            let managed = ManagedAppConfig.load()
            guard !managed.lockProfiles else {
                throw ProfileTransferError.lockedByOrganization
            }
            guard let name = rest.first(where: { !$0.hasPrefix("--") }), !name.isEmpty else {
                fputs("usage: bao-buddy profile remove <name>\n", stderr)
                exit(2)
            }
            let managedIDs = Set(managed.profiles.map(\.id))
            let multi = MultiProfileStore()
            var collection = multi.load()
            let target = try BaoProfile.resolveProfile(selector: name, in: collection.profiles)
            guard !managedIDs.contains(target.id) else {
                throw ProfileError.invalidField("id", "managed profiles can't be removed on this Mac")
            }
            collection.profiles.removeAll { $0.id == target.id }
            if collection.activeProfileID == target.id {
                collection.activeProfileID = collection.profiles.first?.id
            }
            try multi.save(collection)
            if let nextActive = collection.profiles.first(where: { $0.id == collection.activeProfileID }) {
                try? FileProfileStore().save(nextActive)
            } else {
                try? FileProfileStore().delete()
            }
            print("Removed BaoBuddy profile '\(target.displayName)'.")
        default:
            fputs("bao-buddy profile: unknown subcommand '\(action)' (expected list, use, show, or remove)\n", stderr)
            exit(2)
        }
    }

    private static func runHealth(args: [String]) async throws {
        let opts = parseFlags(args)
        let profile = try loadActiveProfile(selector: opts["profile"])
        let health = try await OpenBaoClient(profile: profile).checkHealth()
        let ver = health.version.isEmpty ? "" : " v\(health.version)"
        if health.sealed {
            fputs("\(profile.displayName) (\(profile.openbao.address)): reachable over TLS, but SEALED\(ver)\n", stderr)
            exit(1)
        }
        print("\(profile.displayName) (\(profile.openbao.address)): OK — OpenBao\(ver) initialized and unsealed")
    }

    private static func runProfiles() {
        let state = effectiveProfiles()
        let managedIDs = Set(state.managed.profiles.map(\.id))
        if state.profiles.isEmpty {
            print("No profiles saved. Import one with `bao-buddy import-profile` or add one in the menu bar Settings.")
            return
        }
        for item in state.profiles {
            let marker = item.id == state.activeID ? "*" : " "
            let remote = item.hasRemoteTarget ? " [SSH: \(item.targetDisplayName)]" : ""
            let mdmTag = managedIDs.contains(item.id) ? " [MDM]" : ""
            print("\(marker) \(item.displayName) — \(item.openbao.address)\(remote)\(mdmTag)")
        }
    }

    private static func runUseProfile(args: [String]) throws {
        guard let name = args.first, !name.isEmpty else {
            fputs("usage: bao-buddy use <profile-name>\n", stderr)
            exit(2)
        }
        let state = effectiveProfiles()
        let matched: BaoProfile
        do {
            matched = try BaoProfile.resolveProfile(selector: name, in: state.profiles)
        } catch ProfileError.notConfigured where state.managed.lockProfiles {
            throw ProfileTransferError.lockedByOrganization
        }
        let multi = MultiProfileStore()
        var collection = multi.load()
        collection.activeProfileID = matched.id
        try multi.save(collection)
        if !state.managed.profiles.contains(where: { $0.id == matched.id }) {
            try? FileProfileStore().save(matched)
        }
        print("Active BaoBuddy profile: \(matched.displayName) (\(matched.openbao.address))")
    }

    /// `local` (this Mac) or `remote` (the profile's remote target). `mac` and `t3` are accepted aliases.
    static func parseTarget(_ raw: String?) throws -> GrantTarget {
        switch (raw ?? "local").lowercased() {
        case "local", "mac": return .mac
        case "remote", "t3": return .t3
        case let other: throw GrantRequestError.invalidTarget(other)
        }
    }

    /// Prefers the Secure Enclave SSH key (`bao-buddy ssh-key`); falls back to `/usr/bin/ssh`
    /// with `~/.ssh/id_ed25519` for granter hosts set up before that existed.
    static func remoteTransport(for profile: BaoProfile) -> any T3GranterTransport {
        if let identity = try? SSHKeyStore().loadIdentity() {
            return NIOSSHGranterClient(config: profile.t3Granter, identity: identity)
        }
        return MacSSHGranterClient(config: profile.t3Granter)
    }

    private static func runGrant(args: [String]) async throws {
        let opts = parseFlags(args)
        var profile = try loadActiveProfile(selector: opts["profile"], exactID: opts["profile-id"])
        profile = try resolveRemoteTargetFromCLI(opts: opts, profile: profile)
        let rawOn = (opts["on"] ?? "local").lowercased()
        let directMode = rawOn == "direct"
        let target: GrantTarget = directMode ? .mac : try parseTarget(opts["on"])
        var words: [String] = []
        if let hours = opts["hours"], !hours.isEmpty { words.append("HOURS=\(hours)") }
        if let policies = opts["policies"], !policies.isEmpty { words.append("POLICIES=\(policies)") }
        if let write = opts["write"], !write.isEmpty { words.append("WRITE=\(write)") }
        if let keys = opts["keys"], !keys.isEmpty { words.append("KEYS=\(keys)") }
        if let ssh = opts["ssh"], !ssh.isEmpty { words.append("SSH=\(ssh)") }
        if let push = opts["push"], !push.isEmpty { words.append("PUSH=\(push)") }
        if let ext = opts["ext"], !ext.isEmpty { words.append("EXT=\(ext)") }
        if let why = opts["why"], !why.isEmpty { words.append("WHY=\(why)") }

        let request = try GrantRequest.parse(requestString: words.joined(separator: " "), target: target, profile: profile)

        if directMode {
            guard request.extensions.isEmpty else {
                throw GrantRequestError.invalidTarget(
                    "direct (credential extensions are delivered to this Mac's Keychain with --on local, or to a remote target)"
                )
            }
            let orchestrator = GrantOrchestrator(
                profile: profile,
                signer: keyStore(for: profile),
                openbao: try OpenBaoClient(profile: profile),
                via: "mac"
            )
            let outcome = try await orchestrator.mintDirectToken(request, destination: .caller)
            guard let token = outcome.mintedToken else {
                throw OpenBaoError.unexpectedResponse("missing minted token")
            }
            GrantActivityStore().record(GrantActivityEntry(
                action: .directToken,
                serverName: profile.displayName,
                namespace: profile.openbao.namespace,
                targetName: "Direct Token",
                policies: request.openBaoPolicies(profile: profile),
                hours: request.hours,
                why: request.why,
                elevated: request.isElevated(profile: profile),
                via: "cli"
            ))
            print(token)
            return
        }

        let granter = remoteTransport(for: profile)
        if request.target == .t3 {
            let running = await granter.runningTasks()
            if running.brokerUnavailable {
                guard confirmProceed("Couldn't check running tasks on \(profile.targetDisplayName). Grant anyway? [y/N]: ") else {
                    fputs("Stopped; nothing was granted.\n", stderr)
                    exit(1)
                }
            } else if !running.tasks.isEmpty {
                fputs("\(running.tasks.count) task(s) are running on \(profile.targetDisplayName), and this grant would reach them:\n", stderr)
                for task in running.tasks {
                    fputs("  \(task)\n", stderr)
                }
                guard confirmProceed("Grant anyway? [y/N]: ") else {
                    fputs("Stopped; nothing was granted.\n", stderr)
                    exit(1)
                }
            }
        }

        let focusedProfile = profile
        let accessorStore = GrantAccessorStore()
        let orchestrator = GrantOrchestrator(
            profile: focusedProfile,
            signer: keyStore(for: focusedProfile),
            openbao: try OpenBaoClient(profile: focusedProfile),
            t3Granter: granter,
            macStore: MacKeychainGrantStore(profile: focusedProfile),
            via: "mac",
            onRemoteGrantMinted: { accessor, expiresAt in
                try accessorStore.record(for: focusedProfile, accessor: accessor, expiresAt: expiresAt)
            },
            onRemoteGrantRolledBack: { accessor in
                try? accessorStore.remove(for: focusedProfile, accessor: accessor)
            }
        )
        let outcome = try await orchestrator.execute(request)
        GrantActivityStore().record(GrantActivityEntry(
            action: .granted,
            serverName: focusedProfile.displayName,
            namespace: focusedProfile.openbao.namespace,
            targetName: request.target == .t3 ? focusedProfile.targetDisplayName : "This Mac",
            policies: request.openBaoPolicies(profile: focusedProfile),
            hours: request.hours,
            why: request.why,
            elevated: request.isElevated(profile: focusedProfile),
            via: "cli"
        ))
        print(outcome.message)
    }

    /// Revokes the grant on this Mac or on the remote target. A remote grant is revoked through
    /// OpenBao/Vault by accessor (Touch ID), so it doesn't depend on the remote host cooperating;
    /// the host is then asked to delete its copies.
    private static func runRevoke(args: [String]) async throws {
        let opts = parseFlags(args)
        var profile = try loadActiveProfile(selector: opts["profile"], exactID: opts["profile-id"])
        profile = try resolveRemoteTargetFromCLI(opts: opts, profile: profile)
        let openbao = try OpenBaoClient(profile: profile)
        switch try parseTarget(opts["on"]) {
        case .mac:
            let store = MacKeychainGrantStore(profile: profile)
            guard let token = try store.readGrant(), !token.isEmpty else {
                print("No grant saved on this Mac for \(profile.displayName).")
                return
            }
            try await openbao.revokeSelf(token: token)
            do {
                try store.deleteRevokedGrant(matching: token)
            } catch {
                throw LocalGrantCleanupError(underlying: error)
            }
            GrantActivityStore().record(GrantActivityEntry(
                action: .revoked,
                serverName: profile.displayName,
                namespace: profile.openbao.namespace,
                targetName: "This Mac",
                via: "cli"
            ))
            print("Revoked the grant on this Mac.")
        case .t3:
            let accessors = GrantAccessorStore()
            let recorded = try accessors.entries(for: profile)
            var revokedOnServer = false
            if !recorded.isEmpty {
                let orchestrator = GrantOrchestrator(profile: profile, signer: keyStore(for: profile), openbao: openbao, via: "mac")
                for entry in recorded {
                    try await orchestrator.revokeRemoteGrant(accessor: entry.accessor)
                    try accessors.remove(for: profile, accessor: entry.accessor)
                }
                revokedOnServer = true
                print("Revoked \(recorded.count == 1 ? "the grant" : "\(recorded.count) grants") on \(profile.targetDisplayName) through OpenBao.")
            }
            do {
                let message = try await remoteTransport(for: profile).revoke()
                print(message)
            } catch {
                if revokedOnServer {
                    fputs("The token is revoked, but \(profile.targetDisplayName) didn't confirm deleting its copies: \(error.localizedDescription)\n", stderr)
                } else {
                    throw error
                }
            }
            GrantActivityStore().record(GrantActivityEntry(
                action: .revoked,
                serverName: profile.displayName,
                namespace: profile.openbao.namespace,
                targetName: profile.targetDisplayName,
                via: "cli"
            ))
            if !revokedOnServer {
                fputs("No accessor was recorded for this grant, so only \(profile.targetDisplayName)'s word confirms it was revoked.\n", stderr)
            }
        }
    }

    private static func runSSHKey(args: [String]) throws {
        let identity = try SSHKeyStore().ensureSecureEnclaveIdentity(overwrite: args.contains("--force"))
        let host = Host.current().localizedName ?? "mac"
        let comment = "baobuddy-" + host.lowercased().filter { $0.isLetter || $0.isNumber || $0 == "-" }
        fputs("Secure Enclave SSH key ready. Add this line to the granter host's authorized_keys (with its forced command):\n", stderr)
        print(identity.openSSHPublicKey(comment: comment))
    }

    private static func runPersonalToken(args: [String]) async throws {
        let opts = parseFlags(args)
        let profile = try loadActiveProfile(selector: opts["profile"], exactID: opts["profile-id"])
        let orchestrator = GrantOrchestrator(
            profile: profile,
            signer: keyStore(for: profile),
            openbao: try OpenBaoClient(profile: profile),
            macStore: MacKeychainGrantStore(profile: profile),
            via: "mac"
        )
        let token = try await orchestrator.mintPersonalToken(why: opts["why"] ?? "")
        print(token)
    }

    private static func runStatus(args: [String]) async throws {
        let opts = parseFlags(args)
        var profile = try loadActiveProfile(selector: opts["profile"], exactID: opts["profile-id"])
        profile = try resolveRemoteTargetFromCLI(opts: opts, profile: profile)
        let scope = (opts["on"] ?? "all").lowercased()

        if scope == "remote" || scope == "t3" {
            print(try await remoteTransport(for: profile).status())
            return
        }

        if scope == "all" || scope == "local" || scope == "mac" {
            let store = MacKeychainGrantStore(profile: profile)
            print("This Mac (\(profile.displayName), Keychain service \(store.service)):")
            var lookup: TokenLookupInfo?
            if let token = try store.readGrant() {
                lookup = try await OpenBaoClient(profile: profile).lookupSavedGrant(token: token)
            }
            if let info = lookup, info.ttlSeconds > 0 {
                let policies = info.policies.filter { $0 != "default" }.joined(separator: ", ")
                let ttl = MenuBarState.formatTTL(info.ttlSeconds)
                print("  Active: \(ttl) remaining (\(policies.isEmpty ? "no policies" : policies))")
                if !info.why.isEmpty {
                    print("  Why: \(info.why)")
                }
                let artifacts = try store.artifactNames()
                if !artifacts.isEmpty {
                    print("  Credentials in Keychain (service \(store.artifactServiceName)): \(artifacts.joined(separator: ", "))")
                }
            } else {
                print("  No active grant.")
            }
        }

        if scope == "all" && profile.hasRemoteTarget {
            print("\(profile.targetDisplayName):")
            let raw = try await remoteTransport(for: profile).status()
            for line in raw.split(separator: "\n") {
                print("  \(line)")
            }
        }
    }

    /// Flags that never take a value, so `--save mine` doesn't swallow a positional argument.
    static let booleanFlags: Set<String> = [
        "add-self", "copy", "include-self", "print-config", "qr",
        "require-reason-elevated", "require-reason", "save", "self", "token-stdin", "force"
    ]

    /// Parses `--flag value`, `--flag=value`, and boolean `--flag` (see `booleanFlags`).
    static func parseFlags(_ args: [String]) -> [String: String] {
        parseArguments(args).flags
    }

    /// Arguments that aren't flags or flag values, matching how `parseFlags` pairs them.
    static func positionalArgs(_ args: [String]) -> [String] {
        parseArguments(args).positional
    }

    private static func parseArguments(_ args: [String]) -> (flags: [String: String], positional: [String]) {
        var flags: [String: String] = [:]
        var positional: [String] = []
        var index = 0
        while index < args.count {
            let arg = args[index]
            if arg == "--" {
                positional += args[(index + 1)...]
                break
            }
            if arg.hasPrefix("--") {
                let body = String(arg.dropFirst(2))
                if let eq = body.firstIndex(of: "=") {
                    flags[String(body[..<eq])] = String(body[body.index(after: eq)...])
                } else if booleanFlags.contains(body) {
                    flags[body] = "1"
                } else if index + 1 < args.count, !args[index + 1].hasPrefix("--") {
                    flags[body] = args[index + 1]
                    index += 1
                } else {
                    flags[body] = "1"
                }
            } else {
                positional.append(arg)
            }
            index += 1
        }
        return (flags, positional)
    }

    private static func confirmProceed(_ prompt: String) -> Bool {
        fputs(prompt, stderr)
        guard let line = readLine(strippingNewline: true) else { return false }
        return line.lowercased().hasPrefix("y")
    }

    private static func printUsage() {
        let usage = """
        usage: bao-buddy <command> [options]

        setup & server admin (uses BAO_ADDR and BAO_TOKEN/VAULT_TOKEN, or --token-stdin):
          server-setup --subject USER --policies P1,P2 [--add-self] [--cidrs ...]
                                     Bootstrap OpenBao/Vault granter policy, token role, and ES256 JWT auth
          device add [--self | --file PEM]
                                     Register a Mac/iPhone Secure Enclave PEM (reads stdin by default)
          device list                List registered device key fingerprints on OpenBao
          device remove <prefix>     Revoke a lost device by SHA-256 fingerprint prefix
          export-profile [--policies P1,P2] [--elevated P2] [--copy] [--save]
                                     Print (and optionally copy/save) a BaoBuddy v1 profile JSON

        daily use:
          (no args) | menubar        Start macOS Menu Bar status icon for live grants
          init [--force]             Create Secure Enclave P-256 key and print PEM public key
          pubkey                     Print Secure Enclave PEM public key
          import-profile [FILE | -]  Import a BaoBuddy v1 profile JSON (and make it active)
          profile <list|use|show|remove> [NAME] [--copy]
                                     Manage saved server profiles (aliases: `profiles`, `use`)
          health [--profile NAME]    Verify OpenBao/Vault reachability, TLS pin, and seal state
          grant --on local|remote|direct [--hours N] [--policies P1,P2] [--ext ID1,ID2] --why TEXT
                                     Approve a grant with Touch ID (`direct` prints token to stdout;
                                     --ext mints the profile's credential extensions with the grant)
          revoke --on local|remote   Revoke the grant (remote: through OpenBao by accessor, with Touch ID)
          personal-token --why TEXT  Approve a 15-minute token with Touch ID
          ssh-key [--force]          Create the Secure Enclave SSH key for remote delivery and print it
          status [--on all|local|remote]
                                     Show active Mac and remote target grant status
        """
        fputs(usage + "\n", stderr)
    }
}
#endif
