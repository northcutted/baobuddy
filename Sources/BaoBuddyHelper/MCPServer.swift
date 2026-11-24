#if os(macOS)
import AppKit
import BaoBuddyCore
import Foundation

/// Runs the zero-dependency stdio MCP server (`bao-buddy mcp`) and CLI agent-prompt generator.
enum MacMCPCommand {
    static func runMCP(args: [String]) async throws {
        let opts = BaoBuddyHelperCLI.parseFlags(args)
        if opts["print-config"] != nil {
            let bin = "/Applications/BaoBuddyHelper.app/Contents/MacOS/BaoBuddyHelper"
            print("# Claude Code / Cursor / Windsurf / Antigravity (.mcp.json)")
            print(BaoAgentPrompts.renderMCPConfigJSON(binaryPath: bin))
            print("\n# OpenAI Codex (~/.codex/config.toml)")
            print(BaoAgentPrompts.renderCodexMCPConfigTOML(binaryPath: bin))
            return
        }

        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0"
        let server = BaoMCPServer(backend: LiveMacMCPBackend(), serverVersion: version)

        // Read newline-delimited JSON-RPC 2.0 messages from stdin; write strictly one JSON line per
        // response. A line over 1 MiB is answered with an error and discarded.
        let maxLine = 1 << 20
        while let line = readLine(strippingNewline: true) {
            if line.utf8.count > maxLine {
                let error = #"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Request too large"}}"#
                FileHandle.standardOutput.write(Data((error + "\n").utf8))
                continue
            }
            if let reply = await server.handleLine(line) {
                FileHandle.standardOutput.write(Data((reply + "\n").utf8))
            }
        }
    }

    static func runAgentPrompt(args: [String]) throws {
        let opts = BaoBuddyHelperCLI.parseFlags(args)
        let profile = try? BaoBuddyHelperCLI.loadActiveProfile(selector: opts["profile"])
        let markdown = BaoAgentPrompts.renderAgentsMarkdown(profile: profile)
        if opts["copy"] != nil {
            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setString(markdown, forType: .string)
            fputs("Copied AGENTS.md / CLAUDE.md rule to clipboard.\n", stderr)
        }
        print(markdown)
    }
}

private struct LiveMacMCPBackend: BaoMCPBackend {
    func listProfiles() async -> [BaoProfile] {
        BaoBuddyHelperCLI.effectiveProfiles().profiles
    }

    func activeProfile(selector: String?) async throws -> BaoProfile {
        try BaoBuddyHelperCLI.loadActiveProfile(selector: selector)
    }

    func status(profile: BaoProfile, targetScope: String, remoteTarget: String?) async -> BaoMCPStatusSnapshot {
        // The server core resolves `remote_target` (and rejects unknown names) before calling this.
        let resolved = profile

        var localUnavailable = false
        var localActive = false
        var localTTL = 0
        var localPolicies: [String] = []
        var localWhy = ""

        if targetScope == "all" || targetScope == "local" || targetScope == "mac" {
            do {
                if let token = try MacKeychainGrantStore(profile: resolved).readGrant(),
                   let info = try await OpenBaoClient(profile: resolved).lookupSavedGrant(token: token) {
                    localActive = info.ttlSeconds > 0
                    localTTL = info.ttlSeconds
                    localPolicies = info.policies.filter { $0 != "default" }
                    localWhy = info.why
                }
            } catch {
                localUnavailable = true
            }
        }

        var remoteName: String?
        var remoteText: String?
        if (targetScope == "all" || targetScope == "remote" || targetScope == "t3") && resolved.hasRemoteTarget {
            remoteName = resolved.targetDisplayName
            let granter = BaoBuddyHelperCLI.remoteTransport(for: resolved)
            remoteText = (try? await granter.status()) ?? "unavailable"
        }

        return BaoMCPStatusSnapshot(
            serverName: resolved.displayName,
            namespace: resolved.openbao.namespace,
            localActive: localActive,
            localUnavailable: localUnavailable,
            localTTLSeconds: localTTL,
            localPolicies: localPolicies,
            localWhy: localWhy,
            remoteTargetName: remoteName,
            remoteStatusText: remoteText
        )
    }

    func checkHealth(profile: BaoProfile) async throws -> ServerHealth {
        try await OpenBaoClient(profile: profile).checkHealth()
    }

    func openApprovalUI(deepLink: String) async -> Bool {
        guard let url = URL(string: deepLink) else { return false }
        return await MainActor.run {
            NSWorkspace.shared.open(url)
        }
    }

    func revokeGrant(profile: BaoProfile, target: GrantTarget, remoteTarget: String?) async throws -> BaoMCPRevokeResult {
        let openbao = try OpenBaoClient(profile: profile)
        switch target {
        case .mac:
            let store = MacKeychainGrantStore(profile: profile)
            guard let token = try store.readGrant(), !token.isEmpty else {
                return BaoMCPRevokeResult(revokedOnServer: false, message: "No grant is saved on this Mac for \(profile.displayName).")
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
                via: "mcp"
            ))
            return BaoMCPRevokeResult(revokedOnServer: true, message: "Revoked the grant on this Mac.")
        case .t3:
            // Revoke through OpenBao by accessor first (Touch ID), so a compromised host can't keep
            // the token by claiming it deleted it. Then ask the host to delete its copies.
            var revokedOnServer = false
            let accessors = GrantAccessorStore()
            let recorded = try accessors.entries(for: profile)
            if !recorded.isEmpty {
                let orchestrator = GrantOrchestrator(
                    profile: profile,
                    signer: BaoBuddyHelperCLI.keyStore(for: profile),
                    openbao: openbao,
                    via: "mcp"
                )
                for entry in recorded {
                    try await orchestrator.revokeRemoteGrant(accessor: entry.accessor)
                    try accessors.remove(for: profile, accessor: entry.accessor)
                }
                revokedOnServer = true
            }
            let hostMessage: String
            do {
                hostMessage = try await BaoBuddyHelperCLI.remoteTransport(for: profile).revoke()
            } catch {
                guard revokedOnServer else { throw error }
                hostMessage = "\(profile.targetDisplayName) didn't confirm deleting its copies: \(error.localizedDescription)"
            }
            GrantActivityStore().record(GrantActivityEntry(
                action: .revoked,
                serverName: profile.displayName,
                namespace: profile.openbao.namespace,
                targetName: profile.targetDisplayName,
                via: "mcp"
            ))
            return BaoMCPRevokeResult(
                revokedOnServer: revokedOnServer,
                message: hostMessage,
                warning: revokedOnServer ? nil : "No accessor was recorded for this grant, so only \(profile.targetDisplayName) reported the revocation; OpenBao didn't confirm it."
            )
        }
    }
}
#endif
