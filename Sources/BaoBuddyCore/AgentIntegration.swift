import Foundation

/// Generates tailored AI agent rules (`AGENTS.md` / `CLAUDE.md`), MCP client configurations,
/// and canonical `baobuddy://grant` deep links so agents can request hardware-approved grants safely.
public enum BaoAgentPrompts {
    /// Builds a percent-encoded `baobuddy://grant?...` deep link for a validated request.
    /// Carries stable `profile_id` and `remote_target_id` alongside canonical endpoint/mount hints
    /// so same-device links never suffer name collisions and cross-device links resolve safely.
    public static func buildGrantDeepLink(profile: BaoProfile, request: GrantRequest) -> String {
        var components = URLComponents()
        components.scheme = "baobuddy"
        components.host = "grant"
        var items: [URLQueryItem] = []
        if !profile.id.isEmpty {
            items.append(URLQueryItem(name: "profile_id", value: profile.id))
        }
        if !profile.displayName.isEmpty {
            items.append(URLQueryItem(name: "profile", value: profile.displayName))
        }
        items.append(URLQueryItem(name: "server", value: profile.openbao.normalizedBaseEndpoint))
        items.append(URLQueryItem(name: "mount", value: profile.openbao.jwtAuth.mount))
        let ns = profile.openbao.namespace.trimmingCharacters(in: .whitespacesAndNewlines)
        items.append(URLQueryItem(name: "namespace", value: ns))
        items.append(URLQueryItem(name: "issuer_binding", value: profile.openbao.issuerBindingKey))
        items.append(URLQueryItem(name: "target", value: request.target == .t3 ? "remote" : "local"))
        if request.target == .t3, profile.hasRemoteTarget {
            items.append(URLQueryItem(name: "remote_target_id", value: profile.t3Granter.id))
            items.append(URLQueryItem(name: "remote_target", value: profile.targetDisplayName))
            items.append(URLQueryItem(name: "remote_ssh", value: profile.t3Granter.sshDestination))
            let hostKeyFP = profile.t3Granter.hostKeyFingerprint
            if !hostKeyFP.isEmpty {
                items.append(URLQueryItem(name: "remote_host_key_fp", value: hostKeyFP))
            }
        }
        items.append(URLQueryItem(name: "r", value: request.canonicalText))
        components.queryItems = items
        return components.string ?? "baobuddy://grant"
    }

    /// Generates a drop-in `.mcp.json` / Claude Code / Cursor MCP configuration snippet.
    public static func renderMCPConfigJSON(
        binaryPath: String = "/Applications/BaoBuddyHelper.app/Contents/MacOS/BaoBuddyHelper"
    ) -> String {
        """
        {
          "mcpServers": {
            "baobuddy": {
              "command": "\(binaryPath)",
              "args": ["mcp"]
            }
          }
        }
        """
    }

    /// Generates a drop-in OpenAI Codex `config.toml` MCP block.
    public static func renderCodexMCPConfigTOML(
        binaryPath: String = "/Applications/BaoBuddyHelper.app/Contents/MacOS/BaoBuddyHelper"
    ) -> String {
        """
        [mcp_servers.baobuddy]
        command = "\(binaryPath)"
        args = ["mcp"]
        """
    }

    /// Generates a tailored `AGENTS.md` / `CLAUDE.md` rule block for an active profile (or generic defaults).
    public static func renderAgentsMarkdown(profile: BaoProfile? = nil) -> String {
        let serverLine: String
        let policySection: String
        let auditNote: String
        let remoteNote: String

        if let profile {
            let nsSuffix = profile.openbao.namespace.isEmpty ? "" : " (namespace `\(profile.openbao.namespace)`)"
            serverLine = "Active OpenBao / Vault server: **\(profile.displayName)** (`\(profile.openbao.address)`)\(nsSuffix)."

            if profile.openbao.usesCustomPolicies {
                let items = profile.openbao.grantPolicies.map { pol -> String in
                    let tag = pol.elevated ? " *(elevated)*" : ""
                    return "`\(pol.name)`\(tag)"
                }.joined(separator: ", ")
                policySection = "- Available policies: \(items)."
            } else {
                policySection = "- Standard policies: read (`\(profile.openbao.policies.read)`), write (`\(profile.openbao.policies.write)`)."
            }

            let audit = profile.openbao.auditPolicy
            if audit.requireReason || audit.requireReasonForElevated {
                let scope = audit.requireReason ? "all grants" : "elevated grants"
                let patternHint = audit.reasonPattern.isEmpty ? "" : " matching `\(audit.reasonPattern)`"
                auditNote = "- **Audit policy**: A clear `why` reason is **required** for \(scope)\(patternHint)."
            } else {
                auditNote = "- Always include a concise `why` reason explaining the task (for OpenBao audit logs)."
            }

            let targets = profile.configuredRemoteTargets
            if targets.isEmpty {
                remoteNote = "- Delivery target: `local` (this Mac's Keychain)."
            } else {
                let names = targets.map { "`\($0.displayName)`" }.joined(separator: ", ")
                remoteNote = "- Delivery targets: `local` (this Mac) or `remote` (\(names))."
            }
        } else {
            serverLine = "Secrets and ephemeral credentials are managed by **BaoBuddy** (OpenBao / HashiCorp Vault with Touch ID / Face ID)."
            policySection = "- Call `baobuddy_list_profiles` first to inspect available servers and policies."
            auditNote = "- Always include a concise `why` reason (or change-ticket ID) for OpenBao audit logs."
            remoteNote = "- Request only the target (`local` or `remote`) required for the current task."
        }

        let keychainService: String
        let artifactService: String
        if let profile {
            keychainService = "openbao-grant.\(profile.openbao.issuerBindingKey)"
            artifactService = "openbao-grant-artifact.\(profile.openbao.issuerBindingKey)"
        } else {
            keychainService = "<openbao-grant-service-from-bao-buddy-status>"
            artifactService = "<openbao-grant-artifact-service-from-bao-buddy-status>"
        }

        return """
        ## Secrets & Ephemeral Access (BaoBuddy)

        \(serverLine)

        1. **Never ask the user to paste passwords, static Vault tokens, or API keys in chat.**
        2. **Check status first**: Call `baobuddy_status` (or run `bao-buddy status`) before requesting a new grant.
        3. **Request least-privilege access**: Call `baobuddy_request_grant` with the smallest set of policies and shortest duration (`hours`) needed:
        \(policySection)
        \(auditNote)
        \(remoteNote)
        4. **Wait for human biometric approval**: BaoBuddy triggers Touch ID / Face ID (or produces a `baobuddy://` link). Never attempt to work around a missing or expired grant; call `baobuddy_wait_for_grant` or pause until the human approves.
        5. **Revoke immediately when done**: Call `baobuddy_revoke_grant` (or run `bao-buddy revoke`) as soon as the task finishes instead of leaving an active grant open until TTL expiry.
        6. **Never handle a token directly**: don't run `bao-buddy grant --on direct` or `bao-buddy personal-token`, and don't print, store, or pass tokens as arguments. Use a local grant only inside the command that needs it: `VAULT_TOKEN="$(security find-generic-password -s \(keychainService) -w)" <command>` (and credential artifacts via `-s \(artifactService) -a <deliver_as>`).
        """
    }
}

// MARK: - Zero-Dependency MCP Server Core (JSON-RPC 2.0)

public struct BaoMCPStatusSnapshot: Equatable, Sendable {
    public let serverName: String
    public let namespace: String
    public let localUnavailable: Bool
    public let localActive: Bool
    public let localTTLSeconds: Int
    public let localPolicies: [String]
    public let localWhy: String
    public let remoteTargetName: String?
    public let remoteStatusText: String?

    public init(
        serverName: String,
        namespace: String = "",
        localActive: Bool,
        localUnavailable: Bool = false,
        localTTLSeconds: Int = 0,
        localPolicies: [String] = [],
        localWhy: String = "",
        remoteTargetName: String? = nil,
        remoteStatusText: String? = nil
    ) {
        self.serverName = serverName
        self.namespace = namespace
        self.localUnavailable = localUnavailable
        self.localActive = localActive
        self.localTTLSeconds = localTTLSeconds
        self.localPolicies = localPolicies
        self.localWhy = localWhy
        self.remoteTargetName = remoteTargetName
        self.remoteStatusText = remoteStatusText
    }

    static func sanitizeHostText(_ raw: String) -> String {
        let lines = raw.split(whereSeparator: \.isNewline).prefix(10).map { line in
            String(String.UnicodeScalarView(line.unicodeScalars.filter { scalar in
                switch scalar.properties.generalCategory {
                case .control, .format, .lineSeparator, .paragraphSeparator: return false
                default: return true
                }
            }).prefix(200))
        }
        return lines.joined(separator: "\n")
    }

    public func toDictionary() -> [String: Any] {
        var dict: [String: Any] = [
            "server": serverName,
            "local": [
                "active": localActive,
                "ttl_seconds": localTTLSeconds,
                "policies": localPolicies,
                "why": localWhy
            ] as [String: Any]
        ]
        if localUnavailable { dict["local"] = ["status": "unknown", "active": NSNull()] as [String: Any] }
        if !namespace.isEmpty { dict["namespace"] = namespace }
        if let remoteTargetName {
            // The remote host writes this text, so it's untrusted input to the agent: strip
            // control and formatting characters, cap its length, and label it.
            dict["remote"] = [
                "target": remoteTargetName,
                "status_reported_by_host": Self.sanitizeHostText(remoteStatusText ?? "unavailable")
            ]
        }
        return dict
    }
}

/// Platform abstraction for `BaoMCPServer` so all JSON-RPC dispatch, validation,
/// redaction, prompts, and resources are 100% unit-tested without Keychain/UI side effects.
public struct BaoMCPArgumentError: Error, LocalizedError {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// What a revoke actually achieved. `revokedOnServer` is true only when OpenBao confirmed it;
/// a remote host's own report of deleting its copy isn't proof the token is dead.
public struct BaoMCPRevokeResult: Equatable, Sendable {
    public let revokedOnServer: Bool
    public let message: String
    public let warning: String?

    public init(revokedOnServer: Bool, message: String, warning: String? = nil) {
        self.revokedOnServer = revokedOnServer
        self.message = message
        self.warning = warning
    }

    public func toDictionary() -> [String: Any] {
        var dict: [String: Any] = ["revoked_on_server": revokedOnServer, "message": message]
        if let warning { dict["warning"] = warning }
        return dict
    }
}

public protocol BaoMCPBackend: Sendable {
    func listProfiles() async -> [BaoProfile]
    func activeProfile(selector: String?) async throws -> BaoProfile
    func status(profile: BaoProfile, targetScope: String, remoteTarget: String?) async -> BaoMCPStatusSnapshot
    func checkHealth(profile: BaoProfile) async throws -> ServerHealth
    func openApprovalUI(deepLink: String) async -> Bool
    func revokeGrant(profile: BaoProfile, target: GrantTarget, remoteTarget: String?) async throws -> BaoMCPRevokeResult
}

/// Least-privilege, zero-dependency MCP (Model Context Protocol) JSON-RPC 2.0 server.
///
/// Security invariants:
/// - Never returns raw OpenBao tokens, private keys, or CA PEMs in any tool or resource.
/// - Never mints or approves a grant without human biometric confirmation (only builds validated
///   requests and opens the native approval UI / returns a `baobuddy://` link).
/// - Never mutates profiles, TLS pins, or hardware keys.
public struct BaoMCPServer: Sendable {
    public let backend: any BaoMCPBackend
    public let serverVersion: String

    /// MCP protocol revisions this server implements, newest first.
    public static let supportedProtocolVersions = ["2025-06-18", "2025-03-26", "2024-11-05"]

    public init(backend: any BaoMCPBackend, serverVersion: String = "0.1.0") {
        self.backend = backend
        self.serverVersion = serverVersion
    }

    /// Handles a single JSON-RPC 2.0 request line and returns an optional response JSON object.
    /// Returns `nil` for JSON-RPC notifications (messages without an `id`).
    public func handleLine(_ line: String) async -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard let data = trimmed.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) else {
            return encodeJSON(errorResponse(id: NSNull(), code: -32700, message: "Parse error"))
        }
        guard let object = parsed as? [String: Any] else {
            return encodeJSON(errorResponse(id: NSNull(), code: -32600, message: "Invalid Request: batch requests aren't supported"))
        }

        let id = object["id"]
        guard let method = object["method"] as? String else {
            guard let id else { return nil }
            return encodeJSON(errorResponse(id: id, code: -32600, message: "Invalid Request: missing method"))
        }
        let params = object["params"] as? [String: Any] ?? [:]

        // Notifications have no `id` and expect no response.
        if id == nil {
            return nil
        }
        let reqID = id ?? NSNull()

        let response: [String: Any]
        switch method {
        case "initialize":
            // Answer with the client's version only if this server implements it; otherwise offer
            // the newest one it does, and the client decides whether to continue.
            let requested = params["protocolVersion"] as? String ?? ""
            let negotiated = Self.supportedProtocolVersions.contains(requested)
                ? requested
                : Self.supportedProtocolVersions[0]
            response = successResponse(id: reqID, result: [
                "protocolVersion": negotiated,
                "capabilities": [
                    "tools": ["listChanged": false],
                    "resources": ["subscribe": false, "listChanged": false],
                    "prompts": ["listChanged": false]
                ],
                "serverInfo": [
                    "name": "baobuddy",
                    "version": serverVersion
                ]
            ])
        case "ping":
            response = successResponse(id: reqID, result: [:])
        case "tools/list":
            response = successResponse(id: reqID, result: ["tools": Self.toolDefinitions()])
        case "tools/call":
            let name = params["name"] as? String ?? ""
            let args = params["arguments"] as? [String: Any] ?? [:]
            response = await handleToolCall(id: reqID, name: name, args: args)
        case "resources/list":
            response = successResponse(id: reqID, result: ["resources": Self.resourceDefinitions()])
        case "resources/read":
            let uri = params["uri"] as? String ?? ""
            response = await handleResourceRead(id: reqID, uri: uri)
        case "prompts/list":
            response = successResponse(id: reqID, result: ["prompts": Self.promptDefinitions()])
        case "prompts/get":
            let name = params["name"] as? String ?? ""
            let rawArgs = params["arguments"] as? [String: Any] ?? [:]
            let args = rawArgs.compactMapValues { $0 as? String }
            response = await handlePromptGet(id: reqID, name: name, args: args)
        default:
            response = errorResponse(id: reqID, code: -32601, message: "Method not found: \(method)")
        }
        return encodeJSON(response)
    }

    // MARK: - Tool Execution

    private func handleToolCall(id: Any, name: String, args: [String: Any]) async -> [String: Any] {
        do {
            switch name {
            case "baobuddy_list_profiles":
                let profiles = await backend.listProfiles()
                let summaries = profiles.map(Self.redactedProfileSummary)
                return toolSuccess(id: id, json: ["profiles": summaries])

            case "baobuddy_status":
                let profile = try await resolveProfile(args)
                let scope = try Self.stringArg(args, "target", default: "all").lowercased()
                let snapshot = await backend.status(profile: profile, targetScope: scope, remoteTarget: nil)
                return toolSuccess(id: id, json: snapshot.toDictionary())

            case "baobuddy_health":
                let profile = try await backend.activeProfile(selector: args["profile"] as? String)
                let health = try await backend.checkHealth(profile: profile)
                return toolSuccess(id: id, json: [
                    "server": profile.displayName,
                    "address": profile.openbao.address,
                    "initialized": health.initialized,
                    "sealed": health.sealed,
                    "version": health.version,
                    "tls_pinned": profile.openbao.isTLSPinned
                ])

            case "baobuddy_request_grant":
                return try await handleRequestGrant(id: id, args: args)

            case "baobuddy_wait_for_grant":
                return try await handleWaitForGrant(id: id, args: args)

            case "baobuddy_revoke_grant":
                let profile = try await resolveProfile(args)
                let target = try Self.targetArg(args, default: .mac, profile: profile)
                let result = try await backend.revokeGrant(profile: profile, target: target, remoteTarget: nil)
                return toolSuccess(id: id, json: result.toDictionary())

            default:
                return errorResponse(id: id, code: -32602, message: "Unknown tool: \(name)")
            }
        } catch {
            return toolError(id: id, message: error.localizedDescription)
        }
    }

    /// The profile named by `profile`, focused on `remote_target` when given. An unknown or
    /// ambiguous remote target is an error rather than a silent fall back to the default host.
    private func resolveProfile(_ args: [String: Any]) async throws -> BaoProfile {
        let selector = try Self.optionalStringArg(args, "profile")
        var profile = try await backend.activeProfile(selector: selector)
        if let remoteName = try Self.optionalStringArg(args, "remote_target"), !remoteName.isEmpty {
            guard let matched = try profile.resolveRemoteTarget(named: remoteName) else {
                let known = profile.configuredRemoteTargets.map { "\($0.displayName) [\($0.id)]" }.joined(separator: ", ")
                throw BaoMCPArgumentError("remote_target '\(remoteName)' isn't configured (configured: \(known.isEmpty ? "none" : known))")
            }
            profile = profile.focusing(remoteTarget: matched)
        }
        return profile
    }

    private func handleRequestGrant(id: Any, args: [String: Any]) async throws -> [String: Any] {
        let profile = try await resolveProfile(args)
        let target = try Self.targetArg(args, default: profile.hasRemoteTarget ? .t3 : .mac, profile: profile)
        let hours = try Self.intArg(args, "hours", default: 2)
        let write = try Self.boolArg(args, "write", default: false)
        let policies = try Self.stringArrayArg(args, "policies")
        let keys = try Self.stringArrayArg(args, "keys")
        let sshHosts = try Self.stringArrayArg(args, "ssh")
        let extensionIDs = try Self.stringArrayArg(args, "extensions")
        let why = try Self.stringArg(args, "why", default: "")
        let mode = try Self.stringArg(args, "mode", default: "open_ui").lowercased()

        // Same rule as deep links: an agent may only name policies from the profile's catalog.
        if !policies.isEmpty && !profile.openbao.usesCustomPolicies {
            throw GrantRequestError.policiesNeedCatalog
        }

        let request = GrantRequest(
            target: target,
            hours: hours,
            write: write,
            keys: keys,
            sshHosts: sshHosts,
            push: false,
            customPolicies: policies,
            why: why,
            extensions: extensionIDs
        )
        try request.validate(against: profile)

        let deepLink = BaoAgentPrompts.buildGrantDeepLink(profile: profile, request: request)
        var openedUI = false
        if mode != "link_only" {
            openedUI = await backend.openApprovalUI(deepLink: deepLink)
        }

        var cliParts = ["bao-buddy", "grant"]
        if !profile.id.isEmpty {
            cliParts += ["--profile-id", profile.id]
        } else if !profile.displayName.isEmpty {
            cliParts += ["--profile", profile.displayName]
        }
        cliParts += ["--on", target == .t3 ? "remote" : "local", "--hours", "\(request.hours)"]
        if target == .t3, profile.hasRemoteTarget {
            cliParts += ["--target-id", profile.t3Granter.id]
            cliParts += ["--target-ssh", profile.t3Granter.sshDestination]
            let hostKeyFP = profile.t3Granter.hostKeyFingerprint
            if !hostKeyFP.isEmpty {
                cliParts += ["--target-host-key-fp", hostKeyFP]
            }
        }
        if !policies.isEmpty { cliParts += ["--policies", policies.joined(separator: ",")] }
        if write { cliParts += ["--write", "1"] }
        if !keys.isEmpty { cliParts += ["--keys", keys.joined(separator: ",")] }
        if !sshHosts.isEmpty { cliParts += ["--ssh", sshHosts.joined(separator: ",")] }
        if !extensionIDs.isEmpty { cliParts += ["--ext", extensionIDs.joined(separator: ",")] }
        if !request.why.isEmpty { cliParts += ["--why", request.why] }

        return toolSuccess(id: id, json: [
            "approval_required": true,
            "opened_ui": openedUI,
            "profile_id": profile.id,
            "server": profile.displayName,
            "target": target == .t3 ? profile.targetDisplayName : "This Mac",
            "target_id": target == .t3 ? profile.t3Granter.id : "local",
            "elevated": request.isElevated(profile: profile),
            "summary": request.summary(profile: profile),
            "policies": request.openBaoPolicies(profile: profile),
            "deep_link": deepLink,
            "cli_command": cliParts.map(Self.shellQuote).joined(separator: " "),
            "next_step": openedUI
                ? "BaoBuddy approval popover opened on this Mac. Ask the user to approve with Touch ID, or call baobuddy_wait_for_grant."
                : "Present the deep_link (for Mac/iPhone) or cli_command to the user for biometric approval, then call baobuddy_wait_for_grant."
        ])
    }

    /// Waits until a grant is active. `approved` is true only when the active grant has every
    /// policy in `policies` (if given); a grant that was already active may predate the request.
    private func handleWaitForGrant(id: Any, args: [String: Any]) async throws -> [String: Any] {
        let profile = try await resolveProfile(args)
        let target = try Self.targetArg(args, default: .mac, profile: profile)
        let wanted = Set(try Self.stringArrayArg(args, "policies"))
        let timeoutSec = max(1, min(try Self.intArg(args, "timeout_seconds", default: 60), 300))
        let deadline = Date().addingTimeInterval(TimeInterval(timeoutSec))
        let scope = target == .t3 ? "remote" : "local"

        while true {
            let snap = await backend.status(profile: profile, targetScope: scope, remoteTarget: nil)
            let isReady: Bool
            if target == .t3 {
                // The remote host's own report; it can't be checked against policies here.
                isReady = (snap.remoteStatusText ?? "").lowercased().hasPrefix("secrets: active")
            } else {
                isReady = snap.localActive && snap.localTTLSeconds > 0 && wanted.isSubset(of: Set(snap.localPolicies))
            }
            if isReady {
                var out = snap.toDictionary()
                out["approved"] = true
                out["note"] = "A grant is active. It may have been approved before this request; check its policies and TTL."
                return toolSuccess(id: id, json: out)
            }
            if Date() >= deadline {
                var out = snap.toDictionary()
                out["approved"] = false
                out["timed_out"] = true
                return toolSuccess(id: id, json: out)
            }
            try? await Task.sleep(for: .seconds(2))
        }
    }

    // MARK: - Argument parsing (wrong types are errors, not silent defaults)

    static func optionalStringArg(_ args: [String: Any], _ key: String) throws -> String? {
        guard let value = args[key], !(value is NSNull) else { return nil }
        guard let string = value as? String else {
            throw BaoMCPArgumentError("\(key) must be a string")
        }
        return string
    }

    static func stringArg(_ args: [String: Any], _ key: String, default fallback: String) throws -> String {
        try optionalStringArg(args, key) ?? fallback
    }

    static func intArg(_ args: [String: Any], _ key: String, default fallback: Int) throws -> Int {
        guard let value = args[key], !(value is NSNull) else { return fallback }
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
              let int = Int(exactly: number.doubleValue) else {
            throw BaoMCPArgumentError("\(key) must be a whole number")
        }
        return int
    }

    static func boolArg(_ args: [String: Any], _ key: String, default fallback: Bool) throws -> Bool {
        guard let value = args[key], !(value is NSNull) else { return fallback }
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
            throw BaoMCPArgumentError("\(key) must be true or false")
        }
        return number.boolValue
    }

    static func stringArrayArg(_ args: [String: Any], _ key: String) throws -> [String] {
        guard let value = args[key], !(value is NSNull) else { return [] }
        guard let list = value as? [String] else {
            throw BaoMCPArgumentError("\(key) must be an array of strings")
        }
        return list
    }

    static func targetArg(_ args: [String: Any], default fallback: GrantTarget, profile: BaoProfile) throws -> GrantTarget {
        switch try optionalStringArg(args, "target")?.lowercased() {
        case nil, "":
            return fallback
        case "local", "mac":
            return .mac
        case "remote", "t3":
            guard profile.hasRemoteTarget else {
                throw BaoMCPArgumentError("target 'remote': \(profile.displayName) has no remote target")
            }
            return .t3
        case let other?:
            throw BaoMCPArgumentError("target must be 'local' or 'remote', not '\(other)'")
        }
    }

    /// POSIX single-quoting, so a value can never run as shell syntax when the user pastes it.
    static func shellQuote(_ word: String) -> String {
        let safe = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./,=:@")
        if !word.isEmpty && word.unicodeScalars.allSatisfy({ safe.contains($0) }) {
            return word
        }
        return "'" + word.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    // MARK: - Resources & Prompts

    private func handleResourceRead(id: Any, uri: String) async -> [String: Any] {
        switch uri {
        case "baobuddy://profiles":
            let profiles = await backend.listProfiles()
            let text = encodeJSON(["profiles": profiles.map(Self.redactedProfileSummary)])
            return successResponse(id: id, result: [
                "contents": [[
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": text
                ]]
            ])
        case "baobuddy://status":
            do {
                let profile = try await backend.activeProfile(selector: nil)
                let snap = await backend.status(profile: profile, targetScope: "all", remoteTarget: nil)
                let text = encodeJSON(snap.toDictionary())
                return successResponse(id: id, result: [
                    "contents": [[
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": text
                    ]]
                ])
            } catch {
                return errorResponse(id: id, code: -32000, message: error.localizedDescription)
            }
        default:
            return errorResponse(id: id, code: -32602, message: "Unknown resource URI: \(uri)")
        }
    }

    private func handlePromptGet(id: Any, name: String, args: [String: String]) async -> [String: Any] {
        let server = args["server"] ?? ""
        let profile = try? await backend.activeProfile(selector: server.isEmpty ? nil : server)

        switch name {
        case "request-readonly-access":
            let why = args["why"] ?? "read-only investigation"
            let text = """
            Check active BaoBuddy grant status with `baobuddy_status`. If no read-only grant is active, call `baobuddy_request_grant` with minimal read-only policies for 1 hour and reason "\(why)". Never ask the user for raw tokens or passwords. When finished, call `baobuddy_revoke_grant`.
            """
            return promptSuccess(id: id, description: "Request minimal read-only OpenBao/Vault access", text: text)

        case "request-elevated-deploy":
            let policies = args["policies"] ?? "deploy"
            let ticket = args["ticket"] ?? "<CHANGE-TICKET>"
            let hours = args["hours"] ?? "1"
            let text = """
            Prepare an elevated BaoBuddy grant request for policies [\(policies)], duration \(hours)h, with audit reason "\(ticket)". First verify what changes will be applied, then call `baobuddy_request_grant` and wait for human Touch ID / Face ID approval. Immediately call `baobuddy_revoke_grant` after the deployment finishes.
            """
            return promptSuccess(id: id, description: "Request audited elevated access for a deployment", text: text)

        case "finish-and-revoke":
            let target = args["target"] ?? "local"
            let text = "Verify no remaining commands need OpenBao secrets, then call `baobuddy_revoke_grant` for target `\(target)` and confirm revocation."
            return promptSuccess(id: id, description: "Revoke active grant immediately upon task completion", text: text)

        case "agents-md-rule":
            let rule = BaoAgentPrompts.renderAgentsMarkdown(profile: profile)
            return promptSuccess(id: id, description: "Drop-in AGENTS.md / CLAUDE.md rule tailored to your server", text: rule)

        default:
            return errorResponse(id: id, code: -32602, message: "Unknown prompt: \(name)")
        }
    }

    // MARK: - Schema Definitions

    private static func redactedProfileSummary(_ profile: BaoProfile) -> [String: Any] {
        var dict: [String: Any] = [
            "id": profile.id,
            "name": profile.displayName,
            "address": profile.openbao.address,
            "tls_pinned": profile.openbao.isTLSPinned,
            "max_hours": profile.openbao.maxHours,
            "remote_targets": profile.configuredRemoteTargets.map(\.displayName),
            "remote_target_details": profile.configuredRemoteTargets.map { [
                "id": $0.id,
                "name": $0.displayName,
                "host": $0.host,
                "port": $0.port
            ] as [String: Any] }
        ]
        if !profile.openbao.namespace.isEmpty {
            dict["namespace"] = profile.openbao.namespace
        }
        if profile.openbao.usesCustomPolicies {
            dict["policies"] = profile.openbao.grantPolicies.map { [
                "name": $0.name,
                "label": $0.displayLabel,
                "elevated": $0.elevated
            ] as [String: Any] }
        } else {
            dict["policies"] = [
                ["name": profile.openbao.policies.read, "label": "Read", "elevated": false],
                ["name": profile.openbao.policies.write, "label": "Write", "elevated": true]
            ]
        }
        let extensions = profile.openbao.enabledExtensions
        if !extensions.isEmpty {
            dict["credential_extensions"] = extensions.map { [
                "id": $0.id,
                "label": $0.displayLabel,
                "endpoint": $0.endpoint,
                "deliver_as": $0.deliverAs,
                "elevated": $0.elevated
            ] as [String: Any] }
        }
        let audit = profile.openbao.auditPolicy
        if !audit.isEmpty {
            dict["audit_policy"] = [
                "require_reason": audit.requireReason,
                "require_reason_for_elevated": audit.requireReasonForElevated,
                "reason_pattern": audit.reasonPattern,
                "reason_placeholder": audit.reasonPlaceholder
            ] as [String: Any]
        }
        return dict
    }

    private static func toolDefinitions() -> [[String: Any]] {
        [
            [
                "name": "baobuddy_list_profiles",
                "description": "List configured OpenBao / HashiCorp Vault servers, namespaces, available policies (with elevated flags), audit reason rules, and remote targets. Returns zero secrets.",
                "inputSchema": ["type": "object", "properties": [:] as [String: Any]]
            ],
            [
                "name": "baobuddy_status",
                "description": "Check active local and/or remote grant status, remaining TTL, and granted policies. Never returns raw tokens.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "profile": ["type": "string", "description": "Optional server profile name"],
                        "target": ["type": "string", "enum": ["all", "local", "remote"]],
                        "remote_target": ["type": "string", "description": "Optional remote host name when multiple targets exist"]
                    ]
                ]
            ],
            [
                "name": "baobuddy_health",
                "description": "Check OpenBao / Vault server reachability and seal status over pinned TLS.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "profile": ["type": "string", "description": "Optional server profile name"]
                    ]
                ]
            ],
            [
                "name": "baobuddy_request_grant",
                "description": "Request a scoped, time-boxed OpenBao/Vault grant requiring human Touch ID / Face ID approval. Validates policies, max TTL, and audit reason rules. Never returns raw tokens.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "profile": ["type": "string", "description": "Optional server profile name"],
                        "target": ["type": "string", "enum": ["local", "remote"]],
                        "remote_target": ["type": "string", "description": "Optional remote host name"],
                        "hours": ["type": "integer", "minimum": 1, "maximum": 24],
                        "policies": ["type": "array", "items": ["type": "string"]],
                        "write": ["type": "boolean"],
                        "keys": ["type": "array", "items": ["type": "string"]],
                        "ssh": ["type": "array", "items": ["type": "string"]],
                        "extensions": [
                            "type": "array",
                            "items": ["type": "string"],
                            "description": "IDs of the profile's credential_extensions to mint with the grant. They're delivered to the Keychain (local) or the remote host, never returned to you."
                        ],
                        "why": ["type": "string", "description": "Audit reason or change ticket ID"],
                        "mode": ["type": "string", "enum": ["open_ui", "link_only"]]
                    ],
                    "required": ["why"]
                ]
            ],
            [
                "name": "baobuddy_wait_for_grant",
                "description": "Wait (up to 300s) until a grant is active on the target. For local grants, pass the requested policies so an older grant with different policies doesn't count. A grant that was already active may predate your request.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "profile": ["type": "string"],
                        "target": ["type": "string", "enum": ["local", "remote"]],
                        "remote_target": ["type": "string"],
                        "policies": ["type": "array", "items": ["type": "string"]],
                        "timeout_seconds": ["type": "integer", "minimum": 1, "maximum": 300]
                    ]
                ]
            ],
            [
                "name": "baobuddy_revoke_grant",
                "description": "Immediately revoke an active grant once the task finishes.",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "profile": ["type": "string"],
                        "target": ["type": "string", "enum": ["local", "remote"]],
                        "remote_target": ["type": "string"]
                    ]
                ]
            ]
        ]
    }

    private static func resourceDefinitions() -> [[String: Any]] {
        [
            [
                "uri": "baobuddy://profiles",
                "name": "Configured OpenBao / Vault Servers",
                "description": "Non-secret catalog of configured servers, policies, namespaces, and audit rules.",
                "mimeType": "application/json"
            ],
            [
                "uri": "baobuddy://status",
                "name": "Active Grant Status",
                "description": "Current non-secret grant status and remaining TTL for the active server.",
                "mimeType": "application/json"
            ]
        ]
    }

    private static func promptDefinitions() -> [[String: Any]] {
        [
            [
                "name": "request-readonly-access",
                "description": "Request minimal read-only OpenBao / Vault access for investigation.",
                "arguments": [
                    ["name": "server", "description": "Optional server profile name", "required": false],
                    ["name": "why", "description": "Reason for access", "required": false]
                ]
            ],
            [
                "name": "request-elevated-deploy",
                "description": "Request an audited elevated grant with a change ticket and auto-revoke after deploy.",
                "arguments": [
                    ["name": "server", "description": "Optional server profile name", "required": false],
                    ["name": "policies", "description": "Comma-separated policy names", "required": true],
                    ["name": "ticket", "description": "Change ticket ID / reason", "required": true],
                    ["name": "hours", "description": "Duration in hours (default 1)", "required": false]
                ]
            ],
            [
                "name": "finish-and-revoke",
                "description": "Revoke active grant immediately once the task is complete.",
                "arguments": [
                    ["name": "target", "description": "local or remote", "required": false]
                ]
            ],
            [
                "name": "agents-md-rule",
                "description": "Generate a tailored AGENTS.md / CLAUDE.md rule block for your server.",
                "arguments": [
                    ["name": "server", "description": "Optional server profile name", "required": false]
                ]
            ]
        ]
    }

    // MARK: - JSON-RPC Helpers

    private func successResponse(id: Any, result: [String: Any]) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id, "result": result]
    }

    private func errorResponse(id: Any, code: Int, message: String) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id, "error": ["code": code, "message": message]]
    }

    private func toolSuccess(id: Any, json: [String: Any]) -> [String: Any] {
        let text = encodeJSON(json)
        return successResponse(id: id, result: [
            "content": [["type": "text", "text": text]],
            "isError": false
        ])
    }

    private func toolError(id: Any, message: String) -> [String: Any] {
        successResponse(id: id, result: [
            "content": [["type": "text", "text": message]],
            "isError": true
        ])
    }

    private func promptSuccess(id: Any, description: String, text: String) -> [String: Any] {
        successResponse(id: id, result: [
            "description": description,
            "messages": [[
                "role": "user",
                "content": ["type": "text", "text": text]
            ]]
        ])
    }

    private func encodeJSON(_ obj: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes]),
              let str = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return str
    }
}
