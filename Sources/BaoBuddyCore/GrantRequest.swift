import Foundation

public enum GrantTarget: String, Codable, Equatable, CaseIterable, Sendable {
    case mac
    case t3
}

public enum GrantRequestError: Error, LocalizedError, Equatable {
    case unknownToken(String)
    case invalidHours(Int)
    case invalidFlag(String, String)
    case unknownSSHHost(String, [String])
    case unknownKey(String, [String])
    case unknownPolicy(String, [String])
    case emptyPolicies
    case invalidTarget(String)
    case sshOnlyForT3
    case pushOnlyForT3
    case invalidURL(String)
    case policiesNeedCatalog
    case reasonRequired(elevatedOnly: Bool)
    case reasonPatternMismatch(String)
    case organizationPolicy(String)
    case unknownExtension(String, [String])

    public var errorDescription: String? {
        switch self {
        case let .unknownToken(token):
            return String(localized: "Unknown grant parameter '\(token)'", table: "BaoBuddyCore", comment: "Error parsing a baobuddy:// grant link. %@ is the unrecognized parameter.")
        case let .invalidHours(max):
            return String(localized: "HOURS must be between 1 and \(max)", table: "BaoBuddyCore", comment: "Error parsing a grant link. Do not translate HOURS (a link parameter name). %lld is the maximum number of hours.")
        case let .invalidFlag(name, value):
            return String(localized: "\(name) must be 1 or 0, not '\(value)'", table: "BaoBuddyCore", comment: "Error parsing a grant link. %1$@ is a link parameter name (do not translate it); %2$@ is the value received.")
        case let .unknownSSHHost(host, allowed):
            return String(localized: "Unknown SSH host '\(host)'; expected one of \(allowed.joined(separator: ", "))", table: "BaoBuddyCore", comment: "Error. %1$@ is a host name; %2$@ is a comma-separated list of allowed host names.")
        case let .unknownKey(key, allowed):
            return String(localized: "Unknown key '\(key)'; expected one of \(allowed.joined(separator: ", "))", table: "BaoBuddyCore", comment: "Error. 'key' means a restricted secret key name. %1$@ is the name; %2$@ is a comma-separated list of allowed names.")
        case let .unknownPolicy(policy, allowed):
            return String(localized: "Unknown policy '\(policy)'; expected one of \(allowed.joined(separator: ", "))", table: "BaoBuddyCore", comment: "Error. %1$@ is an OpenBao policy name; %2$@ is a comma-separated list of allowed policy names.")
        case .emptyPolicies:
            return String(localized: "Select at least one OpenBao policy", table: "BaoBuddyCore", comment: "Error when no policy is selected for a grant.")
        case let .invalidTarget(target):
            return String(localized: "The target must be local or remote, not '\(target)'", table: "BaoBuddyCore", comment: "Error parsing a grant link. 'local' and 'remote' are the accepted link values. %@ is a technical detail.")
        case .sshOnlyForT3:
            return String(localized: "SSH= only applies to grants delivered to a remote target", table: "BaoBuddyCore", comment: "Error parsing a grant link. Do not translate SSH= (a link parameter).")
        case .pushOnlyForT3:
            return String(localized: "PUSH= only applies to grants delivered to a remote target", table: "BaoBuddyCore", comment: "Error parsing a grant link. Do not translate PUSH= (a link parameter).")
        case let .invalidURL(raw):
            return String(localized: "Invalid BaoBuddy URL: \(raw)", table: "BaoBuddyCore", comment: "Error. %@ is the link that was opened.")
        case .policiesNeedCatalog:
            return String(localized: "This link names policies, but the server profile has no grant_policies catalog to check them against", table: "BaoBuddyCore", comment: "Error. Do not translate grant_policies (a setting name).")
        case let .reasonRequired(elevatedOnly):
            return elevatedOnly
                ? String(localized: "An audit reason or ticket ID is required for elevated grants on this server", table: "BaoBuddyCore", comment: "Error when the user approves an elevated (higher-privilege) grant without a reason.")
                : String(localized: "An audit reason or ticket ID is required for grants on this server", table: "BaoBuddyCore", comment: "Error when the user approves a grant without a reason.")
        case let .reasonPatternMismatch(hint):
            return String(localized: "Grant reason must match server format (\(hint))", table: "BaoBuddyCore", comment: "Error. %@ is the expected format (a hint or regular expression set by the server admin).")
        case let .unknownExtension(id, allowed):
            return allowed.isEmpty
                ? String(localized: "Unknown credential extension '\(id)'; this server profile has no enabled extensions", table: "BaoBuddyCore", comment: "Error. %@ is an extension ID. A credential extension mints extra credentials (for example AWS keys) with a grant.")
                : String(localized: "Unknown credential extension '\(id)'; expected one of \(allowed.joined(separator: ", "))", table: "BaoBuddyCore", comment: "Error. %1$@ is an extension ID; %2$@ is a comma-separated list of allowed IDs.")
        case let .organizationPolicy(detail):
            return String(localized: "This server profile doesn't meet your organization's policy: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ explains which organization (MDM) rule is not met.")
        }
    }
}

/// Canonical, validated OpenBao grant request shared across CLI, iOS UI, and `baobuddy://` links.
public struct GrantRequest: Equatable, Sendable {
    public var target: GrantTarget
    public var hours: Int
    public var write: Bool
    public var keys: [String]
    public var sshHosts: [String]
    public var push: Bool
    /// Explicit OpenBao/Vault policy names (used when a profile defines `grant_policies` or `POLICIES=...`).
    public var customPolicies: [String]
    public var why: String
    /// IDs of enabled credential extensions to mint with this grant (`EXT=...`).
    public var extensions: [String]

    public init(
        target: GrantTarget = .t3,
        hours: Int = 2,
        write: Bool = false,
        keys: [String] = [],
        sshHosts: [String] = [],
        push: Bool = false,
        customPolicies: [String] = [],
        why: String = "",
        extensions: [String] = []
    ) {
        self.extensions = extensions
        self.target = target
        self.hours = hours
        self.write = write
        self.keys = keys
        self.sshHosts = sshHosts
        self.push = push
        self.customPolicies = customPolicies
        self.why = Self.sanitizeWhy(why)
    }

    public static func sanitizeWhy(_ raw: String) -> String {
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,:;()/_+-#")
        let filtered = String(raw.unicodeScalars.filter { allowed.contains($0) })
        let trimmed = filtered.trimmingCharacters(in: .whitespacesAndNewlines)
        return String(trimmed.prefix(120))
    }

    /// Extracts an optional `profile_id` or `profile` selector from a `baobuddy://grant?...` URL.
    public static func profileSelector(from url: URL) -> String? {
        guard let scheme = url.scheme?.lowercased(),
              scheme == "baobuddy" || scheme == "baogrant",
              url.host?.lowercased() == "grant" else {
            return nil
        }
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        if let id = components?.queryItems?.first(where: { $0.name == "profile_id" })?.value?
            .trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty {
            return id
        }
        let raw = components?.queryItems?.first(where: { $0.name == "profile" })?.value?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return raw?.isEmpty == false ? raw : nil
    }

    /// Resolves which local `BaoProfile` an incoming `baobuddy://grant?...` link targets.
    /// Precedence:
    /// 1. Exact `profile_id` match (never collides with another server's display name).
    /// 2. Cross-device fallback when `profile_id` belongs to another device: exact unique
    ///    `server` (`normalizedBaseEndpoint`) + `mount` match (plus `namespace` if present),
    ///    or unique `profile` name match if `server`/`mount` were omitted. Ambiguous matches fail closed.
    /// 3. Legacy/manual `profile=` selector resolved via `BaoProfile.resolveProfile` (exact ID precedence, rejects ambiguity).
    /// 4. Active profile when no profile selector was supplied in the link.
    public static func resolveProfile(
        from url: URL,
        in profiles: [BaoProfile],
        active: BaoProfile?
    ) throws -> BaoProfile {
        guard let scheme = url.scheme?.lowercased(),
              scheme == "baobuddy" || scheme == "baogrant",
              url.host?.lowercased() == "grant" else {
            throw GrantRequestError.invalidURL(url.absoluteString)
        }
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func item(_ name: String) -> String? {
            let value = items.first(where: { $0.name == name })?.value?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return value?.isEmpty == false ? value : nil
        }

        let profileID = item("profile_id")
        let profileName = item("profile")
        let serverHint = item("server")
        let mountHint = item("mount")
        let issuerBindingHint = item("issuer_binding")
        let hasNamespaceParam = items.contains(where: { $0.name == "namespace" })
        let rawNamespace = items.first(where: { $0.name == "namespace" })?.value?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        func matchesDeploymentHints(_ candidate: BaoProfile) -> Bool {
            if let serverHint {
                let expectedEndpoint = BaoOpenBaoConfig.normalizeBaseEndpoint(serverHint)
                guard candidate.openbao.normalizedBaseEndpoint == expectedEndpoint else { return false }
            }
            if let mountHint {
                let cleanMount = mountHint.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                let candidateMount = candidate.openbao.jwtAuth.mount.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                guard candidateMount == cleanMount else { return false }
            }
            if hasNamespaceParam || (serverHint != nil && mountHint != nil) {
                let expectedNS = rawNamespace.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                let candidateNS = candidate.openbao.namespace.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                guard candidateNS == expectedNS else { return false }
            }
            if let issuerBindingHint {
                guard candidate.openbao.issuerBindingKey == issuerBindingHint else { return false }
            }
            return true
        }

        if let profileID {
            let exactID = profiles.filter { $0.id.lowercased() == profileID.lowercased() }
            if exactID.count == 1 {
                let matched = exactID[0]
                guard matchesDeploymentHints(matched) else {
                    throw GrantRequestError.invalidTarget(
                        "link server/mount/namespace/trust conflicts with saved profile '\(matched.displayName)' [\(matched.id)]"
                    )
                }
                return matched
            }
            if exactID.count > 1 {
                throw ProfileError.ambiguousProfile(profileID, exactID.map { "\($0.displayName) [\($0.id)]" })
            }
            // Cross-device link (Mac → iPhone with different local UUIDs): require exact endpoint + mount + namespace (+ issuer_binding when present).
            if let serverHint, let mountHint {
                let byDeployment = profiles.filter(matchesDeploymentHints)
                if byDeployment.count == 1 {
                    return byDeployment[0]
                }
                if byDeployment.count > 1 {
                    throw ProfileError.ambiguousProfile(
                        profileName ?? profileID,
                        byDeployment.map { "\($0.displayName) [\($0.id)]" }
                    )
                }
                let normalizedServer = BaoOpenBaoConfig.normalizeBaseEndpoint(serverHint)
                let cleanMount = mountHint.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                let nsLabel = rawNamespace.isEmpty ? "root" : rawNamespace
                throw ProfileError.notConfigured(
                    "No server profile matching '\(profileName ?? profileID)' (\(normalizedServer), ns: \(nsLabel), auth/\(cleanMount)/) is configured on this device."
                )
            }
            if let issuerBindingHint {
                let byBinding = profiles.filter(matchesDeploymentHints)
                if byBinding.count == 1 {
                    return byBinding[0]
                }
                if byBinding.count > 1 {
                    throw ProfileError.ambiguousProfile(
                        profileName ?? profileID,
                        byBinding.map { "\($0.displayName) [\($0.id)]" }
                    )
                }
                throw ProfileError.notConfigured(
                    "No server profile matching trust binding '\(issuerBindingHint)' is configured on this device."
                )
            }
            if let profileName {
                let matched = try BaoProfile.resolveProfile(selector: profileName, in: profiles)
                guard matchesDeploymentHints(matched) else {
                    throw GrantRequestError.invalidTarget(
                        "link server/mount/namespace/trust conflicts with saved profile '\(matched.displayName)' [\(matched.id)]"
                    )
                }
                return matched
            }
            throw ProfileError.notConfigured("No server profile with ID '\(profileID)' is configured on this device.")
        }

        if let profileName {
            let matched = try BaoProfile.resolveProfile(selector: profileName, in: profiles)
            guard matchesDeploymentHints(matched) else {
                throw GrantRequestError.invalidTarget(
                    "link server/mount/namespace/trust conflicts with saved profile '\(matched.displayName)' [\(matched.id)]"
                )
            }
            return matched
        }

        if let active {
            guard matchesDeploymentHints(active) else {
                throw GrantRequestError.invalidTarget(
                    "link server/mount/namespace/trust conflicts with active profile '\(active.displayName)' [\(active.id)]"
                )
            }
            return active
        }
        throw ProfileError.notConfigured("Configure a server profile in Settings before approving grant links.")
    }

    /// Applies a link's optional `remote_target_id=` / `remote_target=` and SSH destination/trust
    /// pins (`remote_ssh=`, `remote_host_key_fp=`) to the profile it names.
    /// - When `remote_target_id` is supplied and absent locally, NEVER falls back to display name
    ///   (which could pick a different machine with the same display name on another device).
    ///   Cross-device fallback requires a matching `remote_ssh` (and `remote_host_key_fp` if present).
    /// - Any conflict against `remote_ssh` or `remote_host_key_fp` fails closed.
    public static func linkProfile(url: URL, base: BaoProfile) throws -> BaoProfile {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func item(_ name: String) -> String? {
            let value = items.first(where: { $0.name == name })?.value?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return value?.isEmpty == false ? value : nil
        }

        let targetID = item("remote_target_id")
        let targetName = item("remote_target")
        let remoteSSH = item("remote_ssh")
        let remoteHostKeyFP = item("remote_host_key_fp")?.lowercased()

        func matchesRemoteTrust(_ candidate: BaoT3GranterConfig) -> Bool {
            if let remoteSSH, candidate.sshDestination != remoteSSH {
                return false
            }
            if let remoteHostKeyFP,
               candidate.hostKeyFingerprint.isEmpty || candidate.hostKeyFingerprint != remoteHostKeyFP {
                return false
            }
            return true
        }

        if let targetID {
            let exact = base.configuredRemoteTargets.filter { $0.id.lowercased() == targetID.lowercased() }
            if !exact.isEmpty {
                let verified = exact.filter(matchesRemoteTrust)
                if verified.count == 1 {
                    return base.focusing(remoteTarget: verified[0])
                }
                if verified.count > 1 {
                    throw ProfileError.ambiguousRemoteTarget(targetID, verified.map(\.sshDestination))
                }
                throw GrantRequestError.invalidTarget(
                    "remote target '\(targetID)' does not match the link's pinned SSH destination or host key"
                )
            }
            // Cross-device fallback: ONLY match by explicit SSH destination (+ host-key pin when present),
            // never by display name alone.
            if remoteSSH != nil {
                let byTrust = base.configuredRemoteTargets.filter(matchesRemoteTrust)
                if byTrust.count == 1 {
                    return base.focusing(remoteTarget: byTrust[0])
                }
                if byTrust.count > 1 {
                    throw ProfileError.ambiguousRemoteTarget(remoteSSH ?? targetID, byTrust.map(\.sshDestination))
                }
            }
            throw GrantRequestError.invalidTarget("remote target '\(targetID)' isn't configured for \(base.displayName)")
        }

        if let targetName {
            guard let matched = try base.resolveRemoteTarget(named: targetName) else {
                throw GrantRequestError.invalidTarget("remote target '\(targetName)' isn't configured for \(base.displayName)")
            }
            guard matchesRemoteTrust(matched) else {
                throw GrantRequestError.invalidTarget(
                    "remote target '\(targetName)' does not match the link's pinned SSH destination or host key"
                )
            }
            return base.focusing(remoteTarget: matched)
        }

        if remoteSSH != nil || remoteHostKeyFP != nil {
            let byTrust = base.configuredRemoteTargets.filter(matchesRemoteTrust)
            if byTrust.count == 1 {
                return base.focusing(remoteTarget: byTrust[0])
            }
            if byTrust.count > 1 {
                throw ProfileError.ambiguousRemoteTarget(remoteSSH ?? "remote", byTrust.map(\.sshDestination))
            }
            throw GrantRequestError.invalidTarget(
                "no remote target on \(base.displayName) matches the link's pinned SSH destination or host key"
            )
        }

        return base
    }

    /// Parses a `baobuddy://grant?r=HOURS%3D2%20SSH%3Ddocker...` (or legacy `baogrant://`) URL into a validated `GrantRequest`.
    public static func parse(url: URL, profile: BaoProfile) throws -> GrantRequest {
        guard let scheme = url.scheme?.lowercased(),
              scheme == "baobuddy" || scheme == "baogrant" else {
            throw GrantRequestError.invalidURL(url.absoluteString)
        }
        guard url.host?.lowercased() == "grant" else {
            throw GrantRequestError.invalidURL(url.absoluteString)
        }
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        let raw = components?.queryItems?.first(where: { $0.name == "r" })?.value ?? ""
        let target: GrantTarget
        switch components?.queryItems?.first(where: { $0.name == "target" })?.value?.lowercased() {
        case nil, "":
            target = profile.hasRemoteTarget ? .t3 : .mac
        case "local", "mac":
            target = .mac
        case "remote", "t3":
            guard profile.hasRemoteTarget else {
                throw GrantRequestError.invalidTarget("remote (this server profile has no remote target)")
            }
            target = .t3
        case let other?:
            throw GrantRequestError.invalidTarget(other)
        }
        // Links come from outside the app, so they may only name policies from the profile's catalog.
        return try parse(requestString: raw, target: target, profile: profile, allowUncataloguedPolicies: false)
    }

    /// Parses canonical `HOURS=2 WRITE=1 SSH=docker KEYS=talos PUSH=1 POLICIES=... WHY=...` text.
    /// `allowUncataloguedPolicies` lets typed CLI input name any policy when the profile has no
    /// `grant_policies` catalog. Deep links always pass `false`.
    public static func parse(
        requestString: String,
        target: GrantTarget = .t3,
        profile: BaoProfile,
        allowUncataloguedPolicies: Bool = true
    ) throws -> GrantRequest {
        var remaining = requestString.trimmingCharacters(in: .whitespacesAndNewlines)
        var why = ""

        if let range = remaining.range(of: #"\bWHY=(.*)$"#, options: [.regularExpression, .caseInsensitive]) {
            let matched = String(remaining[range])
            if let eq = matched.firstIndex(of: "=") {
                why = sanitizeWhy(String(matched[matched.index(after: eq)...]))
            }
            remaining = String(remaining[..<range.lowerBound]).trimmingCharacters(in: .whitespaces)
        }

        let allowedKeys = profile.openbao.keys.map(\.name)
        let allowedHosts = profile.openbao.ssh.hosts.map(\.name)
        let allowedCustomPolicies = profile.openbao.grantPolicies.map(\.name)
        let maxHours = profile.openbao.maxHours

        var hours = 2
        var write = false
        var keys: [String] = []
        var sshHosts: [String] = []
        var push = false
        var customPolicies: [String] = []
        var extensionIDs: [String] = []
        let allowedExtensions = profile.openbao.enabledExtensions.map(\.id)

        for word in remaining.split(whereSeparator: \.isWhitespace).map(String.init) {
            guard let eq = word.firstIndex(of: "=") else {
                throw GrantRequestError.unknownToken(word)
            }
            let key = String(word[..<eq]).uppercased()
            let rawValue = String(word[word.index(after: eq)...])
            let value = rawValue.lowercased()

            switch key {
            case "HOURS":
                guard let parsed = Int(value), parsed >= 1, parsed <= maxHours else {
                    throw GrantRequestError.invalidHours(maxHours)
                }
                hours = parsed
            case "WRITE":
                write = try parseBoolFlag(name: "WRITE", value: value)
            case "PUSH":
                push = try parseBoolFlag(name: "PUSH", value: value)
            case "SSH":
                sshHosts = try parseList(value: value, allowed: allowedHosts) {
                    GrantRequestError.unknownSSHHost($0, allowedHosts)
                }
            case "KEYS":
                keys = try parseList(value: value, allowed: allowedKeys) {
                    GrantRequestError.unknownKey($0, allowedKeys)
                }
            case "POLICIES":
                if allowedCustomPolicies.isEmpty {
                    guard allowUncataloguedPolicies else {
                        throw GrantRequestError.policiesNeedCatalog
                    }
                    customPolicies = rawValue
                        .split(separator: ",")
                        .map { String($0).trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }
                } else {
                    customPolicies = try parseList(value: rawValue, allowed: allowedCustomPolicies) {
                        GrantRequestError.unknownPolicy($0, allowedCustomPolicies)
                    }
                }
            case "EXT":
                // Only the profile's enabled extensions can be named, so links can use EXT= too.
                extensionIDs = try parseList(value: value, allowed: allowedExtensions) {
                    GrantRequestError.unknownExtension($0, allowedExtensions)
                }
            default:
                throw GrantRequestError.unknownToken(word)
            }
        }

        let request = GrantRequest(
            target: target,
            hours: hours,
            write: write,
            keys: keys,
            sshHosts: sshHosts,
            push: push,
            customPolicies: customPolicies,
            why: why,
            extensions: extensionIDs
        )
        try request.validate(against: profile)
        return request
    }

    public func validate(against profile: BaoProfile) throws {
        guard hours >= 1, hours <= profile.openbao.maxHours else {
            throw GrantRequestError.invalidHours(profile.openbao.maxHours)
        }
        let allowedKeys = Set(profile.openbao.keys.map(\.name))
        for key in keys where !allowedKeys.contains(key) {
            throw GrantRequestError.unknownKey(key, profile.openbao.keys.map(\.name))
        }
        let allowedHosts = Set(profile.openbao.ssh.hosts.map(\.name))
        for host in sshHosts where !allowedHosts.contains(host) {
            throw GrantRequestError.unknownSSHHost(host, profile.openbao.ssh.hosts.map(\.name))
        }
        // Uncatalogued names (typed CLI input) still reach the biometric prompt and the server, so
        // they get the same character rules as profile identifiers: no globs, spaces, or bidi.
        for policy in customPolicies where !ProfileText.isIdentifier(policy) {
            throw GrantRequestError.unknownPolicy(policy, profile.openbao.grantPolicies.map(\.name))
        }
        if !customPolicies.isEmpty, profile.openbao.usesCustomPolicies {
            let allowed = Set(profile.openbao.grantPolicies.map(\.name))
            for policy in customPolicies where !allowed.contains(policy) {
                throw GrantRequestError.unknownPolicy(policy, profile.openbao.grantPolicies.map(\.name))
            }
        }
        let enabledIDs = profile.openbao.enabledExtensions.map(\.id)
        for id in extensions where !enabledIDs.contains(id) {
            throw GrantRequestError.unknownExtension(id, enabledIDs)
        }
        if openBaoPolicies(profile: profile).isEmpty {
            throw GrantRequestError.emptyPolicies
        }
        if target == .mac {
            if !sshHosts.isEmpty { throw GrantRequestError.sshOnlyForT3 }
            if push { throw GrantRequestError.pushOnlyForT3 }
        }

        let audit = profile.openbao.auditPolicy
        let elevated = isElevated(profile: profile)
        let needsReason = audit.requireReason || (audit.requireReasonForElevated && elevated)
        if needsReason && why.isEmpty {
            throw GrantRequestError.reasonRequired(elevatedOnly: !audit.requireReason && audit.requireReasonForElevated)
        }
        let pattern = audit.reasonPattern.trimmingCharacters(in: .whitespacesAndNewlines)
        if !pattern.isEmpty && (needsReason || !why.isEmpty) {
            // Fails closed: a pattern that doesn't compile, or that takes too long on this input
            // (catastrophic backtracking), counts as a mismatch.
            if !ReasonPattern.matches(pattern: pattern, text: why) {
                let hint = audit.reasonPlaceholder.trimmingCharacters(in: .whitespacesAndNewlines)
                throw GrantRequestError.reasonPatternMismatch(hint.isEmpty ? pattern : hint)
            }
        }
    }

    public var canonicalText: String {
        var words = ["HOURS=\(hours)"]
        if !customPolicies.isEmpty {
            words.append("POLICIES=\(customPolicies.joined(separator: ","))")
            if !sshHosts.isEmpty { words.append("SSH=\(sshHosts.joined(separator: ","))") }
        } else {
            if write { words.append("WRITE=1") }
            if !sshHosts.isEmpty { words.append("SSH=\(sshHosts.joined(separator: ","))") }
            if !keys.isEmpty { words.append("KEYS=\(keys.joined(separator: ","))") }
        }
        if push { words.append("PUSH=1") }
        if !extensions.isEmpty { words.append("EXT=\(extensions.joined(separator: ","))") }
        if !why.isEmpty { words.append("WHY=\(why)") }
        return words.joined(separator: " ")
    }

    /// OpenBao policy list for this grant: explicit custom policies or the profile's policy naming
    /// rules, plus the policy each selected credential extension declares.
    public func openBaoPolicies(profile: BaoProfile) -> [String] {
        var policies = basePolicies(profile: profile)
        for ext in selectedExtensions(profile: profile) where !ext.policy.isEmpty && !policies.contains(ext.policy) {
            policies.append(ext.policy)
        }
        return policies
    }

    /// The selected extensions, in profile order. Unknown or disabled IDs are left out
    /// (`validate` rejects them).
    public func selectedExtensions(profile: BaoProfile) -> [BaoCredentialExtension] {
        let selected = Set(extensions)
        return profile.openbao.enabledExtensions.filter { selected.contains($0.id) }
    }

    private func basePolicies(profile: BaoProfile) -> [String] {
        if !customPolicies.isEmpty {
            return customPolicies
        }
        if profile.openbao.usesCustomPolicies {
            return profile.openbao.grantPolicies.filter(\.defaultSelected).map(\.name)
        }
        let cfg = profile.openbao.policies
        var policies: [String] = []
        if !cfg.read.isEmpty {
            policies.append(cfg.read)
        }
        if write, !cfg.write.isEmpty {
            policies.append(cfg.write)
        }
        for key in keys {
            policies.append("\(cfg.keyPrefix)\(key)")
            if write, !cfg.keyWriteSuffix.isEmpty {
                policies.append("\(cfg.keyPrefix)\(key)\(cfg.keyWriteSuffix)")
            }
        }
        return policies
    }

    /// OpenBao SSH principals in profile order.
    public func sshPrincipals(profile: BaoProfile) -> [String] {
        let selected = Set(sshHosts)
        return profile.openbao.ssh.hosts.compactMap { selected.contains($0.name) ? $0.principal : nil }
    }

    /// Canonical audit scope string written into the signed JWT `scope` claim and grant metadata.
    /// Includes resolved SSH signing role and exact principals when SSH access is requested.
    public func auditScope(profile: BaoProfile) -> String {
        var text = canonicalText
        if !sshHosts.isEmpty {
            let principals = sshPrincipals(profile: profile)
            var extra: [String] = []
            if !profile.openbao.ssh.role.isEmpty {
                extra.append("SSH_ROLE=\(profile.openbao.ssh.role)")
            }
            if !principals.isEmpty {
                extra.append("SSH_PRINCIPALS=\(principals.joined(separator: ","))")
            }
            if !extra.isEmpty {
                text += " " + extra.joined(separator: " ")
            }
        }
        return text
    }

    /// Plain-English summary shown in the biometric prompt and approval UI.
    /// Always names the destination server (and namespace when configured) so two servers remain distinct.
    public func summary(profile: BaoProfile) -> String {
        let duration = GrantDurationText.hours(hours)
        var text = String(
            localized: "\(targetLabel(profile: profile)) on \(profile.promptServerDescription) (\(duration)): \(scopeDescription(profile: profile))",
            table: "BaoBuddyCore",
            comment: "Grant summary in the Face ID / Touch ID prompt. %1$@ is where the grant or token goes (for example: Grant to Build Host, or Show token in BaoBuddy); %2$@ is the server; %3$@ is the duration (for example: 2 hours); %4$@ is what it can access."
        )
        if !why.isEmpty {
            text += " — \(why)"
        }
        return text
    }

    /// Where the grant goes, as shown in prompts: the remote target's name, or this device.
    public func targetLabel(profile: BaoProfile) -> String {
        switch target {
        case .t3:
            return String(localized: "Grant to \(profile.targetDisplayName)", table: "BaoBuddyCore", comment: "Where a grant goes, in the Face ID / Touch ID prompt. %@ is the remote host's name.")
        case .mac:
            return String(localized: "Token for this device", table: "BaoBuddyCore", comment: "Where a grant goes, in the Face ID / Touch ID prompt: a token shown on this device.")
        }
    }

    /// Plain-English description of what the grant can reach, without duration or reason.
    /// Policy names are always shown next to any profile-supplied label, so a misleading label
    /// can't hide what is actually requested.
    public func scopeDescription(profile: BaoProfile) -> String {
        var parts: [String] = []
        if !customPolicies.isEmpty || profile.openbao.usesCustomPolicies {
            let labels = openBaoPolicies(profile: profile).map { name -> String in
                let label = profile.openbao.policyLabel(for: name)
                return label == name ? name : "\(label) [\(name)]"
            }
            parts.append(String(localized: "Policies: \(labels.joined(separator: ", "))", table: "BaoBuddyCore", comment: "Grant scope. %@ is a comma-separated list of OpenBao policy names, which are not translated."))
        } else {
            parts.append(write
                ? String(localized: "Read and write secrets", table: "BaoBuddyCore", comment: "Grant scope: the grant can read and write secrets.")
                : String(localized: "Read secrets", table: "BaoBuddyCore", comment: "Grant scope: the grant can only read secrets."))
            if !keys.isEmpty {
                parts.append(String(localized: "keys: \(keys.joined(separator: ", "))", table: "BaoBuddyCore", comment: "Grant scope, after a semicolon. %@ is a comma-separated list of restricted secret key names (not translated)."))
            }
        }
        if !sshHosts.isEmpty {
            let selected = Set(sshHosts)
            let labels = profile.openbao.ssh.hosts
                .filter { selected.contains($0.name) }
                .map {
                    String(
                        localized: "\($0.user)@\($0.name) [principal: \($0.principal)]",
                        table: "BaoBuddyCore",
                        comment: "One SSH login in a grant scope: user@host, then the SSH certificate principal. Keep the @ and brackets; translate only the word principal (an SSH term)."
                    )
                }
            let hostList = labels.joined(separator: ", ")
            parts.append(profile.openbao.ssh.role.isEmpty
                ? String(localized: "SSH: \(hostList)", table: "BaoBuddyCore", comment: "Grant scope. %@ is a comma-separated list of SSH logins.")
                : String(localized: "SSH (role \(profile.openbao.ssh.role)): \(hostList)", table: "BaoBuddyCore", comment: "Grant scope. %1$@ is the OpenBao SSH signing role name; %2$@ is a comma-separated list of SSH logins."))
        }
        if push {
            parts.append(String(localized: "GitHub push (1h)", table: "BaoBuddyCore", comment: "Grant scope: a one-hour token for pushing to GitHub. 1h means one hour."))
        }
        let exts = selectedExtensions(profile: profile)
        if !exts.isEmpty {
            // The endpoint is always shown, so a label can't hide which secrets engine is called.
            let labels = exts.map { ext in
                ext.policy.isEmpty
                    ? "\(ext.displayLabel) [\(ext.endpoint)]"
                    : String(
                        localized: "\(ext.displayLabel) [\(ext.endpoint), policy \(ext.policy)]",
                        table: "BaoBuddyCore",
                        comment: "A credential extension in a grant scope. %1$@ is its name; %2$@ is an OpenBao path; %3$@ is an OpenBao policy name."
                    )
            }
            parts.append(String(localized: "Credentials: \(labels.joined(separator: ", "))", table: "BaoBuddyCore", comment: "Grant scope. %@ is a comma-separated list of credential extensions (extra credentials minted with the grant)."))
        }
        return parts.joined(separator: "; ")
    }

    public var hasElevatedPermissions: Bool {
        write || !keys.isEmpty || !sshHosts.isEmpty || push
    }

    public func isElevated(profile: BaoProfile) -> Bool {
        if hasElevatedPermissions { return true }
        if selectedExtensions(profile: profile).contains(where: \.elevated) { return true }
        let selected = Set(openBaoPolicies(profile: profile))
        return profile.openbao.grantPolicies.contains { selected.contains($0.name) && $0.elevated }
    }

    private static func parseBoolFlag(name: String, value: String) throws -> Bool {
        switch value {
        case "1", "yes", "true": return true
        case "0", "no", "false", "": return false
        default: throw GrantRequestError.invalidFlag(name, value)
        }
    }

    private static func parseList(
        value: String,
        allowed: [String],
        unknownError: (String) -> GrantRequestError
    ) throws -> [String] {
        switch value {
        case "", "0", "no", "none":
            return []
        case "1", "yes", "all":
            return allowed
        default:
            // Match case-insensitively but return the profile's own spelling.
            let parts = value.split(separator: ",").map { String($0).lowercased() }
            let allowedLower = Set(allowed.map { $0.lowercased() })
            for item in parts where !allowedLower.contains(item) {
                throw unknownError(item)
            }
            let selected = Set(parts)
            return allowed.filter { selected.contains($0.lowercased()) }
        }
    }
}

/// Matches an admin-supplied reason pattern with a time limit. `NSRegularExpression` has no
/// timeout and a badly written pattern can backtrack for minutes, so the match runs on a
/// background thread and the caller stops waiting after `timeout`.
enum ReasonPattern {
    /// True only when the pattern compiles and matches within `timeout`. A pattern that doesn't
    /// compile or a match that runs too long returns false (fail closed). A match that times out
    /// keeps running on its background thread until it finishes.
    static func matches(pattern: String, text: String, timeout: TimeInterval = 0.25) -> Bool {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return false }
        final class Box: @unchecked Sendable {
            var result = false
        }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        let thread = Thread {
            let range = NSRange(text.startIndex..<text.endIndex, in: text)
            box.result = regex.firstMatch(in: text, range: range) != nil
            done.signal()
        }
        thread.stackSize = 1 << 20
        thread.start()
        guard done.wait(timeout: .now() + timeout) == .success else {
            return false
        }
        return box.result
    }
}

/// Grant durations as shown in prompts and banners. "1 hour" is its own string so the English
/// text stays right where the strings aren't localized (the macOS helper and CLI).
enum GrantDurationText {
    static func hours(_ hours: Int) -> String {
        hours == 1
            ? String(localized: "1 hour", table: "BaoBuddyCore", comment: "A grant's duration.")
            : String(localized: "\(hours) hours", table: "BaoBuddyCore", comment: "A grant's duration. %lld is a number of hours, 2 or more.")
    }
}
