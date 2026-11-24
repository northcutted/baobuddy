import CryptoKit
import Foundation

public struct BaoJWTAuthConfig: Codable, Equatable, Sendable {
    public var mount: String
    public var role: String
    public var issuer: String
    public var audience: String
    public var subject: String

    public init(mount: String, role: String, issuer: String, audience: String = "", subject: String) {
        self.mount = mount
        self.role = role
        self.issuer = issuer
        self.audience = audience
        self.subject = subject
    }

    enum CodingKeys: String, CodingKey {
        case mount
        case role
        case issuer
        case audience
        case subject
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mount = try container.decode(String.self, forKey: .mount)
        self.role = try container.decode(String.self, forKey: .role)
        self.issuer = try container.decode(String.self, forKey: .issuer)
        self.audience = try container.decodeIfPresent(String.self, forKey: .audience) ?? ""
        self.subject = try container.decode(String.self, forKey: .subject)
    }
}

public struct BaoTokenRolesConfig: Codable, Equatable, Sendable {
    public var mac: String
    public var t3: String

    enum CodingKeys: String, CodingKey {
        case mac
        case t3
        case local
        case remote
    }

    public init(mac: String, t3: String) {
        self.mac = mac
        self.t3 = t3
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let localRole = try container.decodeIfPresent(String.self, forKey: .mac)
            ?? container.decodeIfPresent(String.self, forKey: .local)
            ?? "grant"
        let remoteRole = try container.decodeIfPresent(String.self, forKey: .t3)
            ?? container.decodeIfPresent(String.self, forKey: .remote)
            ?? localRole
        self.mac = localRole
        self.t3 = remoteRole
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        // Written with the generic `local` / `remote` names; `mac` / `t3` are still read for old profiles.
        try container.encode(mac, forKey: .local)
        try container.encode(t3, forKey: .remote)
    }
}

/// Customizable OpenBao/Vault policy names for standard read/write/keys profiles.
public struct BaoPolicyConfig: Codable, Equatable, Sendable {
    public var read: String
    public var write: String
    public var keyPrefix: String
    public var keyWriteSuffix: String

    enum CodingKeys: String, CodingKey {
        case read
        case write
        case keyPrefix = "key_prefix"
        case keyWriteSuffix = "key_write_suffix"
    }

    /// Default standard-mode policy names when a profile omits `policies`.
    /// New profiles should name their policies explicitly (or use `grant_policies`).
    public static let defaultStandard = BaoPolicyConfig(
        read: "app-read",
        write: "app-write",
        keyPrefix: "key-",
        keyWriteSuffix: "-write"
    )

    public init(
        read: String = "app-read",
        write: String = "app-write",
        keyPrefix: String = "key-",
        keyWriteSuffix: String = "-write"
    ) {
        self.read = read
        self.write = write
        self.keyPrefix = keyPrefix
        self.keyWriteSuffix = keyWriteSuffix
    }
}

/// A user-defined OpenBao / Vault policy that dynamically renders as a selectable option in the UI.
public struct BaoBuddyPolicy: Codable, Equatable, Identifiable, Sendable {
    public var name: String
    public var label: String
    public var description: String
    public var elevated: Bool
    public var defaultSelected: Bool

    public var id: String { name }

    public var displayLabel: String {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? name : trimmed
    }

    enum CodingKeys: String, CodingKey {
        case name
        case label
        case description
        case elevated
        case defaultSelected = "default_selected"
    }

    public init(
        name: String,
        label: String = "",
        description: String = "",
        elevated: Bool = false,
        defaultSelected: Bool = false
    ) {
        self.name = name
        self.label = label
        self.description = description
        self.elevated = elevated
        self.defaultSelected = defaultSelected
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)
        self.label = try container.decodeIfPresent(String.self, forKey: .label) ?? ""
        self.description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        self.elevated = try container.decodeIfPresent(Bool.self, forKey: .elevated) ?? false
        self.defaultSelected = try container.decodeIfPresent(Bool.self, forKey: .defaultSelected) ?? false
    }
}

public struct BaoKeyItem: Codable, Equatable, Identifiable, Sendable {
    public var name: String
    public var item: String
    public var id: String { name }

    public init(name: String, item: String) {
        self.name = name
        self.item = item
    }
}

public struct BaoSSHHost: Codable, Equatable, Identifiable, Sendable {
    public var name: String
    public var user: String
    public var principal: String
    public var id: String { name }

    public init(name: String, user: String, principal: String) {
        self.name = name
        self.user = user
        self.principal = principal
    }
}

public struct BaoSSHConfig: Codable, Equatable, Sendable {
    public var role: String
    public var hosts: [BaoSSHHost]

    public init(role: String, hosts: [BaoSSHHost]) {
        self.role = role
        self.hosts = hosts
    }
}

/// Optional audit & change-management requirements enforced before approving a grant.
public struct BaoAuditPolicy: Codable, Equatable, Sendable {
    public var requireReason: Bool
    public var requireReasonForElevated: Bool
    /// Optional regular expression that the grant reason must match (for example `^(INC|CHG|JIRA)-[0-9]+`).
    public var reasonPattern: String
    /// Optional UI prompt hint (for example `INC-12345 — brief change summary`).
    public var reasonPlaceholder: String

    public static let none = BaoAuditPolicy()

    public var isEmpty: Bool {
        !requireReason
            && !requireReasonForElevated
            && reasonPattern.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && reasonPlaceholder.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    enum CodingKeys: String, CodingKey {
        case requireReason = "require_reason"
        case requireReasonForElevated = "require_reason_for_elevated"
        case reasonPattern = "reason_pattern"
        case reasonPlaceholder = "reason_placeholder"
    }

    public init(
        requireReason: Bool = false,
        requireReasonForElevated: Bool = false,
        reasonPattern: String = "",
        reasonPlaceholder: String = ""
    ) {
        self.requireReason = requireReason
        self.requireReasonForElevated = requireReasonForElevated
        self.reasonPattern = reasonPattern
        self.reasonPlaceholder = reasonPlaceholder
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.requireReason = try container.decodeIfPresent(Bool.self, forKey: .requireReason) ?? false
        self.requireReasonForElevated = try container.decodeIfPresent(Bool.self, forKey: .requireReasonForElevated) ?? false
        self.reasonPattern = try container.decodeIfPresent(String.self, forKey: .reasonPattern) ?? ""
        self.reasonPlaceholder = try container.decodeIfPresent(String.self, forKey: .reasonPlaceholder) ?? ""
    }
}

public struct BaoOpenBaoConfig: Codable, Equatable, Sendable {
    public typealias JWTAuth = BaoJWTAuthConfig
    public typealias TokenRoles = BaoTokenRolesConfig
    public typealias PolicyConfig = BaoPolicyConfig
    public typealias GrantPolicy = BaoBuddyPolicy
    public typealias KeyItem = BaoKeyItem
    public typealias SSHHost = BaoSSHHost
    public typealias SSHConfig = BaoSSHConfig
    public typealias AuditPolicy = BaoAuditPolicy

    public var address: String
    /// Optional Vault Enterprise / HCP Vault / OpenBao 2.x namespace sent via `X-Vault-Namespace`.
    public var namespace: String
    public var caPEM: String
    /// Optional Keychain client certificate label (Common Name or SHA-256 fingerprint) for mTLS.
    /// References a client identity already installed in the Apple Keychain (e.g. via MDM/SCEP);
    /// private keys are never stored in profile JSON.
    public var mtlsClientIdentity: String
    public var jwtAuth: BaoJWTAuthConfig
    public var tokenRoles: BaoTokenRolesConfig
    public var policies: BaoPolicyConfig
    /// Optional custom OpenBao/Vault policy catalog. When non-empty, the UI renders dynamic toggles for these policies.
    public var grantPolicies: [BaoBuddyPolicy]
    /// Optional enterprise audit / change-ticket rules (required reason, ticket regex).
    public var auditPolicy: BaoAuditPolicy
    /// Optional OpenTelemetry OTLP/HTTP telemetry config (disabled by default).
    public var telemetry: BaoTelemetryConfig
    /// Optional workflow-agnostic dynamic credential extensions (AWS STS, K8s, DB, PKI, GitHub, etc.).
    public var extensions: [BaoCredentialExtension]
    public var maxHours: Int
    public var keys: [BaoKeyItem]
    public var ssh: BaoSSHConfig
    /// Legacy: KV v2 item holding a GitHub App private key that the client reads to mint push tokens.
    /// This sends a non-expiring credential to every client; prefer `githubTokenPath`.
    public var githubAppItem: String
    /// Path of a server-side GitHub token endpoint (for example a `vault-plugin-secrets-github`
    /// permission set such as `github/token/push`). The server mints the token, so the App key
    /// never leaves OpenBao/Vault.
    public var githubTokenPath: String

    public var usesCustomPolicies: Bool {
        !grantPolicies.isEmpty
    }

    /// Whether TLS is pinned to `ca_pem`. When false, the system trust store is used.
    public var isTLSPinned: Bool {
        !caPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Canonical `scheme://host[:port]` origin (without path).
    public var normalizedOrigin: String {
        Self.normalizeOrigin(address)
    }

    /// Canonical `host[:port]` authority (omitting default ports 443 for https and 80 for http).
    public var normalizedAuthority: String {
        Self.normalizeAuthority(address)
    }

    /// Canonical normalized base path (empty string for root, or `/prefix/sub` without trailing slash).
    public var normalizedBasePath: String {
        Self.normalizeBasePath(address)
    }

    /// Canonical full base endpoint (`scheme://host[:port][/base/path]`).
    public var normalizedBaseEndpoint: String {
        Self.normalizeBaseEndpoint(address)
    }

    /// Canonical authority + base path (`host[:port][/base/path]`) for human prompts and display.
    public var normalizedAuthorityAndPath: String {
        Self.normalizeAuthorityAndPath(address)
    }

    /// Stable v3 hash identifying this exact OpenBao/Vault deployment trust domain
    /// (origin + normalized base path + namespace + TLS CA pin + mTLS identity).
    /// Bumped from `v2` so pre-upgrade ambiguous path-aliased Keychain entries are never reused.
    public var issuerBindingKey: String {
        Self.issuerBindingKey(
            address: address,
            namespace: namespace,
            caPEM: caPEM,
            mtlsClientIdentity: mtlsClientIdentity
        )
    }

    public static func issuerBindingKey(
        address: String,
        namespace: String = "",
        caPEM: String = "",
        mtlsClientIdentity: String = ""
    ) -> String {
        let trimmedNS = namespace.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let trimmedCA = caPEM.trimmingCharacters(in: .whitespacesAndNewlines)
        let caHash = trimmedCA.isEmpty
            ? "system"
            : SHA256.hash(data: Data(trimmedCA.utf8)).map { String(format: "%02x", $0) }.joined()
        let trimmedMTLS = mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = [
            "v3",
            Self.encodeBindingComponent(normalizeOrigin(address)),
            Self.encodeBindingComponent(normalizeBasePath(address)),
            Self.encodeBindingComponent(trimmedNS),
            Self.encodeBindingComponent(caHash),
            Self.encodeBindingComponent(trimmedMTLS)
        ]
        let digest = SHA256.hash(data: Data(parts.joined(separator: "|").utf8))
            .map { String(format: "%02x", $0) }.joined()
        return "v3-\(digest.prefix(24))"
    }

    /// Expected endpoint-, base-path-, namespace-, trust-pin/mTLS-, and mount-bound JWT audience.
    public var expectedOriginMountAudience: String {
        Self.defaultAudience(
            address: address,
            namespace: namespace,
            mount: jwtAuth.mount,
            caPEM: caPEM,
            mtlsClientIdentity: mtlsClientIdentity
        )
    }

    /// True when the profile uses a deployment-bound `baobuddy://...` audience matching this profile.
    public var usesBoundAudience: Bool {
        jwtAuth.audience.trimmingCharacters(in: .whitespacesAndNewlines) == expectedOriginMountAudience
    }

    /// True when the profile does not use a `baobuddy://...` deployment-bound audience.
    public var isLegacySharedAudience: Bool {
        !jwtAuth.audience.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("baobuddy://")
    }

    /// Derives a trust-domain-bound JWT audience:
    /// `baobuddy://<host[:port]>[/ns/<ns>]/auth/<mount>[?base=<path>&mtls=<hash16>&pin=<hash16>]`
    /// Distinct reverse-proxy base paths, mTLS client identities, and TLS CA/leaf pins on the
    /// same host produce distinct audiences so tokens/JWTs cannot be replayed across backends.
    public static func defaultAudience(
        address: String,
        namespace: String = "",
        mount: String,
        caPEM: String = "",
        mtlsClientIdentity: String = ""
    ) -> String {
        let authority = normalizeAuthority(address)
        let basePath = normalizeBasePath(address)
        let cleanNS = namespace.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let cleanMount = mount.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        var result: String
        if cleanNS.isEmpty {
            result = "baobuddy://\(authority)/auth/\(cleanMount)"
        } else {
            result = "baobuddy://\(authority)/ns/\(cleanNS)/auth/\(cleanMount)"
        }
        var queryItems: [String] = []
        if !basePath.isEmpty {
            queryItems.append("base=\(encodeBindingComponent(basePath))")
        }
        let trimmedMTLS = mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedMTLS.isEmpty {
            let mtlsHash = SHA256.hash(data: Data(trimmedMTLS.utf8))
                .map { String(format: "%02x", $0) }.joined()
            queryItems.append("mtls=\(mtlsHash.prefix(16))")
        }
        let trimmedCA = caPEM.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedCA.isEmpty {
            let pinHash = SHA256.hash(data: Data(trimmedCA.utf8))
                .map { String(format: "%02x", $0) }.joined()
            queryItems.append("pin=\(pinHash.prefix(16))")
        }
        if !queryItems.isEmpty {
            result += "?" + queryItems.joined(separator: "&")
        }
        return result
    }

    public static func normalizeOrigin(_ address: String) -> String {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              let host = url.host?.lowercased(), !host.isEmpty else {
            return trimmed.lowercased()
        }
        let authority = normalizeAuthority(address)
        return "\(scheme)://\(authority)"
    }

    public static func normalizeBasePath(_ address: String) -> String {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed) else { return "" }
        let raw = url.path
        guard !raw.isEmpty, raw != "/" else { return "" }
        var cleaned = raw
        while cleaned.hasSuffix("/") && cleaned.count > 1 {
            cleaned.removeLast()
        }
        return cleaned == "/" ? "" : cleaned
    }

    public static func normalizeBaseEndpoint(_ address: String) -> String {
        let origin = normalizeOrigin(address)
        let basePath = normalizeBasePath(address)
        return origin + basePath
    }

    public static func normalizeAuthorityAndPath(_ address: String) -> String {
        normalizeAuthority(address) + normalizeBasePath(address)
    }

    public static func encodeBindingComponent(_ value: String) -> String {
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    public static func normalizeAuthority(_ address: String) -> String {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              let rawHost = url.host?.lowercased(), !rawHost.isEmpty else {
            return trimmed.lowercased()
        }
        let host = rawHost.contains(":") && !rawHost.hasPrefix("[") ? "[\(rawHost)]" : rawHost
        if let port = url.port {
            let isDefault = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
            return isDefault ? host : "\(host):\(port)"
        }
        return host
    }

    /// Enabled credential extensions available during grant approval.
    public var enabledExtensions: [BaoCredentialExtension] {
        extensions.filter(\.enabled)
    }

    /// Display label for a policy name. The first catalog entry wins when a profile lists a name
    /// twice, so a duplicated name in an imported or MDM profile can't crash the UI.
    public func policyLabel(for name: String) -> String {
        grantPolicies.first(where: { $0.name == name })?.displayLabel ?? name
    }

    enum CodingKeys: String, CodingKey {
        case address
        case namespace
        case caPEM = "ca_pem"
        case mtlsClientIdentity = "mtls_client_identity"
        case jwtAuth = "jwt_auth"
        case tokenRoles = "token_roles"
        case policies
        case grantPolicies = "grant_policies"
        case auditPolicy = "audit_policy"
        case telemetry
        case extensions
        case maxHours = "max_hours"
        case keys
        case ssh
        case githubAppItem = "github_app_item"
        case githubTokenPath = "github_token_path"
    }

    public init(
        address: String,
        namespace: String = "",
        caPEM: String,
        mtlsClientIdentity: String = "",
        jwtAuth: BaoJWTAuthConfig,
        tokenRoles: BaoTokenRolesConfig,
        policies: BaoPolicyConfig = .defaultStandard,
        grantPolicies: [BaoBuddyPolicy] = [],
        auditPolicy: BaoAuditPolicy = .none,
        telemetry: BaoTelemetryConfig = .disabled,
        extensions: [BaoCredentialExtension] = [],
        maxHours: Int,
        keys: [BaoKeyItem],
        ssh: BaoSSHConfig,
        githubAppItem: String,
        githubTokenPath: String = ""
    ) {
        self.address = address
        self.namespace = namespace
        self.caPEM = caPEM
        self.mtlsClientIdentity = mtlsClientIdentity
        self.jwtAuth = jwtAuth
        self.tokenRoles = tokenRoles
        self.policies = policies
        self.grantPolicies = grantPolicies
        self.auditPolicy = auditPolicy
        self.telemetry = telemetry
        self.extensions = extensions
        self.maxHours = maxHours
        self.keys = keys
        self.ssh = ssh
        self.githubAppItem = githubAppItem
        self.githubTokenPath = githubTokenPath
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedAddress = try container.decode(String.self, forKey: .address)
        let decodedNS = try container.decodeIfPresent(String.self, forKey: .namespace) ?? ""
        let decodedCA = try container.decodeIfPresent(String.self, forKey: .caPEM) ?? ""
        let decodedMTLS = try container.decodeIfPresent(String.self, forKey: .mtlsClientIdentity) ?? ""
        var decodedJWT = try container.decode(BaoJWTAuthConfig.self, forKey: .jwtAuth)
        // Omitting or leaving `jwt_auth.audience` empty derives the canonical trust-domain-bound
        // audience from deployment inputs (including base path, CA pin, and mTLS identity), so
        // MDM templates and profiles never need hand-maintained hashes. Non-empty custom audiences
        // (for external JWT roles) are kept verbatim, and mismatched `baobuddy://` audiences still
        // fail validation in JWTSigner.
        if decodedJWT.audience.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            decodedJWT.audience = Self.defaultAudience(
                address: decodedAddress,
                namespace: decodedNS,
                mount: decodedJWT.mount,
                caPEM: decodedCA,
                mtlsClientIdentity: decodedMTLS
            )
        }
        self.address = decodedAddress
        self.namespace = decodedNS
        self.caPEM = decodedCA
        self.mtlsClientIdentity = decodedMTLS
        self.jwtAuth = decodedJWT
        self.tokenRoles = try container.decodeIfPresent(BaoTokenRolesConfig.self, forKey: .tokenRoles)
            ?? BaoTokenRolesConfig(mac: "grant", t3: "grant")
        self.policies = try container.decodeIfPresent(BaoPolicyConfig.self, forKey: .policies) ?? .defaultStandard
        self.grantPolicies = try container.decodeIfPresent([BaoBuddyPolicy].self, forKey: .grantPolicies) ?? []
        self.auditPolicy = try container.decodeIfPresent(BaoAuditPolicy.self, forKey: .auditPolicy) ?? .none
        self.telemetry = try container.decodeIfPresent(BaoTelemetryConfig.self, forKey: .telemetry) ?? .disabled
        self.extensions = try container.decodeIfPresent([BaoCredentialExtension].self, forKey: .extensions) ?? []
        self.maxHours = try container.decodeIfPresent(Int.self, forKey: .maxHours) ?? 12
        self.keys = try container.decodeIfPresent([BaoKeyItem].self, forKey: .keys) ?? []
        self.ssh = try container.decodeIfPresent(BaoSSHConfig.self, forKey: .ssh) ?? BaoSSHConfig(role: "", hosts: [])
        self.githubAppItem = try container.decodeIfPresent(String.self, forKey: .githubAppItem) ?? ""
        self.githubTokenPath = try container.decodeIfPresent(String.self, forKey: .githubTokenPath) ?? ""
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(address, forKey: .address)
        let trimmedNS = namespace.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedNS.isEmpty {
            try container.encode(trimmedNS, forKey: .namespace)
        }
        try container.encode(caPEM, forKey: .caPEM)
        let trimmedMTLS = mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedMTLS.isEmpty {
            try container.encode(trimmedMTLS, forKey: .mtlsClientIdentity)
        }
        try container.encode(jwtAuth, forKey: .jwtAuth)
        try container.encode(tokenRoles, forKey: .tokenRoles)
        try container.encode(policies, forKey: .policies)
        if !grantPolicies.isEmpty {
            try container.encode(grantPolicies, forKey: .grantPolicies)
        }
        if !auditPolicy.isEmpty {
            try container.encode(auditPolicy, forKey: .auditPolicy)
        }
        if telemetry.isEnabled {
            try container.encode(telemetry, forKey: .telemetry)
        }
        if !extensions.isEmpty {
            try container.encode(extensions, forKey: .extensions)
        }
        try container.encode(maxHours, forKey: .maxHours)
        try container.encode(keys, forKey: .keys)
        try container.encode(ssh, forKey: .ssh)
        try container.encode(githubAppItem, forKey: .githubAppItem)
        if !githubTokenPath.isEmpty {
            try container.encode(githubTokenPath, forKey: .githubTokenPath)
        }
    }
}

/// Optional remote SSH granter endpoint (e.g., an agent host, bastion, or CI runner).
public struct BaoT3GranterConfig: Codable, Equatable, Identifiable, Sendable {
    public var name: String
    public var host: String
    public var port: Int
    public var user: String
    public var hostKey: String

    public var id: String {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedName.isEmpty {
            return "\(trimmedName.lowercased())@\(host.lowercased()):\(port)"
        }
        return "\(user.lowercased())@\(host.lowercased()):\(port)"
    }

    public var displayName: String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty { return trimmed }
        if !host.isEmpty { return host }
        return String(localized: "Remote Target", table: "BaoBuddyCore", comment: "Fallback name for a remote SSH host that has no name or address.")
    }

    public var normalizedSSHUser: String {
        let trimmed = user.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "granter" : trimmed
    }

    public var normalizedSSHHost: String {
        host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Canonical SSH destination (`<user>@<host>:<port>`) binding user, host, and port.
    public var sshDestination: String {
        "\(normalizedSSHUser)@\(normalizedSSHHost):\(port)"
    }

    /// Short canonical SHA-256 fingerprint (16 hex chars) of the pinned SSH host key, or empty if unpinned.
    public var hostKeyFingerprint: String {
        let normalized = hostKey.split(whereSeparator: \.isWhitespace).prefix(2).joined(separator: " ")
        guard !normalized.isEmpty else { return "" }
        let digest = SHA256.hash(data: Data(normalized.utf8)).map { String(format: "%02x", $0) }.joined()
        return String(digest.prefix(16))
    }

    enum CodingKeys: String, CodingKey {
        case name
        case host
        case port
        case user
        case hostKey = "host_key"
    }

    public init(
        name: String = "Remote Target",
        host: String,
        port: Int = 22,
        user: String = "granter",
        hostKey: String = ""
    ) {
        self.name = name
        self.host = host
        self.port = port
        self.user = user
        self.hostKey = hostKey
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        self.host = try container.decode(String.self, forKey: .host)
        self.port = try container.decodeIfPresent(Int.self, forKey: .port) ?? 22
        self.user = try container.decodeIfPresent(String.self, forKey: .user) ?? "granter"
        self.hostKey = try container.decodeIfPresent(String.self, forKey: .hostKey) ?? ""
    }

    public var isConfigured: Bool {
        !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Stable v3 target identity binding case-preserving SSH destination (`user@host:port`)
    /// and pinned SSH host-key fingerprint. Distinct case-sensitive Unix logins or replacement
    /// SSH hosts with new host keys get separate accessor buckets, and older ambiguous buckets
    /// without a pin or case-sensitive user are never auto-attributed.
    public var canonicalScopeKey: String {
        let pin = hostKeyFingerprint.isEmpty ? "unpinned" : hostKeyFingerprint
        return "v3|\(BaoOpenBaoConfig.encodeBindingComponent(sshDestination))|\(pin)"
    }

    /// Rejects a `user`, `host`, or `port` that `/usr/bin/ssh` could read as an option
    /// (for example a user of `-oProxyCommand=...`) or that isn't a plain name or address.
    public func validateForSSH() throws {
        let userChars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        let hostChars = userChars.union(CharacterSet(charactersIn: ":[]%"))
        func isSafe(_ value: String, _ allowed: CharacterSet) -> Bool {
            !value.isEmpty && !value.hasPrefix("-") && value.unicodeScalars.allSatisfy { allowed.contains($0) }
        }
        guard isSafe(user, userChars) else {
            throw ProfileError.invalidRemoteTarget("user '\(user)'")
        }
        guard isSafe(host, hostChars) else {
            throw ProfileError.invalidRemoteTarget("host '\(host)'")
        }
        guard (1...65535).contains(port) else {
            throw ProfileError.invalidRemoteTarget("port \(port)")
        }
    }
}

public typealias BaoRemoteTargetConfig = BaoT3GranterConfig

/// Non-secret profile matching `make bao-profile` (version 1) or any generic OpenBao / Vault server.
public struct BaoProfile: Codable, Equatable, Identifiable, Sendable {
    public typealias OpenBaoConfig = BaoOpenBaoConfig
    public typealias T3GranterConfig = BaoT3GranterConfig
    public typealias RemoteTargetConfig = BaoT3GranterConfig

    public var id: String
    public var version: Int
    public var name: String
    public var openbao: BaoOpenBaoConfig
    /// One or more optional remote SSH delivery targets (VMs, bastions, CI runners) sharing this server.
    public var remoteTargets: [BaoT3GranterConfig]

    /// Primary remote SSH target (first configured entry in `remoteTargets`), kept for compatibility.
    public var t3Granter: BaoT3GranterConfig {
        get {
            remoteTargets.first(where: \.isConfigured) ?? BaoT3GranterConfig(name: "", host: "")
        }
        set {
            if newValue.isConfigured {
                if remoteTargets.isEmpty {
                    remoteTargets = [newValue]
                } else {
                    remoteTargets[0] = newValue
                }
            } else {
                remoteTargets = []
            }
        }
    }

    public var configuredRemoteTargets: [BaoT3GranterConfig] {
        remoteTargets.filter(\.isConfigured)
    }

    /// Finds a configured remote target by exact `id` first, then by unique name, displayName, or host.
    /// Rejects ambiguous selectors rather than silently picking the first target.
    public func resolveRemoteTarget(named selector: String?) throws -> BaoT3GranterConfig? {
        let targets = configuredRemoteTargets
        guard let raw = selector?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else {
            return targets.first
        }
        let lower = raw.lowercased()
        let exactID = targets.filter { $0.id.lowercased() == lower }
        if exactID.count == 1 {
            return exactID[0]
        }
        if exactID.count > 1 {
            throw ProfileError.ambiguousRemoteTarget(raw, exactID.map(\.id))
        }
        let byName = targets.filter {
            $0.name.lowercased() == lower ||
            $0.displayName.lowercased() == lower ||
            $0.host.lowercased() == lower
        }
        if byName.count == 1 {
            return byName[0]
        }
        if byName.count > 1 {
            throw ProfileError.ambiguousRemoteTarget(raw, byName.map(\.id))
        }
        return nil
    }

    /// Exact-only remote target resolution by `id` (never falls back to display name or host).
    /// Also verifies `sshDestination` (`user@host:port`) and `hostKeyFingerprint` when supplied.
    public func resolveRemoteTargetExact(
        id: String,
        sshDestination: String? = nil,
        hostKeyFingerprint: String? = nil
    ) throws -> BaoT3GranterConfig {
        let raw = id.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = raw.lowercased()
        let exactID = configuredRemoteTargets.filter { $0.id.lowercased() == lower }
        guard !exactID.isEmpty else {
            throw ProfileError.invalidRemoteTarget("no remote target with exact ID '\(raw)' is configured on \(displayName)")
        }
        let expectedSSH = sshDestination?.trimmingCharacters(in: .whitespacesAndNewlines)
        let expectedFP = hostKeyFingerprint?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let matching = exactID.filter { candidate in
            if let expectedSSH, !expectedSSH.isEmpty, candidate.sshDestination != expectedSSH {
                return false
            }
            if let expectedFP, !expectedFP.isEmpty,
               candidate.hostKeyFingerprint.isEmpty || candidate.hostKeyFingerprint != expectedFP {
                return false
            }
            return true
        }
        if matching.count == 1 {
            return matching[0]
        }
        if matching.count > 1 {
            throw ProfileError.ambiguousRemoteTarget(raw, matching.map(\.sshDestination))
        }
        throw ProfileError.invalidRemoteTarget(
            "remote target '\(raw)' does not match the pinned SSH destination or host key"
        )
    }

    /// Finds a configured remote target by name, host, or `id`, falling back to the primary target when `selector` is nil/empty.
    /// Returns `nil` when the selector is ambiguous or unknown.
    public func remoteTarget(named selector: String? = nil) -> BaoT3GranterConfig? {
        try? resolveRemoteTarget(named: selector)
    }

    /// Exact-only profile resolution by `id` (never falls back to display `name`).
    /// Prevents a stale generated profile ID from matching a different profile whose display name happens to collide.
    public static func resolveProfileExact(id: String, in profiles: [BaoProfile]) throws -> BaoProfile {
        let raw = id.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = raw.lowercased()
        let exactID = profiles.filter { $0.id.lowercased() == lower }
        if exactID.count == 1 {
            return exactID[0]
        }
        if exactID.count > 1 {
            throw ProfileError.ambiguousProfile(raw, exactID.map { "\($0.displayName) [\($0.id)]" })
        }
        throw ProfileError.notConfigured("No saved profile with exact ID '\(raw)'. Run `bao-buddy profiles` to list them.")
    }

    /// Resolves a profile selector (`id` takes strict precedence over `name`/`displayName`) and
    /// refuses ambiguous names rather than silently picking the first match.
    public static func resolveProfile(selector: String, in profiles: [BaoProfile]) throws -> BaoProfile {
        let raw = selector.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = raw.lowercased()
        let exactID = profiles.filter { $0.id.lowercased() == lower }
        if exactID.count == 1 {
            return exactID[0]
        }
        if exactID.count > 1 {
            throw ProfileError.ambiguousProfile(raw, exactID.map { "\($0.displayName) [\($0.id)]" })
        }
        let byName = profiles.filter {
            $0.displayName.lowercased() == lower || $0.name.lowercased() == lower
        }
        if byName.count == 1 {
            return byName[0]
        }
        if byName.count > 1 {
            throw ProfileError.ambiguousProfile(raw, byName.map { "\($0.displayName) [\($0.id)]" })
        }
        throw ProfileError.notConfigured("No saved profile matching '\(raw)'. Run `bao-buddy profiles` to list them.")
    }

    /// Returns a copy of this profile focused on a specific remote target (placed first in `remoteTargets`).
    public func focusing(remoteTarget target: BaoT3GranterConfig) -> BaoProfile {
        var copy = self
        var rest = configuredRemoteTargets.filter { $0 != target }
        rest.insert(target, at: 0)
        copy.remoteTargets = rest
        return copy
    }

    enum CodingKeys: String, CodingKey {
        case id
        case version
        case name
        case openbao
        case t3Granter = "t3_granter"
        case remoteTarget = "remote_target"
        case remoteTargets = "remote_targets"
    }

    public init(
        id: String = UUID().uuidString.lowercased(),
        version: Int = 1,
        name: String = "",
        openbao: BaoOpenBaoConfig,
        t3Granter: BaoT3GranterConfig = BaoT3GranterConfig(name: "", host: ""),
        remoteTargets: [BaoT3GranterConfig]? = nil
    ) {
        self.id = id
        self.version = version
        self.name = name
        self.openbao = openbao
        if let remoteTargets {
            self.remoteTargets = remoteTargets.filter(\.isConfigured)
        } else {
            self.remoteTargets = t3Granter.isConfigured ? [t3Granter] : []
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedID = try container.decodeIfPresent(String.self, forKey: .id)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        self.id = decodedID.isEmpty ? UUID().uuidString.lowercased() : decodedID
        self.version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 1
        self.name = try container.decodeIfPresent(String.self, forKey: .name) ?? ""
        self.openbao = try container.decode(BaoOpenBaoConfig.self, forKey: .openbao)
        if let list = try container.decodeIfPresent([BaoT3GranterConfig].self, forKey: .remoteTargets) {
            self.remoteTargets = list.filter(\.isConfigured).map { item in
                var copy = item
                if copy.name.isEmpty { copy.name = "Remote Target" }
                return copy
            }
        } else if var remote = try container.decodeIfPresent(BaoT3GranterConfig.self, forKey: .remoteTarget) {
            if remote.name.isEmpty { remote.name = "Remote Target" }
            self.remoteTargets = remote.isConfigured ? [remote] : []
        } else if var legacy = try container.decodeIfPresent(BaoT3GranterConfig.self, forKey: .t3Granter) {
            if legacy.name.isEmpty { legacy.name = "Remote Target" }
            self.remoteTargets = legacy.isConfigured ? [legacy] : []
        } else {
            self.remoteTargets = []
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(version, forKey: .version)
        if !name.isEmpty {
            try container.encode(name, forKey: .name)
        }
        try container.encode(openbao, forKey: .openbao)
        let configured = configuredRemoteTargets
        if configured.count > 1 {
            try container.encode(configured, forKey: .remoteTargets)
        } else if let single = configured.first {
            try container.encode(single, forKey: .remoteTarget)
        }
    }

    /// Friendly display name for the server (falls back to host from `openbao.address`).
    public var displayName: String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty { return trimmed }
        if let host = URL(string: openbao.address)?.host, !host.isEmpty {
            return host
        }
        return "OpenBao"
    }

    /// Server identity shown in biometric approval prompts: display name, canonical host[:port][/basePath],
    /// and namespace (when configured), so two servers or path-prefixed backends remain distinguishable.
    public var promptServerDescription: String {
        let authorityAndPath = openbao.normalizedAuthorityAndPath
        let ns = openbao.namespace.trimmingCharacters(in: .whitespacesAndNewlines)
        let host = URL(string: openbao.address)?.host?.lowercased() ?? ""
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedName.isEmpty
            || (openbao.normalizedBasePath.isEmpty && (trimmedName.lowercased() == host || trimmedName.lowercased() == authorityAndPath))
            || trimmedName.lowercased() == authorityAndPath {
            return ns.isEmpty ? authorityAndPath : "\(authorityAndPath) [ns: \(ns)]"
        }
        return ns.isEmpty ? "\(trimmedName) (\(authorityAndPath))" : "\(trimmedName) (\(authorityAndPath), ns: \(ns))"
    }

    /// Friendly name for the remote SSH delivery target, if configured.
    public var targetDisplayName: String {
        let trimmed = t3Granter.name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty { return trimmed }
        if !t3Granter.host.isEmpty { return t3Granter.host }
        return String(localized: "Direct Token", table: "BaoBuddyCore", comment: "Where a grant goes when the server has no remote host: a token shown on this device.")
    }

    /// Whether this profile delivers grants over SSH to a remote granter host.
    public var hasRemoteTarget: Bool {
        t3Granter.isConfigured
    }

    /// Whether the profile supports GitHub App push tokens.
    public var supportsPushTokens: Bool {
        !openbao.githubTokenPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || !openbao.githubAppItem.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Decodes and validates an imported profile. See `validate(requireHostKey:)` for the rules.
    public static func decode(from data: Data, requireHostKey: Bool = true) throws -> BaoProfile {
        let profile = try JSONDecoder().decode(BaoProfile.self, from: data)
        try profile.validate(requireHostKey: requireHostKey)
        return profile
    }
}

public enum ProfileError: Error, LocalizedError, Equatable {
    case unsupportedVersion(Int)
    case invalidAddress(String)
    case notConfigured(String)
    case invalidRemoteTarget(String)
    case invalidField(String, String)
    case duplicateName(String, String)
    case ambiguousProfile(String, [String])
    case ambiguousRemoteTarget(String, [String])
    case missingHostKey

    public var errorDescription: String? {
        switch self {
        case let .unsupportedVersion(version):
            return String(localized: "Unsupported profile version \(version) (expected 1)", table: "BaoBuddyCore", comment: "Error. %lld is a version number.")
        case let .invalidAddress(address):
            return String(localized: "Invalid OpenBao address: \(address)", table: "BaoBuddyCore", comment: "Error. %@ is the server address.")
        case let .notConfigured(path):
            return String(localized: "No BaoBuddy profile found at \(path). Import a profile JSON or configure your server in Settings.", table: "BaoBuddyCore", comment: "Error. %@ is a file path.")
        case let .invalidRemoteTarget(detail):
            return String(localized: "Invalid remote target \(detail) in profile", table: "BaoBuddyCore", comment: "Error. %@ is a technical detail. A remote target is an SSH host that receives grants.")
        case let .invalidField(field, reason):
            return String(localized: "Invalid profile field \(field): \(reason)", table: "BaoBuddyCore", comment: "Error. %1$@ is a setting name such as openbao.address (do not translate); %2$@ is the reason.")
        case let .duplicateName(kind, name):
            return String(localized: "Profile lists \(kind) '\(name)' more than once", table: "BaoBuddyCore", comment: "Error. %1$@ is the kind of item (for example policy or SSH host); %2$@ is its name.")
        case let .ambiguousProfile(selector, candidates):
            return String(localized: "Server profile selector '\(selector)' is ambiguous (matches: \(candidates.joined(separator: ", "))). Specify the exact profile ID instead.", table: "BaoBuddyCore", comment: "Error. %1$@ is the text used to select a server; %2$@ is a comma-separated list of matching servers.")
        case let .ambiguousRemoteTarget(selector, candidates):
            return String(localized: "Remote target selector '\(selector)' is ambiguous (matches: \(candidates.joined(separator: ", "))). Specify the exact target ID instead.", table: "BaoBuddyCore", comment: "Error. %1$@ is the text used to select a remote target; %2$@ is a comma-separated list of matching targets.")
        case .missingHostKey:
            return String(localized: "remote_target.host_key is required: BaoBuddy refuses to deliver grants to an unverified SSH host", table: "BaoBuddyCore", comment: "Error. Do not translate remote_target.host_key (a setting name).")
        }
    }
}

public struct FileProfileStore: Sendable {
    public let url: URL
    /// Only the default location falls back to the pre-rename `~/.config/baogrant` file; a store
    /// pointed somewhere else (tests, custom paths) never reads the user's real profile.
    private let usesDefaultLocation: Bool

    public init(url: URL? = nil) {
        self.usesDefaultLocation = url == nil
        if let url {
            self.url = url
        } else {
            #if os(macOS)
            let home = FileManager.default.homeDirectoryForCurrentUser
            self.url = home
                .appendingPathComponent(".config", isDirectory: true)
                .appendingPathComponent("baobuddy", isDirectory: true)
                .appendingPathComponent("profile.json")
            #else
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? FileManager.default.temporaryDirectory
            self.url = appSupport
                .appendingPathComponent("BaoBuddy", isDirectory: true)
                .appendingPathComponent("profile.json")
            #endif
        }
    }

    public func load() throws -> BaoProfile {
        if FileManager.default.fileExists(atPath: url.path) {
            let data = try Data(contentsOf: url)
            return try BaoProfile.decode(from: data, requireHostKey: false)
        }
        #if os(macOS)
        let legacyURL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("baogrant", isDirectory: true)
            .appendingPathComponent("profile.json")
        if usesDefaultLocation, legacyURL != url, FileManager.default.fileExists(atPath: legacyURL.path) {
            let data = try Data(contentsOf: legacyURL)
            return try BaoProfile.decode(from: data, requireHostKey: false)
        }
        #endif
        throw ProfileError.notConfigured(url.path)
    }

    public func save(_ profile: BaoProfile) throws {
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try PrivateFile.write(try encoder.encode(profile), to: url)
    }

    public func delete() throws {
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }
}

/// Stored collection of OpenBao / Vault server profiles with an active selection.
public struct ProfileCollection: Codable, Equatable, Sendable {
    public var activeProfileID: String?
    public var profiles: [BaoProfile]

    enum CodingKeys: String, CodingKey {
        case activeProfileID = "active_profile_id"
        case profiles
    }

    public init(activeProfileID: String? = nil, profiles: [BaoProfile] = []) {
        self.activeProfileID = activeProfileID
        self.profiles = profiles
    }
}

/// Multi-profile store that seamlessly migrates from a legacy single `profile.json`.
public struct MultiProfileStore: Sendable {
    public let url: URL
    public let legacyStore: FileProfileStore

    public init(url: URL? = nil, legacyStore: FileProfileStore = FileProfileStore()) {
        self.legacyStore = legacyStore
        if let url {
            self.url = url
        } else {
            self.url = legacyStore.url
                .deletingLastPathComponent()
                .appendingPathComponent("profiles.json")
        }
    }

    public func load() -> ProfileCollection {
        if FileManager.default.fileExists(atPath: url.path) {
            if let data = try? Data(contentsOf: url),
               let decoded = try? JSONDecoder().decode(ProfileCollection.self, from: data) {
                return decoded
            }
            // Never overwrite a file we couldn't read (for example one written by a newer version).
            // Move it aside so the next save can't destroy it, then fall back.
            let stamp = Int(Date().timeIntervalSince1970)
            let backup = url.deletingLastPathComponent()
                .appendingPathComponent("\(url.lastPathComponent).unreadable-\(stamp)")
            try? FileManager.default.moveItem(at: url, to: backup)
        }
        if let legacy = try? legacyStore.load() {
            let migrated = ProfileCollection(activeProfileID: legacy.id, profiles: [legacy])
            try? save(migrated)
            return migrated
        }
        return ProfileCollection()
    }

    public func save(_ collection: ProfileCollection) throws {
        // Demo profiles live strictly in memory and are never persisted to disk.
        let filteredProfiles = collection.profiles.filter { !$0.isDemoProfile }
        let activeID = filteredProfiles.contains(where: { $0.id == collection.activeProfileID })
            ? collection.activeProfileID
            : filteredProfiles.first?.id
        let sanitized = ProfileCollection(activeProfileID: activeID, profiles: filteredProfiles)
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try PrivateFile.write(try encoder.encode(sanitized), to: url)
    }
}
