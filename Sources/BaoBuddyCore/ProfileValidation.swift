import Foundation

/// Rules for text that comes from an imported, MDM-pushed, or hand-edited profile.
/// Profile strings reach the approval sheet, the biometric prompt, and OpenBao request paths,
/// so they must not carry control or invisible formatting characters (including bidirectional
/// overrides such as U+202E) that could make one value look like another.
public enum ProfileText {
    /// True when `value` has no control (Cc) or format (Cf) scalars, which covers bidi overrides,
    /// zero-width characters, and line breaks.
    public static func isPlain(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { scalar in
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator:
                return false
            default:
                return true
            }
        }
    }

    /// Identifiers (policy, mount, role, key, and host names) are ASCII without spaces.
    public static func isIdentifier(_ value: String, allowSlash: Bool = false) -> Bool {
        let extra = allowSlash ? "._-@:/" : "._-@:"
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + extra)
        return !value.isEmpty && value.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    /// OpenBao API paths (mounts, `github_token_path`, SSH sign paths): identifier characters and
    /// '/', with no empty, '.', or '..' segments. No quotes, braces, '*', or '+', so a path can be
    /// written into generated policy HCL without changing its meaning.
    public static func isAPIPath(_ value: String) -> Bool {
        guard isIdentifier(value, allowSlash: true) else { return false }
        return !value.split(separator: "/", omittingEmptySubsequences: false)
            .contains(where: { $0.isEmpty || $0 == "." || $0 == ".." })
    }

    /// Hosts that may use plain `http://` because traffic never leaves the machine.
    public static func isLoopback(_ host: String) -> Bool {
        let lower = host.lowercased()
        return lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "[::1]"
    }
}

extension BaoProfile {
    /// Validates a profile before it's imported, pushed by MDM, or saved from the editor.
    /// - `https://` only (plain `http://` is allowed for loopback addresses only, because the JWT
    ///   and grant tokens would otherwise cross the network in clear text).
    /// - Identifiers are plain ASCII; display strings have no control or invisible formatting characters.
    /// - Policy, key, and SSH host names are unique.
    /// - A configured remote target has a safe user/host/port and (with `requireHostKey`) a pinned
    ///   host key. Profiles already saved on disk are loaded with `requireHostKey: false` so local
    ///   grants keep working; the SSH clients still refuse to connect without a pin.
    public func validate(
        requireHostKey: Bool = true,
        requireTLSPinning: Bool = false,
        allowDemo: Bool = false
    ) throws {
        guard version == 1 else {
            throw ProfileError.unsupportedVersion(version)
        }
        guard let url = URL(string: openbao.address),
              let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty else {
            throw ProfileError.invalidAddress(openbao.address)
        }
        if !allowDemo {
            if id == BaoDemo.profileID {
                throw ProfileError.invalidField("id", "reserved for built-in demo mode")
            }
            if host.lowercased() == BaoDemo.serverHost {
                throw ProfileError.invalidField("openbao.address", "'\(BaoDemo.serverHost)' is reserved for built-in demo mode")
            }
        }
        if scheme == "http" {
            guard ProfileText.isLoopback(host) else {
                throw ProfileError.invalidField(
                    "openbao.address",
                    "use https:// (plain http:// would send sign-in JWTs and tokens in clear text)"
                )
            }
        } else if scheme != "https" {
            throw ProfileError.invalidAddress(openbao.address)
        }
        do {
            try OpenBaoClient.validateEndpointURL(url, allowDemo: allowDemo)
        } catch {
            throw ProfileError.invalidAddress(error.localizedDescription)
        }
        if requireTLSPinning && !openbao.isTLSPinned {
            throw ProfileError.invalidField(
                "openbao.ca_pem",
                "TLS certificate pinning is required by organization policy"
            )
        }

        func identifier(_ value: String, _ field: String, allowSlash: Bool = false, allowEmpty: Bool = false) throws {
            if allowEmpty && value.isEmpty { return }
            guard ProfileText.isIdentifier(value, allowSlash: allowSlash) else {
                throw ProfileError.invalidField(field, "'\(value)' must be ASCII letters, digits, or . _ - @ :\(allowSlash ? " /" : "")")
            }
        }
        // OpenBao API paths: identifier characters plus '/', no empty, '.', or '..' segments, and
        // no '*' or '+' (they would become globs in generated policies).
        func apiPath(_ value: String, _ field: String, allowEmpty: Bool = false) throws {
            if allowEmpty && value.isEmpty { return }
            try identifier(value, field, allowSlash: true)
            let segments = value.split(separator: "/", omittingEmptySubsequences: false)
            if segments.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) {
                throw ProfileError.invalidField(field, "'\(value)' must be a clean relative path without empty or '..' segments")
            }
        }
        func plain(_ value: String, _ field: String) throws {
            guard ProfileText.isPlain(value) else {
                throw ProfileError.invalidField(field, "contains control or invisible formatting characters")
            }
        }

        try plain(name, "name")
        let trimmedNS = openbao.namespace.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedNS.isEmpty {
            try identifier(trimmedNS, "openbao.namespace", allowSlash: true)
            let segments = trimmedNS.split(separator: "/", omittingEmptySubsequences: false)
            if segments.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) {
                throw ProfileError.invalidField(
                    "openbao.namespace",
                    "'\(trimmedNS)' must not start or end with '/' or contain '..' segments"
                )
            }
        }
        try plain(openbao.mtlsClientIdentity, "openbao.mtls_client_identity")
        try plain(openbao.auditPolicy.reasonPlaceholder, "openbao.audit_policy.reason_placeholder")
        let trimmedPattern = openbao.auditPolicy.reasonPattern.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedPattern.isEmpty {
            guard trimmedPattern.count <= 200 else {
                throw ProfileError.invalidField("openbao.audit_policy.reason_pattern", "pattern must be 200 characters or fewer")
            }
            try plain(trimmedPattern, "openbao.audit_policy.reason_pattern")
            do {
                _ = try NSRegularExpression(pattern: trimmedPattern)
            } catch {
                throw ProfileError.invalidField("openbao.audit_policy.reason_pattern", "invalid regular expression: \(error.localizedDescription)")
            }
        }
        let trimmedOTLP = openbao.telemetry.otlpEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedOTLP.isEmpty {
            guard let otlpURL = URL(string: trimmedOTLP),
                  let otlpScheme = otlpURL.scheme?.lowercased(),
                  let otlpHost = otlpURL.host, !otlpHost.isEmpty,
                  otlpScheme == "https" || (otlpScheme == "http" && ProfileText.isLoopback(otlpHost)) else {
                throw ProfileError.invalidField("openbao.telemetry.otlp_endpoint", "must be an https:// URL (or loopback http://)")
            }
        }
        let jwt = openbao.jwtAuth
        try apiPath(jwt.mount, "jwt_auth.mount")
        try identifier(jwt.role, "jwt_auth.role")
        try identifier(jwt.subject, "jwt_auth.subject")
        try plain(jwt.issuer, "jwt_auth.issuer")
        try plain(jwt.audience, "jwt_auth.audience")
        let trimmedAudience = jwt.audience.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedAudience.lowercased().hasPrefix("baobuddy://") {
            let expected = openbao.expectedOriginMountAudience
            guard trimmedAudience == expected else {
                throw ProfileError.invalidField(
                    "jwt_auth.audience",
                    "'\(trimmedAudience)' does not match this server deployment ('\(expected)'); leave audience empty to derive it automatically"
                )
            }
        }
        try identifier(openbao.tokenRoles.mac, "token_roles.local")
        try identifier(openbao.tokenRoles.t3, "token_roles.remote")

        let cfg = openbao.policies
        try identifier(cfg.read, "policies.read", allowEmpty: true)
        try identifier(cfg.write, "policies.write", allowEmpty: true)
        try identifier(cfg.keyPrefix, "policies.key_prefix", allowEmpty: true)
        try identifier(cfg.keyWriteSuffix, "policies.key_write_suffix", allowEmpty: true)

        var seenPolicies = Set<String>()
        for policy in openbao.grantPolicies {
            try identifier(policy.name, "grant_policies.name")
            try plain(policy.label, "grant_policies.label")
            try plain(policy.description, "grant_policies.description")
            guard seenPolicies.insert(policy.name).inserted else {
                throw ProfileError.duplicateName("policy", policy.name)
            }
        }
        var seenKeys = Set<String>()
        for key in openbao.keys {
            try identifier(key.name, "keys.name")
            try plain(key.item, "keys.item")
            guard seenKeys.insert(key.name.lowercased()).inserted else {
                throw ProfileError.duplicateName("key", key.name)
            }
        }
        try identifier(openbao.ssh.role, "ssh.role", allowEmpty: true)
        var seenHosts = Set<String>()
        for sshHost in openbao.ssh.hosts {
            try identifier(sshHost.name, "ssh.hosts.name")
            try identifier(sshHost.user, "ssh.hosts.user")
            try identifier(sshHost.principal, "ssh.hosts.principal")
            guard seenHosts.insert(sshHost.name.lowercased()).inserted else {
                throw ProfileError.duplicateName("SSH host", sshHost.name)
            }
        }
        try apiPath(openbao.githubAppItem, "github_app_item", allowEmpty: true)
        try apiPath(openbao.githubTokenPath, "github_token_path", allowEmpty: true)
        guard (1...168).contains(openbao.maxHours) else {
            throw ProfileError.invalidField("openbao.max_hours", "must be between 1 and 168")
        }

        var seenExtensions = Set<String>()
        var seenDeliverAs = Set<String>()
        for ext in openbao.extensions {
            try identifier(ext.id, "extensions.id")
            try plain(ext.label, "extensions.label")
            try plain(ext.description, "extensions.description")
            try apiPath(ext.endpoint, "extensions.endpoint")
            // An imported profile must not be able to point an extension at the server's own
            // control plane: token creation, auth config, policy, or identity endpoints.
            let firstSegment = ext.endpoint.split(separator: "/").first.map { String($0).lowercased() } ?? ""
            if ["sys", "auth", "identity", "cubbyhole"].contains(firstSegment) {
                throw ProfileError.invalidField("extensions.endpoint", "'\(ext.endpoint)' must be a secrets engine path, not under \(firstSegment)/")
            }
            // Same filename rules as baobuddy-receiver, which writes the file.
            let fileChars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
            guard !ext.deliverAs.isEmpty, ext.deliverAs.count <= 64,
                  ext.deliverAs.unicodeScalars.allSatisfy({ fileChars.contains($0) }),
                  !ext.deliverAs.hasPrefix("."), !ext.deliverAs.contains("..") else {
                throw ProfileError.invalidField("extensions.deliver_as", "'\(ext.deliverAs)' must be a plain filename of letters, digits, . _ -")
            }
            guard seenExtensions.insert(ext.id.lowercased()).inserted else {
                throw ProfileError.duplicateName("extension", ext.id)
            }
            if !ext.policy.isEmpty {
                try identifier(ext.policy, "extensions.policy")
                guard ext.policy != "root" else {
                    throw ProfileError.invalidField("extensions.policy", "an extension can't add the root policy")
                }
            }
            guard ext.requestBody.keys.allSatisfy({ ProfileText.isIdentifier($0) }),
                  ext.requestBody.values.allSatisfy({ ProfileText.isPlain($0) }) else {
                throw ProfileError.invalidField("extensions.request_body", "keys must be identifiers and values plain text")
            }
            guard seenDeliverAs.insert(ext.deliverAs).inserted else {
                throw ProfileError.duplicateName("extension deliver_as", ext.deliverAs)
            }
        }

        var seenRemoteNames = Set<String>()
        for target in configuredRemoteTargets {
            try plain(target.name, "remote_target.name")
            try target.validateForSSH()
            guard !requireHostKey || !target.hostKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ProfileError.missingHostKey
            }
            try plain(target.hostKey, "remote_target.host_key")
            let normalizedName = target.displayName.lowercased()
            guard seenRemoteNames.insert(normalizedName).inserted else {
                throw ProfileError.duplicateName("remote target", target.displayName)
            }
        }
    }
}
