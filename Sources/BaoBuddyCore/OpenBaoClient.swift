import Foundation

public enum OpenBaoError: Error, LocalizedError, Equatable {
    case invalidBaseURL(String)
    case httpError(Int, String)
    case unexpectedResponse(String)
    case inactiveToken
    case invalidTokenFormat
    case grantMismatch(String)

    public var errorDescription: String? {
        switch self {
        case let .invalidBaseURL(url):
            return String(localized: "Invalid OpenBao URL: \(url)", table: "BaoBuddyCore", comment: "Error. %@ is the server URL. OpenBao is a product name.")
        case let .httpError(code, detail):
            return String(localized: "OpenBao returned HTTP \(code): \(detail)", table: "BaoBuddyCore", comment: "Error. %1$lld is an HTTP status code; %2$@ is the server's error message (English).")
        case let .unexpectedResponse(detail):
            return String(localized: "Unexpected OpenBao response: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is a technical detail.")
        case .inactiveToken:
            return "OpenBao reports this token is invalid or expired."
        case .invalidTokenFormat:
            return String(localized: "OpenBao returned a token with unexpected characters", table: "BaoBuddyCore", comment: "Error.")
        case let .grantMismatch(detail):
            return String(localized: "OpenBao minted a token that doesn't match the approved grant (\(detail)); it was revoked. Check the token role's settings.", table: "BaoBuddyCore", comment: "Error. %@ is a technical detail. A token role is an OpenBao/Vault configuration object.")
        }
    }
}

public enum OpenBaoErrorClassification {
    public static func isConfirmedInvalidToken(_ error: Error) -> Bool {
        if case OpenBaoError.inactiveToken = error { return true }
        return false
    }
}

public struct GitHubAppConfig: Equatable, Sendable {
    public let appID: String
    public let installationID: String
    public let repo: String
    public let privateKeyPEM: String

    public init(appID: String, installationID: String, repo: String, privateKeyPEM: String) {
        self.appID = appID
        self.installationID = installationID
        self.repo = repo
        self.privateKeyPEM = privateKeyPEM
    }
}

public struct GrantTokenParameters: Equatable, Sendable {
    public let role: String
    public let policies: [String]
    public let ttl: String
    public let displayName: String
    public let metadata: [String: String]

    public init(
        role: String,
        policies: [String],
        ttl: String,
        displayName: String,
        metadata: [String: String]
    ) {
        self.role = role
        self.policies = policies
        self.ttl = ttl
        self.displayName = displayName
        self.metadata = metadata
    }
}

public struct SSHSignParameters: Equatable, Sendable {
    public let role: String
    public let publicKey: String
    public let validPrincipals: [String]
    public let ttl: String
    public let keyID: String

    public init(
        role: String,
        publicKey: String,
        validPrincipals: [String],
        ttl: String,
        keyID: String
    ) {
        self.role = role
        self.publicKey = publicKey
        self.validPrincipals = validPrincipals
        self.ttl = ttl
        self.keyID = keyID
    }
}

public struct TokenLookupInfo: Equatable, Sendable {
    public let ttlSeconds: Int
    public let policies: [String]
    public let displayName: String
    public let why: String

    public init(ttlSeconds: Int, policies: [String], displayName: String, why: String) {
        self.ttlSeconds = ttlSeconds
        self.policies = policies
        self.displayName = displayName
        self.why = why
    }
}

/// A token returned by `auth/token/create/<role>`, with the properties BaoBuddy checks
/// before handing it to anyone.
public struct MintedToken: Equatable, Sendable {
    public let token: String
    public let accessor: String
    public let policies: [String]
    public let renewable: Bool
    public let orphan: Bool
    public let leaseDurationSeconds: Int

    public init(token: String, accessor: String, policies: [String], renewable: Bool, orphan: Bool, leaseDurationSeconds: Int) {
        self.token = token
        self.accessor = accessor
        self.policies = policies
        self.renewable = renewable
        self.orphan = orphan
        self.leaseDurationSeconds = leaseDurationSeconds
    }

    /// Confirms the server minted what the user approved: exactly the requested policies (plus
    /// Vault's implicit `default`), an orphan, non-renewable token, and no longer than the approved TTL.
    /// The token role is server configuration BaoBuddy can't see, so a misconfigured role (for
    /// example `renewable=true` or a longer `token_explicit_max_ttl`) is caught here instead of trusted.
    public func verify(requestedPolicies: [String], maxTTLSeconds: Int) throws {
        let requested = Set(requestedPolicies)
        let granted = Set(policies).subtracting(["default"])
        guard granted == requested else {
            let extra = granted.subtracting(requested).sorted()
            let missing = requested.subtracting(granted).sorted()
            throw OpenBaoError.grantMismatch("policies differ; extra: \(extra), missing: \(missing)")
        }
        guard !renewable else {
            throw OpenBaoError.grantMismatch("token is renewable")
        }
        guard orphan else {
            throw OpenBaoError.grantMismatch("token isn't an orphan")
        }
        guard leaseDurationSeconds > 0, leaseDurationSeconds <= maxTTLSeconds else {
            throw OpenBaoError.grantMismatch("TTL \(leaseDurationSeconds)s exceeds the approved \(maxTTLSeconds)s")
        }
    }
}

public struct ServerHealth: Equatable, Sendable {
    public let initialized: Bool
    public let sealed: Bool
    public let version: String

    public init(initialized: Bool, sealed: Bool, version: String) {
        self.initialized = initialized
        self.sealed = sealed
        self.version = version
    }
}

public struct OpenBaoClient: Sendable {
    public let baseURL: URL
    public let transport: any HTTPTransport
    public let namespace: String

    public init(baseURL: URL, transport: any HTTPTransport, namespace: String = "") {
        self.baseURL = Self.canonicalizedBaseURL(baseURL)
        self.transport = transport
        self.namespace = namespace.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Strips a single trailing `/` from non-root paths so equivalent accepted spellings
    /// (`https://proxy.example/vault` and `https://proxy.example/vault/`) send identical request paths.
    static func canonicalizedBaseURL(_ url: URL) -> URL {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return url
        }
        if components.path == "/" {
            components.path = ""
        } else if components.path.hasSuffix("/") && !components.path.hasSuffix("//") {
            components.path.removeLast()
        }
        return components.url ?? url
    }

    /// Validates an OpenBao endpoint URL before sending any request or credential.
    /// Requires `https://`, or plain `http://` on loopback hosts only; rejects embedded userinfo
    /// (without echoing credentials), query/fragment components, percent-encoded escapes, repeated
    /// slashes, and unsafe path segments; and blocks the reserved demo host unless `allowDemo` is set.
    public static func validateEndpointURL(_ url: URL, allowDemo: Bool = false) throws {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let host = components.host, !host.isEmpty else {
            throw OpenBaoError.invalidBaseURL("invalid OpenBao URL")
        }
        if components.user != nil || components.password != nil {
            // Never echo url.absoluteString here, because it may contain an embedded password.
            throw OpenBaoError.invalidBaseURL("OpenBao URL must not contain embedded username or password credentials")
        }
        if components.query != nil || components.fragment != nil {
            throw OpenBaoError.invalidBaseURL("\(scheme)://\(host): URL must not contain query or fragment components")
        }
        let rawPercentPath = components.percentEncodedPath
        if rawPercentPath.contains("%") {
            throw OpenBaoError.invalidBaseURL("\(scheme)://\(host): URL base path must use canonical unencoded path segments (no percent-escapes)")
        }
        if rawPercentPath.contains("//") {
            throw OpenBaoError.invalidBaseURL("\(scheme)://\(host): URL base path must not contain repeated slashes")
        }
        let path = components.path
        if !path.isEmpty && path != "/" {
            guard ProfileText.isPlain(path) else {
                throw OpenBaoError.invalidBaseURL("\(scheme)://\(host): URL path contains control or formatting characters")
            }
            let singleTrimmed = path.hasSuffix("/") ? String(path.dropLast()) : path
            let withoutLeading = singleTrimmed.hasPrefix("/") ? String(singleTrimmed.dropFirst()) : singleTrimmed
            let allowedSegmentChars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~-")
            let segments = withoutLeading.split(separator: "/", omittingEmptySubsequences: false)
            if segments.contains(where: { seg in
                seg.isEmpty || seg == "." || seg == ".."
                    || !seg.unicodeScalars.allSatisfy({ allowedSegmentChars.contains($0) })
            }) {
                throw OpenBaoError.invalidBaseURL("\(scheme)://\(host): URL base path contains invalid or non-canonical path segments")
            }
        }
        if !allowDemo && host.lowercased() == BaoDemo.serverHost {
            throw OpenBaoError.invalidBaseURL("'\(BaoDemo.serverHost)' is reserved for built-in demo mode")
        }
        if scheme == "http" {
            guard ProfileText.isLoopback(host) else {
                throw OpenBaoError.invalidBaseURL("\(scheme)://\(host): refusing to send credentials over plain http")
            }
        } else if scheme != "https" {
            throw OpenBaoError.invalidBaseURL("unsupported URL scheme '\(scheme)'")
        }
    }

    public init(profile: BaoProfile) throws {
        guard !profile.isDemoProfile else {
            throw OpenBaoError.invalidBaseURL("Demo profile must use DemoOpenBaoTransport, never the network")
        }
        guard let url = URL(string: profile.openbao.address) else {
            throw OpenBaoError.invalidBaseURL("invalid OpenBao address")
        }
        try Self.validateEndpointURL(url, allowDemo: false)
        self.baseURL = Self.canonicalizedBaseURL(url)
        self.transport = try PinnedTLSClient(
            caPEM: profile.openbao.caPEM,
            clientIdentityLabel: profile.openbao.mtlsClientIdentity
        )
        self.namespace = profile.openbao.namespace.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Creates an `OpenBaoClient` bound exclusively to the in-memory `DemoOpenBaoTransport`
    /// for the built-in Demo Mode profile. Refuses any non-demo profile.
    public static func forDemo(profile: BaoProfile, transport: DemoOpenBaoTransport) throws -> OpenBaoClient {
        guard profile.isDemoProfile else {
            throw OpenBaoError.invalidBaseURL("Demo transport may only be used for the in-memory demo profile")
        }
        guard let url = URL(string: profile.openbao.address) else {
            throw OpenBaoError.invalidBaseURL(profile.openbao.address)
        }
        return OpenBaoClient(baseURL: url, transport: transport, namespace: profile.openbao.namespace)
    }

    /// Checks `/v1/sys/health` over the pinned TLS transport to verify network and certificate trust.
    public func checkHealth() async throws -> ServerHealth {
        try Self.validateEndpointURL(baseURL, allowDemo: transport is DemoOpenBaoTransport)
        var req = URLRequest(url: endpointURL("v1/sys/health"))
        req.httpMethod = "GET"
        let (data, response) = try await transport.send(req)
        let validStatuses: Set<Int> = [200, 429, 472, 473, 501, 503]
        let parsed = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        guard validStatuses.contains(response.statusCode), let parsed else {
            let detail = (parsed?["errors"] as? [String])?.joined(separator: "; ") ?? "unexpected response"
            throw OpenBaoError.httpError(response.statusCode, Self.safeDetail(detail))
        }
        return ServerHealth(
            initialized: parsed["initialized"] as? Bool ?? (response.statusCode != 501),
            sealed: parsed["sealed"] as? Bool ?? (response.statusCode == 503),
            version: parsed["version"] as? String ?? ""
        )
    }

    /// Exchanges a short-lived Secure Enclave ES256 JWT for a 2-minute `granter` token.
    public func loginJWT(mount: String, role: String, jwt: String) async throws -> String {
        let body: [String: String] = ["role": role, "jwt": jwt]
        let json = try await post(path: "v1/auth/\(mount)/login", token: nil, body: body)
        guard let auth = json["auth"] as? [String: Any],
              let token = auth["client_token"] as? String,
              Self.isValidToken(token) else {
            throw OpenBaoError.unexpectedResponse("missing auth.client_token")
        }
        return token
    }

    /// Creates a grant token against a token role. Callers must `verify` the result: the role's
    /// server-side settings decide whether it's really orphan and non-renewable.
    public func createGrantToken(
        authToken: String,
        parameters: GrantTokenParameters
    ) async throws -> MintedToken {
        let body: [String: Any] = [
            "policies": parameters.policies,
            "ttl": parameters.ttl,
            "display_name": parameters.displayName,
            "meta": parameters.metadata
        ]
        let json = try await postJSONObject(
            path: "v1/auth/token/create/\(parameters.role)",
            token: authToken,
            body: body
        )
        guard let auth = json["auth"] as? [String: Any],
              let token = auth["client_token"] as? String,
              Self.isValidToken(token) else {
            throw OpenBaoError.unexpectedResponse("missing grant auth.client_token")
        }
        let policies = (auth["token_policies"] as? [String]) ?? (auth["policies"] as? [String]) ?? []
        return MintedToken(
            token: token,
            accessor: auth["accessor"] as? String ?? "",
            policies: policies,
            renewable: auth["renewable"] as? Bool ?? true,
            orphan: auth["orphan"] as? Bool ?? false,
            leaseDurationSeconds: auth["lease_duration"] as? Int ?? 0
        )
    }

    /// Signs an Ed25519 SSH public key using OpenBao's SSH secrets engine.
    public func signSSHKey(
        authToken: String,
        parameters: SSHSignParameters
    ) async throws -> String {
        let body: [String: Any] = [
            "public_key": parameters.publicKey,
            "valid_principals": parameters.validPrincipals.joined(separator: ","),
            "ttl": parameters.ttl,
            "cert_type": "user",
            "key_id": parameters.keyID
        ]
        let json = try await postJSONObject(
            path: "v1/ssh/sign/\(parameters.role)",
            token: authToken,
            body: body
        )
        guard let data = json["data"] as? [String: Any],
              let signedKey = data["signed_key"] as? String,
              signedKey.hasPrefix("ssh-ed25519-cert-v01@openssh.com ") else {
            throw OpenBaoError.unexpectedResponse("missing or invalid data.signed_key")
        }
        return signedKey.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Legacy push-token mode: reads a GitHub App private key from a KV v2 item (`<mount>/<path>`).
    /// This hands a non-expiring credential to the client; prefer `mintGitHubToken(authToken:path:)`.
    public func readGitHubApp(authToken: String, itemPath: String) async throws -> GitHubAppConfig {
        guard let slash = itemPath.firstIndex(of: "/"), slash != itemPath.startIndex else {
            throw OpenBaoError.unexpectedResponse("github_app_item must be '<kv-mount>/<path>', not '\(itemPath)'")
        }
        let mount = String(itemPath[..<slash])
        let sub = String(itemPath[itemPath.index(after: slash)...])
        let kvPath = "v1/\(mount)/data/\(sub)"
        let json = try await get(path: kvPath, token: authToken)
        guard let outer = json["data"] as? [String: Any],
              let fields = outer["data"] as? [String: Any],
              let appID = fields["APP_ID"] as? String,
              let installationID = fields["INSTALLATION_ID"] as? String,
              let repo = fields["REPO"] as? String,
              let keyB64 = fields["PRIVATE_KEY_B64"] as? String,
              let keyData = Data(base64Encoded: keyB64),
              let pem = String(data: keyData, encoding: .utf8) else {
            throw OpenBaoError.unexpectedResponse("incomplete GitHub App secret at \(itemPath)")
        }
        return GitHubAppConfig(appID: appID, installationID: installationID, repo: repo, privateKeyPEM: pem)
    }

    /// Looks up metadata and remaining TTL for an existing token.
    public func lookupSelf(token: String, classifyingInactiveToken: Bool = false) async throws -> TokenLookupInfo {
        let req = makeRequest(path: "v1/auth/token/lookup-self", method: "GET", token: token, jsonContent: false)
        let json = try await execute(req, classifyingLookup: classifyingInactiveToken)
        guard let data = json["data"] as? [String: Any],
              let ttl = data["ttl"] as? Int else {
            throw OpenBaoError.unexpectedResponse("missing data.ttl in lookup-self")
        }
        let policies = data["policies"] as? [String] ?? []
        let displayName = data["display_name"] as? String ?? ""
        let meta = data["meta"] as? [String: String] ?? [:]
        return TokenLookupInfo(
            ttlSeconds: ttl,
            policies: policies,
            displayName: displayName,
            why: meta["why"] ?? ""
        )
    }

    /// Absence requires a definitive issuer response. A zero TTL or failed lookup
    /// leaves the local grant’s status unknown.
    public func lookupSavedGrant(token: String) async throws -> TokenLookupInfo? {
        do {
            let info = try await lookupSelf(token: token, classifyingInactiveToken: true)
            guard info.ttlSeconds > 0 else { throw OpenBaoError.unexpectedResponse("ambiguous token lifetime") }
            return info
        } catch OpenBaoError.inactiveToken {
            return nil
        }
    }

    /// Asks a server-side GitHub token endpoint (such as a `vault-plugin-secrets-github` permission
    /// set at `github/token/<set>`) for an installation token. The repositories and permissions are
    /// fixed by the server's permission set, and the App private key never leaves the server.
    /// Returns `"<epoch_expires> <token>"`, the format the remote granter's `install` expects.
    public func mintGitHubToken(authToken: String, path: String, now: Date = Date()) async throws -> String {
        let trimmed = path.trimmingCharacters(in: CharacterSet(charactersIn: "/ "))
        let json = try await postJSONObject(path: "v1/\(trimmed)", token: authToken, body: [:])
        let data = json["data"] as? [String: Any] ?? [:]
        guard let token = data["token"] as? String, !token.isEmpty,
              token.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.contains($0) || $0 == "_" }) else {
            throw OpenBaoError.unexpectedResponse("missing or invalid data.token from \(trimmed)")
        }
        // GitHub installation tokens last one hour. Use the server's expiry when it reports one.
        var expires = now.addingTimeInterval(3600)
        if let raw = data["expires_at"] as? String, let parsed = ISO8601DateFormatter().date(from: raw) {
            expires = min(parsed, expires)
        }
        return "\(Int(expires.timeIntervalSince1970)) \(token)"
    }

    /// Invokes a workflow-agnostic `BaoCredentialExtension` secrets engine endpoint
    /// (AWS STS, Kubernetes, Database, PKI, GitHub, etc.) and returns a named deliverable artifact.
    ///
    /// `GrantOrchestrator` calls this with the minted *grant* token, never the sign-in token: the
    /// grant's policies decide what the extension can reach, and leased secrets are tied to the
    /// grant, so revoking or expiring the grant revokes them. (Leases created with the 2-minute
    /// sign-in token would die with it.)
    public func invokeExtension(
        _ ext: BaoCredentialExtension,
        authToken: String,
        now: Date = Date()
    ) async throws -> MintedExtensionArtifact {
        let trimmed = ext.endpoint.trimmingCharacters(in: CharacterSet(charactersIn: "/ "))
        let json: [String: Any]
        switch ext.method {
        case .get:
            json = try await get(path: "v1/\(trimmed)", token: authToken)
        case .post:
            var body: [String: Any] = [:]
            for (k, v) in ext.requestBody { body[k] = v }
            json = try await postJSONObject(path: "v1/\(trimmed)", token: authToken, body: body)
        }
        // Only the secrets engine's `data` is delivered. Falling back to the whole response could
        // hand over an `auth` block (a token) if the endpoint turned out to be a login or create path.
        guard let data = json["data"] as? [String: Any] else {
            throw OpenBaoError.unexpectedResponse("\(trimmed) returned no data object")
        }
        if let auth = json["auth"], !(auth is NSNull) {
            throw OpenBaoError.unexpectedResponse("\(trimmed) returned a token (auth block); extensions must call secrets engines")
        }

        var expiresEpoch: Int64?
        if !ext.expiryField.isEmpty,
           let rawExp = data[ext.expiryField] as? String,
           let parsed = ISO8601DateFormatter().date(from: rawExp) {
            expiresEpoch = Int64(parsed.timeIntervalSince1970)
        } else if let leaseSeconds = json["lease_duration"] as? Int, leaseSeconds > 0 {
            expiresEpoch = Int64(now.addingTimeInterval(TimeInterval(leaseSeconds)).timeIntervalSince1970)
        }

        let content: String
        let trimmedField = ext.tokenField.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmedField.isEmpty {
            guard let extracted = data[trimmedField] as? String, !extracted.isEmpty else {
                throw OpenBaoError.unexpectedResponse("missing data.\(trimmedField) from \(trimmed)")
            }
            content = extracted
        } else {
            let serialized = try JSONSerialization.data(withJSONObject: data, options: [.prettyPrinted, .sortedKeys])
            guard let text = String(data: serialized, encoding: .utf8) else {
                throw OpenBaoError.unexpectedResponse("could not serialize extension response from \(trimmed)")
            }
            content = text
        }

        return MintedExtensionArtifact(name: ext.deliverAs, content: content, expiresAt: expiresEpoch)
    }

    /// Revokes another token by value (for example a grant whose delivery failed).
    public func revokeToken(authToken: String, targetToken: String) async throws {
        _ = try await post(path: "v1/auth/token/revoke", token: authToken, body: ["token": targetToken])
    }

    /// Revokes a token by accessor, so a grant delivered to a remote host can be revoked from this
    /// device without trusting that host to do it.
    public func revokeAccessor(authToken: String, accessor: String) async throws {
        _ = try await post(path: "v1/auth/token/revoke-accessor", token: authToken, body: ["accessor": accessor])
    }

    /// Lists keys under a path (`LIST`), returning an empty list when nothing exists.
    internal func list(path: String, token: String) async throws -> [String] {
        let req = makeRequest(path: path, method: "LIST", token: token, jsonContent: false)
        do {
            let json = try await execute(req)
            return (json["data"] as? [String: Any])?["keys"] as? [String] ?? []
        } catch OpenBaoError.httpError(404, _) {
            return []
        }
    }

    /// Revokes `token` itself. Throws when the server doesn't confirm the revocation, so callers
    /// never report a token as revoked while it may still be live. Use `try?` only for cleanup of
    /// short-lived tokens, such as the 2-minute `granter` sign-in token.
    public func revokeSelf(token: String) async throws {
        _ = try await postJSONObject(path: "v1/auth/token/revoke-self", token: token, body: [:])
    }

    public static func isValidToken(_ token: String) -> Bool {
        guard !token.isEmpty else { return false }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
        return token.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    private func endpointURL(_ path: String) -> URL {
        baseURL.appendingPathComponent(path)
    }

    private func makeRequest(
        path: String,
        method: String,
        token: String?,
        jsonContent: Bool
    ) -> URLRequest {
        var req = URLRequest(url: endpointURL(path))
        req.httpMethod = method
        if jsonContent {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        if let token {
            req.setValue(token, forHTTPHeaderField: "X-Vault-Token")
        }
        if !namespace.isEmpty {
            req.setValue(namespace, forHTTPHeaderField: "X-Vault-Namespace")
        }
        return req
    }

    internal func get(path: String, token: String) async throws -> [String: Any] {
        let req = makeRequest(path: path, method: "GET", token: token, jsonContent: false)
        return try await execute(req)
    }

    internal func post<T: Encodable>(path: String, token: String?, body: T) async throws -> [String: Any] {
        var req = makeRequest(path: path, method: "POST", token: token, jsonContent: true)
        req.httpBody = try JSONEncoder().encode(body)
        return try await execute(req)
    }

    internal func postJSONObject(path: String, token: String?, body: [String: Any]) async throws -> [String: Any] {
        var req = makeRequest(path: path, method: "POST", token: token, jsonContent: true)
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await execute(req)
    }

    internal func putJSONObject(path: String, token: String?, body: [String: Any]) async throws -> [String: Any] {
        var req = makeRequest(path: path, method: "PUT", token: token, jsonContent: true)
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await execute(req)
    }

    private func execute(_ request: URLRequest, classifyingLookup: Bool = false) async throws -> [String: Any] {
        // Every request here carries a credential (sign-in JWT, granter token, grant, or admin
        // token), so plain http is refused unless the server is on this machine.
        if let url = request.url {
            try Self.validateEndpointURL(url, allowDemo: transport is DemoOpenBaoTransport)
        } else {
            throw OpenBaoError.invalidBaseURL(baseURL.absoluteString)
        }
        let (data, response) = try await transport.send(request)
        if response.statusCode == 204 {
            return [:]
        }
        let parsed = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        guard (200..<300).contains(response.statusCode) else {
            if (300..<400).contains(response.statusCode) {
                throw OpenBaoError.httpError(response.statusCode, "the server answered with a redirect, which BaoBuddy doesn't follow; use the active node's address")
            }
            let messages = parsed?["errors"] as? [String]
            if classifyingLookup, [400, 403].contains(response.statusCode) {
                let invalid = ["bad token", "invalid token", "token is expired", "expired token", "token not found"]
                for message in messages ?? [] {
                    for line in message.split(whereSeparator: \.isNewline) {
                        let text = line.trimmingCharacters(in: .whitespaces).lowercased()
                        let entry = text.hasPrefix("*") ? String(text.dropFirst()).trimmingCharacters(in: .whitespaces) : text
                        if invalid.contains(entry) { throw OpenBaoError.inactiveToken }
                    }
                }
            }
            let errors = messages?.joined(separator: "; ")
            throw OpenBaoError.httpError(response.statusCode, Self.safeDetail(errors ?? (parsed == nil ? "unexpected non-JSON response" : "")))
        }
        return parsed ?? [:]
    }

    /// Server error text shown to the user: control and invisible formatting characters removed
    /// (no bidi tricks in error banners) and truncated. Non-JSON bodies are never echoed, because
    /// a proxy could reflect the request, including a JWT or token, back into the message.
    static func safeDetail(_ raw: String) -> String {
        let cleaned = String(String.UnicodeScalarView(raw.unicodeScalars.filter { scalar in
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator: return false
            default: return true
            }
        }))
        return cleaned.count > 300 ? String(cleaned.prefix(300)) + "…" : cleaned
    }
}

/// Minimal parser & verifier for OpenSSH `ssh-ed25519-cert-v01@openssh.com` user certificates,
/// used to confirm before delivery that OpenBao signed the exact principals and lifetime approved.
public struct OpenSSHCertificate: Equatable, Sendable {
    public let keyType: String
    public let serial: UInt64
    public let certType: UInt32
    public let keyID: String
    public let validPrincipals: [String]
    public let validAfter: UInt64
    public let validBefore: UInt64

    public static let userCertType: UInt32 = 1

    /// Parses an OpenSSH `ssh-ed25519-cert-v01@openssh.com <base64> [comment]` certificate string.
    public static func parse(_ raw: String) throws -> OpenSSHCertificate {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = trimmed.split(whereSeparator: \.isWhitespace).map(String.init)
        guard parts.count >= 2,
              parts[0] == "ssh-ed25519-cert-v01@openssh.com",
              let blob = Data(base64Encoded: parts[1]) else {
            throw OpenBaoError.unexpectedResponse("malformed OpenSSH Ed25519 certificate")
        }
        var cursor = BinaryReader(blob)
        let keyType = try cursor.readUTF8String()
        guard keyType == "ssh-ed25519-cert-v01@openssh.com" else {
            throw OpenBaoError.unexpectedResponse("unexpected SSH certificate type '\(keyType)'")
        }
        _ = try cursor.readBytes() // nonce
        _ = try cursor.readBytes() // Ed25519 public key
        let serial = try cursor.readUInt64()
        let certType = try cursor.readUInt32()
        let keyID = try cursor.readUTF8String()
        let principalsBlob = try cursor.readBytes()
        var principalsReader = BinaryReader(principalsBlob)
        var principals: [String] = []
        while !principalsReader.isAtEnd {
            principals.append(try principalsReader.readUTF8String())
        }
        let validAfter = try cursor.readUInt64()
        let validBefore = try cursor.readUInt64()
        _ = try cursor.readBytes() // critical_options
        _ = try cursor.readBytes() // extensions
        _ = try cursor.readBytes() // reserved
        _ = try cursor.readBytes() // signature_key
        _ = try cursor.readBytes() // signature
        return OpenSSHCertificate(
            keyType: keyType,
            serial: serial,
            certType: certType,
            keyID: keyID,
            validPrincipals: principals,
            validAfter: validAfter,
            validBefore: validBefore
        )
    }

    /// Confirms the signed certificate is a user cert with the exact approved principals and a
    /// `valid_before` that does not exceed `maxValidBeforeEpoch` (zero positive grace window).
    public func verify(
        expectedPrincipals: [String],
        maxValidBeforeEpoch: UInt64
    ) throws {
        guard certType == Self.userCertType else {
            throw OpenBaoError.grantMismatch("SSH certificate type \(certType) is not a user certificate")
        }
        let expected = Set(expectedPrincipals)
        let actual = Set(validPrincipals)
        guard !actual.isEmpty, actual == expected else {
            throw OpenBaoError.grantMismatch(
                "SSH certificate principals \(actual.sorted()) differ from approved \(expected.sorted())"
            )
        }
        guard validBefore > validAfter else {
            throw OpenBaoError.grantMismatch("SSH certificate validity window is empty")
        }
        guard validBefore <= maxValidBeforeEpoch else {
            let overrun = validBefore - maxValidBeforeEpoch
            throw OpenBaoError.grantMismatch(
                "SSH certificate valid_before (\(validBefore)) exceeds the grant deadline (\(maxValidBeforeEpoch)) by \(overrun)s"
            )
        }
    }

    /// Convenience overload computing `maxValidBeforeEpoch` from `now + maxTTLSeconds` with zero grace window.
    public func verify(
        expectedPrincipals: [String],
        maxTTLSeconds: Int,
        now: Date = Date()
    ) throws {
        guard maxTTLSeconds > 0 else {
            throw OpenBaoError.grantMismatch("SSH certificate TTL must be positive")
        }
        let nowEpoch = UInt64(max(0, Int64(floor(now.timeIntervalSince1970))))
        let (deadline, overflow) = nowEpoch.addingReportingOverflow(UInt64(maxTTLSeconds))
        guard !overflow else {
            throw OpenBaoError.grantMismatch("SSH certificate deadline overflow")
        }
        try verify(expectedPrincipals: expectedPrincipals, maxValidBeforeEpoch: deadline)
    }

    /// Encodes a synthetic wire-format `ssh-ed25519-cert-v01@openssh.com` blob (used by Demo Mode and tests).
    public static func encodeSynthetic(
        principals: [String],
        validAfter: UInt64,
        validBefore: UInt64,
        certType: UInt32 = userCertType,
        keyID: String = "baobuddy-demo",
        serial: UInt64 = 1,
        comment: String = "baobuddy-demo"
    ) -> String {
        var out = Data()
        func appendBytes(_ data: Data) {
            var len = UInt32(data.count).bigEndian
            withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
            out.append(data)
        }
        func appendString(_ text: String) { appendBytes(Data(text.utf8)) }
        func appendUInt32(_ value: UInt32) {
            var be = value.bigEndian
            withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
        }
        func appendUInt64(_ value: UInt64) {
            var be = value.bigEndian
            withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
        }

        appendString("ssh-ed25519-cert-v01@openssh.com")
        appendBytes(Data(repeating: 0x11, count: 32)) // nonce
        appendBytes(Data(repeating: 0x22, count: 32)) // pk
        appendUInt64(serial)
        appendUInt32(certType)
        appendString(keyID)

        var principalsBuf = Data()
        for principal in principals {
            let pData = Data(principal.utf8)
            var len = UInt32(pData.count).bigEndian
            withUnsafeBytes(of: &len) { principalsBuf.append(contentsOf: $0) }
            principalsBuf.append(pData)
        }
        appendBytes(principalsBuf)
        appendUInt64(validAfter)
        appendUInt64(validBefore)
        appendBytes(Data()) // critical_options
        appendBytes(Data()) // extensions
        appendBytes(Data()) // reserved
        appendBytes(Data(repeating: 0x33, count: 16)) // signature_key
        appendBytes(Data(repeating: 0x44, count: 16)) // signature
        return "ssh-ed25519-cert-v01@openssh.com \(out.base64EncodedString()) \(comment)"
    }

    private struct BinaryReader {
        private let data: Data
        private var offset: Int = 0

        init(_ data: Data) {
            self.data = data
        }

        var isAtEnd: Bool { offset >= data.count }

        mutating func readUInt32() throws -> UInt32 {
            guard offset + 4 <= data.count else {
                throw OpenBaoError.unexpectedResponse("truncated OpenSSH certificate")
            }
            var value: UInt32 = 0
            for idx in 0..<4 {
                value = (value << 8) | UInt32(data[data.startIndex + offset + idx])
            }
            offset += 4
            return value
        }

        mutating func readUInt64() throws -> UInt64 {
            guard offset + 8 <= data.count else {
                throw OpenBaoError.unexpectedResponse("truncated OpenSSH certificate")
            }
            var value: UInt64 = 0
            for idx in 0..<8 {
                value = (value << 8) | UInt64(data[data.startIndex + offset + idx])
            }
            offset += 8
            return value
        }

        mutating func readBytes() throws -> Data {
            let length = Int(try readUInt32())
            guard length >= 0, offset + length <= data.count else {
                throw OpenBaoError.unexpectedResponse("truncated OpenSSH certificate field")
            }
            let slice = data.subdata(in: (data.startIndex + offset)..<(data.startIndex + offset + length))
            offset += length
            return slice
        }

        mutating func readUTF8String() throws -> String {
            let bytes = try readBytes()
            guard let text = String(data: bytes, encoding: .utf8) else {
                throw OpenBaoError.unexpectedResponse("invalid UTF-8 string in OpenSSH certificate")
            }
            return text
        }
    }
}
