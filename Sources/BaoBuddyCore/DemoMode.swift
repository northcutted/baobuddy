import CryptoKit
import Foundation

/// Constants and factory for BaoBuddy's built-in, in-memory Demo Mode.
///
/// Demo Mode runs the real signing, JWT verification, orchestrator, extension, and remote-delivery
/// code paths against an in-memory simulated server (`demo.baobuddy.invalid`) so App Review,
/// automated screenshots, and first-time users can evaluate BaoBuddy without deploying OpenBao.
///
/// Security invariants:
/// - The demo profile exists **only in memory**; it is never persisted, exported, or shared.
/// - Imported profiles that attempt to claim `BaoDemo.profileID` or `BaoDemo.serverHost` are rejected.
/// - `DemoOpenBaoTransport` cryptographically verifies the real ES256 JWT signature against the
///   device's P-256 public key, exercising Apple Secure Enclave + biometric prompts on hardware.
public enum BaoDemo {
    public static let profileID = "__baobuddy_demo__"
    public static let serverHost = "demo.baobuddy.invalid"
    public static let serverAddress = "https://demo.baobuddy.invalid"
    public static let remoteHost = "runner.demo.baobuddy.invalid"
    public static let jwtMount = "jwt-demo"
    public static let jwtRole = "granter"
    public static let jwtIssuer = "bao-granter"
    public static let demoCAPEM = "-----BEGIN CERTIFICATE-----\nDEMO-IN-MEMORY-TRANSPORT\n-----END CERTIFICATE-----"
    public static let jwtAudience = BaoOpenBaoConfig.defaultAudience(
        address: serverAddress,
        namespace: "",
        mount: jwtMount,
        caPEM: demoCAPEM
    )
    public static let jwtSubject = "demo"

    /// Constructs the ephemeral in-memory Demo Mode server profile.
    public static func makeProfile(remoteTarget: Bool = true) -> BaoProfile {
        let dbExt = BaoCredentialExtension(
            id: "db-demo",
            label: String(localized: "Demo Postgres Credentials", table: "BaoBuddyCore", comment: "Demo mode: name of a simulated credential extension. Postgres is a product name."),
            description: String(localized: "Simulated short-lived database credentials from database/creds/demo.", table: "BaoBuddyCore", comment: "Demo mode: description of a simulated credential extension. Do not translate database/creds/demo (a path)."),
            endpoint: "database/creds/demo",
            method: .get,
            tokenField: "",
            deliverAs: "db-creds.json",
            policy: "db-demo-read",
            elevated: false,
            enabled: true
        )
        let target: BaoRemoteTargetConfig = remoteTarget
            ? BaoRemoteTargetConfig(
                name: String(localized: "Demo Build Runner", table: "BaoBuddyCore", comment: "Demo mode: name of the simulated remote host that receives grants (a build machine)."),
                host: remoteHost,
                port: 22,
                user: "granter",
                hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoSimulatedHostKeyNotForNetworkUse"
            )
            : BaoRemoteTargetConfig(name: "", host: "", port: 22, user: "", hostKey: "")
        return BaoProfile(
            id: profileID,
            version: 1,
            name: String(localized: "Demo OpenBao", table: "BaoBuddyCore", comment: "Demo mode: name of the simulated server. OpenBao is a product name."),
            openbao: BaoOpenBaoConfig(
                address: serverAddress,
                caPEM: demoCAPEM,
                jwtAuth: BaoJWTAuthConfig(
                    mount: jwtMount,
                    role: jwtRole,
                    issuer: jwtIssuer,
                    audience: jwtAudience,
                    subject: jwtSubject
                ),
                tokenRoles: BaoTokenRolesConfig(mac: "grant-demo", t3: "grant-demo"),
                grantPolicies: [
                    BaoBuddyPolicy(
                        name: "db-readonly",
                        label: String(localized: "Database Read-Only", table: "BaoBuddyCore", comment: "Demo mode: display name of a sample OpenBao policy."),
                        description: String(localized: "Read-only access to staging database secrets", table: "BaoBuddyCore", comment: "Demo mode: description of a sample OpenBao policy."),
                        elevated: false,
                        defaultSelected: true
                    ),
                    BaoBuddyPolicy(
                        name: "app-read",
                        label: String(localized: "App Secrets Read", table: "BaoBuddyCore", comment: "Demo mode: display name of a sample OpenBao policy."),
                        description: String(localized: "Read application runtime configuration", table: "BaoBuddyCore", comment: "Demo mode: description of a sample OpenBao policy."),
                        elevated: false,
                        defaultSelected: false
                    ),
                    BaoBuddyPolicy(
                        name: "k8s-deploy",
                        label: String(localized: "Kubernetes Deploy", table: "BaoBuddyCore", comment: "Demo mode: display name of a sample OpenBao policy."),
                        description: String(localized: "Elevated deployment access to cluster namespaces", table: "BaoBuddyCore", comment: "Demo mode: description of a sample OpenBao policy."),
                        elevated: true,
                        defaultSelected: false
                    )
                ],
                extensions: [dbExt],
                maxHours: 4,
                keys: [],
                ssh: BaoSSHConfig(
                    role: "demo",
                    hosts: remoteTarget
                        ? [.init(name: "staging-web", user: "ops", principal: "ops-staging")]
                        : []
                ),
                githubAppItem: ""
            ),
            t3Granter: target
        )
    }
}

extension BaoDemo {
    /// Earlier activity shown in Demo Mode's Recent Activity, so a first-time user sees what the
    /// log records. In memory only, like everything else in Demo Mode.
    public static func sampleActivity(profile: BaoProfile, now: Date = Date()) -> [GrantActivityEntry] {
        [
            GrantActivityEntry(
                timestamp: now.addingTimeInterval(-(2 * 3600 + 25 * 60)),
                action: .revoked,
                serverName: profile.displayName,
                targetName: profile.targetDisplayName,
                via: "demo"
            ),
            GrantActivityEntry(
                timestamp: now.addingTimeInterval(-(3 * 3600 + 10 * 60)),
                action: .granted,
                serverName: profile.displayName,
                targetName: profile.targetDisplayName,
                policies: ["db-readonly", "k8s-deploy"],
                hours: 1,
                // Reasons accept only ASCII (see `GrantRequest.sanitizeWhy`); so does the sample.
                why: GrantRequest.sanitizeWhy(String(localized: "Roll out the hotfix to the staging cluster", table: "BaoBuddyCore", comment: "Demo mode: the reason given for a sample elevated grant in Recent Activity. Grant reasons accept only unaccented letters A-Z, digits, spaces and . , : ; ( ) / _ + - # (other characters are removed), so write it in your language with only those characters if that reads naturally, or else use: INC-2291 hotfix rollout")),
                elevated: true,
                via: "demo"
            )
        ]
    }
}

extension BaoProfile {
    /// True only when this profile is the built-in in-memory Demo Mode profile.
    public var isDemoProfile: Bool {
        guard id == BaoDemo.profileID,
              let host = URL(string: openbao.address)?.host?.lowercased() else {
            return false
        }
        return host == BaoDemo.serverHost
    }
}

/// In-memory `HTTPTransport` simulating an OpenBao / HashiCorp Vault server for Demo Mode.
///
/// Cryptographically verifies incoming ES256 JWTs against `trustedPublicKeyPEMs` using CryptoKit,
/// mints orphan non-renewable demo tokens, serves `database/creds/demo`, and enforces real
/// revocation state on `lookup-self`, `revoke`, `revoke-self`, and `revoke-accessor`.
public final class DemoOpenBaoTransport: HTTPTransport, @unchecked Sendable {
    private struct StoredToken {
        let token: String
        let accessor: String
        let policies: [String]
        let isGranter: Bool
        let displayName: String
        let why: String
        let expiresAt: Date
        var revoked: Bool = false
    }

    private let lock = NSLock()
    private var trustedPublicKeys: [P256.Signing.PublicKey]
    private var tokensByValue: [String: StoredToken] = [:]
    private var tokensByAccessor: [String: String] = [:]
    private let expectedIssuer: String
    private let expectedAudience: String
    private let expectedSubject: String

    public init(
        trustedPublicKeyPEMs: [String],
        expectedIssuer: String = BaoDemo.jwtIssuer,
        expectedAudience: String = BaoDemo.jwtAudience,
        expectedSubject: String = BaoDemo.jwtSubject
    ) throws {
        self.trustedPublicKeys = try trustedPublicKeyPEMs.map { try P256.Signing.PublicKey(pemRepresentation: $0) }
        self.expectedIssuer = expectedIssuer
        self.expectedAudience = expectedAudience
        self.expectedSubject = expectedSubject
    }

    public func updateTrustedPublicKeyPEM(_ pem: String) throws {
        let parsed = try P256.Signing.PublicKey(pemRepresentation: pem)
        lock.lock()
        trustedPublicKeys = [parsed]
        lock.unlock()
    }

    /// Returns the real expiration date for a live demo token, mirroring `lookup-self` on a real server.
    public func tokenExpiry(for tokenValue: String) -> Date? {
        activeToken(for: tokenValue)?.expiresAt
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url else {
            throw OpenBaoError.invalidBaseURL("missing URL")
        }
        guard url.host?.lowercased() == BaoDemo.serverHost else {
            return response(url: url, status: 403, json: ["errors": ["demo transport refused non-demo host"]])
        }

        let method = (request.httpMethod ?? "GET").uppercased()
        let path = url.path
        let authToken = request.value(forHTTPHeaderField: "X-Vault-Token") ?? ""
        let bodyObj = parseJSONBody(request.httpBody)

        switch (method, path) {
        case ("GET", "/v1/sys/health"):
            return response(url: url, status: 200, json: [
                "initialized": true,
                "sealed": false,
                "version": "2.7.2-demo"
            ])

        case ("POST", _) where path.hasPrefix("/v1/auth/") && path.hasSuffix("/login"):
            return handleJWTLogin(url: url, body: bodyObj)

        case ("POST", _) where path.hasPrefix("/v1/auth/token/create/"):
            return handleTokenCreate(url: url, authToken: authToken, body: bodyObj)

        case ("GET", "/v1/auth/token/lookup-self"):
            return handleLookupSelf(url: url, authToken: authToken)

        case ("POST", "/v1/auth/token/revoke-self"):
            return handleRevokeSelf(url: url, authToken: authToken)

        case ("POST", "/v1/auth/token/revoke"):
            let target = bodyObj?["token"] as? String ?? ""
            return handleRevoke(url: url, authToken: authToken, targetToken: target)

        case ("POST", "/v1/auth/token/revoke-accessor"):
            let accessor = bodyObj?["accessor"] as? String ?? ""
            return handleRevokeAccessor(url: url, authToken: authToken, accessor: accessor)

        case ("GET", "/v1/database/creds/demo"):
            return handleDemoDatabaseCreds(url: url, authToken: authToken)

        case ("POST", _) where path.hasPrefix("/v1/ssh/sign/"):
            return handleSSHSign(url: url, authToken: authToken, body: bodyObj)

        default:
            return response(url: url, status: 404, json: ["errors": ["demo endpoint not found: \(path)"]])
        }
    }

    // MARK: - Handlers

    private func handleJWTLogin(url: URL, body: [String: Any]?) -> (Data, HTTPURLResponse) {
        guard let jwt = body?["jwt"] as? String, !jwt.isEmpty else {
            return response(url: url, status: 400, json: ["errors": ["missing jwt"]])
        }
        do {
            try verifyES256JWT(jwt)
        } catch {
            return response(url: url, status: 403, json: ["errors": ["JWT verification failed: \(error.localizedDescription)"]])
        }

        let token = "demo.granter.\(UUID().uuidString.lowercased())"
        let accessor = "demo.gacc.\(UUID().uuidString.lowercased())"
        let record = StoredToken(
            token: token,
            accessor: accessor,
            policies: ["granter"],
            isGranter: true,
            displayName: "jwt-demo",
            why: "",
            expiresAt: Date().addingTimeInterval(120)
        )
        lock.lock()
        tokensByValue[token] = record
        tokensByAccessor[accessor] = token
        lock.unlock()

        return response(url: url, status: 200, json: [
            "auth": [
                "client_token": token,
                "accessor": accessor,
                "policies": ["granter"],
                "lease_duration": 120,
                "renewable": false
            ]
        ])
    }

    private func handleTokenCreate(url: URL, authToken: String, body: [String: Any]?) -> (Data, HTTPURLResponse) {
        guard let caller = activeToken(for: authToken), caller.isGranter else {
            return response(url: url, status: 403, json: ["errors": ["permission denied"]])
        }
        let requestedPolicies = body?["policies"] as? [String] ?? []
        let ttlRaw = body?["ttl"] as? String ?? "1h"
        let ttlSeconds = parseDurationSeconds(ttlRaw) ?? 3600
        let displayName = body?["display_name"] as? String ?? "demo-grant"
        let meta = body?["meta"] as? [String: String] ?? [:]
        let why = meta["why"] ?? ""

        let mintedPolicies = Array(Set(requestedPolicies + ["default"])).sorted()
        let token = "demo.grant.\(UUID().uuidString.lowercased())"
        let accessor = "demo.acc.\(UUID().uuidString.lowercased())"
        let record = StoredToken(
            token: token,
            accessor: accessor,
            policies: mintedPolicies,
            isGranter: false,
            displayName: displayName,
            why: why,
            expiresAt: Date().addingTimeInterval(TimeInterval(ttlSeconds))
        )
        lock.lock()
        tokensByValue[token] = record
        tokensByAccessor[accessor] = token
        lock.unlock()

        return response(url: url, status: 200, json: [
            "auth": [
                "client_token": token,
                "accessor": accessor,
                "policies": mintedPolicies,
                "lease_duration": ttlSeconds,
                "renewable": false,
                "orphan": true
            ]
        ])
    }

    private func handleLookupSelf(url: URL, authToken: String) -> (Data, HTTPURLResponse) {
        guard let record = activeToken(for: authToken) else {
            return response(url: url, status: 403, json: ["errors": ["bad token"]])
        }
        let remaining = max(1, Int(record.expiresAt.timeIntervalSinceNow))
        return response(url: url, status: 200, json: [
            "data": [
                "accessor": record.accessor,
                "ttl": remaining,
                "policies": record.policies,
                "display_name": record.displayName,
                "orphan": !record.isGranter,
                "renewable": false,
                "meta": ["why": record.why]
            ]
        ])
    }

    private func handleRevokeSelf(url: URL, authToken: String) -> (Data, HTTPURLResponse) {
        lock.lock()
        defer { lock.unlock() }
        guard var record = tokensByValue[authToken], !record.revoked else {
            return response(url: url, status: 403, json: ["errors": ["bad token"]])
        }
        record.revoked = true
        tokensByValue[authToken] = record
        return response(url: url, status: 204, json: nil)
    }

    private func handleRevoke(url: URL, authToken: String, targetToken: String) -> (Data, HTTPURLResponse) {
        guard let caller = activeToken(for: authToken), caller.isGranter else {
            return response(url: url, status: 403, json: ["errors": ["permission denied"]])
        }
        lock.lock()
        if var target = tokensByValue[targetToken] {
            target.revoked = true
            tokensByValue[targetToken] = target
        }
        lock.unlock()
        return response(url: url, status: 204, json: nil)
    }

    private func handleRevokeAccessor(url: URL, authToken: String, accessor: String) -> (Data, HTTPURLResponse) {
        guard let caller = activeToken(for: authToken), caller.isGranter else {
            return response(url: url, status: 403, json: ["errors": ["permission denied"]])
        }
        lock.lock()
        if let tokenVal = tokensByAccessor[accessor], var target = tokensByValue[tokenVal] {
            target.revoked = true
            tokensByValue[tokenVal] = target
        }
        lock.unlock()
        return response(url: url, status: 204, json: nil)
    }

    private func handleDemoDatabaseCreds(url: URL, authToken: String) -> (Data, HTTPURLResponse) {
        guard let caller = activeToken(for: authToken), !caller.isGranter else {
            return response(url: url, status: 403, json: ["errors": ["permission denied"]])
        }
        let suffix = String(UUID().uuidString.prefix(8)).lowercased()
        let remaining = max(60, Int(caller.expiresAt.timeIntervalSinceNow))
        return response(url: url, status: 200, json: [
            "lease_id": "database/creds/demo/\(suffix)",
            "lease_duration": remaining,
            "renewable": false,
            "data": [
                "username": "v-demo-readonly-\(suffix)",
                "password": "demo-ephemeral-\(suffix)",
                "host": "db.demo.baobuddy.invalid",
                "port": 5432,
                "database": "demo"
            ]
        ])
    }

    private func handleSSHSign(url: URL, authToken: String, body: [String: Any]?) -> (Data, HTTPURLResponse) {
        guard let caller = activeToken(for: authToken), caller.isGranter else {
            return response(url: url, status: 403, json: ["errors": ["permission denied"]])
        }
        let rawPrincipals = body?["valid_principals"] as? String ?? "ops"
        let principals = rawPrincipals.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let ttlRaw = body?["ttl"] as? String ?? "1h"
        let ttlSeconds = parseDurationSeconds(ttlRaw) ?? 3600
        let nowEpoch = UInt64(max(0, Int64(floor(Date().timeIntervalSince1970))))
        let keyID = body?["key_id"] as? String ?? "baobuddy-demo"
        let cert = OpenSSHCertificate.encodeSynthetic(
            principals: principals.isEmpty ? ["ops"] : principals,
            validAfter: nowEpoch > 30 ? nowEpoch - 30 : 0,
            validBefore: nowEpoch + UInt64(max(1, ttlSeconds)),
            keyID: keyID,
            comment: "baobuddy-demo"
        )
        return response(url: url, status: 200, json: [
            "data": [
                "signed_key": cert,
                "serial_number": "demo-0001"
            ]
        ])
    }

    // MARK: - Helpers

    private func verifyES256JWT(_ jwt: String) throws {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3,
              let headerData = Base64URL.decode(parts[0]),
              let payloadData = Base64URL.decode(parts[1]),
              let sigData = Base64URL.decode(parts[2]),
              let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any],
              let payload = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any] else {
            throw OpenBaoError.unexpectedResponse("malformed JWT")
        }
        guard (header["alg"] as? String) == "ES256" else {
            throw OpenBaoError.unexpectedResponse("unsupported JWT alg")
        }
        guard (payload["iss"] as? String) == expectedIssuer,
              (payload["sub"] as? String) == expectedSubject,
              (payload["aud"] as? String) == expectedAudience else {
            throw OpenBaoError.unexpectedResponse("JWT claims mismatch")
        }
        let now = Int(Date().timeIntervalSince1970)
        if let exp = payload["exp"] as? Int, now > exp + 5 {
            throw OpenBaoError.unexpectedResponse("JWT expired")
        }
        if let iat = payload["iat"] as? Int, iat > now + 5 {
            throw OpenBaoError.unexpectedResponse("JWT issued in the future")
        }

        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: sigData)
        lock.lock()
        let keys = trustedPublicKeys
        lock.unlock()
        guard keys.contains(where: { $0.isValidSignature(signature, for: signingInput) }) else {
            throw OpenBaoError.unexpectedResponse("ES256 signature did not match registered demo device key")
        }
    }

    private func activeToken(for value: String) -> StoredToken? {
        lock.lock()
        defer { lock.unlock() }
        guard let record = tokensByValue[value], !record.revoked, record.expiresAt > Date() else {
            return nil
        }
        return record
    }

    private func parseJSONBody(_ data: Data?) -> [String: Any]? {
        guard let data, !data.isEmpty else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    private func parseDurationSeconds(_ raw: String) -> Int? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if trimmed.hasSuffix("h"), let hrs = Int(trimmed.dropLast()) { return hrs * 3600 }
        if trimmed.hasSuffix("m"), let mins = Int(trimmed.dropLast()) { return mins * 60 }
        if trimmed.hasSuffix("s"), let secs = Int(trimmed.dropLast()) { return secs }
        return Int(trimmed)
    }

    private func response(url: URL, status: Int, json: [String: Any]?) -> (Data, HTTPURLResponse) {
        let data: Data
        if let json {
            data = (try? JSONSerialization.data(withJSONObject: json)) ?? Data()
        } else {
            data = Data()
        }
        let http = HTTPURLResponse(
            url: url,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        ) ?? HTTPURLResponse()
        return (data, http)
    }
}

/// Simulated remote `baobuddy-receiver` host for Demo Mode (in-memory only, zero network).
public final class DemoGranterTransport: T3GranterTransport, @unchecked Sendable {
    private let lock = NSLock()
    private let openbao: DemoOpenBaoTransport?
    private var installedToken: String?
    private var installedSSHCert: String = ""
    private var installedArtifacts: [MintedExtensionArtifact] = []
    private var installedExpiresAt: Date?
    private let sampleTasks: [String]

    public init(
        openbao: DemoOpenBaoTransport? = nil,
        sampleTasks: [String] = DemoGranterTransport.defaultSampleTasks
    ) {
        self.openbao = openbao
        self.sampleTasks = sampleTasks
    }

    /// Simulated workloads on the demo host: a task name (not translated) and its state.
    public static var defaultSampleTasks: [String] {
        [
            String(localized: "ci-deploy-worker (idle)", table: "BaoBuddyCore", comment: "Demo mode: a simulated background task on the remote host. Do not translate ci-deploy-worker (a task name); translate the state in parentheses."),
            String(localized: "db-migration-check (waiting for grant)", table: "BaoBuddyCore", comment: "Demo mode: a simulated background task on the remote host. Do not translate db-migration-check (a task name); translate the state in parentheses.")
        ]
    }

    public func runningTasks() async -> RunningTasksResult {
        RunningTasksResult(tasks: sampleTasks, brokerUnavailable: false)
    }

    public func fetchPublicKey() async throws -> String {
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoRemoteHostUserKeyForSigning demo-runner"
    }

    public func install(_ payload: GrantInstallPayload) async throws -> String {
        // Exercise the exact v1/v2 wire encoder and limits check used by real SSH delivery.
        _ = try payload.encoded()
        let expires = openbao?.tokenExpiry(for: payload.token) ?? Date().addingTimeInterval(3600)
        lock.withLock {
            installedToken = payload.token
            installedSSHCert = payload.sshCert
            installedArtifacts = payload.artifacts
            installedExpiresAt = expires
        }

        let formatter = ISO8601DateFormatter()
        // Hosts answer `Granted until <ISO 8601 time> (<note>)`; the app rewrites the time for display
        // and shows the note as the host wrote it, so only the note is localized.
        let note: String
        switch payload.artifacts.count {
        case 0:
            note = String(localized: "demo", table: "BaoBuddyCore", comment: "Demo mode: marks a simulated grant in the banner after the expiry time and in the remote host status. Don't use parentheses or semicolons.")
        case 1:
            note = String(localized: "demo · 1 credential file", table: "BaoBuddyCore", comment: "Demo mode: note after the grant expiry time. A credential file holds extra credentials minted with the grant.")
        default:
            note = String(localized: "demo · \(payload.artifacts.count) credential files", table: "BaoBuddyCore", comment: "Demo mode: note after the grant expiry time. %lld is a number of credential files, 2 or more.")
        }
        return "Granted until \(formatter.string(from: expires)) (\(note))"
    }

    private struct GrantSnapshot {
        let token: String?
        let sshCert: String
        let artifacts: [MintedExtensionArtifact]
        let expiresAt: Date?
    }

    public func status() async throws -> String {
        let snapshot = lock.withLock {
            GrantSnapshot(
                token: installedToken,
                sshCert: installedSSHCert,
                artifacts: installedArtifacts,
                expiresAt: installedExpiresAt
            )
        }

        if let token = snapshot.token, !token.isEmpty,
           let expires = openbao?.tokenExpiry(for: token) ?? snapshot.expiresAt,
           expires > Date() {
            let remaining = Self.formatDuration(seconds: max(60, Int(expires.timeIntervalSinceNow)))
            // The app parses the `Secrets:`/`SSH:`/`Push:` prefixes and `(<time> left)`, so those stay
            // English; the note after the semicolon is shown as is and can be localized.
            let fileNames = snapshot.artifacts.map(\.name).joined(separator: ", ")
            let note = snapshot.artifacts.isEmpty
                ? String(localized: "demo", table: "BaoBuddyCore", comment: "Demo mode: marks a simulated grant in the banner after the expiry time and in the remote host status. Don't use parentheses or semicolons.")
                : String(localized: "demo • files: \(fileNames)", table: "BaoBuddyCore", comment: "Demo mode: status note for a simulated grant. %@ is a comma-separated list of credential file names (not translated). Don't use parentheses or semicolons.")
            let sshLine = snapshot.sshCert.isEmpty ? "SSH: no certificate." : "SSH: ops@staging-web (\(remaining) left)."
            return """
            Secrets: active (\(remaining) left; \(note)).
            \(sshLine)
            Push: no token.
            """
        }
        return """
        Secrets: no grant.
        SSH: no certificate.
        Push: no token.
        """
    }

    private static func formatDuration(seconds: Int) -> String {
        let totalMinutes = max(1, seconds / 60)
        let hours = totalMinutes / 60
        let mins = totalMinutes % 60
        if hours > 0 && mins > 0 {
            return "\(hours)h \(mins)m"
        }
        if hours > 0 {
            return "\(hours)h"
        }
        return "\(mins)m"
    }

    /// When the simulated grant on this host ends, or nil when none is active. The app uses it to
    /// show the time left in the user's language; `status()` keeps the host's own wire format.
    public var activeGrantExpiry: Date? {
        let snapshot = lock.withLock { (token: installedToken, expiresAt: installedExpiresAt) }
        guard let token = snapshot.token, !token.isEmpty,
              let expires = openbao?.tokenExpiry(for: token) ?? snapshot.expiresAt,
              expires > Date() else {
            return nil
        }
        return expires
    }

    public func revoke() async throws -> String {
        lock.withLock {
            installedToken = nil
            installedSSHCert = ""
            installedArtifacts = []
            installedExpiresAt = nil
        }
        return String(localized: "Revoked demo grant and deleted simulated host credentials.", table: "BaoBuddyCore", comment: "Demo mode: banner after revoking a simulated grant.")
    }

    public var currentArtifactNames: [String] {
        lock.withLock {
            installedArtifacts.map(\.name)
        }
    }
}
