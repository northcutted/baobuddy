import CryptoKit
import Foundation
import XCTest
@testable import BaoBuddyCore

private func makeFixtureProfile() -> BaoProfile {
    BaoProfile(
        version: 1,
        openbao: .init(
            address: "https://192.168.1.4:8200",
            caPEM: "",
            jwtAuth: .init(
                mount: "jwt-granter",
                role: "eddie",
                issuer: "bao-granter",
                audience: "openbao-granter",
                subject: "eddie"
            ),
            tokenRoles: .init(mac: "grant", t3: "grant-t3"),
            maxHours: 12,
            keys: [
                .init(name: "talos", item: "talos"),
                .init(name: "pbs", item: "pbs"),
            ],
            ssh: .init(
                role: "t3",
                hosts: [
                    .init(name: "proxmox", user: "root", principal: "root-proxmox"),
                    .init(name: "docker", user: "root", principal: "root-docker"),
                    .init(name: "nas", user: "eddie", principal: "eddie-nas"),
                ]
            ),
            githubAppItem: "lab/github-app"
        ),
        t3Granter: .init(host: "192.168.1.5", port: 22, user: "granter", hostKey: "")
    )
}

final class MockHTTPTransport: HTTPTransport, @unchecked Sendable {
    var handler: (URLRequest) throws -> (Int, Data)
    private(set) var requests: [URLRequest] = []

    init(handler: @escaping (URLRequest) throws -> (Int, Data)) {
        self.handler = handler
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        requests.append(request)
        let (status, data) = try handler(request)
        let url = request.url ?? URL(fileURLWithPath: "/")
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil)!
        return (data, response)
    }
}

/// Answers `auth/token/create/<role>` the way a correctly configured role does: an orphan,
/// non-renewable token with exactly the requested policies and TTL.
func grantResponse(_ request: URLRequest, token: String, extraPolicies: [String] = [], renewable: Bool = false) -> (Int, Data) {
    let body = (request.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]) ?? [:]
    let policies = (body["policies"] as? [String] ?? []) + extraPolicies
    let ttl = Int((body["ttl"] as? String ?? "0s").dropLast()) ?? 0
    let auth: [String: Any] = [
        "client_token": token,
        "accessor": "acc-\(token)",
        "policies": ["default"] + policies,
        "token_policies": ["default"] + policies,
        "renewable": renewable,
        "orphan": true,
        "lease_duration": ttl
    ]
    return (200, (try? JSONSerialization.data(withJSONObject: ["auth": auth])) ?? Data())
}

final class MockMacGrantStore: MacGrantStore, @unchecked Sendable {
    var stored: String?

    init(initial: String? = nil) {
        self.stored = initial
    }

    var failWrites = false
    var artifacts: [MintedExtensionArtifact] = []

    func replaceGrant(_ newToken: String, artifacts: [MintedExtensionArtifact]) throws -> String? {
        if failWrites { throw NSError(domain: "test", code: 1) }
        let previous = stored
        stored = newToken
        self.artifacts = artifacts
        return previous
    }
}

final class MockT3Granter: T3GranterTransport, @unchecked Sendable {
    var tasksResult = RunningTasksResult(tasks: [], brokerUnavailable: false)
    var pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey t3@t3-vm"
    var installShouldFail = false
    private(set) var installed: (token: String, cert: String, push: String)?
    private(set) var installedPayload: GrantInstallPayload?

    func runningTasks() async -> RunningTasksResult { tasksResult }
    func fetchPublicKey() async throws -> String { pubkey }
    func install(_ payload: GrantInstallPayload) async throws -> String {
        if installShouldFail {
            throw T3GranterError.installRefused("VM rejected grant")
        }
        installed = (payload.token, payload.sshCert, payload.pushToken)
        installedPayload = payload
        return "Granted until 10:15 PM."
    }
    func status() async throws -> String { "Secrets: no grant." }
    func revoke() async throws -> String { "Ended the secrets grant." }
}

final class BaoBuddyCoreTests: XCTestCase {
    func testP256PEMEncodingMatchesCryptoKit() throws {
        let priv = P256.Signing.PrivateKey()
        let pem = try PEMCodec.encodeP256PublicKeyPEM(x963Data: priv.publicKey.x963Representation)
        let roundTrip = try P256.Signing.PublicKey(pemRepresentation: pem)
        XCTAssertEqual(roundTrip.x963Representation, priv.publicKey.x963Representation)
        let fp = try PEMCodec.spkiFingerprint(x963Data: priv.publicKey.x963Representation)
        XCTAssertEqual(fp.count, 16)
    }

    func testDERToRawP256SignatureRoundTrip() throws {
        let priv = P256.Signing.PrivateKey()
        let msg = Data("hello openbao".utf8)
        let sig = try priv.signature(for: msg)
        let raw = try PEMCodec.derToRawP256Signature(sig.derRepresentation)
        XCTAssertEqual(raw, sig.rawRepresentation)
        XCTAssertEqual(raw.count, 64)
    }

    func testGrantRequestParsesURLAndCanonicalizes() throws {
        let profile = makeFixtureProfile()
        let url = try XCTUnwrap(URL(string: "baobuddy://grant?r=hours%3D4%20write%3D1%20ssh%3Dnas,docker%20keys%3Dtalos%20push%3D1%20why%3Dship%20fix%20%3Cscript%3E"))
        let req = try GrantRequest.parse(url: url, profile: profile)
        XCTAssertEqual(req.target, .t3)
        XCTAssertEqual(req.hours, 4)
        XCTAssertTrue(req.write)
        XCTAssertEqual(req.sshHosts, ["docker", "nas"])
        XCTAssertEqual(req.keys, ["talos"])
        XCTAssertTrue(req.push)
        XCTAssertEqual(req.why, "ship fix script")
        XCTAssertEqual(req.canonicalText, "HOURS=4 WRITE=1 SSH=docker,nas KEYS=talos PUSH=1 WHY=ship fix script")
        XCTAssertEqual(req.openBaoPolicies(profile: profile), ["app-read", "app-write", "key-talos", "key-talos-write"])
        XCTAssertEqual(req.sshPrincipals(profile: profile), ["root-docker", "eddie-nas"])
    }

    func testGrantRequestRejectsSSHAndPushOnMac() throws {
        let profile = makeFixtureProfile()
        XCTAssertThrowsError(try GrantRequest.parse(requestString: "SSH=docker", target: .mac, profile: profile)) { err in
            XCTAssertEqual(err as? GrantRequestError, .sshOnlyForT3)
        }
        XCTAssertThrowsError(try GrantRequest.parse(requestString: "PUSH=1", target: .mac, profile: profile)) { err in
            XCTAssertEqual(err as? GrantRequestError, .pushOnlyForT3)
        }
        XCTAssertThrowsError(try GrantRequest.parse(requestString: "HOURS=13", target: .t3, profile: profile)) { err in
            XCTAssertEqual(err as? GrantRequestError, .invalidHours(12))
        }
    }

    func testJWTSignerProducesVerifiableES256JWT() async throws {
        let profile = makeFixtureProfile()
        let signer = EphemeralP256Signer(deviceName: "mac")
        let jwtSigner = JWTSigner(signer: signer, ttlSeconds: 30)
        let now = Date(timeIntervalSince1970: 1_763_770_000)
        let jwt = try await jwtSigner.makeLoginJWT(config: profile.openbao.jwtAuth, reason: "Approve test", scope: "HOURS=1", now: now)
        XCTAssertEqual(signer.lastReason, "Approve test")

        let parts = jwt.split(separator: ".").map(String.init)
        XCTAssertEqual(parts.count, 3)

        let payloadData = try XCTUnwrap(Base64URL.decode(parts[1]))
        let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: payloadData) as? [String: Any])
        XCTAssertEqual(payload["iss"] as? String, "bao-granter")
        XCTAssertEqual(payload["sub"] as? String, "eddie")
        XCTAssertEqual(payload["aud"] as? String, "openbao-granter")
        XCTAssertEqual(payload["device"] as? String, "mac")
        XCTAssertEqual(payload["iat"] as? Int, 1_763_770_000)
        XCTAssertEqual(payload["exp"] as? Int, 1_763_770_030)
        XCTAssertEqual(payload["scope"] as? String, "HOURS=1")

        let rawSig = try XCTUnwrap(Base64URL.decode(parts[2]))
        let ecdsaSig = try P256.Signing.ECDSASignature(rawRepresentation: rawSig)
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        XCTAssertTrue(signer.privateKey.publicKey.isValidSignature(ecdsaSig, for: signingInput))
    }

    func testOrchestratorGrantsT3WithSSHAndRevokesSignIn() async throws {
        let profile = makeFixtureProfile()
        let signer = EphemeralP256Signer(deviceName: "iphone")
        let nowEpoch = UInt64(Date().timeIntervalSince1970)
        let validCert = OpenSSHCertificate.encodeSynthetic(
            principals: ["root-docker"],
            validAfter: nowEpoch - 30,
            validBefore: nowEpoch + 7200
        )
        var paths: [String] = []
        let transport = MockHTTPTransport { req in
            let path = req.url?.path ?? ""
            paths.append(path)
            switch path {
            case "/v1/auth/jwt-granter/login":
                return (200, Data(#"{"auth":{"client_token":"s.granter1"}}"#.utf8))
            case "/v1/auth/token/create/grant-t3":
                XCTAssertEqual(req.value(forHTTPHeaderField: "X-Vault-Token"), "s.granter1")
                return grantResponse(req, token: "s.t3grant")
            case "/v1/ssh/sign/t3":
                let payload = try! JSONSerialization.data(withJSONObject: ["data": ["signed_key": validCert]])
                return (200, payload)
            case "/v1/auth/token/revoke-self":
                return (204, Data())
            default:
                XCTFail("Unexpected OpenBao path: \(path)")
                return (404, Data())
            }
        }
        let openbao = OpenBaoClient(baseURL: URL(string: profile.openbao.address)!, transport: transport)
        let granter = MockT3Granter()
        let orchestrator = GrantOrchestrator(
            profile: profile,
            signer: signer,
            openbao: openbao,
            t3Granter: granter,
            via: "app",
            onRemoteGrantMinted: { _, _ in }
        )

        let req = try GrantRequest.parse(requestString: "HOURS=2 SSH=docker WHY=prune", target: .t3, profile: profile)
        let outcome = try await orchestrator.execute(req)
        XCTAssertEqual(outcome.message, "Granted until 10:15 PM.")
        XCTAssertEqual(granter.installed?.token, "s.t3grant")
        XCTAssertEqual(granter.installed?.cert, validCert)
        XCTAssertEqual(paths, [
            "/v1/auth/jwt-granter/login",
            "/v1/auth/token/create/grant-t3",
            "/v1/ssh/sign/t3",
            "/v1/auth/token/revoke-self",
        ])
    }

    func testOrchestratorRevokesMintedGrantWhenVMInstallFails() async throws {
        let profile = makeFixtureProfile()
        let signer = EphemeralP256Signer(deviceName: "iphone")
        var revokedTarget: String?
        var revokedSelf = false
        let transport = MockHTTPTransport { req in
            let path = req.url?.path ?? ""
            switch path {
            case "/v1/auth/jwt-granter/login":
                return (200, Data(#"{"auth":{"client_token":"s.granter1"}}"#.utf8))
            case "/v1/auth/token/create/grant-t3":
                return grantResponse(req, token: "s.t3grant")
            case "/v1/auth/token/revoke":
                if let body = req.httpBody,
                   let obj = try? JSONSerialization.jsonObject(with: body) as? [String: String] {
                    revokedTarget = obj["token"]
                }
                return (204, Data())
            case "/v1/auth/token/revoke-self":
                revokedSelf = true
                return (204, Data())
            default:
                return (404, Data())
            }
        }
        let openbao = OpenBaoClient(baseURL: URL(string: profile.openbao.address)!, transport: transport)
        let granter = MockT3Granter()
        granter.installShouldFail = true
        let orchestrator = GrantOrchestrator(
            profile: profile,
            signer: signer,
            openbao: openbao,
            t3Granter: granter,
            via: "app",
            onRemoteGrantMinted: { _, _ in }
        )

        let req = try GrantRequest.parse(requestString: "HOURS=1", target: .t3, profile: profile)
        do {
            _ = try await orchestrator.execute(req)
            XCTFail("Expected install error")
        } catch {
            // expected
        }
        XCTAssertEqual(revokedTarget, "s.t3grant")
        XCTAssertTrue(revokedSelf)
    }

    func testFailedMacReplacementRevokesOnlyNewGrant() async throws {
        let profile = makeFixtureProfile()
        var revoked: [String] = []
        let transport = MockHTTPTransport { request in
            switch request.url?.path {
            case "/v1/auth/jwt-granter/login":
                return (200, Data(#"{"auth":{"client_token":"sign-in"}}"#.utf8))
            case "/v1/auth/token/create/grant":
                return grantResponse(request, token: "replacement")
            case "/v1/auth/token/revoke":
                let payload = try JSONSerialization.jsonObject(with: XCTUnwrap(request.httpBody)) as? [String: String]
                revoked.append(try XCTUnwrap(payload?["token"]))
                return (204, Data())
            case "/v1/auth/token/revoke-self":
                revoked.append(try XCTUnwrap(request.value(forHTTPHeaderField: "X-Vault-Token")))
                return (204, Data())
            default:
                XCTFail("Unexpected endpoint")
                return (404, Data())
            }
        }
        let store = MockMacGrantStore(initial: "previous")
        store.failWrites = true
        let openbao = OpenBaoClient(baseURL: try XCTUnwrap(URL(string: profile.openbao.address)), transport: transport)
        let orchestrator = GrantOrchestrator(profile: profile, signer: EphemeralP256Signer(deviceName: "mac"),
                                             openbao: openbao, macStore: store, via: "test")
        do {
            _ = try await orchestrator.execute(GrantRequest(target: .mac, hours: 1))
            XCTFail("Commit failure must reach the caller")
        } catch {
            XCTAssertEqual(store.stored, "previous")
            XCTAssertEqual(revoked, ["replacement", "sign-in"])
        }
    }

    func testOrchestratorGrantsMacAndRevokesOldGrant() async throws {
        let profile = makeFixtureProfile()
        let signer = EphemeralP256Signer(deviceName: "mac")
        var revokedSelfTokens: [String] = []
        let transport = MockHTTPTransport { req in
            let path = req.url?.path ?? ""
            switch path {
            case "/v1/auth/jwt-granter/login":
                return (200, Data(#"{"auth":{"client_token":"s.granter1"}}"#.utf8))
            case "/v1/auth/token/create/grant":
                return grantResponse(req, token: "s.macnew")
            case "/v1/auth/token/revoke-self":
                if let tok = req.value(forHTTPHeaderField: "X-Vault-Token") {
                    revokedSelfTokens.append(tok)
                }
                return (204, Data())
            default:
                return (404, Data())
            }
        }
        let openbao = OpenBaoClient(baseURL: URL(string: profile.openbao.address)!, transport: transport)
        let macStore = MockMacGrantStore(initial: "s.macold")
        let orchestrator = GrantOrchestrator(
            profile: profile,
            signer: signer,
            openbao: openbao,
            macStore: macStore,
            via: "mac"
        )

        let req = try GrantRequest.parse(requestString: "HOURS=2 WHY=plan", target: .mac, profile: profile)
        let outcome = try await orchestrator.execute(req)
        XCTAssertTrue(outcome.replacedOldGrant)
        XCTAssertEqual(macStore.stored, "s.macnew")
        XCTAssertEqual(revokedSelfTokens, ["s.granter1", "s.macold"])
    }

    #if os(macOS)
    func testPinnedTLSClientAcceptsPinnedLongLivedSelfSignedLeafAndRejectsOther() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("baogrant-tls-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        func makeCert(name: String) throws -> String {
            let keyURL = dir.appendingPathComponent("\(name).key")
            let crtURL = dir.appendingPathComponent("\(name).crt")
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            proc.arguments = [
                "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-days", "3650", "-subj", "/CN=\(name)",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "subjectAltName=IP:192.168.1.4",
                "-keyout", keyURL.path, "-out", crtURL.path,
            ]
            proc.standardError = FileHandle.nullDevice
            try proc.run()
            proc.waitUntilExit()
            XCTAssertEqual(proc.terminationStatus, 0)
            return try String(contentsOf: crtURL, encoding: .utf8)
        }

        let pinnedPEM = try makeCert(name: "bao")
        let otherPEM = try makeCert(name: "other")
        let pinnedCerts = try PinnedTLSClient.parseCertificates(from: pinnedPEM)
        let otherCerts = try PinnedTLSClient.parseCertificates(from: otherPEM)
        XCTAssertEqual(pinnedCerts.count, 1)

        var matchingTrust: SecTrust?
        XCTAssertEqual(
            SecTrustCreateWithCertificates(pinnedCerts as CFArray, SecPolicyCreateSSL(true, "192.168.1.4" as CFString), &matchingTrust),
            errSecSuccess
        )
        let matchResult = PinnedTLSClient.evaluate(trust: try XCTUnwrap(matchingTrust), pinnedCertificates: pinnedCerts)
        if case let .failure(err) = matchResult {
            XCTFail("Expected pinned 10-year self-signed leaf to be accepted, got: \(err)")
        }

        var wrongTrust: SecTrust?
        XCTAssertEqual(
            SecTrustCreateWithCertificates(otherCerts as CFArray, SecPolicyCreateSSL(true, "192.168.1.4" as CFString), &wrongTrust),
            errSecSuccess
        )
        let wrongResult = PinnedTLSClient.evaluate(trust: try XCTUnwrap(wrongTrust), pinnedCertificates: pinnedCerts)
        if case .success = wrongResult {
            XCTFail("Expected mismatched certificate to be rejected")
        }
    }
    #endif

    func testGenericProfileDecodingAndDirectTokenMint() async throws {
        let json = """
        {
          "version": 1,
          "name": "Production Vault",
          "openbao": {
            "address": "https://vault.example.com:8200",
            "jwt_auth": {
              "mount": "jwt-mobile",
              "role": "ops",
              "issuer": "bao-granter",
              "audience": "openbao-granter",
              "subject": "alice"
            },
            "token_roles": { "local": "ops-grant" },
            "policies": {
              "read": "prod-read",
              "write": "prod-write",
              "key_prefix": "prod-key-",
              "key_write_suffix": "-rw"
            },
            "max_hours": 8,
            "keys": [{ "name": "signing", "item": "signing" }]
          }
        }
        """
        let profile = try BaoProfile.decode(from: Data(json.utf8))
        XCTAssertEqual(profile.displayName, "Production Vault")
        XCTAssertFalse(profile.hasRemoteTarget)
        XCTAssertFalse(profile.supportsPushTokens)

        let req = try GrantRequest.parse(requestString: "HOURS=4 WRITE=1 KEYS=signing WHY=deploy", target: .mac, profile: profile)
        XCTAssertEqual(req.openBaoPolicies(profile: profile), ["prod-read", "prod-write", "prod-key-signing", "prod-key-signing-rw"])

        var capturedBody: [String: Any]?
        let transport = MockHTTPTransport { request in
            switch request.url?.path {
            case "/v1/auth/jwt-mobile/login":
                return (200, Data(#"{"auth":{"client_token":"s.granter"}}"#.utf8))
            case "/v1/auth/token/create/ops-grant":
                if let body = request.httpBody {
                    capturedBody = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
                }
                return grantResponse(request, token: "s.directtoken")
            case "/v1/auth/token/revoke-self":
                return (204, Data())
            default:
                return (404, Data())
            }
        }
        let openbao = OpenBaoClient(baseURL: URL(string: profile.openbao.address)!, transport: transport)
        let orchestrator = GrantOrchestrator(
            profile: profile,
            signer: EphemeralP256Signer(deviceName: "iphone"),
            openbao: openbao,
            via: "app"
        )
        let outcome = try await orchestrator.mintDirectToken(req)
        XCTAssertEqual(outcome.mintedToken, "s.directtoken")
        XCTAssertEqual(capturedBody?["policies"] as? [String], ["prod-read", "prod-write", "prod-key-signing", "prod-key-signing-rw"])
    }

    func testDynamicCustomPolicyCatalogAndMultiProfileStore() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("baogrant-multi-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let legacyStore = FileProfileStore(url: dir.appendingPathComponent("profile.json"))
        let homelab = makeFixtureProfile()
        try legacyStore.save(homelab)

        // MultiProfileStore migrates legacy profile.json automatically.
        let multi = MultiProfileStore(url: dir.appendingPathComponent("profiles.json"), legacyStore: legacyStore)
        var collection = multi.load()
        XCTAssertEqual(collection.profiles.count, 1)
        XCTAssertEqual(collection.activeProfileID, homelab.id)

        // Second server with custom dynamic policy catalog.
        let prodJSON = """
        {
          "version": 1,
          "name": "Prod",
          "openbao": {
            "address": "https://bao.prod.internal:8200",
            "jwt_auth": {
              "mount": "jwt-granter",
              "role": "ops",
              "issuer": "bao-granter",
              "audience": "openbao-granter",
              "subject": "alice"
            },
            "grant_policies": [
              { "name": "db-readonly", "label": "DB Read-Only", "default_selected": true },
              { "name": "k8s-deploy", "label": "Kubernetes Deploy", "description": "Roll out workloads", "elevated": true }
            ]
          }
        }
        """
        let prod = try BaoProfile.decode(from: Data(prodJSON.utf8))
        XCTAssertTrue(prod.openbao.usesCustomPolicies)
        collection.profiles.append(prod)
        collection.activeProfileID = prod.id
        try multi.save(collection)

        let reloaded = multi.load()
        XCTAssertEqual(reloaded.profiles.count, 2)
        XCTAssertEqual(reloaded.activeProfileID, prod.id)

        // Deep-link profile routing + custom POLICIES= parsing + elevated detection.
        let url = try XCTUnwrap(URL(string: "baobuddy://grant?profile=Prod&r=HOURS%3D1%20POLICIES%3Ddb-readonly,k8s-deploy%20WHY%3Drelease"))
        XCTAssertEqual(GrantRequest.profileSelector(from: url), "Prod")
        let req = try GrantRequest.parse(url: url, profile: prod)
        XCTAssertEqual(req.openBaoPolicies(profile: prod), ["db-readonly", "k8s-deploy"])
        XCTAssertTrue(req.isElevated(profile: prod))
        XCTAssertEqual(req.canonicalText, "HOURS=1 POLICIES=db-readonly,k8s-deploy WHY=release")

        let readOnlyReq = try GrantRequest.parse(requestString: "HOURS=1 POLICIES=db-readonly", target: .mac, profile: prod)
        XCTAssertFalse(readOnlyReq.isElevated(profile: prod))

        XCTAssertThrowsError(try GrantRequest.parse(requestString: "HOURS=1 POLICIES=root-admin", target: .mac, profile: prod))
    }

    func testPersonalTokenPromptNamesFullScope() async throws {
        let profile = makeFixtureProfile()
        let signer = EphemeralP256Signer(deviceName: "mac")
        var capturedPolicies: [String]?
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-granter/login":
                return (200, Data(#"{"auth":{"client_token":"s.granter1"}}"#.utf8))
            case "/v1/auth/token/create/grant":
                if let body = req.httpBody,
                   let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any] {
                    capturedPolicies = obj["policies"] as? [String]
                }
                return grantResponse(req, token: "s.personal")
            case "/v1/auth/token/revoke-self":
                return (204, Data())
            default:
                return (404, Data())
            }
        }
        let openbao = OpenBaoClient(baseURL: URL(string: profile.openbao.address)!, transport: transport)
        let orchestrator = GrantOrchestrator(profile: profile, signer: signer, openbao: openbao, via: "mac")

        let token = try await orchestrator.mintPersonalToken(why: "bao kv get")
        XCTAssertEqual(token, "s.personal")
        XCTAssertEqual(capturedPolicies, [
            "app-read", "app-write",
            "key-talos", "key-talos-write",
            "key-pbs", "key-pbs-write",
        ])
        XCTAssertEqual(
            signer.lastReason,
            "15-minute token — Print token to the program that asked on 192.168.1.4:8200: Read and write secrets; keys: talos, pbs — bao kv get"
        )
    }

    func testRevokeSelfThrowsWhenServerRejects() async throws {
        let transport = MockHTTPTransport { _ in
            (503, Data(#"{"errors":["sealed"]}"#.utf8))
        }
        let openbao = OpenBaoClient(baseURL: URL(string: "https://bao.example")!, transport: transport)
        do {
            try await openbao.revokeSelf(token: "s.live")
            XCTFail("Expected revokeSelf to throw")
        } catch {
            XCTAssertEqual(error as? OpenBaoError, .httpError(503, "sealed"))
        }
    }

    func testCheckHealthParsesUnsealedAndSealedResponses() async throws {
        let unsealed = OpenBaoClient(
            baseURL: URL(string: "https://bao.example")!,
            transport: MockHTTPTransport { _ in
                (200, Data(#"{"initialized":true,"sealed":false,"version":"2.7.2"}"#.utf8))
            }
        )
        let ok = try await unsealed.checkHealth()
        XCTAssertEqual(ok, ServerHealth(initialized: true, sealed: false, version: "2.7.2"))

        let sealed = OpenBaoClient(
            baseURL: URL(string: "https://bao.example")!,
            transport: MockHTTPTransport { _ in
                (503, Data(#"{"initialized":true,"sealed":true,"version":"2.7.2"}"#.utf8))
            }
        )
        let locked = try await sealed.checkHealth()
        XCTAssertEqual(locked, ServerHealth(initialized: true, sealed: true, version: "2.7.2"))
    }

    func testServerAdminBootstrapAndDeviceLifecycle() async throws {
        let keyA = P256.Signing.PrivateKey().publicKey
        let keyB = P256.Signing.PrivateKey().publicKey
        var mounted = false
        var storedPubKeys: [String] = []
        var capturedPolicyHCL = ""
        var capturedRoleBody: [String: Any] = [:]

        let transport = MockHTTPTransport { req in
            let path = req.url?.path ?? ""
            let bodyObj = req.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
            switch (req.httpMethod, path) {
            case ("GET", "/v1/sys/policies/acl/granter-alice"):
                return (404, Data())
            case ("PUT", "/v1/sys/policies/acl/granter-alice"):
                capturedPolicyHCL = bodyObj["policy"] as? String ?? ""
                return (204, Data())
            case ("POST", "/v1/auth/token/roles/grant-alice"):
                return (204, Data())
            case ("GET", "/v1/sys/auth"):
                let payload = mounted ? #"{"data":{"jwt-alice/":{"type":"jwt"}}}"# : #"{"data":{}}"#
                return (200, Data(payload.utf8))
            case ("POST", "/v1/sys/auth/jwt-alice"):
                mounted = true
                return (204, Data())
            case ("GET", "/v1/auth/jwt-alice/config"):
                let data = try! JSONSerialization.data(withJSONObject: [
                    "data": ["bound_issuer": "bao-granter", "jwt_validation_pubkeys": storedPubKeys]
                ])
                return (200, data)
            case ("POST", "/v1/auth/jwt-alice/config"):
                storedPubKeys = bodyObj["jwt_validation_pubkeys"] as? [String] ?? []
                return (204, Data())
            case ("POST", "/v1/auth/jwt-alice/role/granter"):
                capturedRoleBody = bodyObj
                return (204, Data())
            case ("GET", "/v1/auth/token/roles/grant-alice"):
                return (200, Data(#"{"data":{"allowed_policies":["db-readonly","k8s-deploy"]}}"#.utf8))
            default:
                return (404, Data())
            }
        }

        let client = OpenBaoClient(baseURL: URL(string: "https://bao.example")!, transport: transport)
        let admin = BaoServerAdmin(client: client, adminToken: "s.admin")

        let steps = try await admin.bootstrap(ServerBootstrapOptions(
            subject: "alice",
            allowedPolicies: ["db-readonly", "k8s-deploy"],
            maxHours: 8,
            boundCIDRs: ["10.0.0.0/24"],
            initialPubKeys: [keyA.pemRepresentation]
        ))
        XCTAssertEqual(steps.count, 5)
        XCTAssertTrue(mounted)
        XCTAssertTrue(capturedPolicyHCL.contains("auth/token/create/grant-alice"))
        XCTAssertEqual(capturedRoleBody["bound_subject"] as? String, "alice")
        XCTAssertEqual(capturedRoleBody["bound_audiences"] as? [String], ["baobuddy://bao.example/auth/jwt-alice"])
        XCTAssertEqual(capturedRoleBody["token_bound_cidrs"] as? [String], ["10.0.0.0/24"])

        // Adding the same key again is idempotent; adding a second key preserves the first.
        let dup = try await admin.addDeviceKey(mount: "jwt-alice", pem: keyA.pemRepresentation)
        XCTAssertFalse(dup.added)
        XCTAssertEqual(dup.total, 1)

        let second = try await admin.addDeviceKey(mount: "jwt-alice", pem: keyB.pemRepresentation)
        XCTAssertTrue(second.added)
        XCTAssertEqual(second.total, 2)

        let listed = try await admin.listDeviceKeys(mount: "jwt-alice")
        XCTAssertEqual(listed.count, 2)

        let removed = try await admin.removeDeviceKey(mount: "jwt-alice", fingerprintPrefix: "sha256:\(second.key.fingerprint.prefix(12))")
        XCTAssertEqual(removed.removed.fingerprint, second.key.fingerprint)
        XCTAssertEqual(removed.remaining, 1)

        let policies = try await admin.readTokenRolePolicies(role: "grant-alice")
        XCTAssertEqual(policies, ["db-readonly", "k8s-deploy"])

        XCTAssertThrowsError(try BaoServerAdmin.validateP256PEM("not-a-pem"))
    }

    func testMacGrantDoesNotReportReplacementWhenOldRevokeFails() async throws {
        let profile = makeFixtureProfile()
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-granter/login":
                return (200, Data(#"{"auth":{"client_token":"s.granter1"}}"#.utf8))
            case "/v1/auth/token/create/grant":
                return grantResponse(req, token: "s.macnew")
            case "/v1/auth/token/revoke-self":
                let token = req.value(forHTTPHeaderField: "X-Vault-Token")
                return token == "s.macold" ? (403, Data(#"{"errors":["permission denied"]}"#.utf8)) : (204, Data())
            default:
                return (404, Data())
            }
        }
        let openbao = OpenBaoClient(baseURL: URL(string: profile.openbao.address)!, transport: transport)
        let macStore = MockMacGrantStore(initial: "s.macold")
        let orchestrator = GrantOrchestrator(
            profile: profile,
            signer: EphemeralP256Signer(deviceName: "mac"),
            openbao: openbao,
            macStore: macStore,
            via: "mac"
        )
        let req = try GrantRequest.parse(requestString: "HOURS=1", target: .mac, profile: profile)
        let outcome = try await orchestrator.execute(req)
        XCTAssertFalse(outcome.replacedOldGrant)
        XCTAssertEqual(macStore.stored, "s.macnew")
    }

    func testRemoteTargetRejectsSSHOptionInjection() throws {
        XCTAssertNoThrow(try BaoT3GranterConfig(host: "192.168.1.5", user: "granter").validateForSSH())
        XCTAssertNoThrow(try BaoT3GranterConfig(host: "t3-vm.lan", user: "granter").validateForSSH())

        let hostile: [BaoT3GranterConfig] = [
            BaoT3GranterConfig(host: "t3", user: "-oProxyCommand=open -a Calculator"),
            BaoT3GranterConfig(host: "-oProxyCommand=touch /tmp/x", user: "granter"),
            BaoT3GranterConfig(host: "t3 -v", user: "granter"),
            BaoT3GranterConfig(host: "t3", user: "granter\nx"),
            BaoT3GranterConfig(host: "t3", port: 0, user: "granter"),
        ]
        for config in hostile {
            XCTAssertThrowsError(try config.validateForSSH(), "expected rejection: \(config.user)@\(config.host):\(config.port)")
        }
    }

    func testDuplicatePolicyNamesDoNotCrashSummary() throws {
        let json = """
        {
          "version": 1,
          "openbao": {
            "address": "https://bao.example:8200",
            "jwt_auth": {
              "mount": "jwt-granter", "role": "ops", "issuer": "bao-granter",
              "audience": "openbao-granter", "subject": "alice"
            },
            "grant_policies": [
              { "name": "db-readonly", "label": "DB Read-Only", "default_selected": true },
              { "name": "db-readonly", "label": "Duplicate" }
            ]
          }
        }
        """
        XCTAssertThrowsError(try BaoProfile.decode(from: Data(json.utf8))) { error in
            XCTAssertEqual(error as? ProfileError, .duplicateName("policy", "db-readonly"))
        }
        // Stored profiles from older versions skip validation; they must still not crash.
        let profile = try JSONDecoder().decode(BaoProfile.self, from: Data(json.utf8))
        let req = try GrantRequest.parse(requestString: "HOURS=1", target: .mac, profile: profile)
        XCTAssertEqual(req.summary(profile: profile), "Token for this device on bao.example:8200 (1 hour): Policies: DB Read-Only [db-readonly]")
        XCTAssertEqual(profile.openbao.policyLabel(for: "db-readonly"), "DB Read-Only")
        XCTAssertEqual(profile.openbao.policyLabel(for: "unknown"), "unknown")
    }

    func testManagedAppConfigParsesMDMPoliciesAndProfiles() throws {
        let profileJSON = """
        {
          "id": "mdm-prod",
          "version": 1,
          "name": "Corp Vault",
          "openbao": {
            "address": "https://vault.corp.example:8200",
            "jwt_auth": {
              "mount": "jwt-granter",
              "role": "corp",
              "issuer": "bao-granter",
              "audience": "openbao-granter",
              "subject": "alice"
            }
          }
        }
        """
        let managed = ManagedAppConfig.parse(dictionary: [
            "disable_clipboard": true,
            "lock_profiles": true,
            "profile_json": profileJSON,
        ])
        XCTAssertTrue(managed.disableClipboard)
        XCTAssertTrue(managed.lockProfiles)
        XCTAssertEqual(managed.profiles.count, 1)
        XCTAssertEqual(managed.profiles[0].id, "mdm-prod")
        XCTAssertEqual(managed.profiles[0].displayName, "Corp Vault")
    }
}
