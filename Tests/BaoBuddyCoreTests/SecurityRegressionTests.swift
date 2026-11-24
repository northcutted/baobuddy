import CryptoKit
import Foundation
import XCTest
@testable import BaoBuddyCore

/// One test per security finding, so a regression names the finding it reopens.
final class SecurityRegressionTests: XCTestCase {
    private func profile(remote: Bool = false, catalog: [BaoBuddyPolicy] = [], githubTokenPath: String = "") -> BaoProfile {
        BaoProfile(
            version: 1,
            name: "Test",
            openbao: .init(
                address: "https://bao.example:8200",
                caPEM: "",
                jwtAuth: .init(mount: "jwt-alice", role: "alice", issuer: "bao-granter", audience: "openbao-granter", subject: "alice"),
                tokenRoles: .init(mac: "grant", t3: "grant-remote"),
                policies: .init(read: "app-read", write: "app-write", keyPrefix: "app-key-", keyWriteSuffix: "-write"),
                grantPolicies: catalog,
                maxHours: 12,
                keys: [.init(name: "Signing", item: "signing")],
                ssh: .init(role: "ops", hosts: [.init(name: "Docker", user: "root", principal: "root-docker")]),
                githubAppItem: "",
                githubTokenPath: githubTokenPath
            ),
            t3Granter: remote
                ? .init(name: "Agent VM", host: "10.0.0.5", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample")
                : .init(name: "", host: "")
        )
    }

    private func client(_ transport: MockHTTPTransport) -> OpenBaoClient {
        OpenBaoClient(baseURL: URL(string: "https://bao.example:8200")!, transport: transport)
    }

    // MARK: Minted tokens are checked against the approval

    func testGrantWithExtraPoliciesIsRevokedAndRejected() async throws {
        var revoked: [String] = []
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/create/grant":
                return grantResponse(req, token: "s.toomuch", extraPolicies: ["admin"])
            case "/v1/auth/token/revoke":
                let body = try? JSONSerialization.jsonObject(with: req.httpBody ?? Data()) as? [String: String]
                revoked.append(body?["token"] ?? "")
                return (204, Data())
            default:
                return (204, Data())
            }
        }
        let orchestrator = GrantOrchestrator(profile: profile(), signer: EphemeralP256Signer(), openbao: client(transport), via: "app")
        let request = GrantRequest(target: .mac, hours: 1)
        do {
            _ = try await orchestrator.mintDirectToken(request)
            XCTFail("expected a mismatch")
        } catch let OpenBaoError.grantMismatch(detail) {
            XCTAssertTrue(detail.contains("admin"))
        }
        XCTAssertEqual(revoked, ["s.toomuch"])
    }

    func testRenewableGrantIsRejected() throws {
        let minted = MintedToken(token: "s.x", accessor: "a", policies: ["default", "app-read"], renewable: true, orphan: true, leaseDurationSeconds: 3600)
        XCTAssertThrowsError(try minted.verify(requestedPolicies: ["app-read"], maxTTLSeconds: 3600))
        let tooLong = MintedToken(token: "s.x", accessor: "a", policies: ["app-read"], renewable: false, orphan: true, leaseDurationSeconds: 7200)
        XCTAssertThrowsError(try tooLong.verify(requestedPolicies: ["app-read"], maxTTLSeconds: 3600))
        let child = MintedToken(token: "s.x", accessor: "a", policies: ["app-read"], renewable: false, orphan: false, leaseDurationSeconds: 3600)
        XCTAssertThrowsError(try child.verify(requestedPolicies: ["app-read"], maxTTLSeconds: 3600))
        let good = MintedToken(token: "s.x", accessor: "a", policies: ["default", "app-read"], renewable: false, orphan: true, leaseDurationSeconds: 3600)
        XCTAssertNoThrow(try good.verify(requestedPolicies: ["app-read"], maxTTLSeconds: 3600))
    }

    // MARK: No live token is left without an owner

    func testLocalGrantIsRevokedWhenKeychainWriteFails() async throws {
        var revoked: [String] = []
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/create/grant":
                return grantResponse(req, token: "s.orphaned")
            case "/v1/auth/token/revoke":
                let body = try? JSONSerialization.jsonObject(with: req.httpBody ?? Data()) as? [String: String]
                revoked.append(body?["token"] ?? "")
                return (204, Data())
            default:
                return (204, Data())
            }
        }
        let store = MockMacGrantStore()
        store.failWrites = true
        let orchestrator = GrantOrchestrator(profile: profile(), signer: EphemeralP256Signer(), openbao: client(transport), macStore: store, via: "mac")
        await XCTAssertThrowsErrorAsync(try await orchestrator.execute(GrantRequest(target: .mac, hours: 1)))
        XCTAssertEqual(revoked, ["s.orphaned"])
    }

    func testPushTokenIsRevokedWhenRemoteInstallFails() async throws {
        var githubDeletes = 0
        let github = MockHTTPTransport { req in
            if req.httpMethod == "DELETE", req.url?.path == "/installation/token" {
                githubDeletes += 1
                XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer ghs_pushtoken")
            }
            return (204, Data())
        }
        var pluginCalled = false
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/create/grant-remote":
                return grantResponse(req, token: "s.remote")
            case "/v1/github/token/push":
                pluginCalled = true
                return (200, Data(#"{"data":{"token":"ghs_pushtoken","expires_at":"2099-01-01T00:00:00Z"}}"#.utf8))
            default:
                return (204, Data())
            }
        }
        let granter = MockT3Granter()
        granter.installShouldFail = true
        let orchestrator = GrantOrchestrator(
            profile: profile(remote: true, githubTokenPath: "github/token/push"),
            signer: EphemeralP256Signer(),
            openbao: client(transport),
            github: GitHubPushTokenClient(transport: github),
            t3Granter: granter,
            via: "app",
            onRemoteGrantMinted: { _, _ in }
        )
        await XCTAssertThrowsErrorAsync(try await orchestrator.execute(GrantRequest(target: .t3, hours: 1, push: true)))
        XCTAssertTrue(pluginCalled, "push tokens come from the server-side endpoint, not a client-held App key")
        XCTAssertEqual(githubDeletes, 1)
    }

    func testServerSideGitHubTokenCapsExpiryAtOneHour() async throws {
        let transport = MockHTTPTransport { _ in
            (200, Data(#"{"data":{"token":"ghs_abc"}}"#.utf8))
        }
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let line = try await client(transport).mintGitHubToken(authToken: "s.x", path: "github/token/push", now: now)
        XCTAssertEqual(line, "1800003600 ghs_abc")
    }

    // MARK: Remote grants can be revoked without trusting the remote host

    func testRemoteGrantRevokesByAccessorThroughOpenBao() async throws {
        var revokedAccessor: String?
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/revoke-accessor":
                let body = try? JSONSerialization.jsonObject(with: req.httpBody ?? Data()) as? [String: String]
                revokedAccessor = body?["accessor"]
                return (204, Data())
            default:
                return (204, Data())
            }
        }
        let orchestrator = GrantOrchestrator(profile: profile(remote: true), signer: EphemeralP256Signer(), openbao: client(transport), via: "app")
        try await orchestrator.revokeRemoteGrant(accessor: "acc-123")
        XCTAssertEqual(revokedAccessor, "acc-123")
    }

    func testRemoteGrantOutcomeCarriesAccessor() async throws {
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/create/grant-remote":
                return grantResponse(req, token: "s.remote")
            default:
                return (204, Data())
            }
        }
        let orchestrator = GrantOrchestrator(
            profile: profile(remote: true),
            signer: EphemeralP256Signer(),
            openbao: client(transport),
            t3Granter: MockT3Granter(),
            via: "app",
            onRemoteGrantMinted: { _, _ in }
        )
        let outcome = try await orchestrator.execute(GrantRequest(target: .t3, hours: 2))
        XCTAssertEqual(outcome.accessor, "acc-s.remote")
    }

    func testAccessorStoreExpiresEntries() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("accessors-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = GrantAccessorStore(url: url)
        try store.record(profileID: "p1", accessor: "acc", expiresAt: Date().addingTimeInterval(60))
        XCTAssertEqual(store.entry(profileID: "p1")?.accessor, "acc")
        XCTAssertNil(store.entry(profileID: "p1", now: Date().addingTimeInterval(120)))
    }

    // MARK: The JWT records the approved scope

    func testSignInJWTCarriesApprovedScope() async throws {
        var scope: String?
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                let body = try? JSONSerialization.jsonObject(with: req.httpBody ?? Data()) as? [String: String]
                let payload = body?["jwt"]?.split(separator: ".").dropFirst().first.map(String.init) ?? ""
                let claims = Base64URL.decode(payload).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                scope = claims?["scope"] as? String
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/create/grant":
                return grantResponse(req, token: "s.direct")
            default:
                return (204, Data())
            }
        }
        let orchestrator = GrantOrchestrator(profile: profile(), signer: EphemeralP256Signer(), openbao: client(transport), via: "app")
        _ = try await orchestrator.mintDirectToken(GrantRequest(target: .mac, hours: 3, write: true, why: "deploy"))
        // A direct token leaves BaoBuddy, so its scope says so.
        XCTAssertEqual(scope, "DIRECT=1 HOURS=3 WRITE=1 WHY=deploy")
    }

    // MARK: Deep links can't invent policies

    func testDeepLinkCannotNamePoliciesWithoutCatalog() throws {
        let url = try XCTUnwrap(URL(string: "baobuddy://grant?r=HOURS%3D1%20POLICIES%3Droot"))
        XCTAssertThrowsError(try GrantRequest.parse(url: url, profile: profile())) { error in
            XCTAssertEqual(error as? GrantRequestError, .policiesNeedCatalog)
        }
        // Typed CLI input may still name policies directly.
        let typed = try GrantRequest.parse(requestString: "HOURS=1 POLICIES=custom-a", target: .mac, profile: profile())
        XCTAssertEqual(typed.customPolicies, ["custom-a"])
    }

    func testListValuesMatchCaseInsensitively() throws {
        let request = try GrantRequest.parse(requestString: "KEYS=signing SSH=DOCKER", target: .t3, profile: profile(remote: true))
        XCTAssertEqual(request.keys, ["Signing"])
        XCTAssertEqual(request.sshHosts, ["Docker"])
    }

    func testPromptShowsPolicyNameBehindMisleadingLabel() throws {
        let catalog = [BaoBuddyPolicy(name: "root-admin", label: "Read only", defaultSelected: true)]
        let p = profile(catalog: catalog)
        let request = GrantRequest(target: .mac, hours: 1)
        XCTAssertEqual(request.scopeDescription(profile: p), "Policies: Read only [root-admin]")
    }

    // MARK: Profile validation

    private func json(address: String = "https://bao.example", name: String = "Prod", remote: String = "") -> Data {
        Data("""
        {"version":1,"name":"\(name)","openbao":{"address":"\(address)","jwt_auth":{"mount":"jwt-a","role":"a","issuer":"i","audience":"aud","subject":"a"}}\(remote)}
        """.utf8)
    }

    func testPlainHTTPIsRejectedExceptLoopback() throws {
        XCTAssertThrowsError(try BaoProfile.decode(from: json(address: "http://bao.example:8200")))
        XCTAssertNoThrow(try BaoProfile.decode(from: json(address: "http://127.0.0.1:8200")))
    }

    func testBidiOverrideInProfileNameIsRejected() throws {
        XCTAssertThrowsError(try BaoProfile.decode(from: json(name: "Prod\\u202Eevil")))
    }

    func testRemoteTargetNeedsPinnedHostKeyOnImport() throws {
        let remote = #","remote_target":{"host":"10.0.0.5","user":"granter"}"#
        XCTAssertThrowsError(try BaoProfile.decode(from: json(remote: remote))) { error in
            XCTAssertEqual(error as? ProfileError, .missingHostKey)
        }
        // Already-saved profiles still load, so local grants keep working.
        XCTAssertNoThrow(try BaoProfile.decode(from: json(remote: remote), requireHostKey: false))
    }

    func testMDMDropsInvalidProfiles() {
        let managed = ManagedAppConfig.parse(dictionary: [
            "profiles_json": "[{\"version\":1,\"openbao\":{\"address\":\"http://bao.example\",\"jwt_auth\":{\"mount\":\"m\",\"role\":\"r\",\"issuer\":\"i\",\"audience\":\"a\",\"subject\":\"s\"}}}]"
        ])
        XCTAssertTrue(managed.profiles.isEmpty)
    }

    func testUnreadableProfilesFileIsMovedAsideNotOverwritten() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("profiles-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("profiles.json")
        try Data("{ from a future version".utf8).write(to: url)
        let store = MultiProfileStore(url: url, legacyStore: FileProfileStore(url: dir.appendingPathComponent("profile.json")))
        XCTAssertTrue(store.load().profiles.isEmpty)
        let backups = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.contains("unreadable") }
        XCTAssertEqual(backups.count, 1)
    }

    func testTokenRolesAreWrittenWithGenericNames() throws {
        let data = try JSONEncoder().encode(BaoTokenRolesConfig(mac: "grant", t3: "grant-remote"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: String])
        XCTAssertEqual(object, ["local": "grant", "remote": "grant-remote"])
    }

    // MARK: Server bootstrap

    func testGranterPolicyHasNoSudoAndCanRevokeByAccessor() {
        let hcl = BaoServerAdmin.granterPolicyHCL(tokenRole: "grant", sshSignPath: "ssh/sign/ops", githubTokenPath: "github/token/push")
        XCTAssertFalse(hcl.contains("sudo"))
        XCTAssertTrue(hcl.contains(#"path "auth/token/revoke-accessor""#))
        XCTAssertTrue(hcl.contains(#"path "auth/token/revoke-self""#))
        XCTAssertTrue(hcl.contains(#"path "github/token/push""#))
        XCTAssertFalse(hcl.contains("data/"), "the granter never reads secrets")
    }

    func testLoginRoleTightensJWTLeewayAndRecordsScope() {
        let body = BaoServerAdmin.loginRoleBody(subject: "alice", audience: "aud", granterPolicyName: "granter", boundCIDRs: [])
        XCTAssertEqual(body["expiration_leeway"] as? Int, 5)
        XCTAssertEqual(body["clock_skew_leeway"] as? Int, 5)
        XCTAssertEqual(body["token_no_default_policy"] as? Bool, true)
        XCTAssertEqual((body["claim_mappings"] as? [String: String])?["scope"], "scope")
    }

    func testBootstrapRefusesMountThatBelongsToAnotherSubject() async throws {
        var wrote = false
        let transport = MockHTTPTransport { req in
            if req.httpMethod == "POST" || req.httpMethod == "PUT" { wrote = true }
            switch (req.httpMethod, req.url?.path) {
            case ("GET", "/v1/sys/auth"):
                return (200, Data(#"{"data":{"jwt-granter/":{"type":"jwt"}}}"#.utf8))
            case ("LIST", "/v1/auth/jwt-granter/role"):
                return (200, Data(#"{"data":{"keys":["bob"]}}"#.utf8))
            case ("GET", "/v1/auth/jwt-granter/role/bob"):
                return (200, Data(#"{"data":{"bound_subject":"bob"}}"#.utf8))
            default:
                return (404, Data())
            }
        }
        let admin = BaoServerAdmin(client: client(transport), adminToken: "s.admin")
        do {
            _ = try await admin.bootstrap(ServerBootstrapOptions(mount: "jwt-granter", role: "alice", subject: "alice", allowedPolicies: ["db-read"]))
            XCTFail("expected sharedMount")
        } catch let ServerAdminError.sharedMount(_, otherRole, otherSubject) {
            XCTAssertEqual(otherRole, "bob")
            XCTAssertEqual(otherSubject, "bob")
        }
        XCTAssertFalse(wrote, "nothing may be written before the ownership check passes")
    }

    func testAddingDeviceNeverWipesKeysWhenConfigReadFails() async throws {
        var wroteConfig = false
        let transport = MockHTTPTransport { req in
            if req.httpMethod == "POST", req.url?.path == "/v1/auth/jwt-a/config" { wroteConfig = true }
            return req.httpMethod == "GET" ? (503, Data(#"{"errors":["sealed"]}"#.utf8)) : (204, Data())
        }
        let admin = BaoServerAdmin(client: client(transport), adminToken: "s.admin")
        let pem = P256.Signing.PrivateKey().publicKey.pemRepresentation
        await XCTAssertThrowsErrorAsync(try await admin.addDeviceKey(mount: "jwt-a", pem: pem))
        XCTAssertFalse(wroteConfig)
    }

    func testAddingDeviceKeepsKeysItCantParseAndOtherSettings() async throws {
        let existing = P256.Signing.PrivateKey().publicKey.pemRepresentation
        let rsaLike = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----"
        var written: [String: Any]?
        let transport = MockHTTPTransport { req in
            if req.httpMethod == "GET" {
                let data: [String: Any] = [
                    "jwt_validation_pubkeys": [existing, rsaLike],
                    "bound_issuer": "corp",
                    "jwt_supported_algs": ["RS256"],
                    "default_role": "ops"
                ]
                return (200, try JSONSerialization.data(withJSONObject: ["data": data]))
            }
            written = try JSONSerialization.jsonObject(with: req.httpBody ?? Data()) as? [String: Any]
            return (204, Data())
        }
        let admin = BaoServerAdmin(client: client(transport), adminToken: "s.admin")
        let newKey = P256.Signing.PrivateKey().publicKey.pemRepresentation
        let result = try await admin.addDeviceKey(mount: "jwt-a", pem: newKey)
        XCTAssertTrue(result.added)
        let keys = written?["jwt_validation_pubkeys"] as? [String] ?? []
        XCTAssertEqual(keys.count, 3)
        XCTAssertTrue(keys.contains(rsaLike))
        XCTAssertEqual(written?["bound_issuer"] as? String, "corp")
        XCTAssertEqual(written?["default_role"] as? String, "ops")
        XCTAssertEqual(Set(written?["jwt_supported_algs"] as? [String] ?? []), ["RS256", "ES256"])
    }

    // MARK: macOS ssh hardening

    #if os(macOS)
    func testLegacySSHIgnoresUserConfigAndRefusesUnpinnedHosts() throws {
        let pinned = MacSSHGranterClient(config: profile(remote: true).t3Granter, identityPath: "/tmp/id")
        let args = try pinned.sshArguments(command: "status", knownHostsPath: "/tmp/kh")
        XCTAssertEqual(Array(args.prefix(2)), ["-F", "/dev/null"])
        for option in ["ForwardAgent=no", "StrictHostKeyChecking=yes", "GlobalKnownHostsFile=/dev/null", "ClearAllForwardings=yes", "IdentityAgent=none"] {
            XCTAssertTrue(args.contains(option), option)
        }
        XCTAssertEqual(Array(args.suffix(3)), ["--", "granter@10.0.0.5", "status"])
        XCTAssertEqual(try pinned.knownHostsLine(), "10.0.0.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample")

        var unpinned = profile(remote: true).t3Granter
        unpinned.hostKey = ""
        XCTAssertThrowsError(try MacSSHGranterClient(config: unpinned).knownHostsLine())
    }

    // MARK: - Pre-publication security review regressions (Findings 1–15)

    // Finding 1: Two remote targets on one profile isolate grant accessors and preserve multiple live grants.
    func testTwoRemoteTargetsIsolateAccessorsAndPreserveMultipleGrants() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("accessors-multi-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let store = GrantAccessorStore(url: url)

        let targetA = BaoT3GranterConfig(name: "Staging", host: "10.0.0.10", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA")
        let targetB = BaoT3GranterConfig(name: "Prod", host: "10.0.0.20", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB")
        var base = profile(remote: true)
        base.id = "shared-profile"
        base.remoteTargets = [targetA, targetB]
        let focusedA = base.focusing(remoteTarget: targetA)
        let focusedB = base.focusing(remoteTarget: targetB)

        let future = Date().addingTimeInterval(3600)
        try store.record(for: focusedA, accessor: "acc-a1", expiresAt: future)
        try store.record(for: focusedA, accessor: "acc-a2", expiresAt: future)
        try store.record(for: focusedB, accessor: "acc-b1", expiresAt: future)

        XCTAssertEqual(try store.entries(for: focusedA).map(\.accessor), ["acc-a1", "acc-a2"])
        XCTAssertEqual(try store.entries(for: focusedB).map(\.accessor), ["acc-b1"])

        // Revoking Target A must NOT touch Target B's accessor.
        try store.removeAll(for: focusedA)
        XCTAssertTrue(try store.entries(for: focusedA).isEmpty)
        XCTAssertEqual(try store.entries(for: focusedB).map(\.accessor), ["acc-b1"])

        // Legacy untargeted profileID entries must NEVER apply to a multi-target profile.
        try store.record(profileID: base.id, accessor: "acc-legacy", expiresAt: future)
        XCTAssertEqual(try store.entries(for: focusedA), [])
        XCTAssertEqual(try store.entries(for: focusedB).map(\.accessor), ["acc-b1"])
        XCTAssertEqual(try store.pendingLegacyEntries(profileID: base.id).map(\.accessor), ["acc-legacy"])
    }

    // Finding 2: Two servers get distinct Secure Enclave trust-domain accounts and origin+mount-bound JWT audiences.
    func testTwoServersHaveDistinctTrustDomainKeysAndBoundAudiences() async throws {
        var serverA = profile()
        serverA.openbao.address = "https://vault-a.example:8200"
        serverA.openbao.jwtAuth.mount = "jwt-alice"
        serverA.openbao.jwtAuth.audience = BaoServerAdmin.defaultAudience(
            address: serverA.openbao.address,
            namespace: "prod",
            mount: "jwt-alice"
        )
        serverA.openbao.namespace = "prod"

        var serverB = profile()
        serverB.openbao.address = "https://vault-b.example:8200"
        serverB.openbao.jwtAuth.mount = "jwt-alice"
        serverB.openbao.namespace = "prod"
        // Malicious Server B profile attempts to declare Server A's audience.
        serverB.openbao.jwtAuth.audience = serverA.openbao.jwtAuth.audience

        XCTAssertEqual(serverA.openbao.jwtAuth.audience, "baobuddy://vault-a.example:8200/ns/prod/auth/jwt-alice")
        XCTAssertNotEqual(
            SecureEnclaveKeyStore.accountName(for: serverA),
            SecureEnclaveKeyStore.accountName(for: serverB)
        )
        XCTAssertNoThrow(try JWTSigner.validateAudience(for: serverA))
        XCTAssertThrowsError(try JWTSigner.validateAudience(for: serverB))

        // Orchestrator refuses to sign or transmit a JWT when a baobuddy:// audience targets another server.
        var loginCalled = false
        let transport = MockHTTPTransport { _ in
            loginCalled = true
            return (200, Data())
        }
        let orchestrator = GrantOrchestrator(
            profile: serverB,
            signer: EphemeralP256Signer(),
            openbao: OpenBaoClient(baseURL: URL(string: serverB.openbao.address)!, transport: transport),
            via: "mac"
        )
        await XCTAssertThrowsErrorAsync(try await orchestrator.mintDirectToken(GrantRequest(target: .mac, hours: 1)))
        XCTAssertFalse(loginCalled, "must not sign or send JWT for mismatched baobuddy:// audience")
    }

    // Finding 3: Admin/export endpoint validation refuses non-loopback HTTP and unpinned TLS before sending any token.
    func testAdminClientValidationRejectsInsecureTransportBeforeSendingToken() throws {
        var transportBuilt = false
        XCTAssertThrowsError(
            try BaoServerAdmin.makeValidatedClient(
                address: "http://vault.remote.example:8200",
                transportFactory: { _, _ in
                    transportBuilt = true
                    return MockHTTPTransport { _ in (200, Data()) }
                }
            )
        )
        XCTAssertFalse(transportBuilt, "non-loopback http:// must fail before constructing transport or sending admin token")

        XCTAssertThrowsError(
            try BaoServerAdmin.makeValidatedClient(
                address: "https://vault.remote.example:8200",
                caPEM: "",
                enforceTLSPinning: true,
                transportFactory: { _, _ in
                    transportBuilt = true
                    return MockHTTPTransport { _ in (200, Data()) }
                }
            )
        )
        XCTAssertFalse(transportBuilt, "missing CA pin under enforceTLSPinning must fail before sending admin token")

        // Loopback http:// remains allowed for local dev servers.
        let loopback = try BaoServerAdmin.makeValidatedClient(
            address: "http://127.0.0.1:8200",
            transportFactory: { _, _ in MockHTTPTransport { _ in (200, Data()) } }
        )
        XCTAssertEqual(loopback.baseURL.host, "127.0.0.1")
    }

    // Finding 4: Two operators get isolated default token roles & granter policies, and bootstrap refuses collisions.
    func testTwoOperatorsGetIsolatedDefaultsAndRefuseSharedRoleOrPolicy() async throws {
        let aliceOpts = ServerBootstrapOptions(subject: "alice", allowedPolicies: ["app-read"])
        let bobOpts = ServerBootstrapOptions(subject: "bob", allowedPolicies: ["prod-admin"])
        XCTAssertEqual(aliceOpts.mount, "jwt-alice")
        XCTAssertEqual(aliceOpts.tokenRole, "grant-alice")
        XCTAssertEqual(aliceOpts.granterPolicyName, "granter-alice")
        XCTAssertEqual(bobOpts.mount, "jwt-bob")
        XCTAssertEqual(bobOpts.tokenRole, "grant-bob")
        XCTAssertEqual(bobOpts.granterPolicyName, "granter-bob")

        // Attempting to configure Bob with Alice's token role must be refused BEFORE any write.
        var wrote = false
        let transport = MockHTTPTransport { req in
            if req.httpMethod == "POST" || req.httpMethod == "PUT" { wrote = true }
            switch (req.httpMethod, req.url?.path) {
            case ("GET", "/v1/sys/auth"):
                return (200, Data(#"{"data":{"jwt-alice/":{"type":"jwt"}}}"#.utf8))
            case ("LIST", "/v1/auth/jwt-alice/role"):
                return (200, Data(#"{"data":{"keys":["granter"]}}"#.utf8))
            case ("GET", "/v1/auth/jwt-alice/role/granter"):
                return (200, Data(#"{"data":{"bound_subject":"alice","token_policies":["granter-alice"]}}"#.utf8))
            case ("GET", "/v1/sys/policies/acl/granter-alice"):
                let hcl = BaoServerAdmin.granterPolicyHCL(tokenRole: "grant-alice")
                let body = try! JSONSerialization.data(withJSONObject: ["data": ["policy": hcl]])
                return (200, body)
            case ("GET", "/v1/sys/policies/acl/granter-bob"):
                return (404, Data())
            default:
                return (404, Data())
            }
        }
        let admin = BaoServerAdmin(client: client(transport), adminToken: "s.admin")

        // Case A: Bob tries to reuse Alice's token role (`grant-alice`).
        do {
            _ = try await admin.bootstrap(ServerBootstrapOptions(
                mount: "jwt-bob",
                subject: "bob",
                granterPolicyName: "granter-bob",
                tokenRole: "grant-alice",
                allowedPolicies: ["prod-admin"]
            ))
            XCTFail("expected sharedTokenRole error")
        } catch let ServerAdminError.sharedTokenRole(role, otherMount, otherSubject) {
            XCTAssertEqual(role, "grant-alice")
            XCTAssertEqual(otherMount, "jwt-alice")
            XCTAssertEqual(otherSubject, "alice")
        }
        XCTAssertFalse(wrote, "no OpenBao writes allowed when shared token role is detected")

        // Case B: Bob tries to reuse Alice's granter policy (`granter-alice`).
        do {
            _ = try await admin.bootstrap(ServerBootstrapOptions(
                mount: "jwt-bob",
                subject: "bob",
                granterPolicyName: "granter-alice",
                tokenRole: "grant-bob",
                allowedPolicies: ["prod-admin"]
            ))
            XCTFail("expected incompatibleGranterPolicy or sharedGranterPolicy error")
        } catch is ServerAdminError {
            // Expected rejection before any write.
        }
        XCTAssertFalse(wrote, "no OpenBao writes allowed when shared granter policy is detected")
    }

    // Finding 5: Two servers use distinct macOS Keychain services so Server A's bearer token is never sent to Server B.
    func testTwoServersHaveIsolatedMacKeychainServices() {
        var serverA = profile()
        serverA.openbao.address = "https://vault-a.example:8200"
        serverA.openbao.namespace = "ns-a"

        var serverB = profile()
        serverB.openbao.address = "https://vault-b.example:8200"
        serverB.openbao.namespace = "ns-a"

        var serverAOtherNS = serverA
        serverAOtherNS.openbao.namespace = "ns-b"

        let storeA = MacKeychainGrantStore(profile: serverA)
        let storeB = MacKeychainGrantStore(profile: serverB)
        let storeAOtherNS = MacKeychainGrantStore(profile: serverAOtherNS)

        XCTAssertNotEqual(storeA.service, storeB.service)
        XCTAssertNotEqual(storeA.artifactServiceName, storeB.artifactServiceName)
        XCTAssertNotEqual(storeA.service, storeAOtherNS.service)
        XCTAssertNotEqual(storeA.service, MacKeychainGrantStore.legacyService)
    }

    // Finding 6: Remote grant accessor is persisted BEFORE install and kept if rollback fails.
    func testRemoteGrantRecordsAccessorBeforeInstallAndRetainsOnFailedRollback() async throws {
        final class AccessorLog: @unchecked Sendable {
            private let lock = NSLock()
            var minted: [String] = []
            var rolledBack: [String] = []
            func addMinted(_ acc: String) { lock.lock(); minted.append(acc); lock.unlock() }
            func addRolledBack(_ acc: String) { lock.lock(); rolledBack.append(acc); lock.unlock() }
        }
        let log = AccessorLog()
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/create/grant-remote":
                return grantResponse(req, token: "s.remote-stuck")
            case "/v1/auth/token/revoke":
                return (503, Data(#"{"errors":["sealed"]}"#.utf8))
            default:
                return (204, Data())
            }
        }
        let granter = MockT3Granter()
        granter.installShouldFail = true
        let orchestrator = GrantOrchestrator(
            profile: profile(remote: true),
            signer: EphemeralP256Signer(),
            openbao: client(transport),
            t3Granter: granter,
            via: "mac",
            onRemoteGrantMinted: { accessor, _ in log.addMinted(accessor) },
            onRemoteGrantRolledBack: { accessor in log.addRolledBack(accessor) }
        )
        await XCTAssertThrowsErrorAsync(try await orchestrator.execute(GrantRequest(target: .t3, hours: 1)))
        XCTAssertEqual(log.minted, ["acc-s.remote-stuck"], "accessor must be persisted before delivery")
        XCTAssertTrue(log.rolledBack.isEmpty, "accessor must NOT be removed when rollback fails")
    }

    // Finding 7: MDM lock_profiles rejects local profiles in both resolver and GrantOrchestrator.enforce.
    func testMDMLockProfilesBlocksLocalProfilesInResolverAndOrchestrator() async throws {
        var managedProfile = profile()
        managedProfile.id = "corp-managed"
        managedProfile.name = "Corp Vault"

        var localProfile = profile()
        localProfile.id = "rogue-local"
        localProfile.name = "Personal"

        let policy = ManagedAppConfig(
            profiles: [managedProfile],
            disableClipboard: false,
            lockProfiles: true,
            enforceTLSPinning: false,
            requireReasonForElevated: false,
            isManaged: true
        )

        let effective = policy.effectiveProfiles(local: [localProfile])
        XCTAssertEqual(effective.map(\.id), ["corp-managed"])

        let localCollection = ProfileCollection(activeProfileID: "rogue-local", profiles: [localProfile])
        let resolvedDefault = try policy.resolveProfile(selector: nil, localCollection: localCollection)
        XCTAssertEqual(resolvedDefault.id, "corp-managed")
        XCTAssertThrowsError(try policy.resolveProfile(selector: "Personal", localCollection: localCollection))
        XCTAssertThrowsError(try policy.enforce(on: localProfile))

        let orchestrator = GrantOrchestrator(
            profile: localProfile,
            signer: EphemeralP256Signer(),
            openbao: client(MockHTTPTransport { _ in (200, Data()) }),
            via: "mac",
            organizationPolicy: policy
        )
        await XCTAssertThrowsErrorAsync(try await orchestrator.mintDirectToken(GrantRequest(target: .mac, hours: 1)))
    }

    // Finding 9: MCP fallback cli_command preserves --profile and --target; prompt shows server identity and namespace.
    func testMCPFallbackCommandIncludesProfileAndTargetAndPromptShowsServerIdentity() async throws {
        var p = profile(remote: true, catalog: [BaoBuddyPolicy(name: "db-read", label: "DB Read", defaultSelected: true)])
        p.name = "Staging"
        p.openbao.namespace = "team-a"
        let backend = MockMCPBackendForSecurity(profiles: [p])
        let mcp = BaoMCPServer(backend: backend)

        let reqLine = #"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"baobuddy_request_grant","arguments":{"profile":"Staging","target":"remote","hours":1,"policies":["db-read"],"why":"check","mode":"link_only"}}}"#
        let rawReply = await mcp.handleLine(reqLine)
        let reply = try XCTUnwrap(rawReply)
        let outer = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(reply.utf8)) as? [String: Any])
        let result = try XCTUnwrap(outer["result"] as? [String: Any])
        let content = try XCTUnwrap((result["content"] as? [[String: Any]])?.first?["text"] as? String)
        let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(content.utf8)) as? [String: Any])

        let cliCmd = try XCTUnwrap(payload["cli_command"] as? String)
        XCTAssertTrue(cliCmd.contains("--profile-id \(p.id)"), "expected exact --profile-id in \(cliCmd)")
        let targetID = p.t3Granter.id
        XCTAssertTrue(cliCmd.contains("--target-id '\(targetID)'"), "expected exact --target-id in \(cliCmd)")
        XCTAssertTrue(cliCmd.contains("--target-ssh \(p.t3Granter.sshDestination)"), "expected --target-ssh in \(cliCmd)")
        XCTAssertTrue(cliCmd.contains("--target-host-key-fp \(p.t3Granter.hostKeyFingerprint)"), "expected --target-host-key-fp in \(cliCmd)")

        let deepLinkStr = try XCTUnwrap(payload["deep_link"] as? String)
        XCTAssertTrue(deepLinkStr.contains("issuer_binding=\(p.openbao.issuerBindingKey)"), deepLinkStr)
        XCTAssertTrue(deepLinkStr.contains("remote_ssh="), deepLinkStr)
        XCTAssertTrue(deepLinkStr.contains("remote_host_key_fp=\(p.t3Granter.hostKeyFingerprint)"), deepLinkStr)

        let summary = try XCTUnwrap(payload["summary"] as? String)
        XCTAssertTrue(summary.contains("Staging"), "expected server name in \(summary)")
        XCTAssertTrue(summary.contains("bao.example:8200"), "expected host in \(summary)")
        XCTAssertTrue(summary.contains("ns: team-a"), "expected namespace in \(summary)")
    }

    // Finding 10: Shortened server token TTL caps SSH cert request and rejects an oversized SSH certificate.
    func testShortenedGrantCapsSSHCertTTLAndRejectsOversizedCert() async throws {
        var requestedSSHTTL: String?
        var revokedTokens: [String] = []
        let nowEpoch = UInt64(Date().timeIntervalSince1970)
        // Server shortens token lease to 600s (10m) even though 4h was requested, then returns a 4h SSH cert.
        let oversizedCert = OpenSSHCertificate.encodeSynthetic(
            principals: ["root-docker"],
            validAfter: nowEpoch - 30,
            validBefore: nowEpoch + 14400
        )
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/create/grant-remote":
                let payload = try! JSONSerialization.data(withJSONObject: [
                    "auth": [
                        "client_token": "s.short",
                        "accessor": "acc-short",
                        "policies": ["default", "app-read"],
                        "renewable": false,
                        "orphan": true,
                        "lease_duration": 600
                    ]
                ])
                return (200, payload)
            case "/v1/ssh/sign/ops":
                let body = req.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                requestedSSHTTL = body?["ttl"] as? String
                let payload = try! JSONSerialization.data(withJSONObject: ["data": ["signed_key": oversizedCert]])
                return (200, payload)
            case "/v1/auth/token/revoke":
                let body = req.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: String] }
                revokedTokens.append(body?["token"] ?? "")
                return (204, Data())
            default:
                return (204, Data())
            }
        }
        let granter = MockT3Granter()
        let orchestrator = GrantOrchestrator(
            profile: profile(remote: true),
            signer: EphemeralP256Signer(),
            openbao: client(transport),
            t3Granter: granter,
            via: "mac",
            now: { Date(timeIntervalSince1970: Double(nowEpoch)) },
            onRemoteGrantMinted: { _, _ in }
        )
        let req = GrantRequest(target: .t3, hours: 4, sshHosts: ["Docker"])
        do {
            _ = try await orchestrator.execute(req)
            XCTFail("expected oversized SSH certificate to be rejected")
        } catch let OpenBaoError.grantMismatch(detail) {
            XCTAssertTrue(detail.contains("grant deadline"), detail)
        }
        XCTAssertEqual(requestedSSHTTL, "600s", "SSH signing request must use effective server TTL")
        XCTAssertEqual(revokedTokens, ["s.short"], "grant must be revoked when SSH cert verification fails")
        XCTAssertNil(granter.installed, "oversized SSH cert must never be installed")
    }

    // Finding 11: Prompt, signed JWT scope, and import plan expose actual SSH signing role and principals.
    func testSSHPrincipalAndRoleShownInPromptSignedScopeAndImportPlan() throws {
        var p = profile(remote: true)
        p.openbao.ssh = BaoSSHConfig(
            role: "ops-ca",
            hosts: [.init(name: "web-readonly", user: "viewer", principal: "root")]
        )
        let req = GrantRequest(target: .t3, hours: 1, sshHosts: ["web-readonly"])
        let scopeDesc = req.scopeDescription(profile: p)
        XCTAssertTrue(scopeDesc.contains("role ops-ca"), scopeDesc)
        XCTAssertTrue(scopeDesc.contains("[principal: root]"), scopeDesc)

        let audit = req.auditScope(profile: p)
        XCTAssertTrue(audit.contains("SSH_ROLE=ops-ca"), audit)
        XCTAssertTrue(audit.contains("SSH_PRINCIPALS=root"), audit)

        var updated = p
        updated.openbao.ssh = BaoSSHConfig(
            role: "ops-ca",
            hosts: [.init(name: "web-readonly", user: "viewer", principal: "superadmin")]
        )
        let plan = try ProfileImportPlan.make(
            importing: updated,
            existing: [p],
            managedIDs: [],
            organizationPolicy: .empty
        )
        XCTAssertTrue(plan.changes.contains("SSH signing role / principals"))
        XCTAssertTrue(plan.notices.contains(where: { $0.contains("superadmin") }))
    }

    // Finding 12: Personal tokens enforce audit reason & ticket regex and carry DIRECT=1 + caller destination warning.
    func testPersonalTokenEnforcesReasonValidationAndMarksDirectScope() async throws {
        var p = profile()
        p.openbao.auditPolicy = BaoAuditPolicy(
            requireReason: true,
            requireReasonForElevated: true,
            reasonPattern: #"^INC-[0-9]+$"#,
            reasonPlaceholder: "INC-1234"
        )
        var capturedScope: String?
        var capturedOn: String?
        let transport = MockHTTPTransport { req in
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                let body = req.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: String] }
                let payload = body?["jwt"]?.split(separator: ".").dropFirst().first.map(String.init) ?? ""
                let claims = Base64URL.decode(payload).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                capturedScope = claims?["scope"] as? String
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/create/grant":
                let body = req.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                capturedOn = (body?["meta"] as? [String: String])?["on"]
                return grantResponse(req, token: "s.personal")
            default:
                return (204, Data())
            }
        }
        let signer = EphemeralP256Signer()
        let orchestrator = GrantOrchestrator(profile: p, signer: signer, openbao: client(transport), via: "mac")

        await XCTAssertThrowsErrorAsync(try await orchestrator.mintPersonalToken(why: ""))
        await XCTAssertThrowsErrorAsync(try await orchestrator.mintPersonalToken(why: "not-a-ticket"))

        let token = try await orchestrator.mintPersonalToken(why: "INC-99")
        XCTAssertEqual(token, "s.personal")
        XCTAssertTrue(capturedScope?.hasPrefix("DIRECT=1 MINUTES=15 ") == true, capturedScope ?? "")
        XCTAssertEqual(capturedOn, "direct")
        XCTAssertTrue(signer.lastReason?.contains("Print token to the program that asked") == true)
    }

    // Findings 14 & 15: System SSH process helper enforces timeout without hanging and rejects oversized output.
    func testBoundedProcessTerminatesOnTimeoutAndRejectsOversizedOutput() async throws {
        let start = Date()
        do {
            _ = try await MacSSHGranterClient.runBoundedProcess(
                executableURL: URL(fileURLWithPath: "/bin/sleep"),
                arguments: ["30"],
                command: "status",
                stdin: nil,
                timeoutSeconds: 0.25,
                maxOutputBytes: 1024
            )
            XCTFail("expected timeout")
        } catch T3GranterError.timedOut(let cmd) {
            XCTAssertEqual(cmd, "status")
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 5.0, "timeout must terminate child without hanging")

        do {
            _ = try await MacSSHGranterClient.runBoundedProcess(
                executableURL: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "head -c 8192 /dev/zero | tr '\\0' A"],
                command: "status",
                stdin: nil,
                timeoutSeconds: 5.0,
                maxOutputBytes: 1024
            )
            XCTFail("expected outputLimitExceeded")
        } catch T3GranterError.outputLimitExceeded(let cmd, let limit) {
            XCTAssertEqual(cmd, "status")
            XCTAssertEqual(limit, 1024)
        }
    }
    #endif

    // MARK: - Second-pass blocker regressions

    // Blocker 1: Legacy unbound accessors are never inferred onto today's single target; concurrent writes never lose updates; corrupt state fails closed; missing/failing persistence or empty accessor blocks delivery and revokes the minted token.
    func testLegacyAccessorNeverInferredOntoChangedSingleTargetAndCorruptStateFailsClosed() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("acc-legacy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("remote-grants.json")
        let store = GrantAccessorStore(url: url)

        var single = profile(remote: true)
        single.id = "single-prof"
        let future = Date().addingTimeInterval(3600)

        // Legacy unbound entry recorded under profileID only (e.g. before target host changed).
        try store.record(profileID: single.id, accessor: "acc-old-target", expiresAt: future)
        XCTAssertTrue(try store.entries(for: single).isEmpty, "must never infer legacy unbound entry onto today's single target")
        XCTAssertEqual(try store.pendingLegacyEntries(profileID: single.id).map(\.accessor), ["acc-old-target"])

        // Case-sensitive SSH user and replacement SSH host-key pin get isolated accessor buckets,
        // and pre-v3 buckets without pin/case-preserving user are never auto-attributed.
        let lowerUser = BaoT3GranterConfig(name: "Box", host: "10.0.0.5", port: 22, user: "ops", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1")
        let upperUser = BaoT3GranterConfig(name: "Box", host: "10.0.0.5", port: 22, user: "Ops", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1")
        let replacedPin = BaoT3GranterConfig(name: "Box", host: "10.0.0.5", port: 22, user: "ops", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2")
        var profLower = single
        profLower.remoteTargets = [lowerUser]
        var profUpper = single
        profUpper.remoteTargets = [upperUser]
        var profReplaced = single
        profReplaced.remoteTargets = [replacedPin]
        XCTAssertNotEqual(GrantAccessorStore.scopeKey(for: profLower), GrantAccessorStore.scopeKey(for: profUpper))
        XCTAssertNotEqual(GrantAccessorStore.scopeKey(for: profLower), GrantAccessorStore.scopeKey(for: profReplaced))
        try store.record(for: profLower, accessor: "acc-lower", expiresAt: future)
        XCTAssertEqual(try store.entries(for: profLower).map(\.accessor), ["acc-lower"])
        XCTAssertTrue(try store.entries(for: profUpper).isEmpty)
        XCTAssertTrue(try store.entries(for: profReplaced).isEmpty)

        // Corrupt state file must fail closed on both read and write without overwriting the evidence.
        let corrupt = Data("{ corrupt json".utf8)
        try corrupt.write(to: url)
        XCTAssertThrowsError(try store.entries(for: single)) { err in
            guard case GrantAccessorStoreError.unreadableState = err else {
                XCTFail("expected unreadableState, got \(err)")
                return
            }
        }
        XCTAssertThrowsError(try store.record(for: single, accessor: "acc-new", expiresAt: future))
        XCTAssertEqual(try Data(contentsOf: url), corrupt, "corrupt state file must not be silently overwritten")
    }

    func testAccessorStoreConcurrentWritesPreserveAllEntries() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("acc-concurrent-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("remote-grants.json")

        let targetA = BaoT3GranterConfig(name: "A", host: "10.0.0.10", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA")
        let targetB = BaoT3GranterConfig(name: "B", host: "10.0.0.20", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB")
        var base = profile(remote: true)
        base.id = "concurrent-prof"
        base.remoteTargets = [targetA, targetB]
        let focusedA = base.focusing(remoteTarget: targetA)
        let focusedB = base.focusing(remoteTarget: targetB)
        let future = Date().addingTimeInterval(3600)

        try await withThrowingTaskGroup(of: Void.self) { group in
            for idx in 0..<20 {
                let targetProfile = idx.isMultiple(of: 2) ? focusedA : focusedB
                let accessor = "acc-\(idx)"
                group.addTask {
                    let workerStore = GrantAccessorStore(url: url)
                    try workerStore.record(for: targetProfile, accessor: accessor, expiresAt: future)
                }
            }
            try await group.waitForAll()
        }

        let reader = GrantAccessorStore(url: url)
        let aAccessors = Set(try reader.entries(for: focusedA).map(\.accessor))
        let bAccessors = Set(try reader.entries(for: focusedB).map(\.accessor))
        XCTAssertEqual(aAccessors.count, 10, "all 10 concurrent writes for target A must survive")
        XCTAssertEqual(bAccessors.count, 10, "all 10 concurrent writes for target B must survive")
    }

    func testRemoteGrantFailsClosedOnMissingRecorderPersistenceFailureOrEmptyAccessor() async throws {
        final class Box: @unchecked Sendable {
            private let lock = NSLock()
            var mintedCount = 0
            var revoked: [String] = []
            var rolledBack: [String] = []
            var emptyAccessor = false
            func noteMint() { lock.lock(); mintedCount += 1; lock.unlock() }
            func addRevoked(_ tok: String) { lock.lock(); revoked.append(tok); lock.unlock() }
            func addRolledBack(_ acc: String) { lock.lock(); rolledBack.append(acc); lock.unlock() }
        }

        func makeTransport(_ box: Box) -> MockHTTPTransport {
            MockHTTPTransport { req in
                switch req.url?.path {
                case "/v1/auth/jwt-alice/login":
                    return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
                case "/v1/auth/token/create/grant-remote":
                    box.noteMint()
                    let acc = box.emptyAccessor ? "" : "acc-remote"
                    let body = try! JSONSerialization.data(withJSONObject: [
                        "auth": [
                            "client_token": "s.minted",
                            "accessor": acc,
                            "policies": ["default", "app-read"],
                            "renewable": false,
                            "orphan": true,
                            "lease_duration": 3600
                        ]
                    ])
                    return (200, body)
                case "/v1/auth/token/revoke":
                    let body = req.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: String] }
                    box.addRevoked(body?["token"] ?? "")
                    return (204, Data())
                default:
                    return (204, Data())
                }
            }
        }

        // Case A: Missing onRemoteGrantMinted recorder on non-demo transport must fail closed BEFORE minting or installing.
        let boxA = Box()
        let granterA = MockT3Granter()
        let orchA = GrantOrchestrator(
            profile: profile(remote: true),
            signer: EphemeralP256Signer(),
            openbao: client(makeTransport(boxA)),
            t3Granter: granterA,
            via: "mac",
            onRemoteGrantMinted: nil
        )
        await XCTAssertThrowsErrorAsync(try await orchA.execute(GrantRequest(target: .t3, hours: 1)))
        XCTAssertEqual(boxA.mintedCount, 0, "must fail closed before minting a token when no recorder is wired")
        XCTAssertNil(granterA.installed, "must not deliver SSH grant without a persistence recorder")

        // Case B: Persistence callback throws -> revoke minted token, never deliver, never call rollback.
        let boxB = Box()
        let granterB = MockT3Granter()
        let orchB = GrantOrchestrator(
            profile: profile(remote: true),
            signer: EphemeralP256Signer(),
            openbao: client(makeTransport(boxB)),
            t3Granter: granterB,
            via: "mac",
            onRemoteGrantMinted: { _, _ in throw GrantAccessorStoreError.lockingFailed("disk full") },
            onRemoteGrantRolledBack: { acc in boxB.addRolledBack(acc) }
        )
        await XCTAssertThrowsErrorAsync(try await orchB.execute(GrantRequest(target: .t3, hours: 1)))
        XCTAssertNil(granterB.installed, "must not deliver SSH grant after accessor persistence failure")
        XCTAssertEqual(boxB.revoked, ["s.minted"])
        XCTAssertTrue(boxB.rolledBack.isEmpty)

        // Case C: Empty accessor from OpenBao -> fail closed before delivery and revoke.
        let boxC = Box()
        boxC.emptyAccessor = true
        let granterC = MockT3Granter()
        let orchC = GrantOrchestrator(
            profile: profile(remote: true),
            signer: EphemeralP256Signer(),
            openbao: client(makeTransport(boxC)),
            t3Granter: granterC,
            via: "mac",
            onRemoteGrantMinted: { _, _ in }
        )
        await XCTAssertThrowsErrorAsync(try await orchC.execute(GrantRequest(target: .t3, hours: 1)))
        XCTAssertNil(granterC.installed, "must not deliver SSH grant when OpenBao returned an empty accessor")
        XCTAssertEqual(boxC.revoked, ["s.minted"])
    }

    // Blocker 2: SecureEnclaveKeyStore never falls back to legacy unscoped signing-key, and JWTSigner rejects empty or mismatched audiences.
    func testNoLegacyKeyFallbackAndStrictAudienceValidation() throws {
        var legacyStyle = profile()
        legacyStyle.openbao.address = "https://nonexistent-\(UUID().uuidString.lowercased()).invalid:8200"
        legacyStyle.openbao.jwtAuth.audience = "openbao-granter"

        let account = SecureEnclaveKeyStore.accountName(for: legacyStyle)
        XCTAssertTrue(account.hasPrefix("signing-key.v3."), "expected v3 scoped key account, got \(account)")
        XCTAssertNotEqual(account, "signing-key")

        let isolatedTag = "com.northcutt.baogrant.test.\(UUID().uuidString.lowercased())"
        XCTAssertThrowsError(try SecureEnclaveKeyStore.resolve(for: legacyStyle, deviceName: "test", tag: isolatedTag).publicKeyPEM()) { err in
            #if os(macOS)
            // An unsigned SwiftPM runner is denied the release helper’s private access group.
            if case SecureEnclaveError.keychainError(errSecMissingEntitlement) = err { return }
            #endif
            guard case SecureEnclaveError.scopedKeyRequired(let server, let mount) = err else {
                XCTFail("expected scopedKeyRequired (no fallback to legacy signing-key), got \(err)")
                return
            }
            XCTAssertTrue(server.contains("nonexistent-"))
            XCTAssertEqual(mount, "jwt-alice")
        }

        // Same URL + mount with distinct mTLS client identities or TLS CA pins MUST get distinct
        // signing keys, distinct trust-domain audiences, and distinct Mac Keychain services.
        var mtlsA = profile()
        mtlsA.openbao.address = "https://Bao.Example:443/Prod"
        mtlsA.openbao.mtlsClientIdentity = "client-a"
        mtlsA.openbao.jwtAuth.audience = mtlsA.openbao.expectedOriginMountAudience

        var mtlsB = mtlsA
        mtlsB.openbao.mtlsClientIdentity = "client-b"
        mtlsB.openbao.jwtAuth.audience = mtlsB.openbao.expectedOriginMountAudience

        var pinA = profile()
        pinA.openbao.address = "https://Bao.Example:443/Prod"
        pinA.openbao.caPEM = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"
        pinA.openbao.jwtAuth.audience = pinA.openbao.expectedOriginMountAudience

        var pinB = pinA
        pinB.openbao.caPEM = "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----"
        pinB.openbao.jwtAuth.audience = pinB.openbao.expectedOriginMountAudience

        // Verify canonical host lowercasing, default :443 omission, and base-path case preservation.
        XCTAssertEqual(
            BaoOpenBaoConfig.defaultAudience(address: "https://Bao.Example:443/Prod", mount: "jwt-alice"),
            "baobuddy://bao.example/auth/jwt-alice?base=%2FProd"
        )
        XCTAssertNotEqual(SecureEnclaveKeyStore.accountName(for: mtlsA), SecureEnclaveKeyStore.accountName(for: mtlsB))
        XCTAssertNotEqual(mtlsA.openbao.expectedOriginMountAudience, mtlsB.openbao.expectedOriginMountAudience)
        XCTAssertNotEqual(SecureEnclaveKeyStore.accountName(for: pinA), SecureEnclaveKeyStore.accountName(for: pinB))
        XCTAssertNotEqual(pinA.openbao.expectedOriginMountAudience, pinB.openbao.expectedOriginMountAudience)
        XCTAssertNotEqual(SecureEnclaveKeyStore.accountName(for: mtlsA), SecureEnclaveKeyStore.accountName(for: pinA))
        #if os(macOS)
        XCTAssertNotEqual(MacKeychainGrantStore(profile: mtlsA).service, MacKeychainGrantStore(profile: mtlsB).service)
        XCTAssertNotEqual(MacKeychainGrantStore(profile: pinA).service, MacKeychainGrantStore(profile: pinB).service)
        #endif

        // Cross-identity and cross-pin audiences are rejected by JWTSigner.
        var crossMTLS = mtlsB
        crossMTLS.openbao.jwtAuth.audience = mtlsA.openbao.expectedOriginMountAudience
        XCTAssertThrowsError(try JWTSigner.validateAudience(for: crossMTLS))
        var crossPin = pinB
        crossPin.openbao.jwtAuth.audience = pinA.openbao.expectedOriginMountAudience
        XCTAssertThrowsError(try JWTSigner.validateAudience(for: crossPin))

        // OpenTofu spec propagates ca_pem and mtls_client_identity.
        let tofuSpecMTLS = BaoTofuDeploymentSpec.from(profile: mtlsA)
        XCTAssertEqual(tofuSpecMTLS.mtlsClientIdentity, "client-a")
        XCTAssertEqual(tofuSpecMTLS.audience, "", "bound audience should stay auto-derived in OpenTofu")
        let tofuFilesMTLS = BaoTofuBuilder.generate(tofuSpecMTLS)
        XCTAssertTrue(tofuFilesMTLS["terraform.tfvars"]?.contains(#"mtls_client_identity = "client-a""#) == true)
        XCTAssertTrue(tofuFilesMTLS["main.tf"]?.contains("trimsuffix(local.addr_authority_raw, \":443\")") == true)

        // Empty audience is rejected.
        var emptyAud = profile()
        emptyAud.openbao.jwtAuth.audience = "   "
        XCTAssertThrowsError(try JWTSigner.validateAudience(for: emptyAud))
    }

    // Blocker 3: Path-prefixed endpoints bind full canonical base path, canonicalize trailing slash on outgoing requests, and reject non-canonical URLs without leaking embedded passwords.
    func testPathPrefixedEndpointBindingCanonicalizationAndSafeErrorReporting() async throws {
        var baseA = profile()
        baseA.openbao.address = "https://proxy.example/vault-a"
        baseA.openbao.jwtAuth.audience = baseA.openbao.expectedOriginMountAudience

        var baseATrailing = baseA
        baseATrailing.openbao.address = "https://proxy.example/vault-a/"

        var baseB = baseA
        baseB.openbao.address = "https://proxy.example/vault-b"
        baseB.openbao.jwtAuth.audience = baseB.openbao.expectedOriginMountAudience

        var root = baseA
        root.openbao.address = "https://proxy.example"
        root.openbao.jwtAuth.audience = root.openbao.expectedOriginMountAudience

        // Equivalent trailing-slash spellings share identical binding & audience AND send identical outgoing path.
        XCTAssertEqual(baseA.openbao.issuerBindingKey, baseATrailing.openbao.issuerBindingKey)
        XCTAssertTrue(baseA.openbao.issuerBindingKey.hasPrefix("v3-"))
        XCTAssertEqual(baseA.openbao.expectedOriginMountAudience, "baobuddy://proxy.example/auth/jwt-alice?base=%2Fvault-a")
        XCTAssertEqual(baseA.openbao.expectedOriginMountAudience, baseATrailing.openbao.expectedOriginMountAudience)

        // Distinct base paths & root on one origin have distinct keys, audiences, and Keychain services.
        XCTAssertNotEqual(baseA.openbao.issuerBindingKey, baseB.openbao.issuerBindingKey)
        XCTAssertNotEqual(baseA.openbao.issuerBindingKey, root.openbao.issuerBindingKey)
        XCTAssertNotEqual(SecureEnclaveKeyStore.accountName(for: baseA), SecureEnclaveKeyStore.accountName(for: baseB))
        XCTAssertNotEqual(SecureEnclaveKeyStore.accountName(for: baseA), SecureEnclaveKeyStore.accountName(for: root))
        #if os(macOS)
        XCTAssertNotEqual(MacKeychainGrantStore(profile: baseA).service, MacKeychainGrantStore(profile: baseB).service)
        #endif

        // Cross-base-path audience is rejected by JWTSigner.
        var spoofedBase = baseB
        spoofedBase.openbao.jwtAuth.audience = baseA.openbao.expectedOriginMountAudience
        XCTAssertThrowsError(try JWTSigner.validateAudience(for: spoofedBase))

        // Outgoing request paths for `/vault-a` and `/vault-a/` are identical.
        final class PathBox: @unchecked Sendable {
            var paths: [String] = []
        }
        let box = PathBox()
        let transport = MockHTTPTransport { req in
            box.paths.append(req.url?.path ?? "")
            return (200, Data(#"{"initialized":true,"sealed":false,"version":"2.7.2"}"#.utf8))
        }
        let client1 = OpenBaoClient(baseURL: URL(string: "https://proxy.example/vault-a")!, transport: transport)
        let client2 = OpenBaoClient(baseURL: URL(string: "https://proxy.example/vault-a/")!, transport: transport)
        _ = try await client1.checkHealth()
        _ = try await client2.checkHealth()
        XCTAssertEqual(box.paths, ["/vault-a/v1/sys/health", "/vault-a/v1/sys/health"])

        // Reject ambiguous / non-canonical URLs and NEVER echo embedded userinfo password.
        for bad in [
            "https://proxy.example/vault//a",
            "https://proxy.example/vault/a//",
            "https://proxy.example/vault%2Fa",
            "https://proxy.example/vault%20a",
            "https://proxy.example/vault/..",
            "https://proxy.example/vault?x=1",
            "https://proxy.example/vault#frag"
        ] {
            let url = try XCTUnwrap(URL(string: bad))
            XCTAssertThrowsError(try OpenBaoClient.validateEndpointURL(url), "expected rejection for \(bad)")
        }

        let withCreds = try XCTUnwrap(URL(string: "https://alice:TopSecretPass99@proxy.example/vault"))
        do {
            try OpenBaoClient.validateEndpointURL(withCreds)
            XCTFail("expected embedded credentials URL to be rejected")
        } catch {
            let msg = error.localizedDescription
            XCTAssertFalse(msg.contains("TopSecretPass99"), "error message leaked password: \(msg)")
            XCTAssertFalse(msg.contains("alice"), "error message leaked username: \(msg)")
        }

        // OpenTofu generator defaults audience to "" and supports ?base= for path-prefixed addresses.
        let tofuSpec = BaoTofuDeploymentSpec(
            serverName: "Proxy Vault",
            openbaoAddress: "https://proxy.example/vault-a",
            users: [BaoTofuUserSpec(name: "alice", mount: "jwt-alice", subject: "alice", devicePublicKeysPEM: [], allowedPolicies: ["read"])]
        )
        XCTAssertEqual(tofuSpec.audience, "")
        let tofuFiles = BaoTofuBuilder.generate(tofuSpec)
        XCTAssertTrue(tofuFiles["main.tf"]?.contains("base=${urlencode(local.addr_base_path)}") == true)
        XCTAssertTrue(tofuFiles["variables.tf"]?.contains(#"default     = """#) == true)
    }

    // Blocker 4: Exact ID precedence, ambiguity refusal, conflicting link hints rejected, and exact cross-device namespace matching.
    func testProfileAndTargetResolutionExactIDPrecedenceAmbiguityAndLinkHints() throws {
        var prodUS = profile(remote: true)
        prodUS.id = "prod-us"
        prodUS.name = "Prod"
        prodUS.openbao.address = "https://us.vault.example:8200"
        prodUS.openbao.namespace = ""
        prodUS.openbao.jwtAuth.mount = "jwt-alice"

        var prodEU = profile(remote: true)
        prodEU.id = "prod-eu"
        prodEU.name = "Prod"
        prodEU.openbao.address = "https://eu.vault.example:8200"
        prodEU.openbao.namespace = "eu"
        prodEU.openbao.jwtAuth.mount = "jwt-alice"

        let dupes = [prodUS, prodEU]
        // Ambiguous display name must fail closed.
        XCTAssertThrowsError(try BaoProfile.resolveProfile(selector: "Prod", in: dupes)) { err in
            guard case ProfileError.ambiguousProfile = err else {
                XCTFail("expected ambiguousProfile, got \(err)")
                return
            }
        }
        // Exact ID resolves cleanly.
        XCTAssertEqual(try BaoProfile.resolveProfile(selector: "prod-eu", in: dupes).id, "prod-eu")

        // Exact ID takes precedence over another profile's display name.
        var idMatchesSelector = prodUS
        idMatchesSelector.id = "prod"
        idMatchesSelector.name = "Alpha"
        var nameMatchesSelector = prodEU
        nameMatchesSelector.id = "other"
        nameMatchesSelector.name = "Prod"
        XCTAssertEqual(
            try BaoProfile.resolveProfile(selector: "prod", in: [nameMatchesSelector, idMatchesSelector]).id,
            "prod"
        )

        // Ambiguous remote target names fail closed; exact target ID succeeds.
        let t1 = BaoT3GranterConfig(name: "Runner", host: "10.0.0.1", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA")
        let t2 = BaoT3GranterConfig(name: "Runner", host: "10.0.0.2", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB")
        var multiTarget = prodUS
        multiTarget.remoteTargets = [t1, t2]
        XCTAssertThrowsError(try multiTarget.resolveRemoteTarget(named: "Runner")) { err in
            guard case ProfileError.ambiguousRemoteTarget = err else {
                XCTFail("expected ambiguousRemoteTarget, got \(err)")
                return
            }
        }
        XCTAssertEqual(try multiTarget.resolveRemoteTarget(named: t2.id)?.host, "10.0.0.2")

        // Deep link with exact profile_id BUT conflicting server / mount / namespace hint MUST be rejected.
        let conflictingServer = try XCTUnwrap(URL(string: "baobuddy://grant?profile_id=prod-us&server=https%3A%2F%2Feu.vault.example%3A8200&mount=jwt-alice&namespace=&r=HOURS%3D1"))
        XCTAssertThrowsError(try GrantRequest.resolveProfile(from: conflictingServer, in: dupes, active: prodUS))

        let conflictingNamespace = try XCTUnwrap(URL(string: "baobuddy://grant?profile_id=prod-us&server=https%3A%2F%2Fus.vault.example%3A8200&mount=jwt-alice&namespace=eu&r=HOURS%3D1"))
        XCTAssertThrowsError(try GrantRequest.resolveProfile(from: conflictingNamespace, in: dupes, active: prodUS))

        let conflictingMount = try XCTUnwrap(URL(string: "baobuddy://grant?profile_id=prod-us&server=https%3A%2F%2Fus.vault.example%3A8200&mount=jwt-bob&namespace=&r=HOURS%3D1"))
        XCTAssertThrowsError(try GrantRequest.resolveProfile(from: conflictingMount, in: dupes, active: prodUS))

        // Valid cross-device link (different device's profile_id) resolves by exact (server, mount, namespace) including root namespace="".
        let crossDeviceRoot = try XCTUnwrap(URL(string: "baobuddy://grant?profile_id=mac-uuid-123&profile=Prod&server=https%3A%2F%2Fus.vault.example%3A8200&mount=jwt-alice&namespace=&r=HOURS%3D1"))
        XCTAssertEqual(try GrantRequest.resolveProfile(from: crossDeviceRoot, in: dupes, active: prodEU).id, "prod-us")

        // Cross-device link with root namespace="" must NOT match a profile with namespace="eu".
        let rootMismatch = try XCTUnwrap(URL(string: "baobuddy://grant?profile_id=mac-uuid-123&profile=Prod&server=https%3A%2F%2Feu.vault.example%3A8200&mount=jwt-alice&namespace=&r=HOURS%3D1"))
        XCTAssertThrowsError(try GrantRequest.resolveProfile(from: rootMismatch, in: dupes, active: prodUS))

        // Exact-only CLI resolvers NEVER fall back from a stale ID to another profile's or target's display name.
        XCTAssertThrowsError(try BaoProfile.resolveProfileExact(id: "Prod", in: [nameMatchesSelector]))
        XCTAssertEqual(try BaoProfile.resolveProfileExact(id: "other", in: [nameMatchesSelector]).id, "other")
        XCTAssertThrowsError(try multiTarget.resolveRemoteTargetExact(id: "Runner"))
        XCTAssertEqual(try multiTarget.resolveRemoteTargetExact(id: t2.id, sshDestination: t2.sshDestination, hostKeyFingerprint: t2.hostKeyFingerprint).host, "10.0.0.2")
        XCTAssertThrowsError(try multiTarget.resolveRemoteTargetExact(id: t2.id, sshDestination: "otheruser@10.0.0.2:22"))
        XCTAssertThrowsError(try multiTarget.resolveRemoteTargetExact(id: t2.id, hostKeyFingerprint: "deadbeef00000000"))

        // Same URL + namespace + mount with two different mTLS identities sharing display name "Prod":
        // issuer_binding distinguishes them on both exact profile_id conflict checks and cross-device fallback.
        var sharedURLA = prodUS
        sharedURLA.id = "mtls-prof-a"
        sharedURLA.name = "Prod"
        sharedURLA.openbao.mtlsClientIdentity = "client-a"
        var sharedURLB = prodUS
        sharedURLB.id = "mtls-prof-b"
        sharedURLB.name = "Prod"
        sharedURLB.openbao.mtlsClientIdentity = "client-b"

        let linkForB = try XCTUnwrap(URL(string: BaoAgentPrompts.buildGrantDeepLink(
            profile: sharedURLB,
            request: GrantRequest(target: .mac, hours: 1)
        )))
        // Cross-device simulation: device 2 has different local UUIDs for the same two mTLS profiles.
        var dev2A = sharedURLA
        dev2A.id = "ios-a"
        var dev2B = sharedURLB
        dev2B.id = "ios-b"
        XCTAssertEqual(
            try GrantRequest.resolveProfile(from: linkForB, in: [dev2A, dev2B], active: dev2A).id,
            "ios-b",
            "issuer_binding must select the matching mTLS/CA profile even when URL, namespace, mount, and display name are identical"
        )
        // Conflicting issuer_binding on an exact profile_id match fails closed.
        let spoofedTrust = try XCTUnwrap(URL(string: "baobuddy://grant?profile_id=mtls-prof-a&issuer_binding=\(sharedURLB.openbao.issuerBindingKey)&r=HOURS%3D1"))
        XCTAssertThrowsError(try GrantRequest.resolveProfile(from: spoofedTrust, in: [sharedURLA, sharedURLB], active: sharedURLA))

        // Remote target trust binding across two devices sharing the display name "Build":
        // Device 1 has "Build" -> granter@10.0.0.10:22 (key A).
        // Device 2 has "Build" -> granter@10.0.0.99:22 (key B) (a DIFFERENT machine with the same display name!).
        let dev1Build = BaoT3GranterConfig(name: "Build", host: "10.0.0.10", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyA")
        let dev2DifferentBuild = BaoT3GranterConfig(name: "Build", host: "10.0.0.99", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyB")
        let dev2SameMachineDifferentName = BaoT3GranterConfig(name: "CI Runner", host: "10.0.0.10", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyA")
        let dev2WrongUser = BaoT3GranterConfig(name: "Build", host: "10.0.0.10", port: 22, user: "otheruser", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyA")
        let dev2WrongPin = BaoT3GranterConfig(name: "Build", host: "10.0.0.10", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDifferentPin")

        var dev1Profile = prodUS
        dev1Profile.remoteTargets = [dev1Build]
        let generatedRemoteLink = try XCTUnwrap(URL(string: BaoAgentPrompts.buildGrantDeepLink(
            profile: dev1Profile,
            request: GrantRequest(target: .t3, hours: 1)
        )))

        // 1. Different host with same "Build" display name MUST fail closed (never fall back to display name).
        var dev2ProfileWrongHost = prodUS
        dev2ProfileWrongHost.remoteTargets = [dev2DifferentBuild]
        XCTAssertThrowsError(try GrantRequest.linkProfile(url: generatedRemoteLink, base: dev2ProfileWrongHost))

        // 2. Same name@host:port ID but DIFFERENT SSH user MUST fail closed!
        var dev2ProfileWrongUser = prodUS
        dev2ProfileWrongUser.remoteTargets = [dev2WrongUser]
        XCTAssertThrowsError(try GrantRequest.linkProfile(url: generatedRemoteLink, base: dev2ProfileWrongUser))

        // 3. Same name@host:port ID + user but DIFFERENT host-key pin MUST fail closed!
        var dev2ProfileWrongPin = prodUS
        dev2ProfileWrongPin.remoteTargets = [dev2WrongPin]
        XCTAssertThrowsError(try GrantRequest.linkProfile(url: generatedRemoteLink, base: dev2ProfileWrongPin))

        // 4. Absent remote_target_id without remote_ssh MUST NEVER fall back to remote_target display name.
        let idOnlyMissing = try XCTUnwrap(URL(string: "baobuddy://grant?remote_target_id=build%4010.0.0.10%3A22&remote_target=Build&r=HOURS%3D1"))
        XCTAssertThrowsError(try GrantRequest.linkProfile(url: idOnlyMissing, base: dev2ProfileWrongHost))

        // 5. Cross-device link with matching SSH destination + host-key pin succeeds even if renamed locally.
        var dev2ProfileRenamed = prodUS
        dev2ProfileRenamed.remoteTargets = [dev2DifferentBuild, dev2SameMachineDifferentName]
        let focusedCrossDevice = try GrantRequest.linkProfile(url: generatedRemoteLink, base: dev2ProfileRenamed)
        XCTAssertEqual(focusedCrossDevice.t3Granter.host, "10.0.0.10")
        XCTAssertEqual(focusedCrossDevice.t3Granter.user, "granter")
        XCTAssertEqual(focusedCrossDevice.t3Granter.hostKeyFingerprint, dev1Build.hostKeyFingerprint)
    }

    // Blocker 5: Zero positive grace window on SSH certificate lifetime + elapsed time between mint and sign recomputes remaining TTL.
    func testZeroGraceSSHCertDeadlineRecomputesRemainingTTLAndRejectsOneSecondOverrun() async throws {
        final class ClockAndCapture: @unchecked Sendable {
            private let lock = NSLock()
            var nowEpoch: Double = 1_800_000_000
            var requestedSSHTTL: String?
            var revokedTokens: [String] = []
            var recordedExpiry: Date?
            var certOverrunSeconds: UInt64 = 1

            func currentDate() -> Date { lock.lock(); defer { lock.unlock() }; return Date(timeIntervalSince1970: nowEpoch) }
            func advance(by seconds: Double) { lock.lock(); nowEpoch += seconds; lock.unlock() }
            func setSSHTTL(_ ttl: String?) { lock.lock(); requestedSSHTTL = ttl; lock.unlock() }
            func addRevoked(_ tok: String) { lock.lock(); revokedTokens.append(tok); lock.unlock() }
            func setRecordedExpiry(_ d: Date) { lock.lock(); recordedExpiry = d; lock.unlock() }
        }

        func runAttempt(overrunSeconds: UInt64) async throws -> (ClockAndCapture, MockT3Granter, GrantOutcome?) {
            let state = ClockAndCapture()
            state.certOverrunSeconds = overrunSeconds
            let grantDeadlineEpoch: UInt64 = 1_800_000_000 + 600 // shortened 600s lease anchored at T0

            let transport = MockHTTPTransport { req in
                switch req.url?.path {
                case "/v1/auth/jwt-alice/login":
                    return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
                case "/v1/auth/token/create/grant-remote":
                    // Simulate 45 seconds elapsing before SSH signing happens.
                    state.advance(by: 45)
                    let payload = try! JSONSerialization.data(withJSONObject: [
                        "auth": [
                            "client_token": "s.short",
                            "accessor": "acc-short",
                            "policies": ["default", "app-read"],
                            "renewable": false,
                            "orphan": true,
                            "lease_duration": 600
                        ]
                    ])
                    return (200, payload)
                case "/v1/ssh/sign/ops":
                    let body = req.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                    state.setSSHTTL(body?["ttl"] as? String)
                    let cert = OpenSSHCertificate.encodeSynthetic(
                        principals: ["root-docker"],
                        validAfter: 1_800_000_000,
                        validBefore: grantDeadlineEpoch + state.certOverrunSeconds
                    )
                    let payload = try! JSONSerialization.data(withJSONObject: ["data": ["signed_key": cert]])
                    return (200, payload)
                case "/v1/auth/token/revoke":
                    let body = req.httpBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: String] }
                    state.addRevoked(body?["token"] ?? "")
                    return (204, Data())
                default:
                    return (204, Data())
                }
            }
            let granter = MockT3Granter()
            let orchestrator = GrantOrchestrator(
                profile: profile(remote: true),
                signer: EphemeralP256Signer(),
                openbao: client(transport),
                t3Granter: granter,
                via: "mac",
                now: { state.currentDate() },
                onRemoteGrantMinted: { _, expiresAt in state.setRecordedExpiry(expiresAt) }
            )
            let req = GrantRequest(target: .t3, hours: 4, sshHosts: ["Docker"])
            do {
                let outcome = try await orchestrator.execute(req)
                return (state, granter, outcome)
            } catch {
                return (state, granter, nil)
            }
        }

        // Even a +1 second overrun past grantDeadlineEpoch MUST be rejected and revoked (zero grace).
        let (overrunState, overrunGranter, overrunOutcome) = try await runAttempt(overrunSeconds: 1)
        XCTAssertNil(overrunOutcome, "SSH cert exceeding grant deadline by even 1s must be rejected")
        XCTAssertEqual(overrunState.requestedSSHTTL, "555s", "SSH signing TTL must subtract elapsed time since mint start")
        XCTAssertEqual(overrunState.revokedTokens, ["s.short"])
        XCTAssertNil(overrunGranter.installed)

        // Exact boundary (0s overrun) succeeds with shared grantDeadline across accessor & outcome.
        let (exactState, exactGranter, exactOutcome) = try await runAttempt(overrunSeconds: 0)
        XCTAssertNotNil(exactOutcome)
        XCTAssertEqual(exactState.requestedSSHTTL, "555s")
        XCTAssertEqual(exactOutcome?.expiresAt, Date(timeIntervalSince1970: 1_800_000_600))
        XCTAssertEqual(exactState.recordedExpiry, Date(timeIntervalSince1970: 1_800_000_600))
        XCTAssertNotNil(exactGranter.installed)
    }

    // MARK: - First-install polish regressions

    // First-install (2): server-setup next steps put profile export/import BEFORE iPhone key creation/registration
    // and preserve deployment, namespace, CA cert path, mTLS identity, mount, and custom role/audience flags.
    func testServerSetupNextStepsOrderExportBeforeDeviceAddAndPreserveTrustContext() {
        let output = BaoServerAdmin.renderSetupNextSteps(
            address: "https://vault.corp.example:8200/prod",
            namespace: "admin/prod-us-east",
            caCertPath: "/etc/ssl/corp ca.pem",
            mtlsClientIdentity: "alice.vault.corp",
            mount: "jwt-alice",
            role: "alice-role",
            issuer: "corp-issuer",
            customAudience: "corp-aud",
            tokenRole: "custom-grant",
            maxHours: 4,
            policies: ["db-readonly", "k8s-deploy"],
            subject: "alice",
            githubTokenPath: "github/token/push"
        )

        let exportRange = output.range(of: "bao-buddy export-profile")
        let iphoneKeyRange = output.range(of: "Hardware Approval Key")
        let deviceAddRange = output.range(of: "pbpaste | bao-buddy device add")
        XCTAssertNotNil(exportRange, output)
        XCTAssertNotNil(iphoneKeyRange, output)
        XCTAssertNotNil(deviceAddRange, output)
        if let e = exportRange, let k = iphoneKeyRange, let d = deviceAddRange {
            XCTAssertLessThan(e.lowerBound, k.lowerBound, "export-profile must precede iPhone key creation")
            XCTAssertLessThan(k.lowerBound, d.lowerBound, "iPhone key creation must precede device add")
        }

        for expected in [
            "--addr https://vault.corp.example:8200/prod",
            "--namespace admin/prod-us-east",
            "--cacert '/etc/ssl/corp ca.pem'",
            "--mtls-identity alice.vault.corp",
            "--mount jwt-alice",
            "--role alice-role",
            "--issuer corp-issuer",
            "--audience corp-aud",
            "--token-role custom-grant",
            "--max-hours 4",
            "--github-token-path github/token/push"
        ] {
            XCTAssertTrue(output.contains(expected), "missing \(expected) in:\n\(output)")
        }
        // Step 3 (device add) must also preserve addr, namespace, cacert, mtls-identity, and mount.
        let step3 = output.components(separatedBy: "3. Register").last ?? ""
        XCTAssertTrue(step3.contains("--addr https://vault.corp.example:8200/prod"), step3)
        XCTAssertTrue(step3.contains("--namespace admin/prod-us-east"), step3)
        XCTAssertTrue(step3.contains("--cacert '/etc/ssl/corp ca.pem'"), step3)
        XCTAssertTrue(step3.contains("--mtls-identity alice.vault.corp"), step3)
        XCTAssertTrue(step3.contains("--mount jwt-alice"), step3)
    }

    // First-install (3): Shipped MDM mobileconfig with real user replacements decodes to a pin-bound audience
    // accepted by JWTSigner without hand-maintained hashes, while preserving custom interoperability audiences.
    func testShippedMDMMobileconfigWithRealReplacementsProducesSignerAcceptedAudience() throws {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let mobileconfigURL = repoRoot.appendingPathComponent("examples/mdm/baobuddy-macos.mobileconfig")
        let plistData = try Data(contentsOf: mobileconfigURL)
        let plist = try XCTUnwrap(
            PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any]
        )
        let payloads = try XCTUnwrap(plist["PayloadContent"] as? [[String: Any]])
        var managedDict = try XCTUnwrap(payloads.first)
        let templateJSON = try XCTUnwrap(managedDict["profiles_json"] as? String)

        let replacedJSON = templateJSON
            .replacingOccurrences(of: "REPLACE_WITH_INTERNAL_CA_PEM", with: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA")
            .replacingOccurrences(of: "REPLACE_WITH_USERNAME", with: "alice")
        managedDict["profiles_json"] = replacedJSON

        let parsed = ManagedAppConfig.parse(dictionary: managedDict)
        XCTAssertTrue(parsed.rejectedProfiles.isEmpty, "rejected: \(parsed.rejectedProfiles)")
        XCTAssertEqual(parsed.profiles.count, 1)

        let mdmProfile = try XCTUnwrap(parsed.profiles.first)
        XCTAssertTrue(mdmProfile.openbao.isTLSPinned)
        XCTAssertTrue(mdmProfile.openbao.usesBoundAudience)
        XCTAssertTrue(mdmProfile.openbao.jwtAuth.audience.contains("?pin="), mdmProfile.openbao.jwtAuth.audience)
        XCTAssertEqual(
            mdmProfile.openbao.jwtAuth.audience,
            BaoOpenBaoConfig.defaultAudience(
                address: mdmProfile.openbao.address,
                namespace: mdmProfile.openbao.namespace,
                mount: mdmProfile.openbao.jwtAuth.mount,
                caPEM: mdmProfile.openbao.caPEM,
                mtlsClientIdentity: mdmProfile.openbao.mtlsClientIdentity
            )
        )
        XCTAssertNoThrow(try JWTSigner.validateAudience(for: mdmProfile))

        // Deliberate interoperability: explicit custom non-baobuddy:// audience is kept verbatim,
        // while a mismatched baobuddy:// audience (e.g. omitting ?pin=) is still rejected.
        let customJSON = replacedJSON.replacingOccurrences(of: #""audience":"""#, with: #""audience":"corp-vault-aud""#)
        var customDict = managedDict
        customDict["profiles_json"] = customJSON
        let customParsed = ManagedAppConfig.parse(dictionary: customDict)
        let customProfile = try XCTUnwrap(customParsed.profiles.first)
        XCTAssertEqual(customProfile.openbao.jwtAuth.audience, "corp-vault-aud")
        XCTAssertNoThrow(try JWTSigner.validateAudience(for: customProfile))

        // Mismatched baobuddy:// audience (e.g. omitting ?pin= when ca_pem is set) is rejected
        // right at validation / MDM parse / import time instead of saving a profile that fails at sign-in.
        let badPinnedJSON = replacedJSON.replacingOccurrences(
            of: #""audience":"""#,
            with: #""audience":"baobuddy://vault.corp.example:8200/ns/admin/prod-us-east/auth/jwt-alice""#
        )
        var badDict = managedDict
        badDict["profiles_json"] = badPinnedJSON
        let badParsed = ManagedAppConfig.parse(dictionary: badDict)
        XCTAssertTrue(badParsed.profiles.isEmpty, "mismatched baobuddy:// audience must be rejected during MDM parse")
        XCTAssertFalse(badParsed.rejectedProfiles.isEmpty)

        // Direct JSON decode / import also rejects mismatched baobuddy:// audience, while omitted audience derives cleanly.
        let singleBadJSON = try XCTUnwrap(
            (JSONSerialization.jsonObject(with: Data(badPinnedJSON.utf8)) as? [[String: Any]])?.first
        )
        let singleBadData = try JSONSerialization.data(withJSONObject: singleBadJSON)
        XCTAssertThrowsError(try BaoProfile.decode(from: singleBadData))

        var singleOmitted = try XCTUnwrap(
            (JSONSerialization.jsonObject(with: Data(replacedJSON.utf8)) as? [[String: Any]])?.first
        )
        var openbaoObj = try XCTUnwrap(singleOmitted["openbao"] as? [String: Any])
        var jwtObj = try XCTUnwrap(openbaoObj["jwt_auth"] as? [String: Any])
        jwtObj.removeValue(forKey: "audience")
        openbaoObj["jwt_auth"] = jwtObj
        singleOmitted["openbao"] = openbaoObj
        let omittedProfile = try BaoProfile.decode(from: try JSONSerialization.data(withJSONObject: singleOmitted))
        XCTAssertTrue(omittedProfile.openbao.usesBoundAudience)
        XCTAssertTrue(omittedProfile.openbao.jwtAuth.audience.contains("?pin="))
        XCTAssertNoThrow(try JWTSigner.validateAudience(for: omittedProfile))
    }

    // First-install (4): ProfileImportPlan.make uses full issuerBindingKey so importing a second
    // same-URL deployment with a different mTLS identity or TLS CA pin never overwrites the first profile's ID.
    func testProfileImportPlanIsolatesSameURLDeploymentsByIssuerBinding() throws {
        var first = profile()
        first.id = "first-id"
        first.name = "Corp Gateway A"
        first.openbao.address = "https://gateway.corp.example:8200"
        first.openbao.namespace = "prod"
        first.openbao.jwtAuth.mount = "jwt-alice"
        first.openbao.mtlsClientIdentity = "client-a"
        first.openbao.caPEM = "-----BEGIN CERTIFICATE-----\nCA-A\n-----END CERTIFICATE-----"
        first.openbao.jwtAuth.audience = first.openbao.expectedOriginMountAudience

        // Second deployment at the exact same URL + namespace + mount, different mTLS identity:
        // must NOT replace `first` even if the incoming JSON tries to reuse `first.id`.
        var secondMTLS = first
        secondMTLS.name = "Corp Gateway B"
        secondMTLS.openbao.mtlsClientIdentity = "client-b"
        secondMTLS.openbao.jwtAuth.audience = secondMTLS.openbao.expectedOriginMountAudience

        let mtlsPlan = try ProfileImportPlan.make(
            importing: secondMTLS,
            existing: [first],
            managedIDs: [],
            organizationPolicy: .empty
        )
        XCTAssertNil(mtlsPlan.replaces, "different mTLS identity at same URL must not replace existing profile")
        XCTAssertNotEqual(mtlsPlan.profile.id, first.id)

        // Third deployment at the exact same URL + namespace + mount + mTLS, different TLS CA pin:
        // must NOT replace `first`.
        var secondPin = first
        secondPin.name = "Corp Gateway Pin B"
        secondPin.openbao.caPEM = "-----BEGIN CERTIFICATE-----\nCA-B\n-----END CERTIFICATE-----"
        secondPin.openbao.jwtAuth.audience = secondPin.openbao.expectedOriginMountAudience

        let pinPlan = try ProfileImportPlan.make(
            importing: secondPin,
            existing: [first],
            managedIDs: [],
            organizationPolicy: .empty
        )
        XCTAssertNil(pinPlan.replaces, "different TLS CA pin at same URL must not replace existing profile")
        XCTAssertNotEqual(pinPlan.profile.id, first.id)

        // Updating the SAME deployment (identical issuerBindingKey + mount + remote host) DOES replace.
        var sameUpdated = first
        sameUpdated.id = "some-other-export-uuid"
        sameUpdated.openbao.maxHours = 6
        let updatePlan = try ProfileImportPlan.make(
            importing: sameUpdated,
            existing: [first],
            managedIDs: [],
            organizationPolicy: .empty
        )
        XCTAssertEqual(updatePlan.replaces?.id, first.id)
        XCTAssertEqual(updatePlan.profile.id, first.id)
    }
}

private struct MockMCPBackendForSecurity: BaoMCPBackend {
    let profiles: [BaoProfile]
    func listProfiles() async -> [BaoProfile] { profiles }
    func activeProfile(selector: String?) async throws -> BaoProfile {
        if let selector, let match = profiles.first(where: { $0.displayName == selector }) {
            return match
        }
        return profiles[0]
    }
    func status(profile: BaoProfile, targetScope: String, remoteTarget: String?) async -> BaoMCPStatusSnapshot {
        BaoMCPStatusSnapshot(serverName: profile.displayName, localActive: false)
    }
    func checkHealth(profile: BaoProfile) async throws -> ServerHealth {
        ServerHealth(initialized: true, sealed: false, version: "2.2.0")
    }
    func openApprovalUI(deepLink: String) async -> Bool { false }
    func revokeGrant(profile: BaoProfile, target: GrantTarget, remoteTarget: String?) async throws -> BaoMCPRevokeResult {
        BaoMCPRevokeResult(revokedOnServer: true, message: "ok")
    }
}

func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("expected an error", file: file, line: line)
    } catch {}
}
