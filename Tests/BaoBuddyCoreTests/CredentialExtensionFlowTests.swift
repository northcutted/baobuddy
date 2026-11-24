import Foundation
import XCTest
@testable import BaoBuddyCore

/// Credential extensions end to end: scope, minting with the grant token, delivery, and cleanup.
final class CredentialExtensionFlowTests: XCTestCase {
    private let awsExtension = BaoCredentialExtension(
        id: "aws-sts",
        label: "AWS STS",
        endpoint: "aws/sts/deploy",
        method: .post,
        requestBody: ["ttl": "1h"],
        deliverAs: "aws-creds.json",
        policy: "aws-deploy",
        elevated: true
    )
    private let dbExtension = BaoCredentialExtension(
        id: "db",
        label: "DB",
        endpoint: "database/creds/readonly",
        method: .get,
        deliverAs: "db-creds.json"
    )

    private func profile(remote: Bool = false) -> BaoProfile {
        BaoProfile(
            version: 1,
            name: "Ext",
            openbao: .init(
                address: "https://bao.example:8200",
                caPEM: "",
                jwtAuth: .init(mount: "jwt-alice", role: "alice", issuer: "bao-granter", audience: "openbao-granter", subject: "alice"),
                tokenRoles: .init(mac: "grant", t3: "grant-remote"),
                policies: .init(read: "app-read", write: "app-write", keyPrefix: "", keyWriteSuffix: ""),
                extensions: [awsExtension, dbExtension, BaoCredentialExtension(id: "off", label: "Off", endpoint: "kv/x", deliverAs: "x", enabled: false)],
                maxHours: 12,
                keys: [],
                ssh: .init(role: "", hosts: []),
                githubAppItem: ""
            ),
            t3Granter: remote
                ? .init(name: "VM", host: "10.0.0.5", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample")
                : .init(name: "", host: "")
        )
    }

    /// Records which token called each extension endpoint and which tokens were revoked.
    private final class Recorder: @unchecked Sendable {
        var extensionCallers: [String: String] = [:]
        var revoked: [String] = []
        var denyAWS = false
    }

    private func transport(_ rec: Recorder) -> MockHTTPTransport {
        MockHTTPTransport { req in
            let token = req.value(forHTTPHeaderField: "X-Vault-Token") ?? ""
            switch req.url?.path {
            case "/v1/auth/jwt-alice/login":
                return (200, Data(#"{"auth":{"client_token":"s.signin"}}"#.utf8))
            case "/v1/auth/token/create/grant", "/v1/auth/token/create/grant-remote":
                return grantResponse(req, token: "s.grant")
            case "/v1/aws/sts/deploy":
                rec.extensionCallers["aws"] = token
                if rec.denyAWS { return (403, Data(#"{"errors":["permission denied"]}"#.utf8)) }
                return (200, Data(#"{"lease_id":"aws/sts/deploy/abc","lease_duration":3600,"data":{"access_key":"ASIA1","secret_key":"s","security_token":"t"}}"#.utf8))
            case "/v1/database/creds/readonly":
                rec.extensionCallers["db"] = token
                XCTAssertEqual(req.httpMethod, "GET")
                return (200, Data(#"{"lease_duration":600,"data":{"username":"u","password":"p"}}"#.utf8))
            case "/v1/auth/token/revoke":
                let body = try? JSONSerialization.jsonObject(with: req.httpBody ?? Data()) as? [String: String]
                rec.revoked.append(body?["token"] ?? "")
                return (204, Data())
            default:
                return (204, Data())
            }
        }
    }

    private func client(_ transport: MockHTTPTransport) -> OpenBaoClient {
        OpenBaoClient(baseURL: URL(string: "https://bao.example:8200")!, transport: transport)
    }

    func testExtensionsArePartOfTheApprovedScope() throws {
        let request = try GrantRequest.parse(requestString: "HOURS=1 EXT=aws-sts WHY=deploy", target: .mac, profile: profile())
        XCTAssertEqual(request.extensions, ["aws-sts"])
        XCTAssertEqual(request.canonicalText, "HOURS=1 EXT=aws-sts WHY=deploy")
        XCTAssertEqual(request.openBaoPolicies(profile: profile()), ["app-read", "aws-deploy"])
        XCTAssertTrue(request.isElevated(profile: profile()))
        XCTAssertTrue(request.scopeDescription(profile: profile()).contains("AWS STS [aws/sts/deploy, policy aws-deploy]"))
        // Disabled or unknown extensions can't be requested, by text or by link.
        XCTAssertThrowsError(try GrantRequest.parse(requestString: "EXT=off", target: .mac, profile: profile()))
        let link = try XCTUnwrap(URL(string: "baobuddy://grant?r=HOURS%3D1%20EXT%3Dnope"))
        XCTAssertThrowsError(try GrantRequest.parse(url: link, profile: profile()))
        let good = try XCTUnwrap(URL(string: "baobuddy://grant?target=local&r=HOURS%3D1%20EXT%3Ddb"))
        XCTAssertEqual(try GrantRequest.parse(url: good, profile: profile()).extensions, ["db"])
    }

    func testRemoteGrantMintsExtensionsWithTheGrantTokenAndDeliversV2() async throws {
        let rec = Recorder()
        let granter = MockT3Granter()
        let orchestrator = GrantOrchestrator(
            profile: profile(remote: true), signer: EphemeralP256Signer(), openbao: client(transport(rec)),
            t3Granter: granter, via: "test",
            onRemoteGrantMinted: { _, _ in }
        )
        _ = try await orchestrator.execute(GrantRequest(target: .t3, hours: 1, why: "deploy", extensions: ["aws-sts", "db"]))
        XCTAssertEqual(rec.extensionCallers["aws"], "s.grant", "extensions must use the grant token, not the sign-in token")
        XCTAssertEqual(rec.extensionCallers["db"], "s.grant")
        let payload = try XCTUnwrap(granter.installedPayload)
        XCTAssertEqual(payload.artifacts.map(\.name), ["aws-creds.json", "db-creds.json"])
        let now = Int64(Date().timeIntervalSince1970)
        for artifact in payload.artifacts {
            XCTAssertLessThanOrEqual(try XCTUnwrap(artifact.expiresAt), now + 3600 + 5, "artifacts can't outlive the grant")
        }
        let wire = try payload.encoded()
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(wire.utf8)) as? [String: Any])
        XCTAssertEqual(json["version"] as? Int, 2)
        XCTAssertEqual(Set(json.keys), ["version", "token", "ssh_cert", "push_token", "artifacts"], "the receiver rejects unknown keys")
        XCTAssertFalse(wire.contains("\\/"), "paths in artifacts shouldn't be escaped")
    }

    func testDeniedExtensionRevokesTheGrant() async throws {
        let rec = Recorder()
        rec.denyAWS = true
        let granter = MockT3Granter()
        let orchestrator = GrantOrchestrator(
            profile: profile(remote: true), signer: EphemeralP256Signer(), openbao: client(transport(rec)),
            t3Granter: granter, via: "test",
            onRemoteGrantMinted: { _, _ in }
        )
        do {
            _ = try await orchestrator.execute(GrantRequest(target: .t3, hours: 1, extensions: ["aws-sts"]))
            XCTFail("expected the extension to fail")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("aws-sts"))
        }
        XCTAssertNil(granter.installedPayload, "nothing is delivered when an extension fails")
        XCTAssertTrue(rec.revoked.contains("s.grant"), "the grant (and its leases) must be revoked")
    }

    func testLocalGrantSavesArtifactsAndRevokesOnFailure() async throws {
        let rec = Recorder()
        let store = MockMacGrantStore()
        let orchestrator = GrantOrchestrator(
            profile: profile(), signer: EphemeralP256Signer(), openbao: client(transport(rec)), macStore: store, via: "test"
        )
        let outcome = try await orchestrator.execute(GrantRequest(target: .mac, hours: 1, extensions: ["db"]))
        XCTAssertEqual(store.artifacts.map(\.name), ["db-creds.json"])
        XCTAssertTrue(outcome.message.contains("db-creds.json"))
        XCTAssertTrue(outcome.artifacts.isEmpty, "local artifacts go to the Keychain, not the caller")

        let failing = MockMacGrantStore()
        failing.failWrites = true
        let orchestrator2 = GrantOrchestrator(
            profile: profile(), signer: EphemeralP256Signer(), openbao: client(transport(rec)), macStore: failing, via: "test"
        )
        _ = try? await orchestrator2.execute(GrantRequest(target: .mac, hours: 1, extensions: ["db"]))
        XCTAssertTrue(rec.revoked.contains("s.grant"))
    }

    func testDirectTokenReturnsArtifacts() async throws {
        let orchestrator = GrantOrchestrator(
            profile: profile(), signer: EphemeralP256Signer(), openbao: client(transport(Recorder())), via: "test"
        )
        let outcome = try await orchestrator.mintDirectToken(GrantRequest(target: .mac, hours: 1, extensions: ["db"]))
        XCTAssertEqual(outcome.artifacts.first?.name, "db-creds.json")
        XCTAssertTrue(outcome.artifacts.first?.content.contains("password") == true)
    }

    func testInstallPayloadStaysV1WithoutArtifacts() throws {
        XCTAssertEqual(try GrantInstallPayload(token: "t", sshCert: "c", pushToken: "p").encoded(), "t\nc\np\n")
        let big = MintedExtensionArtifact(name: "big", content: String(repeating: "x", count: GrantInstallPayload.maxArtifactBytes + 1))
        XCTAssertThrowsError(try GrantInstallPayload(token: "t", artifacts: [big]).encoded())
    }

    func testValidationRejectsDangerousExtensions() {
        var bad = profile()
        bad.openbao.extensions = [BaoCredentialExtension(id: "x", label: "x", endpoint: "auth/token/create/grant", deliverAs: "x")]
        XCTAssertThrowsError(try bad.validate(requireHostKey: false))
        bad.openbao.extensions = [BaoCredentialExtension(id: "x", label: "x", endpoint: "kv/x", deliverAs: "x", policy: "root")]
        XCTAssertThrowsError(try bad.validate(requireHostKey: false))
        bad.openbao.extensions = [
            BaoCredentialExtension(id: "a", label: "a", endpoint: "kv/a", deliverAs: "same"),
            BaoCredentialExtension(id: "b", label: "b", endpoint: "kv/b", deliverAs: "same")
        ]
        XCTAssertThrowsError(try bad.validate(requireHostKey: false))
        XCTAssertNoThrow(try profile().validate(requireHostKey: false))
    }

    func testTofuGeneratesExtensionPolicies() {
        let spec = BaoTofuDeploymentSpec.from(profile: profile())
        XCTAssertEqual(spec.extensionPolicies, [BaoTofuExtensionPolicy(name: "aws-deploy", path: "aws/sts/deploy", capabilities: ["create", "update"])])
        XCTAssertTrue(spec.users.first?.allowedPolicies.contains("aws-deploy") == true)
        let tfvars = BaoTofuBuilder.generate(spec)["terraform.tfvars"] ?? ""
        XCTAssertTrue(tfvars.contains(#""aws-deploy" = { path = "aws/sts/deploy", capabilities = ["create", "update"] }"#))
    }
}
