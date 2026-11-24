@testable import BaoBuddyCore
import CryptoKit
import Foundation
import XCTest

private final class InMemoryMacGrantStore: MacGrantStore, @unchecked Sendable {
    var token: String?
    var artifacts: [String: String] = [:]

    func replaceGrant(_ newToken: String, artifacts list: [MintedExtensionArtifact]) throws -> String? {
        let previous = token
        artifacts = Dictionary(uniqueKeysWithValues: list.map { ($0.name, $0.content) })
        token = newToken
        return previous
    }
}

/// Live end-to-end Swift integration test against a real OpenBao server (`bao server -dev`).
/// Skipped during normal unit tests; enabled automatically by `scripts/integration-test-openbao.sh`
/// when `BAO_E2E_ADDR` and `BAO_E2E_TOKEN` are set.
final class LiveOpenBaoE2ETests: XCTestCase {
    func testSwiftJWTSignInMintExtensionAndAccessorRevokeAgainstLiveOpenBao() async throws {
        let env = ProcessInfo.processInfo.environment
        guard let addr = env["BAO_E2E_ADDR"], !addr.isEmpty,
              let rootToken = env["BAO_E2E_TOKEN"], !rootToken.isEmpty else {
            throw XCTSkip("Set BAO_E2E_ADDR and BAO_E2E_TOKEN (or run scripts/integration-test-openbao.sh) to run live OpenBao E2E tests.")
        }

        let baseURL = try XCTUnwrap(URL(string: addr))
        let transport = try PinnedTLSClient(caPEM: "")
        let client = OpenBaoClient(baseURL: baseURL, transport: transport)
        let admin = BaoServerAdmin(client: client, adminToken: rootToken)

        // 1. Verify health against live OpenBao.
        let health = try await client.checkHealth()
        XCTAssertTrue(health.initialized)
        XCTAssertFalse(health.sealed)

        // 2. Write a demo KV secret + policy that our credential extension will read using the grant token.
        _ = try await client.postJSONObject(
            path: "v1/secret/data/e2e/demo",
            token: rootToken,
            body: ["data": ["api_key": "ephemeral-demo-value"]]
        )
        _ = try await client.putJSONObject(
            path: "v1/sys/policies/acl/e2e-ext-read",
            token: rootToken,
            body: ["policy": "path \"secret/data/e2e/demo\" {\n  capabilities = [\"read\"]\n}\n"]
        )

        // 3. Bootstrap a dedicated ES256 JWT mount + least-privilege granter policy + orphan token role
        //    using the new origin+mount-bound default audience.
        let key = P256.Signing.PrivateKey()
        let pubPEM = key.publicKey.pemRepresentation
        let mount = "jwt-swift-e2e"
        let expectedAudience = BaoServerAdmin.defaultAudience(address: addr, namespace: "", mount: mount)
        let steps = try await admin.bootstrap(ServerBootstrapOptions(
            mount: mount,
            role: "granter",
            issuer: "bao-granter",
            subject: "swift-e2e",
            allowedPolicies: ["app-read", "e2e-ext-read"],
            maxHours: 2,
            initialPubKeys: [pubPEM]
        ))
        XCTAssertFalse(steps.isEmpty)

        // 3b. Two-operator isolation against live OpenBao: a second operator gets isolated defaults
        //     and is refused if attempting to reuse the first operator's token role or granter policy.
        let keyTwo = P256.Signing.PrivateKey()
        do {
            _ = try await admin.bootstrap(ServerBootstrapOptions(
                mount: "jwt-swift-e2e-two",
                role: "granter",
                issuer: "bao-granter",
                subject: "swift-e2e-two",
                granterPolicyName: "granter-swift-e2e-two",
                tokenRole: "grant-swift-e2e", // collides with operator 1!
                allowedPolicies: ["app-read"],
                maxHours: 1,
                initialPubKeys: [keyTwo.publicKey.pemRepresentation]
            ))
            XCTFail("Expected live OpenBao bootstrap to refuse shared token role across two operators")
        } catch ServerAdminError.sharedTokenRole {
            // Expected.
        }
        let op2Steps = try await admin.bootstrap(ServerBootstrapOptions(
            mount: "jwt-swift-e2e-two",
            role: "granter",
            issuer: "bao-granter",
            subject: "swift-e2e-two",
            allowedPolicies: ["app-read"],
            maxHours: 1,
            initialPubKeys: [keyTwo.publicKey.pemRepresentation]
        ))
        XCTAssertFalse(op2Steps.isEmpty)

        // 4. Construct a BaoProfile with an enabled credential extension and run GrantOrchestrator end-to-end.
        let ext = BaoCredentialExtension(
            id: "demo-kv",
            label: "Demo Secret",
            endpoint: "secret/data/e2e/demo",
            method: .get,
            tokenField: "",
            deliverAs: "demo.json",
            policy: "e2e-ext-read",
            elevated: false,
            enabled: true
        )
        let profile = BaoProfile(
            id: "live-e2e",
            version: 1,
            name: "Live E2E",
            openbao: BaoOpenBaoConfig(
                address: addr,
                caPEM: "",
                jwtAuth: BaoJWTAuthConfig(
                    mount: mount,
                    role: "granter",
                    issuer: "bao-granter",
                    audience: expectedAudience,
                    subject: "swift-e2e"
                ),
                tokenRoles: BaoTokenRolesConfig(mac: "grant-swift-e2e", t3: "grant-swift-e2e"),
                grantPolicies: [
                    BaoBuddyPolicy(name: "app-read", label: "App Read", elevated: false, defaultSelected: true)
                ],
                extensions: [ext],
                maxHours: 2,
                keys: [],
                ssh: BaoSSHConfig(role: "", hosts: []),
                githubAppItem: ""
            )
        )
        try profile.validate()

        let store = InMemoryMacGrantStore()
        let signer = EphemeralP256Signer(deviceName: "swift-e2e", privateKey: key)
        let orchestrator = GrantOrchestrator(
            profile: profile,
            signer: signer,
            openbao: client,
            macStore: store,
            via: "e2e"
        )

        let req = GrantRequest(
            target: .mac,
            hours: 1,
            customPolicies: ["app-read"],
            why: "swift live e2e",
            extensions: ["demo-kv"]
        )
        let outcome = try await orchestrator.execute(req)
        let mintedToken = try XCTUnwrap(store.token)
        let accessor = try XCTUnwrap(outcome.accessor)
        XCTAssertFalse(accessor.isEmpty)
        XCTAssertTrue(store.artifacts["demo.json"]?.contains("ephemeral-demo-value") == true)

        // 5. Verify live token policies and TTL via OpenBao lookup-self.
        let info = try await client.lookupSelf(token: mintedToken)
        XCTAssertGreaterThan(info.ttlSeconds, 0)
        XCTAssertTrue(info.policies.contains("app-read"))
        XCTAssertTrue(info.policies.contains("e2e-ext-read"))
        XCTAssertEqual(info.why, "swift live e2e")

        // 6. Revoke the grant by accessor using a fresh ES256 JWT sign-in, then confirm OpenBao rejects it.
        try await orchestrator.revokeRemoteGrant(accessor: accessor)
        do {
            _ = try await client.lookupSelf(token: mintedToken)
            XCTFail("Expected revoked token to be rejected by live OpenBao")
        } catch OpenBaoError.httpError(let code, _) {
            XCTAssertEqual(code, 403)
        }
    }
}
