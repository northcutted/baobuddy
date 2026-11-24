@testable import BaoBuddyCore
import CryptoKit
import Foundation
import XCTest

final class DemoModeTests: XCTestCase {
    func testDemoModeFullRemoteFlowVerifiesES256JWTDeliversV2ExtensionAndRevokesByAccessor() async throws {
        let signer = EphemeralP256Signer(deviceName: "demo-iphone")
        let pubPEM = try signer.publicKeyPEM()
        let demoProfile = BaoDemo.makeProfile(remoteTarget: true)
        XCTAssertTrue(demoProfile.isDemoProfile)
        try demoProfile.validate(requireHostKey: true, allowDemo: true)

        let transport = try DemoOpenBaoTransport(trustedPublicKeyPEMs: [pubPEM])
        let granter = DemoGranterTransport(openbao: transport)
        let openbao = OpenBaoClient(
            baseURL: try XCTUnwrap(URL(string: demoProfile.openbao.address)),
            transport: transport
        )

        // 1. Health check works in memory.
        let health = try await openbao.checkHealth()
        XCTAssertTrue(health.initialized)
        XCTAssertFalse(health.sealed)

        // 2. Running tasks returns simulated workloads.
        let tasks = await granter.runningTasks()
        XCTAssertFalse(tasks.brokerUnavailable)
        XCTAssertFalse(tasks.tasks.isEmpty)

        // 3. Execute a 2-hour remote grant with db-demo credential extension + SSH cert.
        let orchestrator = GrantOrchestrator(
            profile: demoProfile,
            signer: signer,
            openbao: openbao,
            t3Granter: granter,
            via: "demo"
        )
        let req = GrantRequest(
            target: .t3,
            hours: 2,
            sshHosts: ["staging-web"],
            customPolicies: ["db-readonly"],
            why: "demo walkthrough",
            extensions: ["db-demo"]
        )
        let outcome = try await orchestrator.execute(req)
        let accessor = try XCTUnwrap(outcome.accessor)
        XCTAssertFalse(accessor.isEmpty)
        XCTAssertEqual(granter.currentArtifactNames, ["db-creds.json"])

        let activeStatus = try await granter.status()
        let parsed = RemoteStatusSummary.parse(activeStatus)
        XCTAssertEqual(parsed.headerState, .active)
        XCTAssertTrue(
            parsed.entries[0].statusText == "Active · 2h left" || parsed.entries[0].statusText == "Active · 1h 59m left",
            "Expected ~2h left for a 2h demo grant, got: \(parsed.entries[0].statusText)"
        )
        XCTAssertTrue(parsed.entries[0].detail.contains("db-creds.json"))
        XCTAssertEqual(parsed.entries[1].detail, "ops@staging-web")
        XCTAssertTrue(
            parsed.entries[1].statusText == "Active · 2h left" || parsed.entries[1].statusText == "Active · 1h 59m left",
            "Expected ~2h left on SSH row, got: \(parsed.entries[1].statusText)"
        )

        // The app shows the time left from the real expiry, not the host's English text.
        let expiry = try XCTUnwrap(granter.activeGrantExpiry)
        XCTAssertEqual(expiry.timeIntervalSinceNow, 7_200, accuracy: 60)

        // 4. Revoke via OpenBao accessor (real ES256 JWT login again) + remote host revoke.
        try await orchestrator.revokeRemoteGrant(accessor: accessor)
        _ = try await granter.revoke()
        let idleStatus = try await granter.status()
        XCTAssertTrue(idleStatus.contains("Secrets: no grant."))
        XCTAssertNil(granter.activeGrantExpiry)
        XCTAssertTrue(granter.currentArtifactNames.isEmpty)
    }

    func testDemoSampleActivityIsOlderHistoryWithOneElevatedGrantAndSanitizedReasons() {
        let now = Date()
        let profile = BaoDemo.makeProfile(remoteTarget: true)
        let entries = BaoDemo.sampleActivity(profile: profile, now: now)
        XCTAssertEqual(entries.map(\.action), [.revoked, .granted])
        XCTAssertEqual(entries.filter(\.elevated).count, 1)
        XCTAssertTrue(entries.allSatisfy { $0.timestamp < now && $0.via == "demo" })
        XCTAssertTrue(entries.allSatisfy { $0.why == GrantRequest.sanitizeWhy($0.why) })
    }

    func testDemoModeDirectTokenFlowMintsExtensionAndRevokesSelf() async throws {
        let signer = EphemeralP256Signer(deviceName: "demo-iphone")
        let pubPEM = try signer.publicKeyPEM()
        let demoProfile = BaoDemo.makeProfile(remoteTarget: false)
        let transport = try DemoOpenBaoTransport(trustedPublicKeyPEMs: [pubPEM])
        let openbao = OpenBaoClient(
            baseURL: try XCTUnwrap(URL(string: demoProfile.openbao.address)),
            transport: transport
        )
        let orchestrator = GrantOrchestrator(
            profile: demoProfile,
            signer: signer,
            openbao: openbao,
            via: "demo"
        )
        let req = GrantRequest(
            target: .mac,
            hours: 1,
            customPolicies: ["db-readonly"],
            why: "direct demo",
            extensions: ["db-demo"]
        )
        let outcome = try await orchestrator.mintDirectToken(req)
        let token = try XCTUnwrap(outcome.mintedToken)
        XCTAssertEqual(outcome.artifacts.map(\.name), ["db-creds.json"])
        XCTAssertTrue(outcome.artifacts[0].content.contains("v-demo-readonly-"))

        let lookup = try await openbao.lookupSelf(token: token)
        XCTAssertTrue(lookup.policies.contains("db-readonly"))
        XCTAssertTrue(lookup.policies.contains("db-demo-read"))

        try await openbao.revokeSelf(token: token)
        do {
            _ = try await openbao.lookupSelf(token: token)
            XCTFail("Expected revoked demo token to fail lookup-self")
        } catch OpenBaoError.httpError(let code, _) {
            XCTAssertEqual(code, 403)
        }
    }

    func testDemoOpenBaoTransportRejectsUntrustedJWTSignature() async throws {
        let registered = EphemeralP256Signer(deviceName: "registered")
        let attacker = EphemeralP256Signer(deviceName: "attacker")
        let demoProfile = BaoDemo.makeProfile(remoteTarget: false)
        let transport = try DemoOpenBaoTransport(trustedPublicKeyPEMs: [try registered.publicKeyPEM()])
        let openbao = OpenBaoClient(
            baseURL: try XCTUnwrap(URL(string: demoProfile.openbao.address)),
            transport: transport
        )
        let orchestrator = GrantOrchestrator(
            profile: demoProfile,
            signer: attacker,
            openbao: openbao,
            via: "demo"
        )
        let req = GrantRequest(target: .mac, hours: 1, customPolicies: ["db-readonly"], why: "spoof")
        do {
            _ = try await orchestrator.mintDirectToken(req)
            XCTFail("Expected DemoOpenBaoTransport to reject an ES256 JWT signed by an unregistered key")
        } catch OpenBaoError.httpError(let code, _) {
            XCTAssertEqual(code, 403)
        }
    }

    func testDemoProfileIsRejectedOnImportExportAndPersistence() throws {
        let demoProfile = BaoDemo.makeProfile(remoteTarget: true)

        // Cannot validate as a normal profile.
        XCTAssertThrowsError(try demoProfile.validate(requireHostKey: true))

        // Cannot export/share as a pairing URI.
        XCTAssertThrowsError(try ProfileTransferCodec.encodeURI(demoProfile))

        // Cannot import JSON that claims the reserved demo host or ID.
        let jsonData = try JSONEncoder().encode(demoProfile)
        let jsonText = try XCTUnwrap(String(data: jsonData, encoding: .utf8))
        XCTAssertThrowsError(try ProfileTransferCodec.decode(text: jsonText, requireHostKey: false))

        var spoofedHost = BaoDemo.makeProfile(remoteTarget: false)
        spoofedHost.id = "custom-id"
        XCTAssertThrowsError(try spoofedHost.validate(requireHostKey: false))

        // MultiProfileStore strips demo profiles on save so they never hit disk.
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("baobuddy-demo-store-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let store = MultiProfileStore(url: tmp)
        try store.save(ProfileCollection(activeProfileID: demoProfile.id, profiles: [demoProfile]))
        let loaded = store.load()
        XCTAssertTrue(loaded.profiles.isEmpty)
        XCTAssertNil(loaded.activeProfileID)
    }
}
