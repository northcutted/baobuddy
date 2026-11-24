@testable import BaoBuddyCore
import Foundation
import XCTest

final class Phase2Tests: XCTestCase {
    private func makeMultiTargetProfile() -> BaoProfile {
        BaoProfile(
            id: "prod-server",
            version: 1,
            name: "Production",
            openbao: .init(
                address: "https://vault.corp.example:8200",
                namespace: "admin/prod",
                caPEM: "-----BEGIN CERTIFICATE-----\n" + String(repeating: "A", count: 800) + "\n-----END CERTIFICATE-----",
                jwtAuth: .init(
                    mount: "jwt-alice",
                    role: "granter",
                    issuer: "bao-granter",
                    audience: "openbao-granter",
                    subject: "alice"
                ),
                tokenRoles: .init(mac: "grant", t3: "grant"),
                grantPolicies: [
                    .init(name: "db-readonly", label: "DB Read-Only", elevated: false, defaultSelected: true),
                    .init(name: "k8s-deploy", label: "K8s Deploy", elevated: true, defaultSelected: false)
                ],
                auditPolicy: .init(requireReasonForElevated: true, reasonPattern: "^CHG-[0-9]+"),
                maxHours: 8,
                keys: [],
                ssh: .init(role: "", hosts: []),
                githubAppItem: ""
            ),
            remoteTargets: [
                .init(name: "T3 VM", host: "10.0.0.5", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOne"),
                .init(name: "Prod Bastion", host: "10.0.0.9", port: 2222, user: "ops", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITwo")
            ]
        )
    }

    // MARK: - Profile Transfer Codec (QR Pairing)

    func testProfileTransferCodecCompressesAndRoundTrips() throws {
        let profile = makeMultiTargetProfile()
        let uri = try ProfileTransferCodec.encodeURI(profile)
        XCTAssertTrue(uri.hasPrefix("baobuddy://import?p="))

        let url = try XCTUnwrap(URL(string: uri))
        XCTAssertTrue(ProfileTransferCodec.isImportURL(url))

        // Compressed URI should be substantially smaller than raw JSON (PEM compresses well).
        let rawJSON = try JSONEncoder().encode(profile)
        XCTAssertLessThan(uri.utf8.count, rawJSON.count)

        let decodedFromURL = try ProfileTransferCodec.decode(url: url)
        XCTAssertEqual(decodedFromURL, profile)

        let decodedFromText = try ProfileTransferCodec.decode(text: uri)
        XCTAssertEqual(decodedFromText, profile)

        let rawJSONString = try XCTUnwrap(String(data: rawJSON, encoding: .utf8))
        let decodedFromJSON = try ProfileTransferCodec.decode(text: rawJSONString)
        XCTAssertEqual(decodedFromJSON, profile)
    }

    func testProfileTransferCodecRejectsGarbagePayload() {
        XCTAssertThrowsError(try ProfileTransferCodec.decode(text: "baobuddy://import?p=not-valid-zlib!!!"))
        XCTAssertThrowsError(try ProfileTransferCodec.decode(text: ""))
    }

    // MARK: - Multi-Remote Targets

    func testMultiRemoteTargetsRoundTripAndSelector() throws {
        let profile = makeMultiTargetProfile()
        try profile.validate()

        let data = try JSONEncoder().encode(profile)
        let jsonText = try XCTUnwrap(String(data: data, encoding: .utf8))
        XCTAssertTrue(jsonText.contains("\"remote_targets\""))

        let decoded = try BaoProfile.decode(from: data)
        XCTAssertEqual(decoded.configuredRemoteTargets.count, 2)
        XCTAssertEqual(decoded.targetDisplayName, "T3 VM")

        let bastion = try XCTUnwrap(decoded.remoteTarget(named: "prod bastion"))
        XCTAssertEqual(bastion.host, "10.0.0.9")
        XCTAssertEqual(bastion.port, 2222)

        let focused = decoded.focusing(remoteTarget: bastion)
        XCTAssertEqual(focused.targetDisplayName, "Prod Bastion")
        XCTAssertEqual(focused.t3Granter.host, "10.0.0.9")
        XCTAssertEqual(focused.configuredRemoteTargets.count, 2)
    }

    func testDuplicateRemoteTargetNamesRejected() {
        var profile = makeMultiTargetProfile()
        profile.remoteTargets = [
            .init(name: "Bastion", host: "10.0.0.5", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAA1"),
            .init(name: "bastion", host: "10.0.0.6", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAA2")
        ]
        XCTAssertThrowsError(try profile.validate())
    }

    // MARK: - Local Grant Activity Store

    func testGrantActivityStorePersistsCapsAndExportsCSV() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = GrantActivityStore(fileURL: dir.appendingPathComponent("activity.json"), maxEntries: 3)

        for idx in 1...5 {
            store.record(GrantActivityEntry(
                action: .granted,
                serverName: "Prod",
                namespace: "admin/prod",
                targetName: "Bastion",
                policies: ["db-readonly", "k8s-deploy"],
                hours: idx,
                why: "CHG-\(idx), \"urgent\"",
                elevated: true,
                via: "mac"
            ))
        }

        let loaded = store.load()
        XCTAssertEqual(loaded.count, 3)
        XCTAssertEqual(loaded.first?.hours, 5)
        XCTAssertEqual(loaded.last?.hours, 3)

        let csv = store.exportCSV(loaded)
        XCTAssertTrue(csv.contains("timestamp,action,server,namespace,target,policies,hours,elevated,via,why"))
        XCTAssertTrue(csv.contains("\"CHG-5, \"\"urgent\"\"\""))

        try store.clear()
        XCTAssertTrue(store.load().isEmpty)
    }
}
