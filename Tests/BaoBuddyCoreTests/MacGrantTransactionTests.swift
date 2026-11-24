#if os(macOS)
@testable import BaoBuddyCore
import Security
import XCTest

private final class TestGrantKeychain: GrantKeychain, @unchecked Sendable {
    typealias Row = [String: Any]
    var rows: [String: Row] = [:]
    var denyReads = false
    var deniedDeleteService: String?
    var deniedAccount: String?
    var denyRollback = false

    private func key(_ q: Row) -> String {
        "\(q[kSecAttrService as String] as! String)/\(q[kSecAttrAccount as String] as! String)"
    }

    func copy(_ q: Row) -> (OSStatus, Any?) {
        if denyReads { return (errSecInteractionNotAllowed, nil) }
        if q[kSecAttrAccount as String] == nil {
            let results = rows.values.filter { ($0[kSecAttrService as String] as? String) == (q[kSecAttrService as String] as? String) }
            return results.isEmpty ? (errSecItemNotFound, nil) : (errSecSuccess, Array(results))
        }
        guard let row = rows[key(q)] else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, row[kSecValueData as String])
    }

    func update(_ q: Row, values: Row) -> OSStatus {
        guard let row = rows[key(q)] else { return errSecItemNotFound }
        if denyRollback, values[kSecValueData as String] as? Data == Data("old contents".utf8) { return errSecIO }
        rows[key(q)] = row.merging(values) { _, value in value }
        return errSecSuccess
    }

    func add(_ q: Row) -> OSStatus {
        if q[kSecAttrAccount as String] as? String == deniedAccount { return errSecIO }
        rows[key(q)] = q
        return errSecSuccess
    }

    func delete(_ q: Row) -> OSStatus {
        if let deniedDeleteService, q[kSecAttrService as String] as? String == deniedDeleteService { return errSecIO }
        if q[kSecAttrAccount as String] == nil {
            rows = rows.filter { ($0.value[kSecAttrService as String] as? String) != (q[kSecAttrService as String] as? String) }
        } else {
            rows.removeValue(forKey: key(q))
        }
        return errSecSuccess
    }
}

final class MacGrantTransactionTests: XCTestCase {
    func testPinnedTransportReleasesItsSession() async throws {
        weak var session: URLSession?
        try autoreleasepool {
            let client = try PinnedTLSClient(caPEM: "")
            session = client.session
            XCTAssertNotNil(session)
        }
        for _ in 0..<100 where session != nil {
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertNil(session)
    }

    func testIssuerEvidenceRequiredToReportAnInactiveSavedGrant() async throws {
        let address = try XCTUnwrap(URL(string: "https://example.invalid"))
        for (status, body, inactive) in [
            (403, #"{"errors":["permission denied","bad token"]}"#, true),
            (403, #"{"errors":["permission denied; bad token"]}"#, false),
            (403, #"{"errors":["permission denied"]}"#, false),
            (503, #"{"errors":["invalid token"]}"#, false),
            (200, #"{"data":{"ttl":0}}"#, false)
        ] {
            let client = OpenBaoClient(baseURL: address, transport: MockHTTPTransport { _ in (status, Data(body.utf8)) })
            do {
                let result = try await client.lookupSavedGrant(token: "fixture")
                XCTAssertNil(result)
                XCTAssertTrue(inactive)
            } catch {
                XCTAssertFalse(inactive)
            }
        }
    }

    func testUnknownStatusNeverSerializesAsInactive() throws {
        let snapshot = BaoMCPStatusSnapshot(serverName: "test", localActive: false, localUnavailable: true)
        let local = try XCTUnwrap(snapshot.toDictionary()["local"] as? [String: Any])
        XCTAssertTrue(local["active"] is NSNull)
        XCTAssertEqual(local["status"] as? String, "unknown")
    }

    func testInterruptedReplacementRecoversPreviousTokenAndArtifacts() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let backend = TestGrantKeychain()
        var store = MacKeychainGrantStore(service: "test")
        store.keychain = backend
        store.lockDirectory = directory

        XCTAssertNil(try store.readGrant())
        let old = MintedExtensionArtifact(name: "first", content: "old contents", expiresAt: 42)
        XCTAssertNil(try store.replaceGrant("previous", artifacts: [old]))
        backend.deniedAccount = "second"
        backend.denyRollback = true
        XCTAssertThrowsError(try store.replaceGrant("replacement", artifacts: [
            .init(name: "first", content: "changed", expiresAt: nil),
            .init(name: "second", content: "another", expiresAt: nil)
        ]))
        XCTAssertThrowsError(try store.readGrant())
        backend.denyRollback = false
        XCTAssertEqual(try store.readGrant(), "previous")
        XCTAssertEqual(backend.rows["test-artifact/first"]?[kSecValueData as String] as? Data, Data(old.content.utf8))
        XCTAssertEqual(backend.rows["test-artifact/first"]?[kSecAttrComment as String] as? String, "expires_at=42")
        XCTAssertEqual(try store.artifactNames(), ["first"])
        XCTAssertEqual(try store.replaceGrant("replacement", artifacts: []), "previous")
        try store.deleteRevokedGrant(matching: "previous")
        XCTAssertEqual(try store.readGrant(), "replacement")
        backend.denyReads = true
        XCTAssertThrowsError(try store.readGrant())
        XCTAssertThrowsError(try store.deleteRevokedGrant(matching: "replacement"))
        backend.denyReads = false
        backend.deniedDeleteService = "test-artifact"
        XCTAssertThrowsError(try store.deleteRevokedGrant(matching: "replacement"))
        XCTAssertThrowsError(try store.readGrant())
        backend.deniedDeleteService = nil
        XCTAssertNil(try store.readGrant())
    }
}
#endif
