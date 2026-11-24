import BaoBuddyCore
import Foundation
import XCTest

/// Emit the exact bytes these clients send to the SSH forced command.
final class ReceiverWireFixtureTests: XCTestCase {
    func testEncodeInstallPayloads() throws {
        let env = ProcessInfo.processInfo.environment
        guard let directory = env["BAOBUDDY_WIRE_FIXTURE_DIR"] else {
            throw XCTSkip("Run scripts/integration-test-openbao.sh --wire to exercise the receiver")
        }
        let root = URL(fileURLWithPath: directory, isDirectory: true)
        let token = try String(contentsOf: root.appendingPathComponent("input-token"), encoding: .utf8)
        let artifact = MintedExtensionArtifact(name: "fixture.txt", content: "wire fixture")
        for (file, artifacts) in [("v1", []), ("v2", [artifact])] {
            let payload = GrantInstallPayload(token: token, artifacts: artifacts)
            try Data(payload.encoded().utf8).write(to: root.appendingPathComponent(file))
        }
    }
}
