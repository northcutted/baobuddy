import BaoBuddyCore
import CryptoKit
import NIOCore
import NIOEmbedded
import NIOSSH
import XCTest
@testable import BaoBuddySSH

final class BaoBuddySSHTests: XCTestCase {
    // MARK: - Exit status handling

    private func runHandler(
        stdout: String = "",
        exitStatus: Int? = nil,
        exitSignal: String? = nil
    ) throws -> Result<String, Error> {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: String.self)
        let handler = ExecIOHandler(command: "status", stdin: nil, resultPromise: promise)
        try channel.pipeline.syncOperations.addHandler(handler)

        if !stdout.isEmpty {
            let buffer = channel.allocator.buffer(string: stdout)
            channel.pipeline.fireChannelRead(NIOAny(SSHChannelData(type: .channel, data: .byteBuffer(buffer))))
        }
        if let exitStatus {
            channel.pipeline.fireUserInboundEventTriggered(SSHChannelRequestEvent.ExitStatus(exitStatus: exitStatus))
        }
        if let exitSignal {
            channel.pipeline.fireUserInboundEventTriggered(
                SSHChannelRequestEvent.ExitSignal(signalName: exitSignal, errorMessage: "", language: "", dumpedCore: false)
            )
        }
        channel.pipeline.fireChannelInactive()

        var result: Result<String, Error>?
        promise.futureResult.whenComplete { result = $0 }
        channel.embeddedEventLoop.run()
        return try XCTUnwrap(result)
    }

    func testZeroExitStatusSucceeds() throws {
        let result = try runHandler(stdout: "Secrets: no grant.\n", exitStatus: 0)
        XCTAssertEqual(try result.get(), "Secrets: no grant.\n")
    }

    func testMissingExitStatusIsFailureNotSuccess() throws {
        let result = try runHandler(stdout: "Granted until 10:00", exitStatus: nil)
        XCTAssertThrowsError(try result.get())
    }

    func testExitSignalIsFailure() throws {
        let result = try runHandler(stdout: "partial", exitSignal: "KILL")
        XCTAssertThrowsError(try result.get()) { error in
            XCTAssertTrue(error.localizedDescription.contains("KILL"))
        }
    }

    func testNonZeroExitStatusIsFailure() throws {
        let result = try runHandler(exitStatus: 3)
        XCTAssertThrowsError(try result.get())
    }

    // Finding 6: Exit statuses above Int32.max (e.g. UInt32.max = 4294967295) must fail cleanly instead of trapping.
    func testLargeUnsignedExitStatusDoesNotTrap() throws {
        let result = try runHandler(stdout: "bad", exitStatus: Int(UInt32.max))
        XCTAssertThrowsError(try result.get()) { error in
            XCTAssertTrue(error.localizedDescription.contains("4294967295"), error.localizedDescription)
        }
    }

    // Finding 15: Unbounded SSH stdout/stderr closes the channel and fails with outputLimitExceeded.
    func testOversizedSSHOutputFailsWithOutputLimitExceeded() throws {
        let channel = EmbeddedChannel()
        let promise = channel.eventLoop.makePromise(of: String.self)
        let handler = ExecIOHandler(command: "status", stdin: nil, resultPromise: promise, maxOutputBytes: 64)
        try channel.pipeline.syncOperations.addHandler(handler)

        let oversized = channel.allocator.buffer(string: String(repeating: "A", count: 128))
        channel.pipeline.fireChannelRead(NIOAny(SSHChannelData(type: .channel, data: .byteBuffer(oversized))))
        channel.pipeline.fireChannelInactive()

        var result: Result<String, Error>?
        promise.futureResult.whenComplete { result = $0 }
        channel.embeddedEventLoop.run()
        let unwrapped = try XCTUnwrap(result)
        XCTAssertThrowsError(try unwrapped.get()) { error in
            guard case T3GranterError.outputLimitExceeded("status", 64) = error else {
                XCTFail("expected outputLimitExceeded, got \(error)")
                return
            }
        }
    }

    // MARK: - Host key pinning

    private func validate(pinned: String, presented: NIOSSHPublicKey) throws -> Bool {
        let loop = EmbeddedEventLoop()
        let delegate = try PinnedHostKeyDelegate(knownHostLine: pinned)
        let promise = loop.makePromise(of: Void.self)
        delegate.validateHostKey(hostKey: presented, validationCompletePromise: promise)
        var accepted = false
        promise.futureResult.whenComplete { accepted = (try? $0.get()) != nil }
        loop.run()
        return accepted
    }

    func testHostKeyPinningAcceptsOnlyThePinnedKey() throws {
        let hostKey = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey()).publicKey
        let other = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey()).publicKey
        let line = String(openSSHPublicKey: hostKey)

        XCTAssertTrue(try validate(pinned: line, presented: hostKey))
        XCTAssertTrue(try validate(pinned: "t3-vm.lan \(line)", presented: hostKey))
        XCTAssertFalse(try validate(pinned: line, presented: other))
        XCTAssertFalse(try validate(pinned: "", presented: hostKey), "an empty pin must refuse, never trust on first use")
    }

    // MARK: - Identity formatting

    func testEd25519IdentityMatchesLegacyFormat() {
        let key = Curve25519.Signing.PrivateKey()
        let identity = SSHClientIdentity.ed25519(key)
        XCTAssertEqual(
            identity.openSSHPublicKey(comment: "test"),
            SSHKeyStore.openSSHPublicKey(for: key.publicKey, comment: "test")
        )
        XCTAssertFalse(identity.isHardwareBacked)
    }
}
