import BaoBuddyCore
import CryptoKit
import Foundation
import NIOCore
import NIOPosix
import NIOSSH

/// Pure-Swift SSH transport to a remote granter host, built on Apple's `swift-nio-ssh`.
/// Pins the host key (refusing to connect without one), authenticates with a Secure Enclave
/// P-256 key (or a legacy Ed25519 key), bounds every command with a timeout, and treats a
/// missing exit status as failure.
///
/// A final class so apps that link this module never need NIO's type layouts (see `SSHClientIdentity`).
public final class NIOSSHGranterClient: T3GranterTransport, Sendable {
    public let config: BaoProfile.T3GranterConfig
    let privateKey: NIOSSHPrivateKey
    let timeout: TimeAmount

    public init(config: BaoProfile.T3GranterConfig, identity: SSHClientIdentity, timeoutSeconds: Int64 = 30) {
        self.config = config
        self.privateKey = identity.nioKey
        self.timeout = .seconds(timeoutSeconds)
    }

    public convenience init(config: BaoProfile.T3GranterConfig, privateKey: Curve25519.Signing.PrivateKey, timeoutSeconds: Int64 = 30) {
        self.init(config: config, identity: .ed25519(privateKey), timeoutSeconds: timeoutSeconds)
    }

    public func runningTasks() async -> RunningTasksResult {
        do {
            let output = try await runExec(command: "tasks", stdin: nil)
            let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                return RunningTasksResult(tasks: [], brokerUnavailable: false)
            }
            if trimmed.hasPrefix("!") {
                return RunningTasksResult(tasks: [], brokerUnavailable: true)
            }
            let lines = trimmed
                .split(separator: "\n")
                .map { String($0).trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            return RunningTasksResult(tasks: lines, brokerUnavailable: false)
        } catch {
            return RunningTasksResult(tasks: [], brokerUnavailable: true)
        }
    }

    public func fetchPublicKey() async throws -> String {
        let out = try await runExec(command: "pubkey", stdin: nil).trimmingCharacters(in: .whitespacesAndNewlines)
        guard out.hasPrefix("ssh-ed25519 ") else {
            throw T3GranterError.invalidPublicKey(out)
        }
        return out
    }

    public func install(_ payload: GrantInstallPayload) async throws -> String {
        let out = try await runExec(command: "install", stdin: try payload.encoded()).trimmingCharacters(in: .whitespacesAndNewlines)
        guard out.hasPrefix("Granted until ") else {
            throw T3GranterError.installRefused(out)
        }
        return out
    }

    public func status() async throws -> String {
        try await runExec(command: "status", stdin: nil).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public func revoke() async throws -> String {
        try await runExec(command: "revoke", stdin: nil).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func runExec(command: String, stdin: String?) async throws -> String {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        do {
            let result = try await runExec(on: group, command: command, stdin: stdin)
            try await group.shutdownGracefully()
            return result
        } catch {
            try? await group.shutdownGracefully()
            throw error
        }
    }

    private func runExec(on group: EventLoopGroup, command: String, stdin: String?) async throws -> String {
        let hostValidator = try PinnedHostKeyDelegate(knownHostLine: config.hostKey)
        let userAuth = PublicKeyUserAuthDelegate(username: config.user, privateKey: privateKey)

        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(.seconds(8))
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let clientConfig = SSHClientConfiguration(
                        userAuthDelegate: userAuth,
                        serverAuthDelegate: hostValidator
                    )
                    try channel.pipeline.syncOperations.addHandler(
                        NIOSSHHandler(
                            role: .client(clientConfig),
                            allocator: channel.allocator,
                            inboundChildChannelInitializer: nil
                        )
                    )
                }
            }

        let channel = try await bootstrap.connect(host: config.host, port: config.port).get()
        do {
            let output = try await executeOnChannel(channel, command: command, stdin: stdin)
            try? await channel.close().get()
            return output
        } catch {
            try? await channel.close().get()
            throw error
        }
    }

    private func executeOnChannel(_ channel: Channel, command: String, stdin: String?) async throws -> String {
        let loop = channel.eventLoop
        let resultPromise = loop.makePromise(of: String.self)
        // Whatever happens first settles the result; later completions are ignored by NIO.
        let deadline = loop.scheduleTask(in: timeout) {
            resultPromise.fail(T3GranterError.timedOut(command))
            channel.close(promise: nil)
        }
        channel.closeFuture.whenComplete { _ in
            resultPromise.fail(T3GranterError.sshFailed(-1, String(localized: "connection closed before '\(command)' finished", table: "BaoBuddyCore", comment: "Error detail. %@ is a command name (for example install); do not translate it.")))
        }
        channel.pipeline.handler(type: NIOSSHHandler.self).whenComplete { result in
            switch result {
            case let .success(sshHandler):
                let createPromise = loop.makePromise(of: Channel.self)
                createPromise.futureResult.whenFailure { resultPromise.fail($0) }
                sshHandler.createChannel(createPromise) { child, channelType in
                    guard channelType == .session else {
                        return child.eventLoop.makeFailedFuture(T3GranterError.sshFailed(-1, "unexpected SSH channel type"))
                    }
                    return child.pipeline.addHandler(
                        ExecIOHandler(command: command, stdin: stdin, resultPromise: resultPromise)
                    )
                }
            case let .failure(error):
                resultPromise.fail(error)
            }
        }
        defer { deadline.cancel() }
        return try await resultPromise.futureResult.get()
    }
}

private final class PublicKeyUserAuthDelegate: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    private let username: String
    private let sshKey: NIOSSHPrivateKey
    private var tried = false

    init(username: String, privateKey: NIOSSHPrivateKey) {
        self.username = username
        self.sshKey = privateKey
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard !tried, availableMethods.contains(.publicKey) else {
            nextChallengePromise.succeed(nil)
            return
        }
        tried = true
        nextChallengePromise.succeed(
            NIOSSHUserAuthenticationOffer(
                username: username,
                serviceName: "",
                offer: .privateKey(.init(privateKey: sshKey))
            )
        )
    }
}

final class PinnedHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {
    private let pinnedKey: NIOSSHPublicKey?

    init(knownHostLine: String) throws {
        let trimmed = knownHostLine.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            self.pinnedKey = nil
            return
        }
        // `ssh-keygen -F` produces: `<host> <type> <base64>` (or bare `<type> <base64>`).
        let parts = trimmed.split(whereSeparator: \.isWhitespace).map(String.init)
        let openSSH: String
        if parts.count >= 3, parts[1].hasPrefix("ssh-") || parts[1].hasPrefix("ecdsa-") {
            openSSH = "\(parts[1]) \(parts[2])"
        } else if parts.count >= 2 {
            openSSH = "\(parts[0]) \(parts[1])"
        } else {
            throw T3GranterError.sshFailed(-1, "invalid pinned host_key in profile")
        }
        self.pinnedKey = try NIOSSHPublicKey(openSSHPublicKey: openSSH)
    }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        guard let pinnedKey else {
            validationCompletePromise.fail(
                T3GranterError.sshFailed(-1, String(localized: "Profile has no pinned t3_granter.host_key; refusing unverified SSH host", table: "BaoBuddyCore", comment: "Error detail. Do not translate t3_granter.host_key (a setting name)."))
            )
            return
        }
        if hostKey == pinnedKey {
            validationCompletePromise.succeed(())
        } else {
            validationCompletePromise.fail(
                T3GranterError.sshFailed(-1, String(localized: "The remote target's SSH host key does not match the pinned key in the profile", table: "BaoBuddyCore", comment: "Error detail: the SSH server presented a different host key than the one saved in the server profile."))
            )
        }
    }
}

final class ExecIOHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    private let command: String
    private let stdin: String?
    private let resultPromise: EventLoopPromise<String>
    private let maxOutputBytes: Int
    private var stdout = ByteBuffer()
    private var stderr = ByteBuffer()
    /// Nil until the server reports one. A session that ends without an exit status (for example
    /// a command killed by a signal) is a failure, never a silent success.
    /// Stored as `Int` (SSH exit status is `uint32`) so values > `Int32.max` never trap.
    private var exitCode: Int?
    private var exitSignal: String?
    private var completed = false

    init(
        command: String,
        stdin: String?,
        resultPromise: EventLoopPromise<String>,
        maxOutputBytes: Int = T3GranterError.maxCommandOutputBytes
    ) {
        self.command = command
        self.stdin = stdin
        self.resultPromise = resultPromise
        self.maxOutputBytes = maxOutputBytes
    }

    func handlerAdded(context: ChannelHandlerContext) {
        let loopBoundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            loopBoundContext.value.fireErrorCaught(error)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        let loopBoundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let exec = SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true)
        context.triggerUserOutboundEvent(exec).whenComplete { [self] result in
            let ctx = loopBoundContext.value
            switch result {
            case .success:
                if let stdin {
                    let buf = ctx.channel.allocator.buffer(string: stdin)
                    let payload = SSHChannelData(type: .channel, data: .byteBuffer(buf))
                    ctx.writeAndFlush(self.wrapOutboundOut(payload)).whenComplete { _ in
                        loopBoundContext.value.close(mode: .output, promise: nil)
                    }
                } else {
                    ctx.close(mode: .output, promise: nil)
                }
            case let .failure(error):
                self.finish(with: .failure(error))
                ctx.close(promise: nil)
            }
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !completed else { return }
        let sshData = unwrapInboundIn(data)
        guard case .byteBuffer(var buffer) = sshData.data else { return }
        switch sshData.type {
        case .channel:
            guard stdout.readableBytes + buffer.readableBytes <= maxOutputBytes else {
                finish(with: .failure(T3GranterError.outputLimitExceeded(command, maxOutputBytes)))
                context.close(promise: nil)
                return
            }
            stdout.writeBuffer(&buffer)
        case .stdErr:
            guard stderr.readableBytes + buffer.readableBytes <= maxOutputBytes else {
                finish(with: .failure(T3GranterError.outputLimitExceeded(command, maxOutputBytes)))
                context.close(promise: nil)
                return
            }
            stderr.writeBuffer(&buffer)
        default:
            break
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let status = event as? SSHChannelRequestEvent.ExitStatus {
            exitCode = status.exitStatus
        } else if let signal = event as? SSHChannelRequestEvent.ExitSignal {
            exitSignal = signal.signalName
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        finish(with: .failure(error))
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        let outText = stdout.readString(length: stdout.readableBytes) ?? ""
        let errText = stderr.readString(length: stderr.readableBytes) ?? ""
        let detail = (errText.isEmpty ? outText : errText).trimmingCharacters(in: .whitespacesAndNewlines)
        switch (exitCode, exitSignal) {
        case (0, nil):
            finish(with: .success(outText))
        case let (code?, nil):
            let clamped = Int32(clamping: code)
            let fullDetail: String
            if code > Int(Int32.max) || code < Int(Int32.min) {
                fullDetail = detail.isEmpty ? "exit status \(code)" : "exit status \(code): \(detail)"
            } else {
                fullDetail = detail
            }
            finish(with: .failure(T3GranterError.sshFailed(clamped, fullDetail)))
        case let (_, signal?):
            finish(with: .failure(T3GranterError.sshFailed(-1, "remote command killed by signal \(signal). \(detail)")))
        case (nil, nil):
            finish(with: .failure(T3GranterError.sshFailed(-1, "remote command ended without an exit status. \(detail)")))
        }
    }

    private func finish(with result: Result<String, Error>) {
        guard !completed else { return }
        completed = true
        resultPromise.completeWith(result)
    }
}
