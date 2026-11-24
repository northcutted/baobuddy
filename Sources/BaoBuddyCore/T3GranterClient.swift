import Foundation

public enum T3GranterError: Error, LocalizedError {
    case sshFailed(Int32, String)
    case invalidPublicKey(String)
    case installRefused(String)
    case timedOut(String)
    case outputLimitExceeded(String, Int)
    case missingHostKey

    public static let maxCommandOutputBytes = 64 * 1024

    public var errorDescription: String? {
        switch self {
        case let .sshFailed(code, detail):
            return String(localized: "SSH to the remote granter failed (exit \(code)): \(detail)", table: "BaoBuddyCore", comment: "Error. %1$d is a numeric exit code; %2$@ is a technical detail. The remote granter is the host that receives grants over SSH.")
        case let .invalidPublicKey(detail):
            return String(localized: "The remote granter returned an unexpected SSH public key: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is the key text received.")
        case let .installRefused(detail):
            return String(localized: "The remote granter refused the grant: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is the remote host's message.")
        case let .timedOut(command):
            return String(localized: "The remote granter didn't finish '\(command)' in time; the connection was closed", table: "BaoBuddyCore", comment: "Error. %@ is a command name (for example install or status); do not translate it.")
        case let .outputLimitExceeded(command, limit):
            return String(localized: "The remote granter exceeded the \(limit)-byte output limit for '\(command)'; the connection was closed", table: "BaoBuddyCore", comment: "Error. %1$lld is a number of bytes; %2$@ is a command name (do not translate it).")
        case .missingHostKey:
            return String(localized: "The profile has no remote_target.host_key; refusing to connect to an unverified SSH host", table: "BaoBuddyCore", comment: "Error. Do not translate remote_target.host_key (a setting name).")
        }
    }
}

public struct RunningTasksResult: Equatable, Sendable {
    public let tasks: [String]
    public let brokerUnavailable: Bool

    public init(tasks: [String], brokerUnavailable: Bool) {
        self.tasks = tasks
        self.brokerUnavailable = brokerUnavailable
    }
}

/// Talks to a remote granter host's forced command (`tasks`, `pubkey`, `install`, `status`, `revoke`).
/// What a remote grant delivers to the remote host's `install` command.
public struct GrantInstallPayload: Equatable, Sendable {
    public let token: String
    public let sshCert: String
    public let pushToken: String
    public let artifacts: [MintedExtensionArtifact]

    /// `baobuddy-receiver` limits, checked here too so an oversized delivery fails before it's sent.
    public static let maxArtifacts = 16
    public static let maxArtifactBytes = 64 * 1024
    public static let maxPayloadBytes = 256 * 1024

    public init(token: String, sshCert: String = "", pushToken: String = "", artifacts: [MintedExtensionArtifact] = []) {
        self.token = token
        self.sshCert = sshCert
        self.pushToken = pushToken
        self.artifacts = artifacts
    }

    /// The stdin text for `install`: the original three-line format when there are no artifacts,
    /// which every granter host understands, or the version 2 JSON envelope that
    /// `baobuddy-receiver` accepts.
    public func encoded() throws -> String {
        guard !artifacts.isEmpty else {
            return "\(token)\n\(sshCert)\n\(pushToken)\n"
        }
        guard artifacts.count <= Self.maxArtifacts else {
            throw T3GranterError.installRefused("too many credential artifacts (\(artifacts.count), max \(Self.maxArtifacts))")
        }
        for artifact in artifacts where artifact.content.utf8.count > Self.maxArtifactBytes {
            throw T3GranterError.installRefused("credential artifact \(artifact.name) exceeds \(Self.maxArtifactBytes) bytes")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(InstallEnvelopeV2(token: token, sshCert: sshCert, pushToken: pushToken, artifacts: artifacts))
        guard data.count <= Self.maxPayloadBytes, let text = String(bytes: data, encoding: .utf8) else {
            throw T3GranterError.installRefused("grant delivery exceeds \(Self.maxPayloadBytes) bytes")
        }
        return text + "\n"
    }
}

/// The `baobuddy-receiver` v2 install envelope. Its keys must match the receiver exactly,
/// because the receiver rejects unknown fields.
private struct InstallEnvelopeV2: Encodable {
    let version = 2
    let token: String
    let sshCert: String
    let pushToken: String
    let artifacts: [MintedExtensionArtifact]

    enum CodingKeys: String, CodingKey {
        case version, token, artifacts
        case sshCert = "ssh_cert"
        case pushToken = "push_token"
    }
}

public protocol T3GranterTransport: Sendable {
    func runningTasks() async -> RunningTasksResult
    func fetchPublicKey() async throws -> String
    func install(_ payload: GrantInstallPayload) async throws -> String
    func status() async throws -> String
    func revoke() async throws -> String
}

extension T3GranterTransport {
    public func install(token: String, sshCert: String, pushToken: String) async throws -> String {
        try await install(GrantInstallPayload(token: token, sshCert: sshCert, pushToken: pushToken))
    }
}

#if os(macOS)
/// Legacy macOS transport using `/usr/bin/ssh` and a key file (by default `~/.ssh/id_ed25519`).
/// The helper prefers `NIOSSHGranterClient` with a Secure Enclave key (`bao-buddy ssh-key`);
/// this path remains for setups whose granter host only trusts an existing key file.
///
/// It ignores the user's ssh configuration entirely (`-F /dev/null`) so settings such as
/// `StrictHostKeyChecking accept-new`, `ForwardAgent yes`, or global known_hosts can't weaken it,
/// and it refuses to run without a pinned host key.
public struct MacSSHGranterClient: T3GranterTransport, Sendable {
    public let config: BaoProfile.T3GranterConfig
    public let identityPath: String
    public let timeoutSeconds: TimeInterval

    public init(
        config: BaoProfile.T3GranterConfig,
        identityPath: String = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh/id_ed25519").path,
        timeoutSeconds: TimeInterval = 30
    ) {
        self.config = config
        self.identityPath = identityPath
        self.timeoutSeconds = timeoutSeconds
    }

    public func runningTasks() async -> RunningTasksResult {
        do {
            let output = try await runSSH(command: "tasks", stdin: nil)
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
        let out = try await runSSH(command: "pubkey", stdin: nil).trimmingCharacters(in: .whitespacesAndNewlines)
        guard out.hasPrefix("ssh-ed25519 ") else {
            throw T3GranterError.invalidPublicKey(out)
        }
        return out
    }

    public func install(_ payload: GrantInstallPayload) async throws -> String {
        let out = try await runSSH(command: "install", stdin: try payload.encoded()).trimmingCharacters(in: .whitespacesAndNewlines)
        guard out.hasPrefix("Granted until ") else {
            throw T3GranterError.installRefused(out)
        }
        return out
    }

    public func status() async throws -> String {
        try await runSSH(command: "status", stdin: nil).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public func revoke() async throws -> String {
        try await runSSH(command: "revoke", stdin: nil).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The exact arguments passed to `/usr/bin/ssh`, exposed for tests.
    public func sshArguments(command: String, knownHostsPath: String) throws -> [String] {
        try config.validateForSSH()
        return [
            "-F", "/dev/null",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=8",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2",
            "-i", identityPath,
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UpdateHostKeys=no",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UserKnownHostsFile=\(knownHostsPath)",
            "-o", "PermitLocalCommand=no",
            "-p", String(config.port),
            // `--` ends option parsing, so the destination can never be read as an ssh option.
            "--", "\(config.user)@\(config.host)", command
        ]
    }

    /// The known_hosts line for the pinned key. `ssh-keygen -F` output (`<host> <type> <key>`) is
    /// re-keyed to this host, and a bare `<type> <key>` gets the host prepended.
    func knownHostsLine() throws -> String {
        let trimmed = config.hostKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw T3GranterError.missingHostKey }
        let parts = trimmed.split(whereSeparator: \.isWhitespace).map(String.init)
        let keyParts: [String]
        if parts.count >= 3, parts[1].hasPrefix("ssh-") || parts[1].hasPrefix("ecdsa-") {
            keyParts = Array(parts[1...2])
        } else if parts.count >= 2 {
            keyParts = Array(parts[0...1])
        } else {
            throw T3GranterError.sshFailed(-1, "invalid pinned host_key in profile")
        }
        let hostField = config.port == 22 ? config.host : "[\(config.host)]:\(config.port)"
        return "\(hostField) \(keyParts.joined(separator: " "))"
    }

    private func runSSH(command: String, stdin: String?) async throws -> String {
        let line = try knownHostsLine()
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("baobuddy-known-\(UUID().uuidString)")
        try (line + "\n").write(to: tmp, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let arguments = try sshArguments(command: command, knownHostsPath: tmp.path)
        return try await Self.runBoundedProcess(
            executableURL: URL(fileURLWithPath: "/usr/bin/ssh"),
            arguments: arguments,
            command: command,
            stdin: stdin,
            timeoutSeconds: timeoutSeconds,
            maxOutputBytes: T3GranterError.maxCommandOutputBytes
        )
    }

    /// Runs a child process with cancellation-aware timeout enforcement, SIGTERM/SIGKILL cleanup,
    /// non-blocking stdin delivery, and strict per-stream output byte limits.
    static func runBoundedProcess(
        executableURL: URL,
        arguments: [String],
        command: String,
        stdin: String?,
        timeoutSeconds: TimeInterval,
        maxOutputBytes: Int = T3GranterError.maxCommandOutputBytes
    ) async throws -> String {
        let process = Process()
        process.executableURL = executableURL
        process.arguments = arguments

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        let inPipe = Pipe()
        process.standardInput = stdin == nil ? FileHandle.nullDevice : inPipe

        let exited = AsyncExit()
        let collector = OutputCollector(maxBytes: maxOutputBytes) {
            // Immediately stop a runaway child that floods stdout/stderr.
            Self.terminateProcess(process)
        }
        outPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if chunk.isEmpty {
                handle.readabilityHandler = nil
                return
            }
            collector.appendOut(chunk)
        }
        errPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if chunk.isEmpty {
                handle.readabilityHandler = nil
                return
            }
            collector.appendErr(chunk)
        }

        process.terminationHandler = { exited.signal($0.terminationStatus) }
        try process.run()

        if let stdin {
            let writeHandle = inPipe.fileHandleForWriting
            let payload = Data(stdin.utf8)
            DispatchQueue.global(qos: .userInitiated).async {
                try? writeHandle.write(contentsOf: payload)
                try? writeHandle.close()
            }
        }

        let timeoutNanos = UInt64(max(0.05, timeoutSeconds) * 1_000_000_000)
        let status: Int32? = await withTaskGroup(of: Int32?.self) { group in
            group.addTask { await exited.wait() }
            group.addTask {
                try? await Task.sleep(nanoseconds: timeoutNanos)
                return nil
            }
            let first = await group.next().flatMap { $0 }
            group.cancelAll()
            return first
        }

        defer {
            outPipe.fileHandleForReading.readabilityHandler = nil
            errPipe.fileHandleForReading.readabilityHandler = nil
            try? outPipe.fileHandleForReading.close()
            try? errPipe.fileHandleForReading.close()
            if stdin != nil {
                try? inPipe.fileHandleForWriting.close()
            }
        }

        if collector.didOverflow {
            Self.terminateProcess(process)
            await Self.waitForExitOrKill(process: process, exited: exited)
            throw T3GranterError.outputLimitExceeded(command, maxOutputBytes)
        }

        guard let status else {
            Self.terminateProcess(process)
            await Self.waitForExitOrKill(process: process, exited: exited)
            if collector.didOverflow {
                throw T3GranterError.outputLimitExceeded(command, maxOutputBytes)
            }
            throw T3GranterError.timedOut(command)
        }

        outPipe.fileHandleForReading.readabilityHandler = nil
        errPipe.fileHandleForReading.readabilityHandler = nil
        if let tailOut = try? outPipe.fileHandleForReading.read(upToCount: maxOutputBytes + 1), !tailOut.isEmpty {
            collector.appendOut(tailOut)
        }
        if let tailErr = try? errPipe.fileHandleForReading.read(upToCount: maxOutputBytes + 1), !tailErr.isEmpty {
            collector.appendErr(tailErr)
        }
        if collector.didOverflow {
            throw T3GranterError.outputLimitExceeded(command, maxOutputBytes)
        }
        let (stdoutData, stderrData) = collector.snapshot()
        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""
        guard status == 0 else {
            let detail = stderr.isEmpty ? stdout : stderr
            throw T3GranterError.sshFailed(status, detail.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return stdout
    }

    private static func terminateProcess(_ process: Process) {
        if process.isRunning {
            process.terminate()
        }
    }

    private static func waitForExitOrKill(process: Process, exited: AsyncExit) async {
        let finished: Int32? = await withTaskGroup(of: Int32?.self) { group in
            group.addTask { await exited.wait() }
            group.addTask {
                try? await Task.sleep(nanoseconds: 500_000_000)
                return nil
            }
            let first = await group.next().flatMap { $0 }
            group.cancelAll()
            return first
        }
        if finished == nil && process.isRunning {
            kill(process.processIdentifier, SIGKILL)
            _ = await exited.wait()
        }
    }
}

private final class OutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private let maxBytes: Int
    private let onOverflow: @Sendable () -> Void
    private var out = Data()
    private var err = Data()
    private var overflowed = false

    init(maxBytes: Int, onOverflow: @escaping @Sendable () -> Void) {
        self.maxBytes = maxBytes
        self.onOverflow = onOverflow
    }

    var didOverflow: Bool {
        lock.lock()
        defer { lock.unlock() }
        return overflowed
    }

    func appendOut(_ data: Data) {
        var trigger = false
        lock.lock()
        if !overflowed {
            if out.count + data.count > maxBytes {
                overflowed = true
                trigger = true
            } else {
                out.append(data)
            }
        }
        lock.unlock()
        if trigger { onOverflow() }
    }

    func appendErr(_ data: Data) {
        var trigger = false
        lock.lock()
        if !overflowed {
            if err.count + data.count > maxBytes {
                overflowed = true
                trigger = true
            } else {
                err.append(data)
            }
        }
        lock.unlock()
        if trigger { onOverflow() }
    }

    func snapshot() -> (Data, Data) {
        lock.lock()
        defer { lock.unlock() }
        return (out, err)
    }
}

/// Bridges `Process.terminationHandler` to async/await with cancellation support so a timed-out
/// `withTaskGroup` never deadlocks waiting for a hung child process.
private final class AsyncExit: @unchecked Sendable {
    private let lock = NSLock()
    private var status: Int32?
    private var waiters: [UUID: CheckedContinuation<Int32?, Never>] = [:]

    func signal(_ value: Int32) {
        lock.lock()
        status = value
        let pending = Array(waiters.values)
        waiters.removeAll()
        lock.unlock()
        pending.forEach { $0.resume(returning: value) }
    }

    private func cancelWaiter(_ id: UUID) {
        lock.lock()
        let cont = waiters.removeValue(forKey: id)
        lock.unlock()
        cont?.resume(returning: nil)
    }

    func wait() async -> Int32? {
        let waiterID = UUID()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                lock.lock()
                if let status {
                    lock.unlock()
                    continuation.resume(returning: status)
                } else if Task.isCancelled {
                    lock.unlock()
                    continuation.resume(returning: nil)
                } else {
                    waiters[waiterID] = continuation
                    lock.unlock()
                }
            }
        } onCancel: {
            cancelWaiter(waiterID)
        }
    }
}
#endif
