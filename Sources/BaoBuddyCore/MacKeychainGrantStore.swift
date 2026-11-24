import CryptoKit
import Foundation
import Security

public protocol MacGrantStore: Sendable {
    /// Commits the token and all artifacts, returning the token actually displaced by this write.
    func replaceGrant(_ token: String, artifacts: [MintedExtensionArtifact]) throws -> String?
}

#if os(macOS)
public struct LocalGrantCleanupError: LocalizedError {
    public let underlying: Error
    public init(underlying: Error) { self.underlying = underlying }
    public var errorDescription: String? {
        "OpenBao confirmed revocation. Local Keychain cleanup is incomplete: " + underlying.localizedDescription
    }
}

protocol GrantKeychain: Sendable {
    func copy(_ query: [String: Any]) -> (OSStatus, Any?)
    func update(_ query: [String: Any], values: [String: Any]) -> OSStatus
    func add(_ query: [String: Any]) -> OSStatus
    func delete(_ query: [String: Any]) -> OSStatus
}

private struct SystemGrantKeychain: GrantKeychain {
    func copy(_ query: [String: Any]) -> (OSStatus, Any?) {
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        return (status, value)
    }
    func update(_ query: [String: Any], values: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, values as CFDictionary)
    }
    func add(_ query: [String: Any]) -> OSStatus { SecItemAdd(query as CFDictionary, nil) }
    func delete(_ query: [String: Any]) -> OSStatus { SecItemDelete(query as CFDictionary) }
}

public enum MacKeychainError: Error, LocalizedError {
    case writeFailed(OSStatus)

    public var errorDescription: String? {
        switch self {
        case let .writeFailed(status):
            return "Could not access grant in macOS Keychain (OSStatus \(status))"
        }
    }
}

/// Reads and writes issuer-scoped login Keychain items for local OpenBao grants and credential artifacts.
///
/// Each OpenBao server trust domain (normalized origin + namespace + CA pin + mTLS identity) gets its own
/// Keychain service (`openbao-grant.<issuerBindingKey>`), preventing a bearer token minted for Server A
/// from ever being sent to Server B during status checks, replacements, or revocations.
public struct MacKeychainGrantStore: MacGrantStore, Sendable {
    /// Legacy global Keychain service name kept only for documentation and explicit local migration notes.
    /// BaoBuddy never automatically reads or transmits untagged legacy items to any server.
    public static let legacyService = "openbao-grant"
    /// Base Keychain service name for credential-extension artifacts.
    public static let artifactService = "openbao-grant-artifact"

    public let service: String
    public let artifactServiceName: String
    public let account: String

    var keychain: any GrantKeychain = SystemGrantKeychain()
    var lockDirectory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/baobuddy")

    /// Computes the issuer-bound Keychain service name for `profile`.
    public static func serviceName(for profile: BaoProfile) -> String {
        "openbao-grant.\(profile.openbao.issuerBindingKey)"
    }

    /// Computes the issuer-bound Keychain artifact service name for `profile`.
    public static func artifactServiceName(for profile: BaoProfile) -> String {
        "openbao-grant-artifact.\(profile.openbao.issuerBindingKey)"
    }

    /// Creates a store bound to `profile`'s OpenBao issuer trust domain.
    public init(profile: BaoProfile, account: String = NSUserName()) {
        self.service = Self.serviceName(for: profile)
        self.artifactServiceName = Self.artifactServiceName(for: profile)
        self.account = account
    }

    public init(
        service: String = MacKeychainGrantStore.legacyService,
        artifactService: String? = nil,
        account: String = NSUserName()
    ) {
        self.service = service
        if let artifactService {
            self.artifactServiceName = artifactService
        } else if service == Self.legacyService {
            self.artifactServiceName = Self.artifactService
        } else {
            self.artifactServiceName = "\(service)-artifact"
        }
        self.account = account
    }

    private var journalService: String { service + ".transaction" }

    private enum Journal: Codable {
        case replacing(newDigest: Data, previousArtifacts: [MintedExtensionArtifact])
        case revoked(digest: Data)
    }

    private func digest(_ token: String) -> Data { Data(SHA256.hash(data: Data(token.utf8))) }

    private func match(_ service: String, _ account: String? = nil) -> [String: Any] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        if let account { query[kSecAttrAccount as String] = account }
        return query
    }

    private func read(_ service: String, itemAccount: String? = nil) throws -> Data? {
        var query = match(service, itemAccount ?? account)
        query[kSecReturnData as String] = true
        let (status, value) = keychain.copy(query)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = value as? Data else { throw MacKeychainError.writeFailed(status) }
        return data
    }

    private func currentToken() throws -> String? {
        guard let data = try read(service) else { return nil }
        guard let token = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !token.isEmpty else { throw MacKeychainError.writeFailed(errSecDecode) }
        return token
    }

    private func put(_ service: String, account: String, data: Data, label: String, comment: String = "") throws {
        let query = match(service, account)
        let values: [String: Any] = [kSecValueData as String: data, kSecAttrLabel as String: label, kSecAttrComment as String: comment]
        var status = keychain.update(query, values: values)
        if status == errSecItemNotFound {
            status = keychain.add(query.merging(values) { _, value in value })
        }
        guard status == errSecSuccess else { throw MacKeychainError.writeFailed(status) }
    }

    private func remove(_ service: String, account: String? = nil) throws {
        let status = keychain.delete(match(service, account))
        guard status == errSecSuccess || status == errSecItemNotFound else { throw MacKeychainError.writeFailed(status) }
    }

    private func artifactRows() throws -> [[String: Any]] {
        var query = match(artifactServiceName)
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnAttributes as String] = true
        let (status, value) = keychain.copy(query)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let rows = value as? [[String: Any]] else { throw MacKeychainError.writeFailed(status) }
        return rows
    }

    private func snapshot() throws -> [MintedExtensionArtifact] {
        try artifactRows().map { row in
            guard let name = row[kSecAttrAccount as String] as? String,
                  let data = try read(artifactServiceName, itemAccount: name),
                  let content = String(data: data, encoding: .utf8) else { throw MacKeychainError.writeFailed(errSecDecode) }
            let comment = row[kSecAttrComment as String] as? String ?? ""
            let expiry = comment.hasPrefix("expires_at=") ? Int64(comment.dropFirst("expires_at=".count)) : nil
            return MintedExtensionArtifact(name: name, content: content, expiresAt: expiry)
        }
    }

    private func setArtifacts(_ artifacts: [MintedExtensionArtifact]) throws {
        let desired = Set(artifacts.map(\.name))
        for artifact in artifacts {
            try put(artifactServiceName, account: artifact.name, data: Data(artifact.content.utf8),
                    label: "BaoBuddy credential: \(artifact.name)", comment: artifact.expiresAt.map { "expires_at=\($0)" } ?? "")
        }
        for name in try names() where !desired.contains(name) {
            try remove(artifactServiceName, account: name)
        }
    }

    private func names() throws -> [String] {
        try artifactRows().map { row in
            guard let name = row[kSecAttrAccount as String] as? String else { throw MacKeychainError.writeFailed(errSecDecode) }
            return name
        }.sorted()
    }

    private func record(_ journal: Journal) throws {
        try put(journalService, account: account, data: JSONEncoder().encode(journal), label: "BaoBuddy credential recovery")
    }

    // The token write is the commit point. After interruption the next helper operation
    // either restores the previous artifacts or discards the completed transaction.
    private func recover() throws {
        guard let data = try read(journalService) else { return }
        let current = try currentToken().map(digest)
        switch try JSONDecoder().decode(Journal.self, from: data) {
        case let .replacing(newDigest, previousArtifacts):
            if current != newDigest { try setArtifacts(previousArtifacts) }
        case let .revoked(digest):
            if current == digest {
                try remove(artifactServiceName)
                try remove(service, account: account)
            }
        }
        try remove(journalService, account: account)
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        let directory = lockDirectory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let fd = open(directory.appendingPathComponent("local-grants.lock").path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(fd) }
        while flock(fd, LOCK_EX) != 0 {
            if errno != EINTR { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        }
        try recover()
        return try body()
    }

    public func readGrant() throws -> String? { try withLock { try currentToken() } }

    public func artifactNames() throws -> [String] { try withLock { try names() } }

    public func replaceGrant(_ token: String, artifacts: [MintedExtensionArtifact]) throws -> String? {
        try withLock {
            let previous = try currentToken()
            try record(.replacing(newDigest: digest(token), previousArtifacts: try snapshot()))
            do {
                try setArtifacts(artifacts)
                try put(service, account: account, data: Data(token.utf8), label: "OpenBao grant")
            } catch {
                try recover()
                throw error
            }
            // A cleanup failure here must never roll back or revoke a committed grant.
            try? remove(journalService, account: account)
            return previous
        }
    }

    public func deleteRevokedGrant(matching token: String) throws {
        try withLock {
            guard try currentToken() == token else { return }
            try record(.revoked(digest: digest(token)))
            try recover()
        }
    }
}
#endif
