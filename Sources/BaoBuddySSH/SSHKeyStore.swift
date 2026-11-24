import CryptoKit
import Foundation
import NIOSSH
import Security

public enum SSHKeyStoreError: Error, LocalizedError {
    case keychainError(OSStatus)
    case invalidKeyData
    case secureEnclaveUnavailable
    case accessControl(String)

    public var errorDescription: String? {
        switch self {
        case let .keychainError(status):
            return String(localized: "SSH key Keychain error (OSStatus \(status))", table: "BaoBuddyCore", comment: "Error. %d is a numeric system error code. Keep OSStatus.")
        case .invalidKeyData:
            return String(localized: "Stored SSH private key data is invalid", table: "BaoBuddyCore", comment: "Error.")
        case .secureEnclaveUnavailable:
            return String(localized: "The Secure Enclave isn't available on this device", table: "BaoBuddyCore", comment: "Error. Secure Enclave is an Apple product name.")
        case let .accessControl(detail):
            return String(localized: "Couldn't create the SSH key's access control: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is a system error message.")
        }
    }
}

/// The key this device uses to sign in to a remote granter host.
///
/// A final class rather than an enum or struct: apps that link this module don't link NIO
/// themselves, so NIO types must not appear in a layout the app has to copy.
public final class SSHClientIdentity: Sendable {
    let nioKey: NIOSSHPrivateKey
    /// True for a non-exportable P-256 key in the Secure Enclave (`ecdsa-sha2-nistp256`); false for
    /// a legacy software Ed25519 key stored in the Keychain.
    public let isHardwareBacked: Bool

    init(nioKey: NIOSSHPrivateKey, isHardwareBacked: Bool) {
        self.nioKey = nioKey
        self.isHardwareBacked = isHardwareBacked
    }

    static func secureEnclave(_ key: NIOSSHPrivateKey) -> SSHClientIdentity {
        SSHClientIdentity(nioKey: key, isHardwareBacked: true)
    }

    public static func ed25519(_ key: Curve25519.Signing.PrivateKey) -> SSHClientIdentity {
        SSHClientIdentity(nioKey: NIOSSHPrivateKey(ed25519Key: key), isHardwareBacked: false)
    }

    /// `authorized_keys` line, for example `ecdsa-sha2-nistp256 AAAA... baobuddy-iphone`.
    public func openSSHPublicKey(comment: String) -> String {
        "\(String(openSSHPublicKey: nioKey.publicKey)) \(comment)"
    }
}

/// Manages this device's SSH client key for remote grant delivery.
///
/// New keys live in the Secure Enclave, so they can't be copied off the device. They aren't
/// gated by biometrics, because status checks run without a prompt; every grant they deliver
/// was minted only after a biometric sign-in. Older installs may still hold a software Ed25519
/// key, which keeps working until a Secure Enclave key is created.
public struct SSHKeyStore: Sendable {
    public let service: String
    public let account: String
    public let secureEnclaveAccount: String

    public init(
        service: String = "com.northcutt.baogrant.ssh",
        account: String = "t3-granter-ed25519",
        secureEnclaveAccount: String = "ssh-p256-secure-enclave"
    ) {
        self.service = service
        self.account = account
        self.secureEnclaveAccount = secureEnclaveAccount
    }

    /// The identity to use: the Secure Enclave key when there is one, otherwise a legacy key.
    public func loadIdentity() throws -> SSHClientIdentity? {
        if let blob = try loadItem(account: secureEnclaveAccount) {
            do {
                let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
                return .secureEnclave(NIOSSHPrivateKey(secureEnclaveP256Key: key))
            } catch {
                throw SSHKeyStoreError.invalidKeyData
            }
        }
        if let legacy = try loadPrivateKey() {
            return .ed25519(legacy)
        }
        return nil
    }

    /// Creates (or with `overwrite`, replaces) the Secure Enclave SSH key. Once it exists it takes
    /// precedence over a legacy Ed25519 key, which is then deleted.
    @discardableResult
    public func ensureSecureEnclaveIdentity(overwrite: Bool = false) throws -> SSHClientIdentity {
        if !overwrite, let existing = try loadIdentity(), existing.isHardwareBacked {
            return existing
        }
        guard SecureEnclave.isAvailable else {
            throw SSHKeyStoreError.secureEnclaveUnavailable
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &error
        ) else {
            throw SSHKeyStoreError.accessControl(error?.takeRetainedValue().localizedDescription ?? "unknown")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try saveItem(account: secureEnclaveAccount, data: key.dataRepresentation)
        try? deleteItem(account: account)
        return .secureEnclave(NIOSSHPrivateKey(secureEnclaveP256Key: key))
    }

    /// Legacy: creates a software Ed25519 key. Kept for tests and granter hosts that can't accept
    /// ECDSA keys; prefer `ensureSecureEnclaveIdentity()`.
    public func ensurePrivateKey(overwrite: Bool = false) throws -> Curve25519.Signing.PrivateKey {
        if !overwrite, let existing = try loadPrivateKey() {
            return existing
        }
        let key = Curve25519.Signing.PrivateKey()
        try saveItem(account: account, data: key.rawRepresentation)
        return key
    }

    public func loadPrivateKey() throws -> Curve25519.Signing.PrivateKey? {
        guard let data = try loadItem(account: account) else { return nil }
        do {
            return try Curve25519.Signing.PrivateKey(rawRepresentation: data)
        } catch {
            throw SSHKeyStoreError.invalidKeyData
        }
    }

    /// Formats an Ed25519 public key in OpenSSH wire format (`ssh-ed25519 AAAA...`).
    public static func openSSHPublicKey(for publicKey: Curve25519.Signing.PublicKey, comment: String = "baobuddy-app") -> String {
        let keyType = Data("ssh-ed25519".utf8)
        let raw = publicKey.rawRepresentation
        var blob = Data()
        var typeLen = UInt32(keyType.count).bigEndian
        blob.append(Data(bytes: &typeLen, count: 4))
        blob.append(keyType)
        var rawLen = UInt32(raw.count).bigEndian
        blob.append(Data(bytes: &rawLen, count: 4))
        blob.append(raw)
        return "ssh-ed25519 \(blob.base64EncodedString()) \(comment)"
    }

    // MARK: - Keychain

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    private func loadItem(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw SSHKeyStoreError.keychainError(status)
        }
        return data
    }

    private func saveItem(account: String, data: Data) throws {
        let match = baseQuery(account: account)
        let status = SecItemUpdate(match as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess {
            return
        }
        if status != errSecItemNotFound {
            throw SSHKeyStoreError.keychainError(status)
        }
        var add = match
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw SSHKeyStoreError.keychainError(addStatus)
        }
    }

    private func deleteItem(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw SSHKeyStoreError.keychainError(status)
        }
    }
}
