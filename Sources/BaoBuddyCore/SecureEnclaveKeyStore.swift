import CryptoKit
import Foundation
import LocalAuthentication
import Security

public protocol BiometricSigner: Sendable {
    var deviceName: String { get }
    func publicKeyPEM() throws -> String
    func signES256(data: Data, reason: String) async throws -> Data
}

public enum SecureEnclaveError: Error, LocalizedError {
    case unavailable
    case accessControlCreationFailed(String)
    case keyGenerationFailed(String)
    case keychainError(OSStatus)
    case keyNotFound
    case scopedKeyRequired(server: String, mount: String)
    case signingFailed(String)
    case biometricCancelled

    public var errorDescription: String? {
        switch self {
        case .unavailable:
            return String(localized: "Apple Secure Enclave is not available on this device", table: "BaoBuddyCore", comment: "Error. Secure Enclave is an Apple product name.")
        case let .accessControlCreationFailed(detail):
            return String(localized: "Failed to create biometric access control: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is a system error message.")
        case let .keyGenerationFailed(detail):
            return String(localized: "Failed to create Secure Enclave key: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is a system error message.")
        case let .keychainError(status):
            return String(localized: "Keychain error storing Secure Enclave key handle (OSStatus \(status))", table: "BaoBuddyCore", comment: "Error. %d is a numeric system error code. Keep OSStatus.")
        case .keyNotFound:
            return String(localized: "No Secure Enclave signing key found for this server. Create and register a dedicated key for it first.", table: "BaoBuddyCore", comment: "Error shown when approving a grant before a key exists.")
        case let .scopedKeyRequired(server, mount):
            return String(localized: "No Secure Enclave key is set up for \(server) (auth/\(mount)/). Create a dedicated key in Settings → Hardware Approval Key (iOS) or run `bao-buddy device add --self` with your server's `--addr` and `--mount \(mount)` (plus `--namespace`, `--cacert`, `--mtls-identity` if configured) on macOS.", table: "BaoBuddyCore", comment: "Error. %1$@ is the server name; %2$@ and %3$@ are the JWT auth mount name. Do not translate anything inside backticks (it is a Terminal command and its options) or auth/…/. 'Settings → Hardware Approval Key' names an app screen and section.")
        case let .signingFailed(detail):
            return String(localized: "Secure Enclave signing failed: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is a system error message.")
        case .biometricCancelled:
            return String(localized: "Biometric authentication was cancelled", table: "BaoBuddyCore", comment: "Error shown when the user cancels Face ID or Touch ID.")
        }
    }
}

/// Manages a non-exportable EC P-256 key inside Apple's Secure Enclave gated by biometrics.
/// The macOS release stores its hardware-sealed handle in the helper’s private access group.
public struct SecureEnclaveKeyStore: BiometricSigner, Sendable {
    public let service: String
    public let account: String
    public let deviceName: String
    /// Optional human-readable server & mount scope for actionable missing-key guidance.
    public let scopeServer: String?
    public let scopeMount: String?

    /// Private designated initializer. Callers MUST use `scoped(...)` or `resolve(for:deviceName:)`
    /// so every biometric signing key is bound to an explicit deployment trust domain.
    private init(
        tag: String = "com.northcutt.baogrant.se.p256",
        account: String,
        deviceName: String,
        scopeServer: String? = nil,
        scopeMount: String? = nil
    ) {
        self.service = tag
        self.account = account
        self.deviceName = deviceName
        self.scopeServer = scopeServer
        self.scopeMount = scopeMount
    }

    /// Derives a distinct v3 Keychain account from the full issuer trust-domain binding
    /// (`issuerBindingKey`: origin + normalized base path + namespace + TLS CA pin + mTLS identity)
    /// plus the JWT mount, so distinct backends routed by path, TLS pin, or mTLS identity never
    /// share signing keys.
    public static func accountName(issuerBindingKey: String, mount: String) -> String {
        let cleanMount = mount.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let parts = [
            "v3",
            BaoOpenBaoConfig.encodeBindingComponent(issuerBindingKey),
            BaoOpenBaoConfig.encodeBindingComponent(cleanMount)
        ]
        let digest = SHA256.hash(data: Data(parts.joined(separator: "|").utf8))
            .map { String(format: "%02x", $0) }.joined()
        return "signing-key.v3.\(digest.prefix(24))"
    }

    public static func accountName(
        address: String,
        namespace: String = "",
        mount: String,
        caPEM: String = "",
        mtlsClientIdentity: String = ""
    ) -> String {
        let binding = BaoOpenBaoConfig.issuerBindingKey(
            address: address,
            namespace: namespace,
            caPEM: caPEM,
            mtlsClientIdentity: mtlsClientIdentity
        )
        return accountName(issuerBindingKey: binding, mount: mount)
    }

    /// Derives the per-trust-domain Keychain account for `profile`.
    public static func accountName(for profile: BaoProfile) -> String {
        accountName(
            issuerBindingKey: profile.openbao.issuerBindingKey,
            mount: profile.openbao.jwtAuth.mount
        )
    }

    /// Returns a key store strictly scoped to one server's full trust domain + JWT mount.
    public static func scoped(
        address: String,
        namespace: String = "",
        mount: String,
        caPEM: String = "",
        mtlsClientIdentity: String = "",
        deviceName: String,
        tag: String = "com.northcutt.baogrant.se.p256"
    ) -> SecureEnclaveKeyStore {
        SecureEnclaveKeyStore(
            tag: tag,
            account: accountName(
                address: address,
                namespace: namespace,
                mount: mount,
                caPEM: caPEM,
                mtlsClientIdentity: mtlsClientIdentity
            ),
            deviceName: deviceName,
            scopeServer: BaoOpenBaoConfig.normalizeAuthorityAndPath(address),
            scopeMount: mount
        )
    }

    /// Returns a key store strictly scoped to `profile`'s full trust domain + JWT mount.
    public static func scoped(
        for profile: BaoProfile,
        deviceName: String,
        tag: String = "com.northcutt.baogrant.se.p256"
    ) -> SecureEnclaveKeyStore {
        SecureEnclaveKeyStore(
            tag: tag,
            account: accountName(for: profile),
            deviceName: deviceName,
            scopeServer: profile.promptServerDescription,
            scopeMount: profile.openbao.jwtAuth.mount
        )
    }

    /// Resolves the signing key for `profile`: strictly returns the per-trust-domain key.
    /// Never falls back implicitly to the legacy shared `signing-key`, so an imported or
    /// unmigrated profile can never sign with another deployment's key.
    public static func resolve(
        for profile: BaoProfile,
        deviceName: String,
        tag: String = "com.northcutt.baogrant.se.p256"
    ) -> SecureEnclaveKeyStore {
        scoped(for: profile, deviceName: deviceName, tag: tag)
    }

    private var keyQuery: [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain as String] = true
        query[kSecAttrAccessGroup as String] = "BDQ47H73HH.com.northcutt.BaoBuddy.Helper"
        #endif
        return query
    }

    /// Metadata-only existence check that never reads secret key bytes and never triggers a
    /// macOS Keychain ACL prompt (`LAContext.interactionNotAllowed = true`).
    public func hasKey() -> Bool {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [String: Any] = keyQuery.merging([
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationContext as String: context
        ]) { _, value in value }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Creates a new hardware-backed P-256 key in the Secure Enclave if one doesn't exist.
    @discardableResult
    public func ensureKey(overwrite: Bool = false) throws -> String {
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.unavailable
        }
        // With `overwrite`, the new key is created first and then replaces the stored one in a
        // single Keychain update, so a failure part-way never leaves the device without a key.
        if !overwrite {
            do {
                return try publicKeyPEM()
            } catch SecureEnclaveError.scopedKeyRequired {
                // First enrollment for this issuer.
            } catch SecureEnclaveError.keyNotFound {
                // First enrollment for an explicitly constructed store.
            }
        }

        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            let detail = error?.takeRetainedValue().localizedDescription ?? "unknown error"
            throw SecureEnclaveError.accessControlCreationFailed(detail)
        }

        let privateKey: SecureEnclave.P256.Signing.PrivateKey
        do {
            privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
        } catch {
            throw SecureEnclaveError.keyGenerationFailed(error.localizedDescription)
        }
        do {
            try saveDataRepresentation(privateKey.dataRepresentation, overwrite: overwrite)
        } catch SecureEnclaveError.keychainError(errSecDuplicateItem) where !overwrite {
            return try publicKeyPEM()
        }
        return privateKey.publicKey.pemRepresentation
    }

    public func deleteKey() throws {
        let query: [String: Any] = keyQuery
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw SecureEnclaveError.keychainError(status)
        }
    }

    public func publicKeyPEM() throws -> String {
        let blob = try loadDataRepresentation()
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        return key.publicKey.pemRepresentation
    }

    public func publicKeyFingerprint() throws -> String {
        let blob = try loadDataRepresentation()
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        return try PEMCodec.spkiFingerprint(x963Data: key.publicKey.x963Representation)
    }

    public func signES256(data: Data, reason: String) async throws -> Data {
        let blob = try loadDataRepresentation()
        let context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0

        do {
            try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            let key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: blob,
                authenticationContext: context
            )
            let signature = try key.signature(for: data)
            return signature.rawRepresentation
        } catch let laError as LAError where laError.code == .userCancel {
            throw SecureEnclaveError.biometricCancelled
        } catch {
            let nsError = error as NSError
            if nsError.domain == LAErrorDomain, nsError.code == LAError.userCancel.rawValue {
                throw SecureEnclaveError.biometricCancelled
            }
            throw SecureEnclaveError.signingFailed(error.localizedDescription)
        }
    }

    private func loadDataRepresentation() throws -> Data {
        let query: [String: Any] = keyQuery.merging([
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]) { _, value in value }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            if let server = scopeServer, let mount = scopeMount {
                throw SecureEnclaveError.scopedKeyRequired(server: server, mount: mount)
            }
            throw SecureEnclaveError.keyNotFound
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw SecureEnclaveError.keychainError(status)
        }
        return data
    }

    private func saveDataRepresentation(_ data: Data, overwrite: Bool) throws {
        let match: [String: Any] = keyQuery
        if overwrite {
            let update = [kSecValueData as String: data]
            let status = SecItemUpdate(match as CFDictionary, update as CFDictionary)
            if status == errSecSuccess { return }
            guard status == errSecItemNotFound else { throw SecureEnclaveError.keychainError(status) }
        }
        var add = match
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        add[kSecAttrLabel as String] = "BaoBuddy Secure Enclave key"
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw SecureEnclaveError.keychainError(addStatus)
        }
    }
}
