import CryptoKit
import Foundation
import Security

public protocol HTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public enum PinnedTLSError: Error, LocalizedError {
    case invalidCertificate
    case nonHTTPResponse
    case trustEvaluationFailed(String)
    case missingClientIdentity(String)
    case ambiguousClientIdentity(String, Int)

    public var errorDescription: String? {
        switch self {
        case .invalidCertificate:
            return String(localized: "Could not parse the pinned OpenBao CA certificate PEM", table: "BaoBuddyCore", comment: "Error. CA = certificate authority; PEM is a file format.")
        case .nonHTTPResponse:
            return String(localized: "Unexpected non-HTTP response", table: "BaoBuddyCore", comment: "Error.")
        case let .trustEvaluationFailed(detail):
            return String(localized: "TLS certificate verification failed: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is a system error message.")
        case let .missingClientIdentity(label):
            return String(localized: "mTLS client certificate '\(label)' was not found in the Apple Keychain", table: "BaoBuddyCore", comment: "Error. %@ is a certificate name or fingerprint. mTLS and Keychain are technical/product names.")
        case let .ambiguousClientIdentity(label, count):
            return String(localized: "\(count) Keychain certificates match '\(label)'; set mtls_client_identity to the certificate's sha256: fingerprint", table: "BaoBuddyCore", comment: "Error. %1$lld is a number of certificates; %2$@ is the name searched for. Do not translate mtls_client_identity or sha256: (they are literal setting names).")
        }
    }
}

/// URLSession transport that pins exclusively to custom PEM certificate(s) (such as `openbao/tls.crt`),
/// and optionally authenticates with an mTLS client certificate (`SecIdentity`) stored in the Apple Keychain.
/// Supports both exact leaf-certificate pinning (e.g. long-lived self-signed server certs)
/// and CA-certificate anchor pinning.
public final class PinnedTLSClient: HTTPTransport, @unchecked Sendable {
    let session: URLSession
    private let delegate: PinningDelegate

    public init(caPEM: String, clientIdentityLabel: String = "", timeoutInterval: TimeInterval = 15) throws {
        let certs = try Self.parseCertificates(from: caPEM)
        let trimmedIdentity = clientIdentityLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        let credential: URLCredential?
        if trimmedIdentity.isEmpty {
            credential = nil
        } else {
            credential = try Self.resolveClientCredential(matching: trimmedIdentity)
        }
        self.delegate = PinningDelegate(pinnedCertificates: certs, clientCredential: credential)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeoutInterval
        config.timeoutIntervalForResource = timeoutInterval
        config.urlCache = nil
        config.httpCookieStorage = nil
        self.session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }

    deinit { session.invalidateAndCancel() }

    /// Looks up a client TLS identity (`SecIdentity`) in the Apple Keychain by certificate Common Name,
    /// subject summary, or SHA-256 fingerprint (with or without `sha256:` prefix / colons).
    public static func resolveClientCredential(matching label: String) throws -> URLCredential {
        let needle = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedNeedle = needle
            .replacingOccurrences(of: "sha256:", with: "", options: .caseInsensitive)
            .replacingOccurrences(of: ":", with: "")
            .lowercased()

        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)
        guard status == errSecSuccess, let identities = items as? [SecIdentity] else {
            throw PinnedTLSError.missingClientIdentity(needle)
        }

        var nameMatches: [(SecIdentity, SecCertificate)] = []
        for identity in identities {
            var cert: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &cert) == errSecSuccess, let cert else {
                continue
            }
            let summary = (SecCertificateCopySubjectSummary(cert) as String?) ?? ""
            var commonName: CFString?
            let cn = SecCertificateCopyCommonName(cert, &commonName) == errSecSuccess
                ? (commonName as String? ?? "")
                : ""
            let der = SecCertificateCopyData(cert) as Data
            let sha256Hex = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()

            if !normalizedNeedle.isEmpty && sha256Hex == normalizedNeedle {
                return URLCredential(identity: identity, certificates: [cert], persistence: .none)
            }
            if summary.caseInsensitiveCompare(needle) == .orderedSame
                || cn.caseInsensitiveCompare(needle) == .orderedSame {
                nameMatches.append((identity, cert))
            }
        }
        // A name can match several certificates (a renewed certificate next to an expired one, or
        // one another app installed). Choosing one silently could present the wrong identity.
        guard nameMatches.count <= 1 else {
            throw PinnedTLSError.ambiguousClientIdentity(needle, nameMatches.count)
        }
        if let (identity, cert) = nameMatches.first {
            return URLCredential(identity: identity, certificates: [cert], persistence: .none)
        }
        throw PinnedTLSError.missingClientIdentity(needle)
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        delegate.clearLastError()
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw PinnedTLSError.nonHTTPResponse
            }
            return (data, http)
        } catch {
            if let trustError = delegate.takeLastError() {
                throw PinnedTLSError.trustEvaluationFailed(trustError)
            }
            throw error
        }
    }

    /// Parses one or more `-----BEGIN CERTIFICATE-----` blocks from a PEM string.
    public static func parseCertificates(from pem: String) throws -> [SecCertificate] {
        let trimmed = pem.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }

        var certs: [SecCertificate] = []
        let lines = trimmed
            .replacingOccurrences(of: "\r\n", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }

        var inside = false
        var bodyLines: [String] = []
        for line in lines {
            if !inside {
                if line == "-----BEGIN CERTIFICATE-----" {
                    inside = true
                    bodyLines = []
                }
            } else if line == "-----END CERTIFICATE-----" {
                inside = false
                guard let der = Data(base64Encoded: bodyLines.joined()),
                      let cert = SecCertificateCreateWithData(nil, der as CFData) else {
                    throw PinnedTLSError.invalidCertificate
                }
                certs.append(cert)
            } else {
                bodyLines.append(line)
            }
        }
        guard !certs.isEmpty else {
            throw PinnedTLSError.invalidCertificate
        }
        return certs
    }

    /// Evaluates a server `SecTrust` against pinned certificates (exact leaf match or anchor CA).
    public static func evaluate(trust: SecTrust, pinnedCertificates: [SecCertificate]) -> Result<Void, PinnedTLSError> {
        let pinnedDERs = Set(pinnedCertificates.map { SecCertificateCopyData($0) as Data })
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
           let leaf = chain.first {
            let leafDER = SecCertificateCopyData(leaf) as Data
            // Exact byte-for-byte leaf pin match (handles self-signed server certs like openbao/tls.crt
            // whose 10-year validity or CA:FALSE flag Apple's default SSL policy otherwise rejects).
            // The TLS handshake proves the server holds this certificate's key, so the pin is the
            // trust decision: hostname and expiry aren't checked. Rotate by updating ca_pem.
            if pinnedDERs.contains(leafDER) {
                return .success(())
            }
        }

        SecTrustSetAnchorCertificates(trust, pinnedCertificates as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)

        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) {
            return .success(())
        }
        let detail = (error as Error?)?.localizedDescription ?? "server certificate does not match pinned CA"
        return .failure(.trustEvaluationFailed(detail))
    }
}

private final class PinningDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    private let pinnedCertificates: [SecCertificate]
    private let clientCredential: URLCredential?
    private let lock = NSLock()
    private var lastError: String?

    init(pinnedCertificates: [SecCertificate], clientCredential: URLCredential?) {
        self.pinnedCertificates = pinnedCertificates
        self.clientCredential = clientCredential
    }

    func clearLastError() {
        lock.lock()
        lastError = nil
        lock.unlock()
    }

    func takeLastError() -> String? {
        lock.lock()
        defer { lock.unlock() }
        let value = lastError
        lastError = nil
        return value
    }

    private func recordError(_ message: String) {
        lock.lock()
        lastError = message
        lock.unlock()
    }

    /// Never follow redirects: URLSession would re-send `X-Vault-Token` and the request body
    /// (sign-in JWTs, tokens being revoked) to the new location.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let method = challenge.protectionSpace.authenticationMethod
        if method == NSURLAuthenticationMethodClientCertificate {
            if let clientCredential {
                completionHandler(.useCredential, clientCredential)
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
            return
        }

        guard method == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        if pinnedCertificates.isEmpty {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        switch PinnedTLSClient.evaluate(trust: trust, pinnedCertificates: pinnedCertificates) {
        case .success:
            completionHandler(.useCredential, URLCredential(trust: trust))
        case let .failure(err):
            recordError(err.localizedDescription)
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
