import Foundation
import Security

public enum GitHubPushTokenError: Error, LocalizedError {
    case invalidPrivateKey
    case signingFailed(String)
    case httpError(Int, String)
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .invalidPrivateKey:
            return String(localized: "Could not parse the GitHub App RSA private key", table: "BaoBuddyCore", comment: "Error. GitHub App is a product name.")
        case let .signingFailed(detail):
            return String(localized: "Failed to sign GitHub App JWT: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is a technical error message. JWT is a token format; keep it.")
        case let .httpError(code, detail):
            return String(localized: "GitHub API returned HTTP \(code): \(detail)", table: "BaoBuddyCore", comment: "Error. %1$lld is an HTTP status code; %2$@ is the server's error message.")
        case .invalidResponse:
            return String(localized: "GitHub API returned an unexpected push token response", table: "BaoBuddyCore", comment: "Error from the GitHub API when minting a git push token.")
        }
    }
}

/// Mints a one-hour GitHub App installation token scoped to Contents read/write on one repo,
/// matching `t3vm/push-token.sh` (`"<epoch_expires> <token>"`).
public struct GitHubPushTokenClient: Sendable {
    public let apiBaseURL: URL
    public let transport: any HTTPTransport

    public init(apiBaseURL: URL? = nil, transport: (any HTTPTransport)? = nil) {
        self.apiBaseURL = apiBaseURL ?? URL(string: "https://api.github.com") ?? URL(fileURLWithPath: "/")
        if let transport {
            self.transport = transport
        } else {
            self.transport = DefaultURLSessionTransport()
        }
    }

    public func mintPushToken(app: GitHubAppConfig, now: Date = Date()) async throws -> String {
        let jwt = try makeAppJWT(appID: app.appID, privateKeyPEM: app.privateKeyPEM, now: now)
        let url = apiBaseURL
            .appendingPathComponent("app")
            .appendingPathComponent("installations")
            .appendingPathComponent(app.installationID)
            .appendingPathComponent("access_tokens")

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(jwt)", forHTTPHeaderField: "Authorization")
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: Any] = [
            "repositories": [app.repo],
            "permissions": ["contents": "write"]
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await transport.send(req)
        guard (200..<300).contains(response.statusCode) else {
            let text = String(data: data, encoding: .utf8) ?? ""
            throw GitHubPushTokenError.httpError(response.statusCode, text)
        }
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = obj["token"] as? String,
              let expiresAt = obj["expires_at"] as? String,
              let date = ISO8601DateFormatter().date(from: expiresAt) else {
            throw GitHubPushTokenError.invalidResponse
        }
        return "\(Int(date.timeIntervalSince1970)) \(token)"
    }

    /// Revokes an installation token (`DELETE /installation/token`), used when delivery fails so
    /// an undelivered push token doesn't stay valid for its hour. Accepts the raw token or the
    /// `"<epoch> <token>"` delivery format.
    public func revokeInstallationToken(_ pushToken: String) async throws {
        let token = pushToken.split(separator: " ").last.map(String.init) ?? pushToken
        guard !token.isEmpty else { return }
        var req = URLRequest(url: apiBaseURL.appendingPathComponent("installation").appendingPathComponent("token"))
        req.httpMethod = "DELETE"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        let (data, response) = try await transport.send(req)
        guard response.statusCode == 204 || response.statusCode == 401 else {
            // 401 means the token is already invalid, which is the outcome we want.
            throw GitHubPushTokenError.httpError(response.statusCode, String(data: data, encoding: .utf8) ?? "")
        }
    }

    public func makeAppJWT(appID: String, privateKeyPEM: String, now: Date = Date()) throws -> String {
        let key = try loadRSAPrivateKey(pem: privateKeyPEM)
        let headerB64 = Base64URL.encode(Data(#"{"alg":"RS256","typ":"JWT"}"#.utf8))
        let iat = Int(now.timeIntervalSince1970) - 60
        let exp = iat + 300
        let payloadJSON = #"{"exp":\#(exp),"iat":\#(iat),"iss":"\#(appID)"}"#
        let payloadB64 = Base64URL.encode(Data(payloadJSON.utf8))
        let signingInput = "\(headerB64).\(payloadB64)"

        var signError: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            key,
            .rsaSignatureMessagePKCS1v15SHA256,
            Data(signingInput.utf8) as CFData,
            &signError
        ) as Data? else {
            let msg = signError?.takeRetainedValue().localizedDescription ?? "unknown"
            throw GitHubPushTokenError.signingFailed(msg)
        }
        return "\(signingInput).\(Base64URL.encode(sig))"
    }

    private func loadRSAPrivateKey(pem: String) throws -> SecKey {
        let (label, der) = try PEMCodec.decodePEM(pem)
        let keyData: Data
        if label == "RSA PRIVATE KEY" {
            keyData = der
        } else if label == "PRIVATE KEY" {
            keyData = try unwrapPKCS8RSAPrivateKey(der)
        } else {
            throw GitHubPushTokenError.invalidPrivateKey
        }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(keyData as CFData, attrs as CFDictionary, &err) else {
            throw GitHubPushTokenError.invalidPrivateKey
        }
        return key
    }

    /// Extracts the inner PKCS#1 RSA key OCTET STRING from a PKCS#8 PrivateKeyInfo wrapper.
    private func unwrapPKCS8RSAPrivateKey(_ der: Data) throws -> Data {
        let bytes = [UInt8](der)
        var offset = 0
        func readTagAndLength() throws -> (UInt8, Int) {
            guard offset + 2 <= bytes.count else { throw GitHubPushTokenError.invalidPrivateKey }
            let tag = bytes[offset]
            offset += 1
            let first = bytes[offset]
            offset += 1
            if first & 0x80 == 0 {
                return (tag, Int(first))
            }
            let count = Int(first & 0x7F)
            guard count > 0, count <= 4, offset + count <= bytes.count else {
                throw GitHubPushTokenError.invalidPrivateKey
            }
            var length = 0
            for _ in 0..<count {
                length = (length << 8) | Int(bytes[offset])
                offset += 1
            }
            return (tag, length)
        }
        let (seqTag, _) = try readTagAndLength()
        guard seqTag == 0x30 else { throw GitHubPushTokenError.invalidPrivateKey }
        let (verTag, verLen) = try readTagAndLength()
        guard verTag == 0x02 else { throw GitHubPushTokenError.invalidPrivateKey }
        offset += verLen
        let (algTag, algLen) = try readTagAndLength()
        guard algTag == 0x30 else { throw GitHubPushTokenError.invalidPrivateKey }
        offset += algLen
        let (octTag, octLen) = try readTagAndLength()
        guard octTag == 0x04, offset + octLen <= bytes.count else {
            throw GitHubPushTokenError.invalidPrivateKey
        }
        return Data(bytes[offset..<(offset + octLen)])
    }
}

public final class DefaultURLSessionTransport: HTTPTransport, @unchecked Sendable {
    private let session: URLSession

    public init(timeoutInterval: TimeInterval = 15) {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeoutInterval
        config.timeoutIntervalForResource = timeoutInterval
        config.urlCache = nil
        config.httpCookieStorage = nil
        self.session = URLSession(configuration: config, delegate: NoRedirectDelegate(), delegateQueue: nil)
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw PinnedTLSError.nonHTTPResponse
        }
        return (data, http)
    }
}

/// Refuses every HTTP redirect. Requests carry bearer credentials (`X-Vault-Token`, GitHub
/// `Authorization`, sign-in JWTs in the body), and URLSession would re-send them to the new
/// location. A redirect becomes a plain 3xx response, which callers treat as an error.
final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
