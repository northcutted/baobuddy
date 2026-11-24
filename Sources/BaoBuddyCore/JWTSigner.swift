import CryptoKit
import Foundation

public struct JWTSigner: Sendable {
    public let signer: any BiometricSigner
    public let ttlSeconds: TimeInterval

    public init(signer: any BiometricSigner, ttlSeconds: TimeInterval = 30) {
        self.signer = signer
        self.ttlSeconds = ttlSeconds
    }

    /// Verifies that the profile's JWT audience is non-empty and, when using the `baobuddy://`
    /// deployment-bound format, matches the receiving server's exact base endpoint, namespace,
    /// and JWT mount. Combined with per-deployment Secure Enclave keys (zero legacy fallback),
    /// a malicious profile for Server B can never elicit a JWT replayable on Server A.
    public static func validateAudience(for profile: BaoProfile) throws {
        let configured = profile.openbao.jwtAuth.audience.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !configured.isEmpty else {
            throw OpenBaoError.grantMismatch("JWT audience must not be empty")
        }
        if configured.lowercased().hasPrefix("baobuddy://") {
            let expected = profile.openbao.expectedOriginMountAudience
            guard configured == expected else {
                throw OpenBaoError.grantMismatch(
                    "JWT audience '\(configured)' does not match server/mount '\(expected)'"
                )
            }
        }
    }

    /// Signs a short-lived ES256 JWT for the profile's JWT auth mount.
    ///
    /// `scope` is the canonical text of what the user approved (for example
    /// `HOURS=2 POLICIES=db-readonly WHY=release`). The server can't enforce it, because the
    /// granter token it returns may mint anything the token role allows, but `server-setup` maps
    /// it into token metadata so audit logs record what the user saw next to what was minted.
    public func makeLoginJWT(
        config: BaoProfile.OpenBaoConfig.JWTAuth,
        reason: String,
        scope: String,
        now: Date = Date()
    ) async throws -> String {
        let header: [String: String] = [
            "alg": "ES256",
            "typ": "JWT"
        ]
        let iat = Int(now.timeIntervalSince1970)
        let exp = iat + Int(ttlSeconds)
        let payload = JWTPayload(
            iss: config.issuer,
            sub: config.subject,
            aud: config.audience,
            device: signer.deviceName,
            iat: iat,
            exp: exp,
            jti: UUID().uuidString.lowercased(),
            scope: scope
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let headerB64 = Base64URL.encode(try encoder.encode(header))
        let payloadB64 = Base64URL.encode(try encoder.encode(payload))
        let signingInput = "\(headerB64).\(payloadB64)"
        let rawSignature = try await signer.signES256(data: Data(signingInput.utf8), reason: reason)
        return "\(signingInput).\(Base64URL.encode(rawSignature))"
    }
}

private struct JWTPayload: Encodable {
    let iss: String
    let sub: String
    let aud: String
    let device: String
    let iat: Int
    let exp: Int
    let jti: String
    let scope: String
}

/// In-memory P-256 signer for unit tests and simulator previews.
public final class EphemeralP256Signer: BiometricSigner, @unchecked Sendable {
    public let deviceName: String
    public let privateKey: P256.Signing.PrivateKey // gitleaks:allow (type name, not a secret)
    public private(set) var lastReason: String?

    public init(deviceName: String = "test-device", privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) { // gitleaks:allow
        self.deviceName = deviceName
        self.privateKey = privateKey
    }

    public func publicKeyPEM() throws -> String {
        privateKey.publicKey.pemRepresentation
    }

    public func signES256(data: Data, reason: String) async throws -> Data {
        lastReason = reason
        let sig = try privateKey.signature(for: data)
        return sig.rawRepresentation
    }
}
