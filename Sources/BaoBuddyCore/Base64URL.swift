import CryptoKit
import Foundation

public enum CryptoEncodingError: Error, LocalizedError, Equatable {
    case invalidDER
    case invalidPEM(String)
    case invalidPublicKeyLength(Int)

    public var errorDescription: String? {
        switch self {
        case .invalidDER:
            return String(localized: "Invalid ASN.1 DER signature", table: "BaoBuddyCore", comment: "Error: a signature could not be decoded. ASN.1 DER is a technical term; keep it.")
        case let .invalidPEM(label):
            return String(localized: "Invalid PEM block for \(label)", table: "BaoBuddyCore", comment: "Error. %@ is the kind of PEM block (for example PUBLIC KEY). PEM is a file format; keep it.")
        case let .invalidPublicKeyLength(length):
            return String(localized: "Expected 65-byte uncompressed P-256 public key, got \(length) bytes", table: "BaoBuddyCore", comment: "Error. %lld is the number of bytes received.")
        }
    }
}

public enum Base64URL {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ string: String) -> Data? {
        var padded = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = padded.count % 4
        if remainder != 0 {
            padded += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: padded)
    }
}

public enum PEMCodec {
    // Fixed ASN.1 DER SubjectPublicKeyInfo header for uncompressed EC P-256 (prime256v1).
    private static let p256SPKIHeader = Data([
        0x30, 0x59,
        0x30, 0x13,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00
    ])

    /// Encodes a 65-byte X9.63 uncompressed P-256 public key (0x04 || X || Y) as SPKI PEM.
    public static func encodeP256PublicKeyPEM(x963Data: Data) throws -> String {
        guard x963Data.count == 65, x963Data.first == 0x04 else {
            throw CryptoEncodingError.invalidPublicKeyLength(x963Data.count)
        }
        let spkiDER = p256SPKIHeader + x963Data
        return wrapPEM(der: spkiDER, label: "PUBLIC KEY")
    }

    /// SHA-256 hex prefix (16 chars) matching `scripts/openbao.sh device_fingerprint`.
    public static func spkiFingerprint(x963Data: Data) throws -> String {
        guard x963Data.count == 65, x963Data.first == 0x04 else {
            throw CryptoEncodingError.invalidPublicKeyLength(x963Data.count)
        }
        let digest = SHA256.hash(data: p256SPKIHeader + x963Data)
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    public static func wrapPEM(der: Data, label: String) -> String {
        let b64 = der.base64EncodedString()
        var lines: [String] = ["-----BEGIN \(label)-----"]
        var index = b64.startIndex
        while index < b64.endIndex {
            let next = b64.index(index, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            lines.append(String(b64[index..<next]))
            index = next
        }
        lines.append("-----END \(label)-----")
        return lines.joined(separator: "\n")
    }

    /// Extracts DER bytes from the first PEM block in `pem`.
    public static func decodePEM(_ pem: String, expectedLabel: String? = nil) throws -> (label: String, der: Data) {
        let lines = pem
            .replacingOccurrences(of: "\r\n", with: "\n")
            .split(separator: "\n", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }

        var foundLabel: String?
        var bodyLines: [String] = []
        for line in lines {
            if foundLabel == nil {
                if line.hasPrefix("-----BEGIN "), line.hasSuffix("-----") {
                    let start = line.index(line.startIndex, offsetBy: "-----BEGIN ".count)
                    let end = line.index(line.endIndex, offsetBy: -"-----".count)
                    foundLabel = String(line[start..<end])
                }
            } else if let label = foundLabel, line == "-----END \(label)-----" {
                if let expectedLabel, label != expectedLabel {
                    throw CryptoEncodingError.invalidPEM(expectedLabel)
                }
                guard let der = Data(base64Encoded: bodyLines.joined()) else {
                    throw CryptoEncodingError.invalidPEM(label)
                }
                return (label, der)
            } else {
                bodyLines.append(line)
            }
        }
        throw CryptoEncodingError.invalidPEM(expectedLabel ?? "PEM")
    }

    /// Converts an ASN.1 DER ECDSA P-256 signature into a 64-byte IEEE P1363 raw `r || s` signature for ES256 JWTs.
    public static func derToRawP256Signature(_ der: Data) throws -> Data {
        let bytes = [UInt8](der)
        guard bytes.count >= 8, bytes[0] == 0x30 else {
            throw CryptoEncodingError.invalidDER
        }
        var offset = 1
        guard offset < bytes.count else { throw CryptoEncodingError.invalidDER }
        let seqLenByte = bytes[offset]
        offset += 1
        if seqLenByte & 0x80 != 0 {
            let count = Int(seqLenByte & 0x7F)
            guard count > 0, offset + count <= bytes.count else { throw CryptoEncodingError.invalidDER }
            offset += count
        }

        func readInteger() throws -> Data {
            guard offset + 2 <= bytes.count, bytes[offset] == 0x02 else {
                throw CryptoEncodingError.invalidDER
            }
            offset += 1
            let len = Int(bytes[offset])
            offset += 1
            guard len > 0, offset + len <= bytes.count else {
                throw CryptoEncodingError.invalidDER
            }
            var slice = Data(bytes[offset..<(offset + len)])
            offset += len
            while slice.count > 32, slice.first == 0x00 {
                slice.removeFirst()
            }
            guard slice.count <= 32 else {
                throw CryptoEncodingError.invalidDER
            }
            if slice.count < 32 {
                slice = Data(repeating: 0, count: 32 - slice.count) + slice
            }
            return slice
        }

        let r = try readInteger()
        let s = try readInteger()
        guard offset == bytes.count else {
            throw CryptoEncodingError.invalidDER
        }
        return r + s
    }
}
