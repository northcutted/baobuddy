import Compression
import Foundation

public enum ProfileTransferError: Error, LocalizedError, Equatable {
    case invalidPayload
    case compressionFailed
    case payloadTooLarge
    case lockedByOrganization

    public var errorDescription: String? {
        switch self {
        case .invalidPayload:
            return String(localized: "Could not decode BaoBuddy profile QR / link payload", table: "BaoBuddyCore", comment: "Error when a scanned QR code or link is not a valid BaoBuddy server profile.")
        case .compressionFailed:
            return String(localized: "Failed to compress or decompress BaoBuddy profile payload", table: "BaoBuddyCore", comment: "Error.")
        case .payloadTooLarge:
            return String(localized: "Profile payload exceeds maximum allowed size", table: "BaoBuddyCore", comment: "Error.")
        case .lockedByOrganization:
            return String(localized: "Server profiles are locked by your organization's MDM policy", table: "BaoBuddyCore", comment: "Error. MDM = mobile device management.")
        }
    }
}

/// Encodes and decodes non-secret `BaoProfile` objects as compact, zlib-compressed
/// `baobuddy://import?p=<base64url>` URIs for crisp QR code pairing (Mac / CLI → iPhone).
/// Also accepts plain JSON seamlessly so paste & QR flows share one decoder.
public enum ProfileTransferCodec {
    private static let maxUncompressedBytes = 256 * 1024

    /// Encodes `profile` into a compact `baobuddy://import?p=<base64url>` URI.
    public static func encodeURI(_ profile: BaoProfile) throws -> String {
        guard !profile.isDemoProfile else {
            throw ProfileError.invalidField("id", "demo profile cannot be exported or shared")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let raw = try encoder.encode(profile.forSharing)
        let compressed = try compressZlib(raw)
        let encoded = Base64URL.encode(compressed)
        return "baobuddy://import?p=\(encoded)"
    }

    /// True if `url` is a `baobuddy://import?p=...` (or legacy `baogrant://import?p=...`) pairing URI.
    public static func isImportURL(_ url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(),
              scheme == "baobuddy" || scheme == "baogrant" else {
            return false
        }
        return url.host?.lowercased() == "import"
    }

    /// Decodes a `BaoProfile` from a `baobuddy://import?p=...` URL.
    public static func decode(
        url: URL,
        requireHostKey: Bool = true,
        requireTLSPinning: Bool = false
    ) throws -> BaoProfile {
        guard isImportURL(url),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let payload = components.queryItems?.first(where: { $0.name == "p" })?.value,
              !payload.isEmpty else {
            throw ProfileTransferError.invalidPayload
        }
        let data = try decompressPayload(payload)
        let profile = try BaoProfile.decode(from: data, requireHostKey: requireHostKey)
        try profile.validate(requireHostKey: requireHostKey, requireTLSPinning: requireTLSPinning)
        return profile
    }

    /// Decodes a `BaoProfile` from either a `baobuddy://import?p=...` URI, `baobuddy-profile:v1:<b64>`,
    /// or plain JSON text.
    public static func decode(
        text: String,
        requireHostKey: Bool = true,
        requireTLSPinning: Bool = false
    ) throws -> BaoProfile {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw ProfileTransferError.invalidPayload
        }
        if let url = URL(string: trimmed), isImportURL(url) {
            return try decode(url: url, requireHostKey: requireHostKey, requireTLSPinning: requireTLSPinning)
        }
        if trimmed.hasPrefix("baobuddy-profile:v1:") {
            let b64 = String(trimmed.dropFirst("baobuddy-profile:v1:".count))
            let data = try decompressPayload(b64)
            let profile = try BaoProfile.decode(from: data, requireHostKey: requireHostKey)
            try profile.validate(requireHostKey: requireHostKey, requireTLSPinning: requireTLSPinning)
            return profile
        }
        let profile = try BaoProfile.decode(from: Data(trimmed.utf8), requireHostKey: requireHostKey)
        try profile.validate(requireHostKey: requireHostKey, requireTLSPinning: requireTLSPinning)
        return profile
    }

    private static func decompressPayload(_ b64: String) throws -> Data {
        guard let compressed = Base64URL.decode(b64), !compressed.isEmpty else {
            throw ProfileTransferError.invalidPayload
        }
        return try decompressZlib(compressed)
    }

    private static func compressZlib(_ input: Data) throws -> Data {
        guard !input.isEmpty else { return Data() }
        let capacity = max(input.count + 64, 1024)
        var out = Data(count: capacity)
        let written: Int = input.withUnsafeBytes { srcBuf in
            out.withUnsafeMutableBytes { dstBuf in
                guard let src = srcBuf.bindMemory(to: UInt8.self).baseAddress,
                      let dst = dstBuf.bindMemory(to: UInt8.self).baseAddress else {
                    return 0
                }
                return compression_encode_buffer(dst, capacity, src, input.count, nil, COMPRESSION_ZLIB)
            }
        }
        guard written > 0 else {
            throw ProfileTransferError.compressionFailed
        }
        out.count = written
        return out
    }

    private static func decompressZlib(_ input: Data) throws -> Data {
        var capacity = min(max(input.count * 4, 4096), maxUncompressedBytes)
        while capacity <= maxUncompressedBytes {
            var out = Data(count: capacity)
            let written: Int = input.withUnsafeBytes { srcBuf in
                out.withUnsafeMutableBytes { dstBuf in
                    guard let src = srcBuf.bindMemory(to: UInt8.self).baseAddress,
                          let dst = dstBuf.bindMemory(to: UInt8.self).baseAddress else {
                        return 0
                    }
                    return compression_decode_buffer(dst, capacity, src, input.count, nil, COMPRESSION_ZLIB)
                }
            }
            if written > 0 && written < capacity {
                out.count = written
                return out
            }
            if capacity == maxUncompressedBytes {
                throw ProfileTransferError.payloadTooLarge
            }
            capacity = min(capacity * 2, maxUncompressedBytes)
        }
        throw ProfileTransferError.compressionFailed
    }
}

/// Rules for adding an imported profile (QR code, `baobuddy://import` link, pasted JSON, or
/// `bao-buddy import-profile`) next to the profiles already on the device.
///
/// - The organization's lock and TLS-pinning rules apply.
/// - The incoming `id` is never trusted: a profile can't take over another one (including a
///   managed one) by reusing its ID. It replaces an existing profile only when both share the
///   same full issuer trust binding (`issuerBindingKey`: origin, base path, namespace, TLS CA pin,
///   and mTLS client identity), JWT mount, and primary remote host, and the caller should show
///   `changes` first. Distinct same-URL deployments with different TLS pins or mTLS identities
///   are added side-by-side instead of overwriting each other.
public struct ProfileImportPlan: Sendable {
    public let profile: BaoProfile
    /// The local profile this import would replace, if any.
    public let replaces: BaoProfile?

    /// Security-relevant differences from the profile being replaced, for a confirmation step.
    public var changes: [String] {
        guard let old = replaces else { return [] }
        var out: [String] = []
        func compare(_ label: String, _ a: String, _ b: String) {
            if a != b { out.append(label) }
        }
        compare(String(localized: "TLS certificate pin (ca_pem)", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile. Do not translate ca_pem (a setting name)."), old.openbao.caPEM, profile.openbao.caPEM)
        compare(String(localized: "Remote host key", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile: the remote host's pinned SSH host key."), old.t3Granter.hostKey, profile.t3Granter.hostKey)
        compare(String(localized: "mTLS client identity", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile."), old.openbao.mtlsClientIdentity, profile.openbao.mtlsClientIdentity)
        compare(String(localized: "Telemetry endpoint", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile: where grant events are sent."), old.openbao.telemetry.otlpEndpoint, profile.openbao.telemetry.otlpEndpoint)
        compare(String(localized: "Namespace", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile: the OpenBao/Vault namespace."), old.openbao.namespace, profile.openbao.namespace)
        compare(String(localized: "JWT subject", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile: the JWT sub claim (user name)."), old.openbao.jwtAuth.subject, profile.openbao.jwtAuth.subject)
        if old.openbao.grantPolicies != profile.openbao.grantPolicies || old.openbao.policies != profile.openbao.policies {
            out.append(String(localized: "Policies", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile: its OpenBao policies."))
        }
        if old.openbao.extensions != profile.openbao.extensions {
            out.append(String(localized: "Credential extensions", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile: extra credentials minted with grants."))
        }
        if old.openbao.ssh != profile.openbao.ssh {
            out.append(String(localized: "SSH signing role / principals", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile."))
        }
        if old.configuredRemoteTargets != profile.configuredRemoteTargets {
            out.append(String(localized: "Remote targets", table: "BaoBuddyCore", comment: "A setting that changed in an imported server profile: the SSH hosts that receive grants."))
        }
        return out
    }

    /// Plain-language lines describing what an imported profile turns on beyond a basic server,
    /// for display before the user accepts it.
    public var notices: [String] {
        var out: [String] = []
        let otlp = profile.openbao.telemetry.otlpEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        if !otlp.isEmpty {
            out.append(String(localized: "Sends grant events (who, policies, reason) to \(otlp)", table: "BaoBuddyCore", comment: "Notice before importing a server profile. %@ is a telemetry server URL."))
        }
        if !profile.openbao.isTLSPinned {
            out.append(String(localized: "TLS isn't pinned: any certificate trusted by this device is accepted", table: "BaoBuddyCore", comment: "Notice before importing a server profile."))
        }
        if !profile.openbao.usesBoundAudience {
            out.append(
                String(
                    localized: "JWT audience '\(profile.openbao.jwtAuth.audience)' isn't bound to this server/mount; prefer '\(profile.openbao.expectedOriginMountAudience)'",
                    table: "BaoBuddyCore",
                    comment: "Notice before importing a server profile. %1$@ is the configured JWT audience value; %2$@ is the recommended value. A mount is an OpenBao auth mount."
                )
            )
        }
        if !profile.openbao.ssh.hosts.isEmpty {
            let mappings = profile.openbao.ssh.hosts.map { "\($0.name)→\($0.principal)" }.joined(separator: ", ")
            let role = profile.openbao.ssh.role.isEmpty
                ? String(localized: "unset", table: "BaoBuddyCore", comment: "Shown in place of an SSH signing role name when none is configured.")
                : profile.openbao.ssh.role
            out.append(String(localized: "SSH signing (role \(role)): \(mappings)", table: "BaoBuddyCore", comment: "Notice before importing a server profile. %1$@ is the SSH signing role; %2$@ lists host→principal mappings."))
        }
        let enabled = profile.openbao.extensions.filter(\.enabled)
        if !enabled.isEmpty {
            out.append(String(localized: "Credential extensions: \(enabled.map(\.endpoint).joined(separator: ", "))", table: "BaoBuddyCore", comment: "Notice before importing a server profile. %@ is a comma-separated list of OpenBao paths."))
        }
        return out
    }

    public static func make(
        importing incoming: BaoProfile,
        existing: [BaoProfile],
        managedIDs: Set<String>,
        organizationPolicy: ManagedAppConfig
    ) throws -> ProfileImportPlan {
        guard !organizationPolicy.lockProfiles else {
            throw ProfileTransferError.lockedByOrganization
        }
        try incoming.validate(requireHostKey: true, requireTLSPinning: organizationPolicy.enforceTLSPinning)
        var profile = incoming
        let match = existing.first {
            !managedIDs.contains($0.id) &&
            $0.openbao.issuerBindingKey == incoming.openbao.issuerBindingKey &&
            $0.openbao.jwtAuth.mount == incoming.openbao.jwtAuth.mount &&
            $0.t3Granter.host.lowercased() == incoming.t3Granter.host.lowercased()
        }
        if let match {
            profile.id = match.id
        } else {
            let taken = Set(existing.map(\.id)).union(managedIDs)
            if profile.id.isEmpty || taken.contains(profile.id) {
                profile.id = UUID().uuidString.lowercased()
            }
        }
        if organizationPolicy.requireReasonForElevated {
            profile.openbao.auditPolicy.requireReasonForElevated = true
        }
        return ProfileImportPlan(profile: profile, replaces: match)
    }
}

extension BaoProfile {
    /// The profile as it may be shared (QR code, link, clipboard, export): telemetry headers are
    /// removed because they usually hold a collector API key. Everything else in a profile is
    /// non-secret by design.
    public var forSharing: BaoProfile {
        var copy = self
        copy.openbao.telemetry.headers = [:]
        return copy
    }
}
