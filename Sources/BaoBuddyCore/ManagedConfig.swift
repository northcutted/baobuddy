import Foundation

/// Enterprise MDM Managed App Configuration.
///
/// Supports both:
/// - iOS Managed App Configuration (`com.apple.configuration.managed` dictionary)
/// - macOS MDM Configuration Profiles (`.mobileconfig` `com.apple.ManagedClient.preferences`
///   targeting `com.northcutt.BaoBuddy.Helper`, either nested under `com.apple.configuration.managed`
///   or pushed directly as top-level preference keys).
public struct ManagedAppConfig: Equatable, Sendable {
    public let profiles: [BaoProfile]
    public let disableClipboard: Bool
    public let lockProfiles: Bool
    public let enforceTLSPinning: Bool
    public let requireReasonForElevated: Bool
    public let isManaged: Bool
    /// Managed profiles that were dropped because they failed validation, with the reason.
    public let rejectedProfiles: [String]

    public init(
        profiles: [BaoProfile] = [],
        disableClipboard: Bool = false,
        lockProfiles: Bool = false,
        enforceTLSPinning: Bool = false,
        requireReasonForElevated: Bool = false,
        isManaged: Bool = false,
        rejectedProfiles: [String] = []
    ) {
        self.rejectedProfiles = rejectedProfiles
        self.profiles = profiles
        self.disableClipboard = disableClipboard
        self.lockProfiles = lockProfiles
        self.enforceTLSPinning = enforceTLSPinning
        self.requireReasonForElevated = requireReasonForElevated
        self.isManaged = isManaged
    }

    public static let empty = ManagedAppConfig()

    private static let managedKeys: [String] = [
        "disable_clipboard",
        "lock_profiles",
        "enforce_tls_pinning",
        "require_reason_for_elevated",
        "profiles_json",
        "profiles",
        "profile_json"
    ]

    public static func load(from defaults: UserDefaults = .standard) -> ManagedAppConfig {
        let nestedKey = "com.apple.configuration.managed"
        #if os(macOS)
        // On macOS any process running as the user can write to the app's preference domain
        // (`defaults write`), so only values an installed configuration profile forces count.
        if defaults.objectIsForced(forKey: nestedKey), let raw = defaults.dictionary(forKey: nestedKey) {
            return parse(dictionary: raw)
        }
        #else
        // On iOS only MDM sets this key.
        if let raw = defaults.dictionary(forKey: nestedKey) {
            return parse(dictionary: raw)
        }
        #endif
        #if os(macOS)
        // Standard macOS MDM `.mobileconfig` payloads push keys directly into the app's preference domain.
        var topLevel: [String: Any] = [:]
        for key in managedKeys where defaults.objectIsForced(forKey: key) {
            if let value = defaults.object(forKey: key) {
                topLevel[key] = value
            }
        }
        if !topLevel.isEmpty {
            return parse(dictionary: topLevel)
        }
        #endif
        return .empty
    }

    public static func parse(dictionary: [String: Any]) -> ManagedAppConfig {
        let disableClipboard = (dictionary["disable_clipboard"] as? Bool) ?? false
        let lockProfiles = (dictionary["lock_profiles"] as? Bool) ?? false
        let enforceTLSPinning = (dictionary["enforce_tls_pinning"] as? Bool) ?? false
        let requireReasonForElevated = (dictionary["require_reason_for_elevated"] as? Bool) ?? false

        var parsed: [BaoProfile] = []
        var rejected: [String] = []
        if let jsonString = dictionary["profiles_json"] as? String,
           let data = jsonString.data(using: .utf8),
           let list = try? JSONDecoder().decode([BaoProfile].self, from: data) {
            parsed = list
        } else if let profileDicts = dictionary["profiles"] as? [[String: Any]],
                  let data = try? JSONSerialization.data(withJSONObject: profileDicts),
                  let list = try? JSONDecoder().decode([BaoProfile].self, from: data) {
            parsed = list
        } else if let singleString = dictionary["profile_json"] as? String,
                  let data = singleString.data(using: .utf8),
                  let single = try? BaoProfile.decode(from: data) {
            parsed = [single]
        }

        if requireReasonForElevated {
            parsed = parsed.map { item in
                var updated = item
                updated.openbao.auditPolicy.requireReasonForElevated = true
                return updated
            }
        }

        // MDM profiles get the same validation as imported ones; an invalid profile is dropped
        // rather than trusted because it arrived through management.
        parsed = parsed.filter { item in
            do {
                try item.validate(requireHostKey: true, requireTLSPinning: enforceTLSPinning)
                return true
            } catch {
                rejected.append("\(item.displayName): \(error.localizedDescription)")
                return false
            }
        }
        if dictionary["profiles_json"] != nil || dictionary["profiles"] != nil || dictionary["profile_json"] != nil,
           parsed.isEmpty, rejected.isEmpty {
            rejected.append("The managed profile list couldn't be decoded")
        }

        let hasAnySetting = !parsed.isEmpty
            || disableClipboard
            || lockProfiles
            || enforceTLSPinning
            || requireReasonForElevated

        return ManagedAppConfig(
            profiles: parsed,
            disableClipboard: disableClipboard,
            lockProfiles: lockProfiles,
            enforceTLSPinning: enforceTLSPinning,
            requireReasonForElevated: requireReasonForElevated,
            isManaged: hasAnySetting,
            rejectedProfiles: rejected
        )
    }

    /// Computes the canonical effective profile list after applying MDM precedence and `lock_profiles`.
    /// Managed profiles always take precedence; when `lock_profiles` is set, local profiles are ignored.
    public func effectiveProfiles(local: [BaoProfile]) -> [BaoProfile] {
        let managedIDs = Set(profiles.map(\.id))
        var merged = profiles
        if !lockProfiles {
            merged += local.filter { !managedIDs.contains($0.id) }
        }
        if requireReasonForElevated {
            merged = merged.map { item in
                var updated = item
                updated.openbao.auditPolicy.requireReasonForElevated = true
                return updated
            }
        }
        return merged
    }

    /// Exact-only profile resolution by `id` while honoring MDM `lock_profiles` and `require_reason_for_elevated`.
    /// Never falls back to display `name`, so a stale generated `--profile-id` cannot resolve to a different profile.
    public func resolveProfileExact(
        id: String,
        localCollection: ProfileCollection,
        legacyProfile: BaoProfile? = nil
    ) throws -> BaoProfile {
        let localList: [BaoProfile]
        if localCollection.profiles.isEmpty, let legacyProfile {
            localList = [legacyProfile]
        } else {
            localList = localCollection.profiles
        }
        let available = effectiveProfiles(local: localList)
        do {
            return try BaoProfile.resolveProfileExact(id: id, in: available)
        } catch ProfileError.notConfigured where lockProfiles {
            throw ProfileTransferError.lockedByOrganization
        }
    }

    /// Resolves the active or explicitly selected profile across CLI, MCP, and apps while honoring
    /// MDM `lock_profiles` and `require_reason_for_elevated`.
    public func resolveProfile(
        selector: String? = nil,
        localCollection: ProfileCollection,
        legacyProfile: BaoProfile? = nil
    ) throws -> BaoProfile {
        let localList: [BaoProfile]
        if localCollection.profiles.isEmpty, let legacyProfile {
            localList = [legacyProfile]
        } else {
            localList = localCollection.profiles
        }
        let available = effectiveProfiles(local: localList)
        if let raw = selector?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty {
            do {
                return try BaoProfile.resolveProfile(selector: raw, in: available)
            } catch ProfileError.notConfigured where lockProfiles {
                throw ProfileTransferError.lockedByOrganization
            }
        }
        if let activeID = localCollection.activeProfileID,
           let match = available.first(where: { $0.id == activeID }) {
            return match
        }
        if let first = available.first {
            return first
        }
        if lockProfiles {
            throw ProfileTransferError.lockedByOrganization
        }
        throw ProfileError.notConfigured("No BaoBuddy profile configured. Import a profile JSON or configure your server in Settings.")
    }

    /// Applies organization policy to a profile before it's used for a grant: the reason rule is
    /// forced on, `lock_profiles` requires the profile (and focused remote target) to match a
    /// canonical managed profile, and the profile must pass validation (including TLS pinning when required).
    /// Saved profiles are checked here, at use, so one that predates a policy can't slip through.
    public func enforce(on profile: BaoProfile, allowDemo: Bool = false) throws -> BaoProfile {
        var updated = profile
        if requireReasonForElevated {
            updated.openbao.auditPolicy.requireReasonForElevated = true
        }
        if lockProfiles {
            guard !allowDemo, !updated.isDemoProfile else {
                throw ProfileTransferError.lockedByOrganization
            }
            guard let managed = profiles.first(where: { $0.id == updated.id }) else {
                throw ProfileTransferError.lockedByOrganization
            }
            var canonicalManaged = managed
            if requireReasonForElevated {
                canonicalManaged.openbao.auditPolicy.requireReasonForElevated = true
            }
            guard updated.openbao == canonicalManaged.openbao else {
                throw ProfileTransferError.lockedByOrganization
            }
            let managedTargets = canonicalManaged.configuredRemoteTargets
            let updatedTargets = updated.configuredRemoteTargets
            guard updatedTargets.count == managedTargets.count,
                  updatedTargets.allSatisfy({ target in managedTargets.contains(target) }) else {
                throw ProfileTransferError.lockedByOrganization
            }
        }
        try updated.validate(requireHostKey: false, requireTLSPinning: enforceTLSPinning, allowDemo: allowDemo)
        return updated
    }
}
