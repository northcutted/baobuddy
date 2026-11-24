import Darwin
import Foundation

public enum GrantAccessorStoreError: Error, LocalizedError, Equatable {
    case unreadableState(String)
    case lockingFailed(String)

    public var errorDescription: String? {
        switch self {
        case let .unreadableState(path):
            return String(localized: "Remote grant accessor state at \(path) is unreadable or corrupt; refusing to overwrite or ignore recorded grants.", table: "BaoBuddyCore", comment: "Error. %@ is a file path. An accessor is the OpenBao/Vault ID of a token.")
        case let .lockingFailed(detail):
            return String(localized: "Could not acquire lock on remote grant accessor store: \(detail)", table: "BaoBuddyCore", comment: "Error. %@ is a system error message.")
        }
    }
}

/// Remembers outstanding grant accessors delivered to each profile's remote target, so this
/// device can revoke them through OpenBao/Vault directly instead of trusting the remote host.
///
/// Security invariants:
/// - Entries are keyed by `(profileID, issuerBindingKey, remoteTargetScopeKey)` and retain all
///   non-expired accessors per target until each is confirmed revoked or expires.
/// - Legacy untargeted `profileID` records from pre-v2 files are preserved on disk for manual
///   recovery inspection (`pendingLegacyEntries`) and are NEVER attributed to a profile's current
///   target (which may have been edited since the legacy grant was minted).
/// - All read-modify-write operations hold an exclusive cross-process `flock` on `<file>.lock`
///   and fail closed when the state file exists but cannot be read or parsed.
public struct GrantAccessorStore: Sendable {
    public struct Entry: Codable, Equatable, Sendable {
        public let accessor: String
        public let expiresAt: Date

        public init(accessor: String, expiresAt: Date) {
            self.accessor = accessor
            self.expiresAt = expiresAt
        }
    }

    private struct StoredV2: Codable {
        var version: Int = 2
        /// Scoped buckets keyed by `scopeKey(for:)`.
        var targets: [String: [Entry]] = [:]
        /// Legacy flat entries keyed only by `profileID` (preserved for explicit recovery, never inferred as a target).
        var legacy: [String: Entry] = [:]
    }

    public let url: URL

    public init(url: URL? = nil) {
        if let url {
            self.url = url
        } else {
            self.url = FileProfileStore().url
                .deletingLastPathComponent()
                .appendingPathComponent("remote-grants.json")
        }
    }

    /// Composite bucket key isolating each profile + OpenBao trust domain + remote SSH target.
    public static func scopeKey(for profile: BaoProfile) -> String {
        "\(profile.id)|\(profile.openbao.issuerBindingKey)|\(profile.t3Granter.canonicalScopeKey)"
    }

    // MARK: - Target-Scoped API (preferred)

    /// Returns all non-expired recorded accessors strictly bound to `profile`'s current issuer
    /// and focused remote target. Throws if the backing file exists but is unreadable/corrupt.
    /// Never attributes untargeted legacy records to `profile`.
    public func entries(for profile: BaoProfile, now: Date = Date()) throws -> [Entry] {
        try withFileLock {
            let store = try loadStoreStrict()
            let key = Self.scopeKey(for: profile)
            return (store.targets[key] ?? []).filter { $0.expiresAt > now }
        }
    }

    /// Returns any non-expired untargeted legacy accessors preserved from pre-v2 files for `profileID`.
    /// Callers may surface these for explicit operator inspection/recovery without assuming which target received them.
    public func pendingLegacyEntries(profileID: String, now: Date = Date()) throws -> [Entry] {
        try withFileLock {
            let store = try loadStoreStrict()
            if let legacyEntry = store.legacy[profileID], legacyEntry.expiresAt > now {
                return [legacyEntry]
            }
            return []
        }
    }

    /// Transactionally appends an accessor to `profile`'s focused remote target bucket without
    /// overwriting earlier live accessors or legacy recovery records. Fails closed on unreadable state.
    public func record(for profile: BaoProfile, accessor: String, expiresAt: Date, now: Date = Date()) throws {
        guard !accessor.isEmpty else { return }
        try withFileLock {
            var store = pruned(try loadStoreStrict(), now: now)
            let key = Self.scopeKey(for: profile)
            var list = store.targets[key] ?? []
            list.removeAll { $0.accessor == accessor }
            list.append(Entry(accessor: accessor, expiresAt: expiresAt))
            store.targets[key] = list
            try saveStore(store)
        }
    }

    /// Transactionally removes one confirmed-revoked accessor from `profile`'s focused remote target bucket.
    public func remove(for profile: BaoProfile, accessor: String, now: Date = Date()) throws {
        try withFileLock {
            var store = pruned(try loadStoreStrict(), now: now)
            let key = Self.scopeKey(for: profile)
            if var list = store.targets[key] {
                list.removeAll { $0.accessor == accessor }
                store.targets[key] = list.isEmpty ? nil : list
            }
            try saveStore(store)
        }
    }

    /// Transactionally removes all recorded accessors for `profile`'s currently focused remote target.
    /// Preserves legacy untargeted records for separate recovery.
    public func removeAll(for profile: BaoProfile, now: Date = Date()) throws {
        try withFileLock {
            var store = pruned(try loadStoreStrict(), now: now)
            store.targets[Self.scopeKey(for: profile)] = nil
            try saveStore(store)
        }
    }

    // MARK: - Profile-ID API (legacy inspection / cleanup on profile deletion)

    public func entry(profileID: String, now: Date = Date()) -> Entry? {
        guard let store = try? withFileLock({ try loadStoreStrict() }) else { return nil }
        if let legacyEntry = store.legacy[profileID], legacyEntry.expiresAt > now {
            return legacyEntry
        }
        return nil
    }

    public func record(profileID: String, accessor: String, expiresAt: Date) throws {
        guard !accessor.isEmpty else { return }
        try withFileLock {
            var store = pruned(try loadStoreStrict(), now: Date())
            store.legacy[profileID] = Entry(accessor: accessor, expiresAt: expiresAt)
            try saveStore(store)
        }
    }

    /// Removes every bucket belonging to `profileID` (both target-scoped and legacy).
    public func remove(profileID: String) throws {
        try withFileLock {
            var store = try loadStoreStrict()
            store.legacy[profileID] = nil
            let prefix = "\(profileID)|"
            for key in store.targets.keys where key.hasPrefix(prefix) {
                store.targets[key] = nil
            }
            try saveStore(store)
        }
    }

    private func pruned(_ store: StoredV2, now: Date) -> StoredV2 {
        var out = StoredV2()
        for (key, list) in store.targets {
            let live = list.filter { $0.expiresAt > now }
            if !live.isEmpty { out.targets[key] = live }
        }
        for (key, entry) in store.legacy where entry.expiresAt > now {
            out.legacy[key] = entry
        }
        return out
    }

    /// Reads the state file strictly: a missing file yields an empty store, while an existing file
    /// that cannot be read or decoded throws `unreadableState` (never silently discarded or overwritten).
    private func loadStoreStrict() throws -> StoredV2 {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return StoredV2()
        }
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            throw GrantAccessorStoreError.unreadableState(url.path)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        if let v2 = try? decoder.decode(StoredV2.self, from: data), v2.version >= 2 {
            return v2
        }
        if let legacy = try? decoder.decode([String: Entry].self, from: data) {
            return StoredV2(version: 2, targets: [:], legacy: legacy)
        }
        throw GrantAccessorStoreError.unreadableState(url.path)
    }

    private func saveStore(_ store: StoredV2) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        try PrivateFile.write(try encoder.encode(store), to: url)
    }

    private func withFileLock<T>(_ body: () throws -> T) throws -> T {
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let lockPath = url.path + ".lock"
        let fd = open(lockPath, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            throw GrantAccessorStoreError.lockingFailed(String(cString: strerror(errno)))
        }
        defer { close(fd) }
        while flock(fd, LOCK_EX) != 0 {
            if errno == EINTR { continue }
            throw GrantAccessorStoreError.lockingFailed(String(cString: strerror(errno)))
        }
        defer { _ = flock(fd, LOCK_UN) }
        return try body()
    }
}
