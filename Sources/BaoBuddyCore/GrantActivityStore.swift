import Foundation

public enum GrantActivityAction: String, Codable, Equatable, Sendable {
    case granted
    case revoked
    case directToken = "direct_token"
    case personalToken = "personal_token"

    public var displayTitle: String {
        switch self {
        case .granted: String(localized: "Approved Grant", table: "BaoBuddyCore", comment: "Activity log entry title: a grant was approved.")
        case .revoked: String(localized: "Revoked Grant", table: "BaoBuddyCore", comment: "Activity log entry title: a grant was revoked.")
        case .directToken: String(localized: "Minted Direct Token", table: "BaoBuddyCore", comment: "Activity log entry title: a token was created and shown on this device (not sent to a remote host).")
        case .personalToken: String(localized: "Minted 15m CLI Token", table: "BaoBuddyCore", comment: "Activity log entry title: a 15-minute token was created for the command line. 15m means 15 minutes; CLI means command-line tool.")
        }
    }

    public var systemImage: String {
        switch self {
        case .granted: "checkmark.shield.fill"
        case .revoked: "xmark.shield.fill"
        case .directToken: "key.fill"
        case .personalToken: "terminal.fill"
        }
    }
}

/// Non-secret local activity record for reviewing grants approved or revoked from this device.
/// Never stores tokens, private keys, or SSH certificates.
public struct GrantActivityEntry: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let action: GrantActivityAction
    public let serverName: String
    public let namespace: String
    public let targetName: String
    public let policies: [String]
    public let hours: Int
    public let why: String
    public let elevated: Bool
    public let via: String

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        action: GrantActivityAction,
        serverName: String,
        namespace: String = "",
        targetName: String,
        policies: [String] = [],
        hours: Int = 0,
        why: String = "",
        elevated: Bool = false,
        via: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.action = action
        self.serverName = serverName
        self.namespace = namespace
        self.targetName = targetName
        self.policies = policies
        self.hours = hours
        self.why = why
        self.elevated = elevated
        self.via = via
    }
}

/// Persists the most recent non-secret grant activity records locally.
public struct GrantActivityStore: Sendable {
    public let fileURL: URL
    public let maxEntries: Int

    public init(fileURL: URL? = nil, maxEntries: Int = 100) {
        self.fileURL = fileURL ?? Self.defaultURL()
        self.maxEntries = maxEntries
    }

    public static func defaultURL() -> URL {
        #if os(macOS)
        let base = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config", isDirectory: true)
            .appendingPathComponent("baobuddy", isDirectory: true)
        return base.appendingPathComponent("activity.json")
        #else
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        return appSupport
            .appendingPathComponent("BaoBuddy", isDirectory: true)
            .appendingPathComponent("activity.json")
        #endif
    }

    public func load() -> [GrantActivityEntry] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([GrantActivityEntry].self, from: data)) ?? []
    }

    public func record(_ entry: GrantActivityEntry) {
        // An unreadable file is moved aside rather than overwritten, so history isn't lost.
        if let data = try? Data(contentsOf: fileURL), !data.isEmpty {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            if (try? decoder.decode([GrantActivityEntry].self, from: data)) == nil {
                let aside = fileURL.appendingPathExtension("unreadable-\(Int(Date().timeIntervalSince1970))")
                try? FileManager.default.moveItem(at: fileURL, to: aside)
            }
        }
        var entries = load()
        entries.insert(entry, at: 0)
        if entries.count > maxEntries {
            entries = Array(entries.prefix(maxEntries))
        }
        try? save(entries)
    }

    public func clear() throws {
        if FileManager.default.fileExists(atPath: fileURL.path) {
            try FileManager.default.removeItem(at: fileURL)
        }
    }

    public func exportCSV(_ entries: [GrantActivityEntry]? = nil) -> String {
        let rows = entries ?? load()
        let iso = ISO8601DateFormatter()
        var lines = ["timestamp,action,server,namespace,target,policies,hours,elevated,via,why"]
        for entry in rows {
            let fields = [
                iso.string(from: entry.timestamp),
                entry.action.rawValue,
                entry.serverName,
                entry.namespace,
                entry.targetName,
                entry.policies.joined(separator: ";"),
                String(entry.hours),
                entry.elevated ? "true" : "false",
                entry.via,
                entry.why
            ]
            lines.append(fields.map(Self.csvEscape).joined(separator: ","))
        }
        return lines.joined(separator: "\n") + "\n"
    }

    private func save(_ entries: [GrantActivityEntry]) throws {
        let dir = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(entries)
        try PrivateFile.write(data, to: fileURL, completeProtection: true)
    }

    private static func csvEscape(_ value: String) -> String {
        // A leading = + - @ (or tab/CR) makes spreadsheets evaluate the cell as a formula, and a
        // grant reason can come from a link. Prefix such values with ' so they stay text.
        var value = value
        if let first = value.unicodeScalars.first, "=+-@\t\r".unicodeScalars.contains(first) {
            value = "'" + value
        }
        if value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r") {
            return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return value
    }
}
