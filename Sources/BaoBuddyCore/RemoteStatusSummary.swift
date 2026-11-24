import Foundation

/// Shared parser for remote granter / `baobuddy-receiver` `status` output, used by both iOS and macOS.
public struct RemoteStatusSummary: Equatable, Sendable {
    public enum EntryState: Equatable, Sendable {
        case active
        case inactive
        case unknown
    }

    public struct Entry: Equatable, Identifiable, Sendable {
        public let id: String
        public let label: String
        public let statusText: String
        public let detail: String
        public let state: EntryState
        public let systemImage: String

        public var isActive: Bool { state == .active }
        public var isUnknown: Bool { state == .unknown }

        public init(
            id: String,
            label: String,
            statusText: String,
            detail: String,
            state: EntryState,
            systemImage: String
        ) {
            self.id = id
            self.label = label
            self.statusText = statusText
            self.detail = detail
            self.state = state
            self.systemImage = systemImage
        }
    }

    public let entries: [Entry]
    public let rawText: String
    public let unavailableReason: String?

    public var hasActiveGrant: Bool {
        entries.contains(where: \.isActive)
    }

    public var hasUnknownStatus: Bool {
        entries.contains(where: \.isUnknown)
    }

    /// Overall header state: surfaces `.unknown` warning whenever any row couldn't be verified
    /// (for example OpenBao is unreachable even though an SSH certificate file is still present).
    public var headerState: EntryState {
        if hasUnknownStatus { return .unknown }
        if hasActiveGrant { return .active }
        return .inactive
    }

    public init(entries: [Entry], rawText: String, unavailableReason: String?) {
        self.entries = entries
        self.rawText = rawText
        self.unavailableReason = unavailableReason
    }

    public static func unavailable(_ message: String) -> RemoteStatusSummary {
        RemoteStatusSummary(entries: [], rawText: "", unavailableReason: message)
    }

    public static func parse(_ raw: String) -> RemoteStatusSummary {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return RemoteStatusSummary(entries: [], rawText: "", unavailableReason: nil)
        }
        var entries: [Entry] = []
        for line in trimmed.split(separator: "\n").map({ String($0).trimmingCharacters(in: .whitespaces) }) {
            if line.hasPrefix("Secrets:") {
                let body = cleanBody(String(line.dropFirst("Secrets:".count)))
                let entryState = classifyState(body, inactivePrefix: "no grant")
                let parsed = splitStatusAndDetail(body, state: entryState)
                let icon: String = switch entryState {
                case .active: "lock.open.fill"
                case .inactive: "lock.fill"
                case .unknown: "exclamationmark.triangle.fill"
                }
                entries.append(Entry(
                    id: "secrets",
                    label: String(localized: "Secrets", table: "BaoBuddyCore", comment: "Row label in the remote host status: whether the host holds a secrets token."),
                    statusText: parsed.status,
                    detail: parsed.detail,
                    state: entryState,
                    systemImage: icon
                ))
            } else if line.hasPrefix("SSH:") {
                let body = cleanBody(String(line.dropFirst("SSH:".count)))
                let entryState = classifyState(body, inactivePrefix: "no certificate")
                let parsed = splitStatusAndDetail(body, state: entryState)
                entries.append(Entry(
                    id: "ssh",
                    label: "SSH",
                    statusText: parsed.status,
                    detail: parsed.detail,
                    state: entryState,
                    systemImage: entryState == .unknown ? "exclamationmark.triangle.fill" : "terminal"
                ))
            } else if line.hasPrefix("Push:") {
                let body = cleanBody(String(line.dropFirst("Push:".count)))
                let entryState = classifyState(body, inactivePrefix: "no token")
                let parsed = splitStatusAndDetail(body, state: entryState)
                entries.append(Entry(
                    id: "push",
                    label: String(localized: "Git Push", table: "BaoBuddyCore", comment: "Row label in the remote host status: whether the host holds a token for git push."),
                    statusText: parsed.status,
                    detail: parsed.detail,
                    state: entryState,
                    systemImage: entryState == .unknown ? "exclamationmark.triangle.fill" : "arrow.up.circle"
                ))
            }
        }
        if entries.isEmpty {
            return .unavailable(trimmed)
        }
        return RemoteStatusSummary(entries: entries, rawText: trimmed, unavailableReason: nil)
    }

    /// Demo Mode knows when its simulated grant really ends, so it shows the time left in the
    /// user's language instead of the host's English text (`1h 59m left`). Output from a real
    /// host is never passed through here: it's parsed and shown as the host wrote it.
    public func localizingTimeLeft(until expiresAt: Date, now: Date = Date(), locale: Locale = .current) -> RemoteStatusSummary {
        let timeLeft = Self.localizedTimeLeft(seconds: Int(expiresAt.timeIntervalSince(now)), locale: locale)
        let updated = entries.map { entry -> Entry in
            // Only rows that carried a time left are rewritten; plain `Active` rows stay as they are.
            guard entry.state == .active, entry.statusText != Self.activeStatus else { return entry }
            return Entry(
                id: entry.id,
                label: entry.label,
                statusText: Self.activeStatus(remaining: timeLeft),
                detail: entry.detail,
                state: entry.state,
                systemImage: entry.systemImage
            )
        }
        return RemoteStatusSummary(entries: updated, rawText: rawText, unavailableReason: unavailableReason)
    }

    /// Time left on a grant in the user's language, in whole minutes (at least one), for example
    /// `1h 59m left` in English.
    public static func localizedTimeLeft(seconds: Int, locale: Locale = .current) -> String {
        let minutes = max(1, seconds / 60)
        var calendar = Calendar(identifier: .gregorian)
        calendar.locale = locale
        let formatter = DateComponentsFormatter()
        formatter.calendar = calendar
        formatter.unitsStyle = .abbreviated
        formatter.allowedUnits = minutes >= 60 ? [.hour, .minute] : [.minute]
        formatter.zeroFormattingBehavior = .dropAll
        let duration = formatter.string(from: TimeInterval(minutes * 60)) ?? "\(minutes)m"
        return String(localized: "\(duration) left", table: "BaoBuddyCore", comment: "Remote host status in Demo Mode: time left on a grant. %@ is a duration already in the user's language, for example: 1h 59m. Shown after: Active ·")
    }

    private static func cleanBody(_ raw: String) -> String {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        while text.hasSuffix(".") {
            text.removeLast()
        }
        return text
    }

    private static func classifyState(_ body: String, inactivePrefix: String) -> EntryState {
        let lower = body.lowercased()
        if lower.hasPrefix(inactivePrefix) {
            return .inactive
        }
        if lower.hasPrefix("unknown") {
            return .unknown
        }
        return .active
    }

    private static func splitStatusAndDetail(_ body: String, state: EntryState) -> (status: String, detail: String) {
        switch state {
        case .inactive:
            return (String(localized: "None", table: "BaoBuddyCore", comment: "Remote host status value: nothing is granted."), "")

        case .unknown:
            let lower = body.lowercased()
            if lower.hasPrefix("unknown ("), let closeIdx = body.lastIndex(of: ")") {
                let start = body.index(body.startIndex, offsetBy: "unknown (".count)
                let reason = String(body[start..<closeIdx]).trimmingCharacters(in: .whitespacesAndNewlines)
                return (unknownStatus, reason)
            }
            return (unknownStatus, lower == "unknown" ? "" : body)

        case .active:
            let lower = body.lowercased()
            // `baobuddy-receiver` emits `SSH: certificate present` when a signed cert file exists.
            if lower == "certificate present" || lower == "active" {
                return (activeStatus, "")
            }

            // `active (<remaining>[; <extra>])[ <suffix>]`
            if lower.hasPrefix("active (") {
                let start = body.index(body.startIndex, offsetBy: "active (".count)
                if let closeIdx = body[start...].firstIndex(of: ")") {
                    let inside = String(body[start..<closeIdx])
                    let parts = inside.split(separator: ";", maxSplits: 1).map {
                        $0.trimmingCharacters(in: .whitespacesAndNewlines)
                    }
                    let remaining = parts.first ?? ""
                    let extra = parts.count > 1 ? parts[1] : ""
                    let suffix = String(body[body.index(after: closeIdx)...]).trimmingCharacters(in: .whitespacesAndNewlines)
                    let detailParts = [extra, suffix].filter { !$0.isEmpty }
                    let status = remaining.isEmpty ? activeStatus : activeStatus(remaining: remaining)
                    return (status, detailParts.joined(separator: " "))
                }
            }

            // `<host-detail> (<remaining left>)`, e.g. `ops@staging-web (1h 59m left)`
            if body.hasSuffix(")"), let openIdx = body.lastIndex(of: "(") {
                let innerStart = body.index(after: openIdx)
                let innerEnd = body.index(before: body.endIndex)
                let inside = String(body[innerStart..<innerEnd]).trimmingCharacters(in: .whitespacesAndNewlines)
                let prefix = String(body[..<openIdx]).trimmingCharacters(in: .whitespacesAndNewlines)
                if inside.lowercased().hasSuffix("left") && !prefix.isEmpty {
                    return (activeStatus(remaining: inside), prefix)
                }
            }

            // Any other host-reported text stays verbatim on the detail line (never altering case).
            return (activeStatus, body)
        }
    }

    private static var unknownStatus: String {
        String(localized: "Unknown", table: "BaoBuddyCore", comment: "Remote host status value: the state couldn't be checked.")
    }

    private static var activeStatus: String {
        String(localized: "Active", table: "BaoBuddyCore", comment: "Remote host status value: a grant is active.")
    }

    /// `remaining` is the host's own text, such as `1h 59m left`, and isn't translated.
    private static func activeStatus(remaining: String) -> String {
        String(localized: "Active · \(remaining)", table: "BaoBuddyCore", comment: "Remote host status value. %@ is the time left as reported by the host, for example: 1h 59m left (not translated).")
    }
}
