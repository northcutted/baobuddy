#if os(iOS) && canImport(ActivityKit)
import ActivityKit
import Foundation

/// Live Activity attributes displaying an active OpenBao grant countdown on the Lock Screen and Dynamic Island.
public struct GrantActivityAttributes: ActivityAttributes, Sendable {
    public struct ContentState: Codable, Hashable, Sendable {
        public var scopeSummary: String
        public var expiresAt: Date
        public var isElevated: Bool

        public init(scopeSummary: String, expiresAt: Date, isElevated: Bool) {
            self.scopeSummary = scopeSummary
            self.expiresAt = expiresAt
            self.isElevated = isElevated
        }
    }

    public var serverName: String
    public var targetName: String
    public var reason: String

    public init(serverName: String, targetName: String, reason: String) {
        self.serverName = serverName
        self.targetName = targetName
        self.reason = reason
    }
}
#endif
