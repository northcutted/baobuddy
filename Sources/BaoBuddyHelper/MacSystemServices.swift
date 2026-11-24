#if os(macOS)
import Foundation
import ServiceManagement
@preconcurrency import UserNotifications

/// Native macOS Launch at Login management via `SMAppService.mainApp`.
@MainActor
enum LaunchAtLoginManager {
    static var isSupported: Bool {
        Bundle.main.bundlePath.hasSuffix(".app")
    }

    static var isEnabled: Bool {
        guard isSupported else { return false }
        return SMAppService.mainApp.status == .enabled
    }

    static var statusSummary: String {
        guard isSupported else { return "Install in /Applications to enable" }
        switch SMAppService.mainApp.status {
        case .enabled: return "Enabled"
        case .requiresApproval: return "Needs approval in System Settings → Login Items"
        case .notRegistered: return "Off"
        case .notFound: return "Not installed"
        @unknown default: return "Off"
        }
    }

    @discardableResult
    static func setEnabled(_ enabled: Bool) -> String? {
        guard isSupported else {
            return "Launch at Login requires running BaoBuddyHelper.app."
        }
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            return nil
        } catch {
            return error.localizedDescription
        }
    }
}

/// Schedules optional macOS local notifications 5 minutes before an active grant expires.
/// Safely no-ops when invoked from a bare CLI binary outside an `.app` bundle.
@MainActor
enum GrantExpiryNotifier {
    private static let enabledKey = "baoBuddy.notifyBeforeExpiry"
    private static let leadSeconds: TimeInterval = 5 * 60

    static var isBundledApp: Bool {
        Bundle.main.bundlePath.hasSuffix(".app") && Bundle.main.bundleIdentifier != nil
    }

    static var isEnabled: Bool {
        get {
            if UserDefaults.standard.object(forKey: enabledKey) == nil {
                return true
            }
            return UserDefaults.standard.bool(forKey: enabledKey)
        }
        set {
            UserDefaults.standard.set(newValue, forKey: enabledKey)
            if !newValue {
                cancelAll()
            }
        }
    }

    static func scheduleWarning(
        identifier: String,
        serverName: String,
        targetName: String,
        ttlSeconds: Int
    ) {
        guard isBundledApp, isEnabled else { return }
        let fireAfter = TimeInterval(ttlSeconds) - leadSeconds
        guard fireAfter > 15 else { return }

        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = "BaoBuddy Grant Expiring Soon"
            content.body = "Your \(serverName) grant on \(targetName) expires in 5 minutes."
            content.sound = .default

            let trigger = UNTimeIntervalNotificationTrigger(timeInterval: fireAfter, repeats: false)
            let req = UNNotificationRequest(
                identifier: "baobuddy.expiry.\(identifier)",
                content: content,
                trigger: trigger
            )
            center.removePendingNotificationRequests(withIdentifiers: [req.identifier])
            center.add(req)
        }
    }

    static func cancel(identifier: String) {
        guard isBundledApp else { return }
        UNUserNotificationCenter.current().removePendingNotificationRequests(
            withIdentifiers: ["baobuddy.expiry.\(identifier)"]
        )
    }

    static func cancelAll() {
        guard isBundledApp else { return }
        UNUserNotificationCenter.current().removeAllPendingNotificationRequests()
    }
}
#endif
