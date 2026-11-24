#if os(macOS)
import AppKit
import BaoBuddyCore
import Foundation
import SwiftUI

/// Native macOS Menu Bar status item for `BaoBuddyHelper.app` when launched without CLI arguments.
/// Keeps a lightweight background poll for the menu bar icon + TTL, and lazily mounts a native
/// SwiftUI `NSPopover` on click so idle memory and CPU stay minimal.
@MainActor
final class MenuBarController: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private let statusItem: NSStatusItem
    private let state = MenuBarState()
    private lazy var settingsWindow = MacSettingsWindowController(state: state)
    private var popover: NSPopover?
    private var refreshTimer: Timer?
    private var clickOutsideMonitor: Any?

    override init() {
        self.statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()
        state.onStatusChange = { [weak self] in
            self?.updateButtonAppearance()
        }
        if let button = statusItem.button {
            button.target = self
            button.action = #selector(togglePopover(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
        updateButtonAppearance()
        startPolling()
        Task { await state.refreshAll() }
    }

    private func startPolling() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.state.refreshAll()
            }
        }
    }

    private func updateButtonAppearance() {
        guard let button = statusItem.button else { return }
        if state.isMacActive || state.isRemoteActive {
            button.image = Self.brandGlyph(
                "MenuBarGlyphUnlocked",
                fallbackSymbol: "lock.open.fill",
                description: "BaoBuddy active grant"
            )
            if let ttl = state.macGrantInfo?.ttlSeconds, ttl > 0 {
                button.title = " " + MenuBarState.formatTTL(ttl)
            } else {
                button.title = " Active"
            }
        } else {
            button.image = Self.brandGlyph(
                "MenuBarGlyph",
                fallbackSymbol: "lock.shield",
                description: "BaoBuddy idle"
            )
            button.title = ""
        }
    }

    /// Bao glyph PNG (@1x/@2x) from the app bundle (see `Branding/generate.py`) as a template image,
    /// so macOS tints it for light, dark and highlighted menu bars. Falls back to an SF Symbol
    /// when running outside the bundle (for example `swift run`).
    private static func brandGlyph(_ name: String, fallbackSymbol: String, description: String) -> NSImage? {
        guard let image = Bundle.main.image(forResource: name) else {
            return NSImage(systemSymbolName: fallbackSymbol, accessibilityDescription: description)
        }
        let height: CGFloat = 18
        image.size = NSSize(width: (image.size.width / image.size.height * height).rounded(), height: height)
        image.isTemplate = true
        image.accessibilityDescription = description
        return image
    }

    @objc private func togglePopover(_ sender: AnyObject?) {
        if let popover, popover.isShown {
            closePopover()
            return
        }
        showPopover()
    }

    private func showPopover() {
        guard let button = statusItem.button else { return }
        let pop = ensurePopover()
        NSApp.activate()
        if !pop.isShown {
            pop.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            installOutsideClickMonitor()
        }
        Task { await state.refreshIfStale(maxAge: 15) }
    }

    /// Handles incoming `baobuddy://grant?r=...` (and legacy `baogrant://`) deep links on macOS.
    func application(_ application: NSApplication, open urls: [URL]) {
        guard let first = urls.first else { return }
        state.handleIncomingURL(first)
        showPopover()
    }

    private func ensurePopover() -> NSPopover {
        if let popover { return popover }
        let pop = NSPopover()
        pop.behavior = .transient
        pop.animates = true
        pop.delegate = self
        let hosting = NSHostingController(
            rootView: MenuBarPopoverView(
                state: state,
                onOpenSettings: { [weak self] tab in
                    self?.closePopover()
                    self?.settingsWindow.show(tab: tab)
                },
                onQuit: {
                    NSApplication.shared.terminate(nil)
                }
            )
        )
        hosting.sizingOptions = .preferredContentSize
        pop.contentViewController = hosting
        self.popover = pop
        return pop
    }

    private func closePopover() {
        popover?.performClose(nil)
        removeOutsideClickMonitor()
    }

    nonisolated func popoverDidClose(_ notification: Notification) {
        Task { @MainActor [weak self] in
            self?.removeOutsideClickMonitor()
        }
    }

    private func installOutsideClickMonitor() {
        removeOutsideClickMonitor()
        clickOutsideMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.closePopover()
            }
        }
    }

    private func removeOutsideClickMonitor() {
        if let monitor = clickOutsideMonitor {
            NSEvent.removeMonitor(monitor)
            clickOutsideMonitor = nil
        }
    }
}

enum MenuBarLauncher {
    @MainActor
    static func run() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        installEditMenu(on: app)
        let controller = MenuBarController()
        app.delegate = controller
        withExtendedLifetime(controller) {
            app.run()
        }
    }

    /// Gives `.accessory` windows working ⌘C / ⌘V / ⌘X / ⌘A / ⌘Z inside text fields.
    @MainActor
    private static func installEditMenu(on app: NSApplication) {
        let mainMenu = NSMenu()
        let editMenuItem = NSMenuItem()
        mainMenu.addItem(editMenuItem)
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editMenuItem.submenu = editMenu
        app.mainMenu = mainMenu
    }
}
#endif
