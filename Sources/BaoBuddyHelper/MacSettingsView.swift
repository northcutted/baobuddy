#if os(macOS)
import AppKit
import BaoBuddyCore
import BaoBuddySSH
import Foundation
import SwiftUI

/// Lazily creates and presents a native macOS Settings & Servers window from the menu bar app.
@MainActor
final class MacSettingsWindowController: NSObject, NSWindowDelegate {
    private var window: NSWindow?
    private let state: MenuBarState
    private var initialTab: MacSettingsTab = .servers

    init(state: MenuBarState) {
        self.state = state
        super.init()
    }

    func show(tab: MacSettingsTab = .servers) {
        initialTab = tab
        if let window {
            window.contentViewController = makeHostingController(tab: tab)
            NSApp.activate()
            window.makeKeyAndOrderFront(nil)
            return
        }
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        win.title = "BaoBuddy Settings"
        win.minSize = NSSize(width: 780, height: 620)
        win.isReleasedWhenClosed = false
        win.delegate = self
        win.contentViewController = makeHostingController(tab: tab)
        win.center()
        self.window = win
        NSApp.activate()
        win.makeKeyAndOrderFront(nil)
    }

    private func makeHostingController(tab: MacSettingsTab) -> NSHostingController<MacSettingsView> {
        NSHostingController(rootView: MacSettingsView(state: state, initialTab: tab))
    }

    nonisolated func windowWillClose(_ notification: Notification) {
        Task { @MainActor [weak self] in
            await self?.state.refreshAll()
        }
    }
}

enum MacSettingsTab: String, CaseIterable, Identifiable {
    case servers = "Servers"
    case keys = "Hardware Keys"
    case activity = "Activity"
    case help = "About"
    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .servers: "server.rack"
        case .keys: "key.fill"
        case .activity: "clock.arrow.circlepath"
        case .help: "info.circle"
        }
    }
}

struct MacSettingsView: View {
    @Bindable var state: MenuBarState
    @State private var selectedTab: MacSettingsTab
    @State private var showImportSheet: Bool = false
    @State private var showAddManualSheet: Bool = false
    @State private var editingProfile: BaoProfile?
    @State private var qrProfile: BaoProfile?
    @State private var pendingDeleteProfile: BaoProfile?
    @State private var serverHealth: [String: (ok: Bool, message: String)] = [:]
    @State private var testingServerIDs: Set<String> = []

    // Keys tab state
    @State private var devicePEM: String = ""
    @State private var deviceFingerprint: String = ""
    @State private var sshPubKey: String = ""
    @State private var sshIsHardware: Bool = false
    @State private var keyError: String?
    @State private var copiedTag: String?
    @State private var showRegisterHowTo: Bool = false
    @State private var showDevicePEM: Bool = false
    @State private var showSSHKey: Bool = false
    @State private var showCLIReference: Bool = false
    @State private var confirmRotateJWT: Bool = false
    @State private var confirmRotateSSH: Bool = false

    // Activity & General state
    @State private var activityEntries: [GrantActivityEntry] = []
    @State private var confirmClearActivity: Bool = false
    @State private var launchAtLogin: Bool = LaunchAtLoginManager.isEnabled
    @State private var launchAtLoginError: String?
    @State private var notifyBeforeExpiry: Bool = GrantExpiryNotifier.isEnabled

    init(state: MenuBarState, initialTab: MacSettingsTab = .servers) {
        self.state = state
        self._selectedTab = State(initialValue: initialTab)
    }

    var body: some View {
        VStack(spacing: 0) {
            tabBar
            Divider()

            switch selectedTab {
            case .servers:
                serversTab
            case .keys:
                keysTab
            case .activity:
                activityTab
            case .help:
                helpTab
            }
        }
        .frame(minWidth: 780, minHeight: 620)
        .onAppear {
            loadKeys()
            activityEntries = GrantActivityStore().load()
            launchAtLogin = LaunchAtLoginManager.isEnabled
            notifyBeforeExpiry = GrantExpiryNotifier.isEnabled
        }
        .onChange(of: selectedTab) { _, tab in
            if tab == .activity {
                activityEntries = GrantActivityStore().load()
            } else if tab == .help {
                launchAtLogin = LaunchAtLoginManager.isEnabled
            } else if tab == .keys {
                loadKeys()
            }
        }
        .onChange(of: state.activeProfileID) { _, _ in
            loadKeys()
        }
        .sheet(isPresented: $showImportSheet) {
            MacImportProfileSheet(state: state)
        }
        .sheet(isPresented: $showAddManualSheet) {
            MacEditProfileSheet(state: state, existing: nil)
        }
        .sheet(item: $editingProfile) { item in
            MacEditProfileSheet(state: state, existing: item)
        }
        .sheet(item: $qrProfile) { item in
            MacQRPairSheet(profile: item, disableClipboard: state.isClipboardDisabled)
        }
    }

    private var tabBar: some View {
        HStack(spacing: 6) {
            ForEach(MacSettingsTab.allCases) { tab in
                let isSelected = selectedTab == tab
                Button {
                    selectedTab = tab
                } label: {
                    Label(tab.rawValue, systemImage: tab.symbol)
                        .font(.subheadline.weight(isSelected ? .semibold : .medium))
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(
                            isSelected ? MacBaoTheme.brand.opacity(0.16) : Color.clear,
                            in: RoundedRectangle(cornerRadius: 8, style: .continuous)
                        )
                        .foregroundStyle(isSelected ? MacBaoTheme.brand : .secondary)
                        .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
        .background(.bar)
    }

    // MARK: - Servers Tab

    private var serversTab: some View {
        Form {
            Section {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "server.rack")
                        .font(.title3)
                        .foregroundStyle(MacBaoTheme.brand)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("OpenBao & HashiCorp Vault servers")
                            .font(.subheadline.weight(.medium))
                        Text("Switch between environments anytime from the menu bar. Each server can mint grants for this Mac and optionally deliver them to a remote host over SSH.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 2)

                HStack(spacing: 8) {
                    if state.areProfilesLocked {
                        statusPill("Managed by Organization (MDM)", tint: MacBaoTheme.brand, symbol: "building.2.fill")
                    } else {
                        Button {
                            showAddManualSheet = true
                        } label: {
                            Label("Add Server…", systemImage: "plus")
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(MacBaoTheme.brand)

                        Button {
                            showImportSheet = true
                        } label: {
                            Label("Import Profile JSON…", systemImage: "doc.badge.arrow.up")
                        }
                        .buttonStyle(.bordered)
                    }

                    Button {
                        MacTofuWindowController.shared.show(
                            profile: state.profile,
                            macPublicKeyPEM: MacSettingsLogic.scopedPublicKeyPEM(for: state.profile)
                        )
                    } label: {
                        Label("OpenTofu Builder…", systemImage: "cube.transparent")
                    }
                    .buttonStyle(.bordered)

                    Spacer()
                }
                .padding(.vertical, 2)
            }

            if state.profiles.isEmpty {
                firstRunSetupSection
            } else {
                ForEach(state.profiles) { item in
                    serverCardSection(for: item)
                }
            }
        }
        .formStyle(.grouped)
        .confirmationDialog(
            "Remove \(pendingDeleteProfile?.displayName ?? "Server")?",
            isPresented: Binding(
                get: { pendingDeleteProfile != nil },
                set: { if !$0 { pendingDeleteProfile = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Remove Server", role: .destructive) {
                if let target = pendingDeleteProfile {
                    state.deleteProfile(id: target.id)
                    serverHealth.removeValue(forKey: target.id)
                }
                pendingDeleteProfile = nil
            }
            Button("Cancel", role: .cancel) {
                pendingDeleteProfile = nil
            }
        } message: {
            Text("This removes the server profile from BaoBuddy on this Mac. Your OpenBao server and Touch ID hardware keys are not affected.")
        }
    }

    private func serverCardSection(for item: BaoProfile) -> some View {
        let isActive = item.id == state.profile?.id
        let isTesting = testingServerIDs.contains(item.id)
        let hasPinnedCert = !item.openbao.caPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        let copyTag = "json-\(item.id)"

        return Section {
            HStack(spacing: 12) {
                keyIconBadge(symbol: "server.rack", tint: isActive ? MacBaoTheme.brand : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.displayName)
                        .font(.headline)
                    Text(verbatim: item.openbao.address)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                Spacer()
                if isActive {
                    statusPill("Active", tint: MacBaoTheme.active, symbol: "checkmark.circle.fill")
                } else {
                    Button("Set Active") {
                        state.selectProfile(id: item.id)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
            .padding(.vertical, 2)

            LabeledContent("Delivery") {
                let targets = item.configuredRemoteTargets
                if targets.count > 1 {
                    Text("This Mac + \(targets.map(\.displayName).joined(separator: ", "))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if let first = targets.first {
                    Text("This Mac + \(first.displayName) (\(first.user)@\(first.host))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("This Mac only")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            LabeledContent("Policies") {
                Text(policySummary(for: item))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }

            LabeledContent("Security") {
                HStack(spacing: 5) {
                    if hasPinnedCert {
                        Image(systemName: "lock.fill")
                            .font(.caption2)
                            .foregroundStyle(MacBaoTheme.active)
                        Text("Pinned TLS")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("System CAs")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if !item.openbao.mtlsClientIdentity.isEmpty {
                        Text("•")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                        Text("mTLS")
                            .font(.caption.weight(.medium))
                            .foregroundStyle(MacBaoTheme.brand)
                    }
                    Text("•")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                    Text("Max \(item.openbao.maxHours)h")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            LabeledContent("JWT Identity") {
                Text("\(item.openbao.jwtAuth.subject) • mount: \(item.openbao.jwtAuth.mount)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }

            if !item.openbao.namespace.isEmpty {
                LabeledContent("Namespace") {
                    Text(item.openbao.namespace)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }

            if !item.openbao.auditPolicy.isEmpty {
                LabeledContent("Audit Policy") {
                    Text(auditSummary(for: item.openbao.auditPolicy))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if let result = serverHealth[item.id] {
                HStack(spacing: 6) {
                    Image(systemName: result.ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(result.ok ? MacBaoTheme.active : .red)
                    Text(result.message)
                        .font(.caption)
                        .foregroundStyle(result.ok ? MacBaoTheme.active : .red)
                        .textSelection(.enabled)
                    Spacer()
                }
            }

            HStack(spacing: 8) {
                Button {
                    Task { await testServerConnection(item) }
                } label: {
                    HStack(spacing: 5) {
                        if isTesting {
                            ProgressView().controlSize(.small)
                        } else {
                            Image(systemName: "network")
                        }
                        Text(isTesting ? "Testing…" : "Test Connection")
                    }
                }
                .buttonStyle(.bordered)
                .fixedSize()
                .disabled(isTesting)

                if !state.areProfilesLocked && !state.isManaged(profileID: item.id) {
                    Button {
                        editingProfile = item
                    } label: {
                        Label("Edit…", systemImage: "slider.horizontal.3")
                    }
                    .buttonStyle(.bordered)
                    .fixedSize()
                }

                Menu {
                    Button {
                        qrProfile = item
                    } label: {
                        Label("Pair iPhone (QR Code)…", systemImage: "qrcode")
                    }

                    if !state.isClipboardDisabled {
                        Button {
                            copyProfileJSON(item, tag: copyTag)
                        } label: {
                            Label("Copy Profile JSON", systemImage: "doc.on.doc")
                        }
                    }

                    Divider()

                    Button {
                        MacTofuWindowController.shared.show(
                            profile: item,
                            macPublicKeyPEM: MacSettingsLogic.scopedPublicKeyPEM(for: item)
                        )
                    } label: {
                        Label("Open in OpenTofu Builder…", systemImage: "cube.transparent")
                    }

                    if !state.isClipboardDisabled {
                        Divider()

                        Button {
                            copyWithFeedback(BaoAgentPrompts.renderAgentsMarkdown(profile: item), tag: copyTag)
                        } label: {
                            Label("Copy Agent Rule (AGENTS.md)", systemImage: "cpu")
                        }

                        Button {
                            copyWithFeedback(BaoAgentPrompts.renderMCPConfigJSON(), tag: copyTag)
                        } label: {
                            Label("Copy MCP Server Config JSON", systemImage: "point.3.connected.trianglepath.dotted")
                        }
                    }
                } label: {
                    Label(
                        copiedTag == copyTag ? "Copied JSON" : "Share & Export",
                        systemImage: copiedTag == copyTag ? "checkmark" : "square.and.arrow.up"
                    )
                }
                .menuStyle(.button)
                .buttonStyle(.bordered)
                .fixedSize()

                Spacer(minLength: 12)

                if !state.areProfilesLocked && !state.isManaged(profileID: item.id) {
                    Button(role: .destructive) {
                        pendingDeleteProfile = item
                    } label: {
                        Label("Remove…", systemImage: "trash")
                            .foregroundStyle(.red)
                    }
                    .buttonStyle(.bordered)
                    .fixedSize()
                }
            }
            .padding(.vertical, 3)
        }
    }

    private func auditSummary(for audit: BaoAuditPolicy) -> String {
        var parts: [String] = []
        if audit.requireReason {
            parts.append("Reason required")
        } else if audit.requireReasonForElevated {
            parts.append("Reason on elevated")
        }
        if !audit.reasonPattern.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            parts.append("Ticket format enforced")
        }
        return parts.joined(separator: " • ")
    }

    private var firstRunSetupSection: some View {
        Section {
            setupStepRow(
                number: 1,
                done: !devicePEM.isEmpty,
                title: "Create your Touch ID Approval Key",
                detail: devicePEM.isEmpty
                    ? "Generates a non-exportable EC P-256 key inside Apple's Secure Enclave."
                    : "Ready (sha256:\(deviceFingerprint.prefix(16))…)."
            ) {
                if devicePEM.isEmpty {
                    Button("Create Key") { createDeviceKey() }
                        .buttonStyle(.borderedProminent)
                        .tint(MacBaoTheme.brand)
                        .controlSize(.small)
                } else {
                    Button(copiedTag == "setup-pem" ? "Copied" : "Copy PEM") {
                        copyWithFeedback(devicePEM, tag: "setup-pem")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }

            setupStepRow(
                number: 2,
                done: false,
                title: "Register this Mac on your OpenBao server",
                detail: "Run `bao-buddy device add --self` in Terminal, or bootstrap a new server with `bao-buddy server-setup`."
            ) {
                Button(copiedTag == "setup-cmd" ? "Copied" : "Copy Command") {
                    copyWithFeedback("bao-buddy device add --self", tag: "setup-cmd")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            setupStepRow(
                number: 3,
                done: !state.profiles.isEmpty,
                title: "Add your server or import a profile",
                detail: "Connect manually or paste the JSON from `bao-buddy export-profile`."
            ) {
                HStack(spacing: 6) {
                    Button("Import JSON…") { showImportSheet = true }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    Button("Add Server…") { showAddManualSheet = true }
                        .buttonStyle(.borderedProminent)
                        .tint(MacBaoTheme.brand)
                        .controlSize(.small)
                }
            }
            inlineNote("Need remote SSH delivery too? Create an optional SSH key anytime in Hardware Keys.")
        } header: {
            Text("Quick Setup")
        }
    }

    private func setupStepRow<Accessory: View>(
        number: Int,
        done: Bool,
        title: String,
        detail: String,
        @ViewBuilder action: () -> Accessory
    ) -> some View {
        HStack(alignment: .center, spacing: 10) {
            ZStack {
                Circle()
                    .fill(done ? MacBaoTheme.active.opacity(0.16) : MacBaoTheme.brand.opacity(0.14))
                    .frame(width: 24, height: 24)
                if done {
                    Image(systemName: "checkmark")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(MacBaoTheme.active)
                } else {
                    Text("\(number)")
                        .font(.caption.weight(.bold).monospacedDigit())
                        .foregroundStyle(MacBaoTheme.brand)
                }
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.medium))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            action()
        }
        .padding(.vertical, 2)
    }

    private func policySummary(for item: BaoProfile) -> String {
        if item.openbao.usesCustomPolicies {
            let names = item.openbao.grantPolicies.map(\.displayLabel)
            return names.isEmpty ? "Custom" : names.joined(separator: ", ")
        }
        var parts = ["Read / Write"]
        if !item.openbao.keys.isEmpty {
            let count = item.openbao.keys.count
            parts.append("\(count) \(count == 1 ? "key" : "keys")")
        }
        if !item.openbao.ssh.hosts.isEmpty {
            let count = item.openbao.ssh.hosts.count
            parts.append("\(count) SSH \(count == 1 ? "host" : "hosts")")
        }
        return parts.joined(separator: " • ")
    }

    // MARK: - Hardware Keys Tab

    private var keysTab: some View {
        Form {
            Section {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "lock.shield.fill")
                        .font(.title3)
                        .foregroundStyle(MacBaoTheme.brand)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Passwordless keys stored in your Mac's Secure Enclave")
                            .font(.subheadline.weight(.medium))
                        Text("Private keys never leave this Mac. You only copy the public half to your server so it can trust your approvals.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 2)
            }

            if let keyError {
                Section {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                        Text(keyError)
                            .font(.caption)
                            .foregroundStyle(.red)
                        Spacer()
                        Button("Dismiss") { self.keyError = nil }
                            .buttonStyle(.borderless)
                            .font(.caption)
                    }
                }
            }

            jwtKeySection
            sshKeySection
        }
        .formStyle(.grouped)
        .confirmationDialog(
            "Rotate Touch ID Approval Key?",
            isPresented: $confirmRotateJWT,
            titleVisibility: .visible
        ) {
            Button("Rotate Key", role: .destructive) {
                createDeviceKey(overwrite: true)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            if let active = state.profile {
                let regCmd = BaoServerAdmin.renderDeviceAddCommand(
                    address: active.openbao.address,
                    namespace: active.openbao.namespace,
                    caCertPath: active.openbao.isTLSPinned ? "<ca.pem>" : "",
                    mtlsClientIdentity: active.openbao.mtlsClientIdentity,
                    mount: active.openbao.jwtAuth.mount,
                    selfKey: true
                )
                Text("This permanently replaces your Mac's approval key for \(active.displayName). Register the new public key (`\(regCmd)`) before approving grants.")
            } else {
                Text("Select a server before rotating its approval key.")
            }
        }
        .confirmationDialog(
            "Rotate Remote Host SSH Key?",
            isPresented: $confirmRotateSSH,
            titleVisibility: .visible
        ) {
            Button("Rotate SSH Key", role: .destructive) {
                createSSHKey(overwrite: true)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This replaces your Mac's SSH key. Update `authorized_keys` on any remote host with the new public key.")
        }
    }

    private var jwtKeySection: some View {
        let active = state.profile
        let mount = active?.openbao.jwtAuth.mount ?? "jwt-user"
        return Section {
            HStack(spacing: 12) {
                keyIconBadge(symbol: "touchid", tint: MacBaoTheme.brand)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Touch ID Approval Key")
                        .font(.headline)
                    if let active {
                        Text("Dedicated key for \(active.displayName) (auth/\(mount)/).")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("Add or select a server in Servers first before creating its approval key.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if !devicePEM.isEmpty {
                    statusPill("Active • Touch ID", tint: MacBaoTheme.active, symbol: "checkmark.shield.fill")
                } else {
                    statusPill("Not Set Up", tint: .secondary, symbol: nil)
                }
            }
            .padding(.vertical, 2)

            if devicePEM.isEmpty {
                HStack {
                    Text(active == nil
                        ? "Configure a server in Servers first; keys are scoped per server deployment."
                        : "Create a dedicated key for \(active?.displayName ?? "this server"), then register its public half on OpenBao.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Create Key") {
                        createDeviceKey()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(active == nil)
                    .tint(MacBaoTheme.brand)
                }
            } else {
                LabeledContent("Where it goes") {
                    Text("Your OpenBao / Vault server (`auth/\(mount)/config`)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                LabeledContent("Key ID") {
                    HStack(spacing: 6) {
                        Text("sha256:\(deviceFingerprint)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                        Button {
                            copyWithFeedback("sha256:\(deviceFingerprint)", tag: "fp")
                        } label: {
                            Image(systemName: copiedTag == "fp" ? "checkmark" : "doc.on.doc")
                                .font(.caption)
                                .foregroundStyle(copiedTag == "fp" ? MacBaoTheme.active : .secondary)
                        }
                        .buttonStyle(.borderless)
                        .help("Copy fingerprint")
                    }
                }

                let registerCmd = active.map {
                    BaoServerAdmin.renderDeviceAddCommand(
                        address: $0.openbao.address,
                        namespace: $0.openbao.namespace,
                        caCertPath: $0.openbao.isTLSPinned ? "<ca.pem>" : "",
                        mtlsClientIdentity: $0.openbao.mtlsClientIdentity,
                        mount: $0.openbao.jwtAuth.mount,
                        selfKey: true
                    )
                } ?? "bao-buddy device add --self --mount \(mount)"

                DisclosureGroup("How to register this key on OpenBao", isExpanded: $showRegisterHowTo) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Run this once in Terminal with an admin `BAO_TOKEN` set:")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        MacCodeBox(text: registerCmd, language: .shell)
                        Text("Or save the `.pem` file below and add it to `jwt_validation_pubkeys` manually.")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.top, 4)
                }

                DisclosureGroup("View Public Key (PEM)", isExpanded: $showDevicePEM) {
                    MacCodeBox(text: devicePEM, language: .pem, fontSize: 11)
                        .padding(.top, 4)
                }

                HStack(spacing: 8) {
                    Button {
                        copyWithFeedback(devicePEM, tag: "pem")
                    } label: {
                        Label(
                            copiedTag == "pem" ? "Copied Public Key" : "Copy Public Key",
                            systemImage: copiedTag == "pem" ? "checkmark" : "doc.on.doc"
                        )
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(copiedTag == "pem" ? MacBaoTheme.active : MacBaoTheme.brand)
                    .fixedSize()

                    Button {
                        copyWithFeedback(registerCmd, tag: "reg")
                    } label: {
                        Label(
                            copiedTag == "reg" ? "Copied Command" : "Copy Setup Command",
                            systemImage: copiedTag == "reg" ? "checkmark" : "terminal"
                        )
                    }
                    .buttonStyle(.bordered)
                    .fixedSize()

                    Button("Save .pem…") {
                        saveTextToFile(devicePEM, defaultName: "baobuddy-mac.pem")
                    }
                    .buttonStyle(.bordered)
                    .fixedSize()

                    Spacer(minLength: 8)

                    Button(role: .destructive) {
                        confirmRotateJWT = true
                    } label: {
                        Label("Rotate…", systemImage: "arrow.triangle.2.circlepath")
                            .foregroundStyle(.red)
                    }
                    .buttonStyle(.bordered)
                    .fixedSize()
                }
                .padding(.vertical, 2)
            }

            inlineNote("EC P-256 hardware key • Invalidates automatically if your Mac's Touch ID fingerprints change.", symbol: "touchid")
        } header: {
            Text("1. Approval Key (Required)")
        }
    }

    private var sshKeySection: some View {
        let sshKeyType = sshPubKey.split(separator: " ").first.map(String.init) ?? ""
        let remoteDesc: String = {
            if let profile = state.profile, profile.hasRemoteTarget {
                return "Used for \(profile.targetDisplayName) (\(profile.t3Granter.user)@\(profile.t3Granter.host))"
            }
            return "Skip if you only mint tokens for this Mac"
        }()

        return Section {
            HStack(spacing: 12) {
                keyIconBadge(
                    symbol: "terminal",
                    tint: sshPubKey.isEmpty || sshIsHardware ? MacBaoTheme.brand : MacBaoTheme.elevated
                )
                VStack(alignment: .leading, spacing: 2) {
                    Text("Remote Host SSH Key")
                        .font(.headline)
                    Text("Only needed if BaoBuddy sends grants to another machine (like a VM or bastion) over SSH.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if sshPubKey.isEmpty {
                    statusPill("Optional", tint: .secondary, symbol: nil)
                } else if sshIsHardware {
                    statusPill("Hardware", tint: MacBaoTheme.active, symbol: "checkmark.shield.fill")
                } else {
                    statusPill("Software", tint: MacBaoTheme.elevated, symbol: "exclamationmark.triangle.fill")
                }
            }
            .padding(.vertical, 2)

            if sshPubKey.isEmpty {
                HStack {
                    Text(remoteDesc)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Create SSH Key") {
                        createSSHKey()
                    }
                    .buttonStyle(.bordered)
                }
            } else {
                LabeledContent("Used for") {
                    Text(remoteDesc)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                LabeledContent("Where it goes") {
                    Text("The remote host's `authorized_keys`")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if !sshKeyType.isEmpty {
                    LabeledContent("Algorithm") {
                        Text(sshIsHardware ? "\(sshKeyType) (Secure Enclave)" : "\(sshKeyType) (Software)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }

                DisclosureGroup("View OpenSSH Public Key", isExpanded: $showSSHKey) {
                    MacCodeBox(text: sshPubKey, language: .openSSH, fontSize: 11)
                        .padding(.top, 4)
                }

                HStack(spacing: 8) {
                    Button {
                        copyWithFeedback(sshPubKey, tag: "ssh")
                    } label: {
                        Label(
                            copiedTag == "ssh" ? "Copied SSH Key" : "Copy SSH Public Key",
                            systemImage: copiedTag == "ssh" ? "checkmark" : "doc.on.doc"
                        )
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(copiedTag == "ssh" ? MacBaoTheme.active : MacBaoTheme.brand)
                    .fixedSize()

                    Button("Save .pub…") {
                        saveTextToFile(sshPubKey + "\n", defaultName: "baobuddy-mac.pub")
                    }
                    .buttonStyle(.bordered)
                    .fixedSize()

                    if !sshIsHardware {
                        Button("Upgrade to Hardware") {
                            createSSHKey(overwrite: true)
                        }
                        .buttonStyle(.bordered)
                        .tint(MacBaoTheme.elevated)
                        .fixedSize()
                    }

                    Spacer(minLength: 8)

                    Button(role: .destructive) {
                        confirmRotateSSH = true
                    } label: {
                        Label("Rotate…", systemImage: "arrow.triangle.2.circlepath")
                            .foregroundStyle(.red)
                    }
                    .buttonStyle(.bordered)
                    .fixedSize()
                }
                .padding(.vertical, 2)
            }

            inlineNote("Lets BaoBuddy check grant status and deliver approved tokens to a remote host without touching ~/.ssh/id_ed25519.", symbol: "terminal")
        } header: {
            Text("2. Remote Host SSH Key (Optional)")
        }
    }

    private func keyIconBadge(symbol: String, tint: Color) -> some View {
        RoundedRectangle(cornerRadius: 9, style: .continuous)
            .fill(tint.gradient)
            .frame(width: 34, height: 34)
            .overlay {
                Image(systemName: symbol)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(MacBaoTheme.cream)
            }
    }

    private func statusPill(_ title: String, tint: Color, symbol: String?) -> some View {
        HStack(spacing: 4) {
            if let symbol {
                Image(systemName: symbol)
                    .font(.caption2)
            }
            Text(title)
                .font(.caption2.weight(.semibold))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(tint.opacity(0.14), in: Capsule())
        .foregroundStyle(tint)
    }

    private func inlineNote(_ text: String, symbol: String = "info.circle") -> some View {
        let iconTint: Color = (symbol == "touchid" || symbol == "lock.shield")
            ? MacBaoTheme.brand.opacity(0.9)
            : .secondary
        return HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(iconTint)
                .frame(width: 16, alignment: .center)
            Text(text)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    // MARK: - Activity Tab

    private var activityTab: some View {
        Form {
            Section {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.title3)
                        .foregroundStyle(MacBaoTheme.brand)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Local Grant Activity")
                            .font(.subheadline.weight(.medium))
                        Text("Recent approvals and revocations from this Mac (menu bar and CLI). Stores metadata only — never tokens or keys.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 2)

                HStack(spacing: 8) {
                    Button {
                        activityEntries = GrantActivityStore().load()
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)

                    if !activityEntries.isEmpty && !state.isClipboardDisabled {
                        Button {
                            let csv = GrantActivityStore().exportCSV(activityEntries)
                            copyWithFeedback(csv, tag: "activity-csv")
                        } label: {
                            Label(
                                copiedTag == "activity-csv" ? "Copied CSV" : "Copy CSV",
                                systemImage: copiedTag == "activity-csv" ? "checkmark" : "doc.on.doc"
                            )
                        }
                        .buttonStyle(.bordered)
                        .tint(copiedTag == "activity-csv" ? MacBaoTheme.active : nil)
                    }

                    Spacer()

                    if !activityEntries.isEmpty {
                        Button(role: .destructive) {
                            confirmClearActivity = true
                        } label: {
                            Label("Clear History…", systemImage: "trash")
                                .foregroundStyle(.red)
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .padding(.vertical, 2)
            }

            if activityEntries.isEmpty {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("No grant activity recorded yet")
                            .font(.subheadline.weight(.medium))
                        Text("Approvals and revocations made from this Mac will appear here.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            } else {
                Section("Recent Events (\(activityEntries.count))") {
                    ForEach(activityEntries) { entry in
                        activityRow(entry)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .confirmationDialog(
            "Clear Local Activity History?",
            isPresented: $confirmClearActivity,
            titleVisibility: .visible
        ) {
            Button("Clear History", role: .destructive) {
                try? GrantActivityStore().clear()
                activityEntries = []
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This removes the local activity log on this Mac. OpenBao / Vault server audit logs are not affected.")
        }
    }

    private func activityRow(_ entry: GrantActivityEntry) -> some View {
        let tint: Color = {
            if entry.action == .revoked { return .secondary }
            return entry.elevated ? MacBaoTheme.elevated : MacBaoTheme.active
        }()

        return HStack(alignment: .top, spacing: 10) {
            Image(systemName: entry.action.systemImage)
                .foregroundStyle(tint)
                .font(.subheadline)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(entry.action.displayTitle)
                        .font(.subheadline.weight(.medium))
                    Text("•")
                        .foregroundStyle(.tertiary)
                    Text("\(entry.serverName) → \(entry.targetName)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if entry.elevated {
                        statusPill("Elevated", tint: MacBaoTheme.elevated, symbol: nil)
                    }
                    Spacer()
                    Text(entry.timestamp, style: .relative)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }

                if !entry.policies.isEmpty || entry.hours > 0 {
                    HStack(spacing: 6) {
                        if !entry.policies.isEmpty {
                            Text(entry.policies.joined(separator: ", "))
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        if entry.hours > 0 {
                            Text("(\(entry.hours)h)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        if !entry.namespace.isEmpty {
                            Text("ns: \(entry.namespace)")
                                .font(.caption2.monospaced())
                                .foregroundStyle(.tertiary)
                        }
                    }
                }

                if !entry.why.isEmpty {
                    Text(entry.why)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 2)
    }

    // MARK: - Help & About Tab

    private static let repoURL = URL(string: "https://github.com/northcutted/baobuddy")!
    private static let issuesURL = URL(string: "https://github.com/northcutted/baobuddy/issues/new")!
    private static let releasesURL = URL(string: "https://github.com/northcutted/baobuddy/releases")!

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0"
    }

    private var appBuild: String {
        Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
    }

    private var helpTab: some View {
        let cliSnippet = """
        bao-buddy server-setup --subject $USER --policies db-readonly,k8s-deploy --add-self
        bao-buddy export-profile --subject $USER --elevated k8s-deploy --copy --save
        bao-buddy status
        bao-buddy health
        bao-buddy grant --on local --hours 2 --why "deploy"
        bao-buddy revoke --on remote
        """
        let configPath = NSHomeDirectory() + "/.config/baobuddy/profiles.json"
        let cliLink = CLILinkResolver.detect()

        return Form {
            Section {
                HStack(spacing: 14) {
                    if let appIcon = NSApp.applicationIconImage {
                        Image(nsImage: appIcon)
                            .resizable()
                            .scaledToFit()
                            .frame(width: 48, height: 48)
                    } else {
                        keyIconBadge(symbol: "lock.shield.fill", tint: MacBaoTheme.brand)
                    }
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 8) {
                            Text("BaoBuddy")
                                .font(.title3.weight(.semibold))
                            statusPill("v\(appVersion)", tint: MacBaoTheme.brand, symbol: nil)
                        }
                        Text("Hardware-backed biometric grants for OpenBao & HashiCorp Vault.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .padding(.vertical, 4)

                LabeledContent("Version") {
                    Text("\(appVersion) (build \(appBuild))")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }

                LabeledContent("macOS") {
                    Text(ProcessInfo.processInfo.operatingSystemVersionString)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                LabeledContent("CLI") {
                    HStack(spacing: 6) {
                        Text(cliLink?.displayPath ?? "Not linked")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        if cliLink != nil {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.caption)
                                .foregroundStyle(MacBaoTheme.active)
                        }
                    }
                }

                LabeledContent("Profiles") {
                    HStack(spacing: 6) {
                        Text("~/.config/baobuddy/profiles.json")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        Button {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: configPath)])
                        } label: {
                            Image(systemName: "folder")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                        .help("Reveal in Finder")
                    }
                }
            } header: {
                Text("About")
            }

            Section {
                Toggle(isOn: Binding(
                    get: { launchAtLogin },
                    set: { newValue in
                        if let err = LaunchAtLoginManager.setEnabled(newValue) {
                            launchAtLoginError = err
                        } else {
                            launchAtLoginError = nil
                        }
                        launchAtLogin = LaunchAtLoginManager.isEnabled
                    }
                )) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Start BaoBuddy at Login")
                        Text(LaunchAtLoginManager.statusSummary)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .tint(MacBaoTheme.brand)
                .disabled(!LaunchAtLoginManager.isSupported)

                if let launchAtLoginError {
                    Text(launchAtLoginError)
                        .font(.caption2)
                        .foregroundStyle(.red)
                }

                Toggle(isOn: Binding(
                    get: { notifyBeforeExpiry },
                    set: { newValue in
                        notifyBeforeExpiry = newValue
                        GrantExpiryNotifier.isEnabled = newValue
                    }
                )) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Expiry Notifications")
                        Text("Send a macOS alert 5 minutes before an active grant expires.")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                .tint(MacBaoTheme.brand)
            } header: {
                Text("General")
            }

            Section {
                Text("Expose BaoBuddy to Claude Code, Codex, Cursor, Windsurf, or Antigravity via stdio MCP (`bao-buddy mcp`). Agents can request grants and self-revoke, but can never bypass Touch ID or read raw tokens into chat context.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                HStack(spacing: 8) {
                    Button {
                        copyWithFeedback(BaoAgentPrompts.renderMCPConfigJSON(), tag: "mcp-json")
                    } label: {
                        Label(
                            copiedTag == "mcp-json" ? "Copied MCP JSON" : "Copy MCP Config",
                            systemImage: copiedTag == "mcp-json" ? "checkmark" : "point.3.connected.trianglepath.dotted"
                        )
                    }
                    .buttonStyle(.bordered)
                    .tint(copiedTag == "mcp-json" ? MacBaoTheme.active : nil)

                    Button {
                        copyWithFeedback(BaoAgentPrompts.renderAgentsMarkdown(profile: state.profile), tag: "agents-md")
                    } label: {
                        Label(
                            copiedTag == "agents-md" ? "Copied Rule" : "Copy AGENTS.md Rule",
                            systemImage: copiedTag == "agents-md" ? "checkmark" : "cpu"
                        )
                    }
                    .buttonStyle(.bordered)
                    .tint(copiedTag == "agents-md" ? MacBaoTheme.active : nil)

                    Spacer()
                }
                .padding(.vertical, 2)
            } header: {
                Text("AI Agents & MCP Server")
            }

            Section {
                externalLinkRow(
                    title: "Documentation & Source Code",
                    subtitle: "github.com/northcutted/baobuddy",
                    symbol: "book.closed",
                    url: Self.repoURL
                )
                externalLinkRow(
                    title: "Report an Issue or Request a Feature",
                    subtitle: "Open a GitHub issue with steps to reproduce",
                    symbol: "ladybug",
                    url: Self.issuesURL
                )
                externalLinkRow(
                    title: "Releases & Changelog",
                    subtitle: "Check for newer macOS and CLI releases",
                    symbol: "arrow.down.circle",
                    url: Self.releasesURL
                )

                HStack(spacing: 12) {
                    Text("Includes app version, macOS build, and key/server counts (no secrets).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 12)
                    Button {
                        copyWithFeedback(diagnosticSummary(), tag: "diag")
                    } label: {
                        Label(
                            copiedTag == "diag" ? "Copied" : "Copy Diagnostics",
                            systemImage: copiedTag == "diag" ? "checkmark" : "doc.on.doc"
                        )
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    .fixedSize()
                    .tint(copiedTag == "diag" ? MacBaoTheme.active : nil)
                }
                .padding(.vertical, 2)
            } header: {
                Text("Support & Links")
            }

            Section {
                Text("Every approval signs a 30-second ES256 JWT in Apple's Secure Enclave after Touch ID, mints only the scoped short-lived token you approved, verifies its policies and TTL, and revokes the sign-in token immediately.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                DisclosureGroup("CLI Quick Reference & Deep Links", isExpanded: $showCLIReference) {
                    VStack(alignment: .leading, spacing: 12) {
                        cliReferenceGroup(title: "Daily Grants", items: [
                            ("bao-buddy grant --on local --hours 2 --why \"deploy\"", "Mint a scoped grant into this Mac's Keychain"),
                            ("bao-buddy status", "Show active local & remote grant status and remaining TTL"),
                            ("bao-buddy revoke --on remote", "Revoke the active grant at OpenBao by accessor"),
                            ("bao-buddy health", "Verify TLS pinning and unsealed status on the active server")
                        ])

                        cliReferenceGroup(title: "Server & Device Setup", items: [
                            ("bao-buddy server-setup --subject $USER --policies db-readonly,k8s-deploy --add-self", "Bootstrap JWT mount, granter policy, token role, and register this Mac"),
                            ("bao-buddy export-profile --subject $USER --elevated k8s-deploy --copy --save", "Export a ready-to-import profile for macOS and iPhone")
                        ])

                        cliReferenceGroup(title: "OpenTofu, AI Agents & Deep Links", items: [
                            ("bao-buddy tofu-init --out ./baobuddy-tofu", "Generate a variablized for_each OpenTofu stack from the CLI"),
                            ("bao-buddy mcp", "Run the zero-dependency stdio MCP server for AI coding agents"),
                            ("baobuddy://grant?r=HOURS%3D2%20WHY%3Ddeploy", "Trigger a pre-filled Touch ID / Face ID approval sheet")
                        ])

                        HStack {
                            Button {
                                copyWithFeedback(cliSnippet, tag: "cli")
                            } label: {
                                Label(
                                    copiedTag == "cli" ? "Copied All Commands" : "Copy All Commands",
                                    systemImage: copiedTag == "cli" ? "checkmark" : "doc.on.doc"
                                )
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .tint(copiedTag == "cli" ? MacBaoTheme.active : nil)
                            Spacer()
                            Text("Run `bao-buddy --help` for full flags")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    .padding(.top, 8)
                }

                inlineNote(
                    "Private keys never leave Apple's Secure Enclave. All connections go directly from your Mac to your OpenBao / Vault server.",
                    symbol: "lock.shield"
                )
            } header: {
                Text("How BaoBuddy Works")
            }
        }
        .formStyle(.grouped)
    }

    private func cliReferenceGroup(title: String, items: [(command: String, summary: String)]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.tertiary)

            ForEach(Array(items.enumerated()), id: \.offset) { index, item in
                let tag = "cli-\(title)-\(index)"
                HStack(alignment: .center, spacing: 10) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(MacCodeHighlighter.highlight(item.command, language: .shell))
                            .font(.system(size: 11.5, design: .monospaced))
                            .textSelection(.enabled)
                            .lineLimit(2)
                        Text(item.summary)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 8)
                    Button {
                        copyWithFeedback(item.command, tag: tag)
                    } label: {
                        Image(systemName: copiedTag == tag ? "checkmark" : "doc.on.doc")
                            .font(.caption)
                            .foregroundStyle(copiedTag == tag ? MacBaoTheme.active : .secondary)
                            .frame(width: 24, height: 22)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .fixedSize()
                    .help("Copy command")
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(
                    Color(nsColor: .textBackgroundColor).opacity(0.65),
                    in: RoundedRectangle(cornerRadius: 8, style: .continuous)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .strokeBorder(Color.primary.opacity(0.08), lineWidth: 1)
                )
            }
        }
    }

    private func externalLinkRow(title: String, subtitle: String, symbol: String, url: URL) -> some View {
        Button {
            NSWorkspace.shared.open(url)
        } label: {
            HStack(spacing: 10) {
                Image(systemName: symbol)
                    .frame(width: 18)
                    .foregroundStyle(MacBaoTheme.brand)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title)
                        .font(.subheadline)
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "arrow.up.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.vertical, 2)
    }

    private func diagnosticSummary() -> String {
        let jwtStatus = devicePEM.isEmpty ? "not set up" : "ready (Secure Enclave)"
        let sshStatus = sshPubKey.isEmpty ? "not set up" : (sshIsHardware ? "hardware (Secure Enclave)" : "software")
        return """
        BaoBuddy macOS \(appVersion) (build \(appBuild))
        macOS: \(ProcessInfo.processInfo.operatingSystemVersionString)
        Servers configured: \(state.profiles.count)
        Approval key: \(jwtStatus)
        SSH delivery key: \(sshStatus)
        """
    }

    // MARK: - Helpers

    private func loadKeys() {
        if let active = state.profile {
            let se = SecureEnclaveKeyStore.scoped(for: active, deviceName: "mac")
            devicePEM = (try? se.publicKeyPEM()) ?? ""
            deviceFingerprint = (try? se.publicKeyFingerprint()) ?? ""
        } else {
            devicePEM = ""
            deviceFingerprint = ""
        }
        if let id = try? SSHKeyStore().loadIdentity() {
            sshPubKey = id.openSSHPublicKey(comment: "baobuddy-mac")
            sshIsHardware = id.isHardwareBacked
        } else {
            sshPubKey = ""
            sshIsHardware = false
        }
    }

    private func createDeviceKey(overwrite: Bool = false) {
        keyError = nil
        guard let active = state.profile else {
            keyError = "Add or select an OpenBao/Vault server first so BaoBuddy can create a dedicated key for it."
            return
        }
        do {
            let se = SecureEnclaveKeyStore.scoped(for: active, deviceName: "mac")
            _ = try se.ensureKey(overwrite: overwrite)
            loadKeys()
        } catch {
            keyError = error.localizedDescription
        }
    }

    private func createSSHKey(overwrite: Bool = false) {
        keyError = nil
        do {
            _ = try SSHKeyStore().ensureSecureEnclaveIdentity(overwrite: overwrite)
            loadKeys()
        } catch {
            keyError = error.localizedDescription
        }
    }

    private func copyWithFeedback(_ text: String, tag: String) {
        copy(text)
        copiedTag = tag
        Task {
            try? await Task.sleep(for: .seconds(2))
            if copiedTag == tag {
                copiedTag = nil
            }
        }
    }

    private func saveTextToFile(_ text: String, defaultName: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = defaultName
        panel.canCreateDirectories = true
        if panel.runModal() == .OK, let url = panel.url {
            do {
                try text.write(to: url, atomically: true, encoding: .utf8)
            } catch {
                keyError = error.localizedDescription
            }
        }
    }

    private func testServerConnection(_ profile: BaoProfile) async {
        testingServerIDs.insert(profile.id)
        defer { testingServerIDs.remove(profile.id) }
        do {
            let health = try await OpenBaoClient(profile: profile).checkHealth()
            if health.sealed {
                serverHealth[profile.id] = (false, "Reachable over TLS, but sealed.")
            } else {
                let ver = health.version.isEmpty ? "" : " v\(health.version)"
                serverHealth[profile.id] = (true, "Connected — OpenBao\(ver) (unsealed).")
            }
        } catch {
            serverHealth[profile.id] = (false, error.localizedDescription)
        }
    }

    private func copy(_ text: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
    }

    private func copyProfileJSON(_ profile: BaoProfile, tag: String) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(profile.forSharing),
              let text = String(data: data, encoding: .utf8) else { return }
        copyWithFeedback(text, tag: tag)
    }
}

// MARK: - Import JSON Sheet

struct MacImportProfileSheet: View {
    @Bindable var state: MenuBarState
    @Environment(\.dismiss) private var dismiss
    @State private var draft: String = ""
    @State private var errorText: String?

    private var preview: BaoProfile? {
        let trimmed = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return try? ProfileTransferCodec.decode(text: trimmed)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Import BaoBuddy Profile JSON")
                    .font(.headline)
                Spacer()
                Button {
                    if let text = NSPasteboard.general.string(forType: .string) {
                        draft = text
                        errorText = nil
                    }
                } label: {
                    Label("Paste from Clipboard", systemImage: "doc.on.clipboard")
                }
            }

            Text("Paste the JSON printed by `bao-buddy export-profile` or `make bao-profile`.")
                .font(.caption)
                .foregroundStyle(.secondary)

            TextEditor(text: $draft)
                .font(.caption.monospaced())
                .frame(minHeight: 200)
                .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.primary.opacity(0.15)))

            if let preview {
                Label(
                    "Valid profile: \(preview.displayName) (\(preview.openbao.address))"
                        + (preview.hasRemoteTarget ? " • SSH: \(preview.targetDisplayName)" : ""),
                    systemImage: "checkmark.circle.fill"
                )
                .font(.caption)
                .foregroundStyle(MacBaoTheme.active)

                if let prettyData = try? {
                    let enc = JSONEncoder()
                    enc.outputFormatting = [.prettyPrinted, .sortedKeys]
                    return try enc.encode(preview.forSharing)
                }(), let prettyText = String(data: prettyData, encoding: .utf8) {
                    ScrollView {
                        MacCodeBox(text: prettyText, language: .json, fontSize: 10.5)
                    }
                    .frame(maxHeight: 130)
                }
                if let plan = try? ProfileImportPlan.make(
                    importing: preview,
                    existing: state.profiles,
                    managedIDs: state.managedProfileIDs,
                    organizationPolicy: state.organizationPolicy
                ) {
                    if let replaced = plan.replaces {
                        Label(
                            "Replaces \(replaced.displayName)"
                                + (plan.changes.isEmpty ? "" : ". Changes: \(plan.changes.joined(separator: ", "))"),
                            systemImage: "arrow.triangle.2.circlepath"
                        )
                        .font(.caption)
                        .foregroundStyle(.orange)
                    }
                    ForEach(plan.notices, id: \.self) { notice in
                        Label(notice, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
            }

            if let errorText {
                Label(errorText, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Import & Use") {
                    do {
                        let decoded = try ProfileTransferCodec.decode(
                            text: draft,
                            requireHostKey: true,
                            requireTLSPinning: state.enforceTLSPinning
                        )
                        try state.importProfile(decoded)
                        dismiss()
                    } catch {
                        errorText = error.localizedDescription
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(MacBaoTheme.brand)
                .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 600)
    }
}

// MARK: - Manual Add / Edit Server Sheet

struct MacEditProfileSheet: View {
    @Bindable var state: MenuBarState
    @Environment(\.dismiss) private var dismiss

    private let existingID: String?
    private let originalExpectedAudience: String?
    private let existingKeys: [BaoKeyItem]
    private let existingSSH: BaoSSHConfig
    private let existingGitHubAppItem: String
    private let existingGitHubTokenPath: String

    @State private var name: String
    @State private var address: String
    @State private var namespace: String
    @State private var caPEM: String
    @State private var mtlsClientIdentity: String
    @State private var jwtMount: String
    @State private var jwtRole: String
    @State private var jwtIssuer: String
    @State private var jwtAudience: String
    @State private var jwtSubject: String
    @State private var localTokenRole: String
    @State private var remoteTokenRole: String
    @State private var maxHours: Int

    @State private var requireReason: Bool
    @State private var requireReasonForElevated: Bool
    @State private var reasonPattern: String
    @State private var reasonPlaceholder: String
    @State private var otlpEndpoint: String
    private let existingTelemetry: BaoTelemetryConfig

    @State private var extensions: [BaoCredentialExtension]
    @State private var newExtID: String = ""
    @State private var newExtLabel: String = ""
    @State private var newExtEndpoint: String = ""
    @State private var newExtDeliverAs: String = ""
    @State private var newExtPolicy: String = ""
    @State private var newExtMethod: BaoExtensionMethod = .post
    @State private var newExtElevated: Bool = false

    @State private var useCustomPolicies: Bool
    @State private var readPolicy: String
    @State private var writePolicy: String
    @State private var customPolicies: [BaoBuddyPolicy]
    @State private var newPolicyName: String = ""
    @State private var newPolicyLabel: String = ""
    @State private var newPolicyElevated: Bool = false

    @State private var enableRemote: Bool
    @State private var remoteTargets: [BaoT3GranterConfig]
    @State private var newTargetName: String = ""
    @State private var newTargetHost: String = ""
    @State private var newTargetPort: String = "22"
    @State private var newTargetUser: String = "granter"
    @State private var newTargetHostKey: String = ""

    @State private var showCAPEM: Bool = false
    @State private var showExtensions: Bool = false
    @State private var showAuditPolicy: Bool = false
    @State private var showAdvancedJWT: Bool = false
    @State private var isTesting: Bool = false
    @State private var testStatus: (ok: Bool, message: String)?
    @State private var errorText: String?

    init(state: MenuBarState, existing: BaoProfile?) {
        self.state = state
        self.existingID = existing?.id
        self.originalExpectedAudience = existing?.openbao.expectedOriginMountAudience
        self.existingKeys = existing?.openbao.keys ?? []
        self.existingSSH = existing?.openbao.ssh ?? BaoSSHConfig(role: "", hosts: [])
        self.existingGitHubAppItem = existing?.openbao.githubAppItem ?? ""
        self.existingGitHubTokenPath = existing?.openbao.githubTokenPath ?? ""

        self._name = State(initialValue: existing?.name ?? "")
        self._address = State(initialValue: existing?.openbao.address ?? "")
        self._namespace = State(initialValue: existing?.openbao.namespace ?? "")
        self._caPEM = State(initialValue: existing?.openbao.caPEM ?? "")
        self._mtlsClientIdentity = State(initialValue: existing?.openbao.mtlsClientIdentity ?? "")
        let defaultUser = ProcessInfo.processInfo.environment["USER"] ?? ""
        let defaultMount = existing?.openbao.jwtAuth.mount ?? BaoServerAdmin.defaultMount(subject: defaultUser)
        let defaultRole = BaoServerAdmin.defaultTokenRole(mount: defaultMount, subject: defaultUser)
        self._jwtMount = State(initialValue: defaultMount)
        self._jwtRole = State(initialValue: existing?.openbao.jwtAuth.role ?? "granter")
        self._jwtIssuer = State(initialValue: existing?.openbao.jwtAuth.issuer ?? "bao-granter")
        self._jwtAudience = State(initialValue: existing?.openbao.jwtAuth.audience ?? "")
        self._jwtSubject = State(initialValue: existing?.openbao.jwtAuth.subject ?? defaultUser)
        self._localTokenRole = State(initialValue: existing?.openbao.tokenRoles.mac ?? defaultRole)
        self._remoteTokenRole = State(initialValue: existing?.openbao.tokenRoles.t3 ?? defaultRole)
        self._maxHours = State(initialValue: existing?.openbao.maxHours ?? 12)

        let audit = existing?.openbao.auditPolicy ?? .none
        self._requireReason = State(initialValue: audit.requireReason)
        self._requireReasonForElevated = State(initialValue: audit.requireReasonForElevated)
        self._reasonPattern = State(initialValue: audit.reasonPattern)
        self._reasonPlaceholder = State(initialValue: audit.reasonPlaceholder)
        self._otlpEndpoint = State(initialValue: existing?.openbao.telemetry.otlpEndpoint ?? "")
        self.existingTelemetry = existing?.openbao.telemetry ?? BaoTelemetryConfig()
        self._extensions = State(initialValue: existing?.openbao.extensions ?? [])

        self._useCustomPolicies = State(initialValue: existing?.openbao.usesCustomPolicies ?? (existing == nil))
        self._readPolicy = State(initialValue: existing?.openbao.policies.read ?? "read")
        self._writePolicy = State(initialValue: existing?.openbao.policies.write ?? "write")
        self._customPolicies = State(initialValue: existing?.openbao.grantPolicies ?? [])

        let configuredRemotes = existing?.configuredRemoteTargets ?? []
        self._enableRemote = State(initialValue: !configuredRemotes.isEmpty)
        self._remoteTargets = State(initialValue: configuredRemotes)
    }

    var body: some View {
        VStack(spacing: 0) {
            sheetHeader
            Divider()

            Form {
                if let errorText {
                    Section {
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.red)
                            Text(errorText)
                                .font(.caption)
                                .foregroundStyle(.red)
                        }
                    }
                }

                connectionSection
                policiesSection
                remoteDeliverySection
                tlsPinningSection
                extensionsSection
                auditGovernanceSection
                advancedJWTSection
            }
            .formStyle(.grouped)

            Divider()
            sheetFooter
        }
        .frame(minWidth: 680, idealWidth: 740, minHeight: 660, idealHeight: 740)
    }

    private func sectionHint(_ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "info.circle")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.secondary)
                .frame(width: 16, alignment: .center)
            Text(text)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var sheetHeader: some View {
        HStack(spacing: 12) {
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(MacBaoTheme.brand.gradient)
                .frame(width: 34, height: 34)
                .overlay {
                    Image(systemName: "server.rack")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(MacBaoTheme.cream)
                }

            VStack(alignment: .leading, spacing: 2) {
                Text(existingID == nil ? "Add OpenBao / Vault Server" : "Edit \(name.isEmpty ? "Server" : name)")
                    .font(.headline)
                Text("Connect this Mac to an OpenBao or HashiCorp Vault server using Touch ID.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 14)
        .background(.bar)
    }

    private var connectionSection: some View {
        Section {
            TextField("Display Name", text: $name, prompt: Text("Production or Staging"))
            TextField("Server URL", text: $address, prompt: Text(verbatim: "https://openbao.example.com:8200"))
            TextField("Namespace", text: $namespace, prompt: Text("Optional (e.g. admin/prod)"))
            TextField("Username", text: $jwtSubject, prompt: Text("alice"))
            Stepper(
                "Max Grant Length: \(maxHours) \(maxHours == 1 ? "hour" : "hours")",
                value: $maxHours,
                in: 1...24
            )
            sectionHint("Leave Namespace empty for root. Username must match the JWT subject (`sub`) on your server.")
        } header: {
            Text("1. Connection")
        }
    }

    private var policiesSection: some View {
        Section {
            Picker("Mode", selection: $useCustomPolicies) {
                Text("Custom Policies").tag(true)
                Text("Read / Write").tag(false)
            }
            .pickerStyle(.segmented)

            if useCustomPolicies {
                if customPolicies.isEmpty {
                    Text("Add at least one OpenBao policy below (for example: db-readonly, k8s-deploy, or app-read).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(customPolicies) { policy in
                        HStack(spacing: 8) {
                            Text(policy.displayLabel)
                            Text(policy.name)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                            Spacer()
                            if policy.elevated {
                                Text("Elevated")
                                    .font(.caption2.weight(.semibold))
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 2)
                                    .background(MacBaoTheme.elevated.opacity(0.14), in: Capsule())
                                    .foregroundStyle(MacBaoTheme.elevated)
                            }
                            Button(role: .destructive) {
                                customPolicies.removeAll { $0.name == policy.name }
                            } label: {
                                Image(systemName: "minus.circle.fill")
                                    .foregroundStyle(.secondary)
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }

                HStack(spacing: 8) {
                    TextField("Policy", text: $newPolicyName, prompt: Text("k8s-deploy"))
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                    TextField("Label", text: $newPolicyLabel, prompt: Text("Label (optional)"))
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                    Toggle("Elevated", isOn: $newPolicyElevated)
                        .toggleStyle(.checkbox)
                        .tint(MacBaoTheme.elevated)
                        .fixedSize()
                    Button("Add") { addPolicy() }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .fixedSize()
                        .disabled(newPolicyName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            } else {
                TextField("Read Policy", text: $readPolicy, prompt: Text("app-read"))
                TextField("Write Policy", text: $writePolicy, prompt: Text("app-write"))
            }

            sectionHint("Policies appear as checkboxes when approving grants. Mark sensitive policies as Elevated to highlight them in orange.")
        } header: {
            Text("2. Grant Policies")
        }
    }

    private var remoteDeliverySection: some View {
        Section {
            Toggle("Deliver grants to remote hosts over SSH", isOn: $enableRemote)
                .tint(MacBaoTheme.brand)
            if enableRemote {
                TextField("Remote Token Role", text: $remoteTokenRole, prompt: Text("grant"))

                ForEach(remoteTargets) { target in
                    HStack(spacing: 8) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(target.displayName)
                                .font(.subheadline.weight(.medium))
                            Text("\(target.user)@\(target.host):\(target.port)")
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(role: .destructive) {
                            remoteTargets.removeAll { $0.id == target.id }
                        } label: {
                            Image(systemName: "minus.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                    }
                }

                Text(remoteTargets.isEmpty ? "Add a remote SSH target" : "Add another remote SSH target")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                TextField("Target Name", text: $newTargetName, prompt: Text("Build Runner or Bastion"))
                TextField("Host or IP", text: $newTargetHost, prompt: Text("bastion.example.com"))
                TextField("SSH Port", text: $newTargetPort, prompt: Text("22"))
                TextField("SSH User", text: $newTargetUser, prompt: Text("granter"))
                TextField("Pinned Host Key", text: $newTargetHostKey, prompt: Text(verbatim: "ssh-ed25519 AAAA..."))
                HStack {
                    Spacer()
                    Button {
                        addRemoteTarget()
                    } label: {
                        Label("Add Target", systemImage: "plus")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(newTargetHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }

            sectionHint("Leave off if you only mint tokens for this Mac. You can attach multiple VMs, bastions, or CI runners to one server.")
        } header: {
            Text("3. Remote Host SSH Delivery (Optional)")
        }
    }

    private func addRemoteTarget() {
        let host = newTargetHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else { return }
        let user = newTargetUser.trimmingCharacters(in: .whitespacesAndNewlines)
        let target = BaoT3GranterConfig(
            name: newTargetName.trimmingCharacters(in: .whitespacesAndNewlines),
            host: host,
            port: Int(newTargetPort.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 22,
            user: user.isEmpty ? "granter" : user,
            hostKey: newTargetHostKey.trimmingCharacters(in: .whitespacesAndNewlines)
        )
        remoteTargets.append(target)
        newTargetName = ""
        newTargetHost = ""
        newTargetPort = "22"
        newTargetUser = "granter"
        newTargetHostKey = ""
    }

    private var tlsPinningSection: some View {
        let hasCert = !caPEM.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        return Section {
            HStack(spacing: 8) {
                if hasCert {
                    Image(systemName: "lock.fill")
                        .foregroundStyle(MacBaoTheme.active)
                    Text("Custom PEM certificate pinned")
                        .font(.caption.weight(.medium))
                } else {
                    Text("Using macOS system trusted CAs")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if hasCert {
                    Button("Clear") {
                        caPEM = ""
                        testStatus = nil
                    }
                    .buttonStyle(.borderless)
                    .font(.caption)
                }
                Button("Load File…") {
                    loadPEMFile()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }

            DisclosureGroup("Paste or edit PEM certificate", isExpanded: $showCAPEM) {
                TextEditor(text: $caPEM)
                    .font(.caption2.monospaced())
                    .frame(minHeight: 80)
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .strokeBorder(Color.primary.opacity(0.12))
                    )
                    .padding(.top, 4)
            }

            TextField(
                "mTLS Client Certificate",
                text: $mtlsClientIdentity,
                prompt: Text("Optional Keychain CN or SHA-256")
            )
            sectionHint("Pin a self-signed cert/private CA, and optionally name a client certificate in your Apple Keychain for mutual TLS.")
        } header: {
            Text("4. TLS & mTLS (Optional)")
        }
    }

    private var extensionsSection: some View {
        let enabledCount = extensions.filter(\.enabled).count
        let summaryText: String = {
            if extensions.isEmpty { return "None configured — add built-in templates or custom OpenBao paths" }
            if enabledCount == 0 { return "\(extensions.count) saved (all disabled)" }
            return "\(enabledCount) enabled: " + extensions.filter(\.enabled).map(\.displayLabel).joined(separator: ", ")
        }()

        return Section {
            DisclosureGroup(isExpanded: $showExtensions) {
                HStack {
                    Text("Start from a disabled example template:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Menu {
                        ForEach(BaoCredentialExtension.builtInTemplates) { template in
                            Button {
                                if !extensions.contains(where: { $0.id == template.id }) {
                                    extensions.append(template)
                                }
                            } label: {
                                Label(template.label, systemImage: template.icon)
                            }
                        }
                    } label: {
                        Label("Add Template", systemImage: "plus.circle")
                    }
                    .menuStyle(.button)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .fixedSize()
                }

                ForEach($extensions) { $ext in
                    HStack(spacing: 8) {
                        Toggle(isOn: $ext.enabled) {
                            VStack(alignment: .leading, spacing: 1) {
                                HStack(spacing: 5) {
                                    Text(ext.displayLabel)
                                        .font(.subheadline.weight(.medium))
                                    Text("\(ext.method.rawValue) \(ext.endpoint)")
                                        .font(.caption2.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                                Text("Delivers → \(ext.deliverAs)")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .tint(MacBaoTheme.brand)
                        Spacer(minLength: 6)
                        TextField("Policy", text: $ext.policy, prompt: Text("policy (optional)"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 140)
                            .help("OpenBao policy that allows this endpoint. Selecting the extension adds it to the grant.")
                        Button(role: .destructive) {
                            extensions.removeAll { $0.id == ext.id }
                        } label: {
                            Image(systemName: "minus.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.borderless)
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("Define a custom secrets engine endpoint:")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                    HStack(spacing: 8) {
                        TextField("ID", text: $newExtID, prompt: Text("aws-sts"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                        TextField("Label", text: $newExtLabel, prompt: Text("AWS STS"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                        Picker("Method", selection: $newExtMethod) {
                            Text("POST").tag(BaoExtensionMethod.post)
                            Text("GET").tag(BaoExtensionMethod.get)
                        }
                        .labelsHidden()
                        .frame(width: 78)
                    }
                    HStack(spacing: 8) {
                        TextField("Endpoint", text: $newExtEndpoint, prompt: Text("aws/sts/deploy"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                        TextField("Filename", text: $newExtDeliverAs, prompt: Text("aws-creds.json"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                        TextField("Policy", text: $newExtPolicy, prompt: Text("policy (optional)"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                    }
                    HStack(spacing: 8) {
                        Toggle("Elevated (highlighted in orange)", isOn: $newExtElevated)
                            .toggleStyle(.checkbox)
                            .tint(MacBaoTheme.elevated)
                            .font(.caption)
                        Spacer()
                        Button {
                            addCustomExtension()
                        } label: {
                            Label("Add Extension", systemImage: "plus")
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                        .fixedSize()
                        .disabled(
                            newExtID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                            newExtEndpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                        )
                    }
                }
                .padding(.top, 4)

                sectionHint("Invoke any OpenBao / Vault secrets engine (AWS STS, Kubernetes, Database, PKI, GitHub) after Touch ID. See docs/EXTENSIONS.md.")
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Credential Extensions (Dynamic Secrets)")
                    Text(summaryText)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Extensions (Optional)")
        }
    }

    private func addCustomExtension() {
        let id = newExtID.trimmingCharacters(in: .whitespacesAndNewlines)
        let endpoint = newExtEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !id.isEmpty, !endpoint.isEmpty else { return }
        let deliver = newExtDeliverAs.trimmingCharacters(in: .whitespacesAndNewlines)
        let ext = BaoCredentialExtension(
            id: id,
            label: newExtLabel.trimmingCharacters(in: .whitespacesAndNewlines),
            endpoint: endpoint,
            method: newExtMethod,
            deliverAs: deliver.isEmpty ? "\(id).json" : deliver,
            policy: newExtPolicy.trimmingCharacters(in: .whitespacesAndNewlines),
            elevated: newExtElevated,
            enabled: true
        )
        extensions.removeAll { $0.id == id }
        extensions.append(ext)
        newExtID = ""
        newExtLabel = ""
        newExtEndpoint = ""
        newExtDeliverAs = ""
        newExtPolicy = ""
        newExtElevated = false
    }

    private var auditGovernanceSection: some View {
        Section {
            DisclosureGroup(isExpanded: $showAuditPolicy) {
                Toggle("Require audit reason on elevated grants", isOn: $requireReasonForElevated)
                    .tint(MacBaoTheme.brand)
                Toggle("Require audit reason on all grants", isOn: $requireReason)
                    .tint(MacBaoTheme.brand)
                TextField(
                    "Ticket Regex",
                    text: $reasonPattern,
                    prompt: Text(verbatim: "^(INC|CHG|JIRA)-[0-9]+")
                )
                TextField(
                    "Reason Prompt Hint",
                    text: $reasonPlaceholder,
                    prompt: Text("INC-12345 — change summary")
                )
                TextField(
                    "OTLP SIEM Endpoint",
                    text: $otlpEndpoint,
                    prompt: Text(verbatim: "Optional (https://otel.corp.example:4318)")
                )
                if !existingTelemetry.headers.isEmpty,
                   MacSettingsLogic.canonicalOTLPEndpoint(existingTelemetry.otlpEndpoint)
                    != MacSettingsLogic.canonicalOTLPEndpoint(otlpEndpoint) {
                    sectionHint("Changing the OTLP endpoint clears saved collector auth headers so they aren't sent to the new collector.")
                }
                sectionHint("Enforce audit reasons or change-ticket IDs (e.g., ServiceNow or Jira) before Touch ID approval.")
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Audit & Change-Ticket Policy")
                    Text(
                        requireReason
                            ? "Reason required on all grants"
                            : (requireReasonForElevated ? "Reason required on elevated grants" : "Optional — no ticket policy enforced")
                    )
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Governance (Optional)")
        }
    }

    private var advancedJWTSection: some View {
        Section {
            DisclosureGroup(isExpanded: $showAdvancedJWT) {
                TextField("Auth Mount", text: $jwtMount, prompt: Text("jwt-granter"))
                TextField("JWT Role", text: $jwtRole, prompt: Text("granter"))
                TextField("Bound Issuer (iss)", text: $jwtIssuer, prompt: Text("bao-granter"))
                TextField("Bound Audience (aud)", text: $jwtAudience, prompt: Text("openbao-granter"))
                TextField("Local Token Role", text: $localTokenRole, prompt: Text("grant"))
                sectionHint("Defaults match `bao-buddy server-setup`. Only change these if your server uses custom mount or role names.")
            } label: {
                VStack(alignment: .leading, spacing: 2) {
                    Text("JWT Auth & Token Roles")
                    Text("mount: \(jwtMount) • role: \(jwtRole) • token: \(localTokenRole)")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Advanced Settings")
        }
    }

    private var sheetFooter: some View {
        VStack(spacing: 8) {
            if let testStatus {
                HStack(spacing: 6) {
                    Image(systemName: testStatus.ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(testStatus.ok ? MacBaoTheme.active : .red)
                    Text(testStatus.message)
                        .font(.caption)
                        .foregroundStyle(testStatus.ok ? MacBaoTheme.active : .red)
                        .lineLimit(2)
                    Spacer()
                }
            }

            HStack(spacing: 10) {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)

                Button {
                    Task { await testDraftConnection() }
                } label: {
                    HStack(spacing: 5) {
                        if isTesting {
                            ProgressView().controlSize(.small)
                        } else {
                            Image(systemName: "network")
                        }
                        Text(isTesting ? "Testing…" : "Test Connection")
                    }
                }
                .disabled(isTesting || address.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                Spacer()

                Button("Save Server") { save() }
                    .buttonStyle(.borderedProminent)
                    .tint(MacBaoTheme.brand)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(.bar)
    }

    private func testDraftConnection() async {
        let trimmedAddress = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmedAddress) else {
            testStatus = (false, "Enter a valid https:// server URL first.")
            return
        }
        do {
            try OpenBaoClient.validateEndpointURL(url, allowDemo: false)
        } catch {
            testStatus = (false, error.localizedDescription)
            return
        }
        isTesting = true
        testStatus = nil
        defer { isTesting = false }

        let probe = BaoProfile(
            id: existingID ?? "probe",
            version: 1,
            name: name.isEmpty ? "Probe" : name,
            openbao: BaoOpenBaoConfig(
                address: trimmedAddress,
                namespace: namespace.trimmingCharacters(in: .whitespacesAndNewlines),
                caPEM: caPEM.trimmingCharacters(in: .whitespacesAndNewlines),
                mtlsClientIdentity: mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines),
                jwtAuth: BaoJWTAuthConfig(
                    mount: jwtMount,
                    role: jwtRole,
                    issuer: jwtIssuer,
                    audience: jwtAudience,
                    subject: jwtSubject.isEmpty ? "probe" : jwtSubject
                ),
                tokenRoles: BaoTokenRolesConfig(mac: localTokenRole, t3: remoteTokenRole),
                policies: BaoPolicyConfig(read: readPolicy, write: writePolicy),
                maxHours: maxHours,
                keys: [],
                ssh: BaoSSHConfig(role: "", hosts: []),
                githubAppItem: ""
            ),
            t3Granter: BaoT3GranterConfig(name: "", host: "")
        )
        do {
            let health = try await OpenBaoClient(profile: probe).checkHealth()
            if health.sealed {
                testStatus = (false, "Reachable over TLS, but OpenBao is sealed.")
            } else {
                let ver = health.version.isEmpty ? "" : " v\(health.version)"
                testStatus = (true, "Connected — OpenBao\(ver) (unsealed).")
            }
        } catch {
            testStatus = (false, error.localizedDescription)
        }
    }

    private func loadPEMFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose a PEM certificate (.crt or .pem) to pin for this server"
        if panel.runModal() == .OK, let url = panel.url,
           let content = try? String(contentsOf: url, encoding: .utf8) {
            caPEM = content.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    private func addPolicy() {
        let trimmed = newPolicyName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let policy = BaoBuddyPolicy(
            name: trimmed,
            label: newPolicyLabel.trimmingCharacters(in: .whitespacesAndNewlines),
            elevated: newPolicyElevated,
            defaultSelected: customPolicies.isEmpty && !newPolicyElevated
        )
        if let idx = customPolicies.firstIndex(where: { $0.name == trimmed }) {
            customPolicies[idx] = policy
        } else {
            customPolicies.append(policy)
        }
        newPolicyName = ""
        newPolicyLabel = ""
        newPolicyElevated = false
    }

    private func save() {
        var targetsToSave: [BaoT3GranterConfig] = []
        if enableRemote {
            // If the user filled out the draft target fields without tapping "Add Target", include it cleanly.
            if !newTargetHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                addRemoteTarget()
            }
            targetsToSave = remoteTargets
            if targetsToSave.isEmpty {
                errorText = "Add at least one remote SSH target, or turn off remote SSH delivery."
                return
            }
        }

        if useCustomPolicies && customPolicies.isEmpty {
            errorText = "Add at least one custom policy, or switch to Read / Write mode."
            return
        }

        let trimmedAddress = address.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedNS = namespace.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedMount = jwtMount.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedSubject = jwtSubject.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedCA = caPEM.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedMTLS = mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines)
        let rawAudience = jwtAudience.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedAudience = MacSettingsLogic.resolvedAudience(
            rawAudience: rawAudience,
            originalExpectedAudience: originalExpectedAudience,
            derivedAudience: BaoOpenBaoConfig.defaultAudience(
                address: trimmedAddress,
                namespace: trimmedNS,
                mount: trimmedMount,
                caPEM: trimmedCA,
                mtlsClientIdentity: trimmedMTLS
            )
        )
        let rawLocalRole = localTokenRole.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedLocalRole = rawLocalRole.isEmpty
            ? BaoServerAdmin.defaultTokenRole(mount: trimmedMount, subject: trimmedSubject)
            : rawLocalRole
        let rawRemoteRole = remoteTokenRole.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedRemoteRole = rawRemoteRole.isEmpty ? resolvedLocalRole : rawRemoteRole

        let profile = BaoProfile(
            id: existingID ?? UUID().uuidString.lowercased(),
            version: 1,
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            openbao: BaoOpenBaoConfig(
                address: trimmedAddress,
                namespace: trimmedNS,
                caPEM: caPEM.trimmingCharacters(in: .whitespacesAndNewlines),
                mtlsClientIdentity: mtlsClientIdentity.trimmingCharacters(in: .whitespacesAndNewlines),
                jwtAuth: BaoJWTAuthConfig(
                    mount: trimmedMount,
                    role: jwtRole.trimmingCharacters(in: .whitespacesAndNewlines),
                    issuer: jwtIssuer.trimmingCharacters(in: .whitespacesAndNewlines),
                    audience: resolvedAudience,
                    subject: trimmedSubject
                ),
                tokenRoles: BaoTokenRolesConfig(
                    mac: resolvedLocalRole,
                    t3: enableRemote ? resolvedRemoteRole : resolvedLocalRole
                ),
                policies: BaoPolicyConfig(
                    read: readPolicy.trimmingCharacters(in: .whitespacesAndNewlines),
                    write: writePolicy.trimmingCharacters(in: .whitespacesAndNewlines)
                ),
                grantPolicies: useCustomPolicies ? customPolicies : [],
                auditPolicy: BaoAuditPolicy(
                    requireReason: requireReason,
                    requireReasonForElevated: requireReasonForElevated,
                    reasonPattern: reasonPattern.trimmingCharacters(in: .whitespacesAndNewlines),
                    reasonPlaceholder: reasonPlaceholder.trimmingCharacters(in: .whitespacesAndNewlines)
                ),
                // Preserve saved collector auth headers ONLY when the canonical OTLP endpoint is unchanged.
                telemetry: MacSettingsLogic.resolvedTelemetry(
                    existing: existingTelemetry,
                    newEndpoint: otlpEndpoint
                ),
                extensions: extensions,
                maxHours: maxHours,
                keys: existingKeys,
                ssh: existingSSH,
                githubAppItem: existingGitHubAppItem,
                githubTokenPath: existingGitHubTokenPath
            ),
            remoteTargets: targetsToSave
        )

        do {
            try profile.validate(requireHostKey: enableRemote, requireTLSPinning: state.enforceTLSPinning)
            try state.upsertProfile(profile)
            dismiss()
        } catch {
            errorText = error.localizedDescription
        }
    }
}
#endif
