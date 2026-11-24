import BaoBuddyCore
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

struct SettingsView: View {
    @Bindable var model: AppModel
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @State private var profileDraft: String = ""
    @State private var showImportSheet: Bool = false
    @State private var showQRScanner: Bool = false
    @State private var showActivitySheet: Bool = false
    @State private var editingProfile: BaoProfile?
    @State private var showAddManualSheet: Bool = false
    @State private var showSetupWizard: Bool = false
    @State private var showHelpSheet: Bool = false
    @State private var showSetupSnippet: Bool = false
    @State private var copiedPEM: Bool = false
    @State private var copiedSSH: Bool = false
    @State private var copiedRegCmd: Bool = false

    var body: some View {
        NavigationStack {
            List {
                BaoRegularColumnTitle(title: "Settings")

                if model.isDemoMode {
                    Section {
                        BaoDemoBanner {
                            model.exitDemoMode()
                        }
                    }
                }
                serversSection
                hardwareIdentitySection
                sshDeliverySection
                helpSection
            }
            .listStyle(.insetGrouped)
            .listSectionSpacing(.compact)
            .baoReadableWidth()
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(horizontalSizeClass == .regular ? .inline : .large)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showHelpSheet = true
                    } label: {
                        Label("Help", systemImage: "questionmark.circle")
                    }
                }
            }
            .sheet(isPresented: $showImportSheet) {
                importJSONSheet
                    .presentationSizing(.form)
            }
            .sheet(isPresented: $showAddManualSheet) {
                ManualProfileSheetView(model: model, existing: nil)
                    .presentationSizing(.form)
            }
            .sheet(item: $editingProfile) { target in
                ManualProfileSheetView(model: model, existing: target)
                    .presentationSizing(.form)
            }
            .sheet(isPresented: $showHelpSheet) {
                HelpSheetView(model: model)
                    .presentationSizing(.form)
            }
            .sheet(isPresented: $showSetupWizard) {
                SetupWizardView(model: model)
                    .presentationSizing(.form)
            }
            .sheet(isPresented: $showQRScanner) {
                QRScannerSheetView(enforceTLSPinning: model.enforceTLSPinning) { scanned in
                    model.stageImport(scanned)
                }
                .presentationSizing(.form)
            }
            .sheet(isPresented: $showActivitySheet) {
                ActivitySheetView(model: model)
                    .presentationSizing(.form)
            }
        }
    }

    private var serversSection: some View {
        Section {
            if model.profiles.isEmpty {
                Text("No servers configured yet.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(model.profiles) { item in
                    let isActive = item.id == model.profile?.id
                    let isManaged = model.isManaged(profileID: item.id)
                    HStack(spacing: 12) {
                        Button {
                            BaoHaptics.impact()
                            model.selectProfile(id: item.id)
                        } label: {
                            BaoAdaptiveStack(spacing: 12) {
                                BaoIconBadge(
                                    symbol: item.isDemoProfile ? "flask.fill" : "server.rack",
                                    tint: isActive ? BaoTheme.brand : .secondary,
                                    size: 34
                                )
                                VStack(alignment: .leading, spacing: 3) {
                                    BaoAdaptiveStack(spacing: 6) {
                                        Text(item.displayName)
                                            .font(.body.weight(isActive ? .semibold : .regular))
                                            .foregroundStyle(.primary)
                                            .fixedSize(horizontal: false, vertical: true)
                                        if isActive {
                                            BaoStatusPill(title: "Active", tint: BaoTheme.active, symbol: "checkmark.circle.fill")
                                        }
                                        if isManaged {
                                            BaoStatusPill(title: "Managed", tint: .secondary, symbol: nil)
                                        }
                                        if item.isDemoProfile {
                                            BaoStatusPill(title: "Demo", tint: BaoTheme.brand, symbol: nil)
                                        }
                                    }
                                    Text(item.openbao.address)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                        .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 1)
                                        .truncationMode(.middle)
                                    Text(serverCaption(for: item))
                                    .baoCaption2Font()
                                    .foregroundStyle(.tertiary)
                                }
                                Spacer()
                            }
                            .frame(minHeight: 44)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(isActive ? [.isSelected] : [])
                        .accessibilityInputLabels([Text(verbatim: item.displayName)])

                        if !isManaged && !item.isDemoProfile {
                            Button {
                                editingProfile = item
                            } label: {
                                Image(systemName: "info.circle")
                                    .foregroundStyle(BaoTheme.brand)
                                    .frame(minWidth: 44, minHeight: 44)
                                    .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("Edit \(item.displayName)")
                        }
                    }
                }
                .onDelete { offsets in
                    for index in offsets {
                        let target = model.profiles[index]
                        if target.isDemoProfile {
                            model.exitDemoMode()
                        } else if !model.isManaged(profileID: target.id) {
                            model.deleteProfile(id: target.id)
                        }
                    }
                }
            }

            if !model.areProfilesLocked {
                Button {
                    showQRScanner = true
                } label: {
                    Label("Scan Pairing QR Code…", systemImage: "qrcode.viewfinder")
                }

                Button {
                    profileDraft = ""
                    showImportSheet = true
                } label: {
                    Label("Import Profile JSON…", systemImage: "doc.badge.arrow.up")
                }

                Button {
                    showAddManualSheet = true
                } label: {
                    Label("Add Server Manually…", systemImage: "plus")
                }
                .accessibilityIdentifier("addServerManually")
            }
        } header: {
            Text("OpenBao / Vault Servers")
        } footer: {
            if model.areProfilesLocked {
                Text("Server profiles are managed by your organization via MDM.")
            } else {
                Text("Swipe left on a server to remove it, or tap info to edit its policies and target.")
            }
        }
    }

    private var hardwareIdentitySection: some View {
        let mount = model.profile?.openbao.jwtAuth.mount ?? "jwt-user"
        return Section {
            BaoAdaptiveStack(spacing: 12) {
                BaoIconBadge(symbol: model.biometry.systemImage, tint: BaoTheme.brand, size: 34)
                VStack(alignment: .leading, spacing: 2) {
                    Group {
                        if model.biometry.name.isEmpty {
                            Text("Biometric Approval Key", comment: "Title of the device's signing key when it has no Face ID or Touch ID.")
                        } else {
                            Text("\(model.biometry.name) Approval Key", comment: "Title of the device's signing key. %@ is Face ID, Touch ID or Optic ID (not translated).")
                        }
                    }
                    .font(.subheadline.weight(.semibold))
                    if let active = model.profile {
                        Text("Scoped to \(active.displayName) (auth/\(mount)/)", comment: "%1$@ is the server's name; %2$@ is its JWT auth mount. Keep auth/…/ as is.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("Add or select a server above before creating its approval key.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if !model.devicePublicKeyPEM.isEmpty {
                    BaoStatusPill(title: "Active", tint: BaoTheme.active, symbol: "checkmark.shield.fill")
                } else if model.isUsingDemoSoftwareKey {
                    BaoStatusPill(title: "Demo Key", tint: BaoTheme.brand, symbol: "cpu")
                } else {
                    BaoStatusPill(title: "Not Set Up", tint: .secondary, symbol: nil)
                }
            }
            .padding(.vertical, 2)

            LabeledContent("Device Claim") {
                TextField(
                    "Device Claim",
                    text: model.isDemoMode ? $model.demoDeviceName : $model.deviceName,
                    prompt: Text(verbatim: AppModel.defaultDeviceName)
                )
                .multilineTextAlignment(.trailing)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.body.monospaced())
            }

            if model.devicePublicKeyPEM.isEmpty {
                if model.isUsingDemoSoftwareKey {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Demo mode is signing with a temporary in-memory P-256 key.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if !model.demoSoftwareKeyFingerprint.isEmpty {
                            Text(verbatim: "sha256:\(model.demoSoftwareKeyFingerprint)")
                                .baoCaption2Font(monospaced: true)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
                Button {
                    model.ensureDeviceKey()
                } label: {
                    Label("Create Secure Enclave Key", systemImage: "key.badge.plus")
                }
                .disabled(model.profile == nil && !model.persistenceDisabled)
            } else {
                LabeledContent("Fingerprint") {
                    Text(verbatim: "sha256:\(model.deviceFingerprint)")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }

                Text(model.devicePublicKeyPEM)
                    .baoCaption2Font(monospaced: true)
                    .textSelection(.enabled)

                Button {
                    copyToClipboard(model.devicePublicKeyPEM)
                    copiedPEM = true
                    BaoHaptics.notify(.success)
                    model.bannerMessage = String(localized: "Copied P-256 public key PEM.", comment: "Banner. P-256 and PEM are technical names.")
                } label: {
                    Label(
                        copiedPEM ? "Copied P-256 Public Key" : "Copy P-256 Public Key PEM",
                        systemImage: copiedPEM ? "checkmark" : "doc.on.doc"
                    )
                }

                Button {
                    let cmd: String
                    if let active = model.profile {
                        cmd = "pbpaste | " + BaoServerAdmin.renderDeviceAddCommand(
                            address: active.openbao.address,
                            namespace: active.openbao.namespace,
                            caCertPath: active.openbao.isTLSPinned ? "<ca.pem>" : "",
                            mtlsClientIdentity: active.openbao.mtlsClientIdentity,
                            mount: mount
                        )
                    } else {
                        cmd = "pbpaste | bao-buddy device add --mount \(mount)"
                    }
                    copyToClipboard(cmd)
                    copiedRegCmd = true
                    BaoHaptics.notify(.success)
                } label: {
                    Label(
                        copiedRegCmd ? "Copied Mac Register Command" : "Copy `bao-buddy device add` Command",
                        systemImage: copiedRegCmd ? "checkmark" : "terminal"
                    )
                }

                DisclosureGroup("OpenBao JWT Auth Snippet", isExpanded: $showSetupSnippet) {
                    Text(model.openBaoSetupSnippet())
                        .baoCaption2Font(monospaced: true)
                        .textSelection(.enabled)
                }
            }
        } header: {
            Text("Hardware Approval Key")
        } footer: {
            Text("Non-exportable EC P-256 key stored inside Apple's Secure Enclave, scoped per server deployment.")
        }
    }

    private var sshDeliverySection: some View {
        Section {
            BaoAdaptiveStack(spacing: 12) {
                BaoIconBadge(
                    symbol: "terminal",
                    tint: model.sshPublicKey.isEmpty || model.sshKeyIsHardwareBacked ? BaoTheme.brand : BaoTheme.elevated,
                    size: 34
                )
                VStack(alignment: .leading, spacing: 2) {
                    Text("Remote Host SSH Key")
                        .font(.subheadline.weight(.semibold))
                    Text("Only needed when delivering grants over SSH.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if model.sshPublicKey.isEmpty {
                    BaoStatusPill(title: "Optional", tint: .secondary, symbol: nil)
                } else if model.sshKeyIsHardwareBacked {
                    BaoStatusPill(title: "Hardware", tint: BaoTheme.active, symbol: "checkmark.shield.fill")
                } else {
                    BaoStatusPill(title: "Software", tint: BaoTheme.elevated, symbol: "exclamationmark.triangle.fill")
                }
            }
            .padding(.vertical, 2)

            if model.sshPublicKey.isEmpty {
                Button {
                    model.ensureSSHKey()
                } label: {
                    Label("Create Secure Enclave SSH Key", systemImage: "terminal")
                }
            } else {
                Text(model.sshPublicKey)
                    .baoCaption2Font(monospaced: true)
                    .textSelection(.enabled)

                if !model.sshKeyIsHardwareBacked {
                    Button {
                        model.ensureSSHKey(overwrite: true)
                    } label: {
                        Label("Replace Legacy Software Key with Secure Enclave Key", systemImage: "cpu")
                    }
                }

                Button {
                    copyToClipboard(model.sshPublicKey)
                    copiedSSH = true
                    BaoHaptics.notify(.success)
                    model.bannerMessage = String(localized: "Copied SSH public key.", comment: "Banner.")
                } label: {
                    Label(
                        copiedSSH ? "Copied SSH Public Key" : "Copy SSH Public Key",
                        systemImage: copiedSSH ? "checkmark" : "doc.on.doc"
                    )
                }
            }
        } header: {
            Text("2. Remote Host SSH Key (Optional)")
        }
    }

    private var helpSection: some View {
        Section {
            if model.isDemoMode {
                Button(role: .destructive) {
                    BaoHaptics.impact()
                    model.exitDemoMode()
                } label: {
                    Label("Exit Demo Mode", systemImage: "xmark.circle")
                }
            } else if !model.areProfilesLocked {
                Button {
                    BaoHaptics.impact()
                    model.enterDemoMode()
                } label: {
                    Label("Try Demo Mode", systemImage: "flask")
                }
            }
            Button {
                showActivitySheet = true
            } label: {
                Label("Recent Activity…", systemImage: "clock.arrow.circlepath")
            }
            if !model.areProfilesLocked {
                Button {
                    showSetupWizard = true
                } label: {
                    Label("Guided Server Setup…", systemImage: "wand.and.stars")
                }
                .accessibilityIdentifier("guidedServerSetup")
            }
            Button {
                showHelpSheet = true
            } label: {
                Label("Help & About", systemImage: "info.circle")
            }
        }
    }

    private var importJSONSheet: some View {
        NavigationStack {
            Form {
                Section {
                    Button {
                        #if canImport(UIKit)
                        if let text = UIPasteboard.general.string {
                            profileDraft = text
                        }
                        #endif
                    } label: {
                        Label("Paste from Clipboard", systemImage: "doc.on.clipboard")
                    }
                    TextEditor(text: $profileDraft)
                        .font(.caption.monospaced())
                        .frame(minHeight: 220)
                        .accessibilityLabel("BaoBuddy Profile JSON")
                } header: {
                    Text("BaoBuddy Profile JSON")
                } footer: {
                    Text("Paste the JSON printed by `bao-buddy export-profile --copy` (or any BaoBuddy v1 server profile).")
                }
                if let error = model.errorMessage {
                    Section {
                        Text(error)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Import Profile")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { showImportSheet = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        model.importProfileJSON(profileDraft)
                        if model.errorMessage == nil {
                            showImportSheet = false
                        }
                    }
                    .disabled(profileDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }

    /// One line under a server's address: how it's trusted, its longest grant, and its remote host.
    private func serverCaption(for item: BaoProfile) -> String {
        var parts: [String] = [
            item.isDemoProfile
                ? String(localized: "Simulated · Local", comment: "Status of the demo server: simulated on this device.")
                : (item.openbao.isTLSPinned
                    ? String(localized: "Pinned TLS", comment: "Status: the server's TLS certificate is pinned (only that certificate is trusted).")
                    : String(localized: "System CAs", comment: "Status: the server is trusted through the system's certificate authorities, not a pinned certificate.")),
            String(localized: "Max \(item.openbao.maxHours)h", comment: "Longest grant the server allows. %lld is a number of hours; h = hours.")
        ]
        if item.hasRemoteTarget {
            parts.append(item.targetDisplayName)
        }
        return parts.joined(separator: " • ")
    }

    private func copyToClipboard(_ text: String) {
        #if canImport(UIKit)
        UIPasteboard.general.string = text
        #endif
    }
}
