import BaoBuddyCore
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// Guided first-server setup wizard:
/// 1. Connect and validate the OpenBao/Vault server profile first.
/// 2. Create and export the deployment-scoped Secure Enclave key for that exact server + JWT mount.
/// 3. Optionally create/authorize the SSH delivery key if the profile has a remote target.
/// 4. Verify live TLS & server connectivity.
struct SetupWizardView: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var step: SetupWizardStep = .server
    @State private var profileDraft: String = ""
    @State private var importError: String?
    @State private var showManualSheet: Bool = false
    @State private var showQRScanner: Bool = false
    @State private var showSetupSnippet: Bool = false
    @State private var copiedPEM: Bool = false
    @State private var copiedSSH: Bool = false
    @State private var isTestingHealth: Bool = false
    @State private var healthMessage: String?
    @State private var healthSucceeded: Bool = false

    private var needsSSHStep: Bool {
        model.profile?.hasRemoteTarget ?? false
    }

    private var visibleSteps: [SetupWizardStep] {
        SetupWizardStep.steps(hasRemoteTarget: needsSSHStep)
    }

    private var currentStepNumber: Int {
        (visibleSteps.firstIndex(of: step) ?? 0) + 1
    }

    private var parsedDraftProfile: BaoProfile? {
        let trimmed = profileDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return try? BaoProfile.decode(from: Data(trimmed.utf8))
    }

    private var biometryText: String {
        model.biometry.nameInSentence
    }

    var body: some View {
        NavigationStack {
            List {
                stepHeaderSection

                switch step {
                case .server:
                    serverSections
                case .deviceKey:
                    deviceKeySections
                case .sshKey:
                    sshKeySections
                case .verify:
                    verifySections
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Setup (\(currentStepNumber) of \(visibleSteps.count))")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if step == .server {
                        Button("Cancel") { dismiss() }
                    } else {
                        Button("Back") { goBack() }
                    }
                }
                if step == .verify {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { dismiss() }
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                bottomActionBar
            }
            .sheet(isPresented: $showManualSheet) {
                ManualProfileSheetView(model: model, existing: nil)
                    .presentationSizing(.form)
            }
            .sheet(isPresented: $showQRScanner) {
                QRScannerSheetView(enforceTLSPinning: model.enforceTLSPinning) { scanned in
                    model.stageImport(scanned)
                }
                .presentationSizing(.form)
            }
            .onChange(of: model.profiles.count) { oldCount, newCount in
                if step == .server && newCount > oldCount {
                    advanceAfterServerSaved()
                }
            }
        }
    }

    // MARK: - Header

    private var stepHeaderSection: some View {
        Section {
            HStack(spacing: 14) {
                BaoBuddyEmblem(tint: BaoTheme.brand, size: 48)
                VStack(alignment: .leading, spacing: 3) {
                    Text(headerTitle)
                        .font(.headline)
                    headerSubtitle
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 4)
        }
    }

    private var headerTitle: LocalizedStringKey {
        switch step {
        case .server: "Connect OpenBao or Vault"
        case .deviceKey: "Create Server-Scoped Key"
        case .sshKey: "Authorize Remote SSH Delivery"
        case .verify: "Check Your Connection"
        }
    }

    private var headerSubtitle: Text {
        switch step {
        case .server:
            Text("Scan a pairing QR code, paste a profile JSON, or enter your server first.")
        case .deviceKey:
            if let active = model.profile {
                Text(
                    "Dedicated Secure Enclave key for \(active.displayName) (auth/\(active.openbao.jwtAuth.mount)/), gated by \(biometryText).",
                    comment: "Setup step subtitle. %1$@ is the server's name; %2$@ is its JWT auth mount (keep auth/…/ as is); %3$@ is Face ID, Touch ID or the word biometrics."
                )
            } else {
                Text("Generated inside Apple's Secure Enclave and protected by \(biometryText).", comment: "Setup step subtitle. %@ is Face ID, Touch ID or the word biometrics.")
            }
        case .sshKey:
            if let target = model.profile?.targetDisplayName {
                Text("Your server delivers grants to \(target) over SSH.", comment: "Setup step subtitle. %@ is the remote host's name.")
            } else {
                Text("Your server delivers grants to a remote host over SSH.")
            }
        case .verify:
            Text("Confirm your phone can reach OpenBao and trusts its certificate.")
        }
    }

    // MARK: - Step 2: Secure Enclave Key (scoped to selected server)

    @ViewBuilder
    private var deviceKeySections: some View {
        if let active = model.profile {
            Section("Target Deployment") {
                LabeledContent("Server", value: active.displayName)
                LabeledContent("Endpoint") {
                    Text(active.openbao.normalizedAuthorityAndPath)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
                LabeledContent("JWT Mount") {
                    Text(verbatim: "auth/\(active.openbao.jwtAuth.mount)/")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
        }

        Section {
            LabeledContent("Device Name") {
                TextField("Device Name", text: $model.deviceName, prompt: Text(verbatim: AppModel.defaultDeviceName))
                    .multilineTextAlignment(.trailing)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.body.monospaced())
            }
        } footer: {
            Text("Recorded in OpenBao audit logs as the `device` claim (for example `\(AppModel.defaultDeviceName)`).", comment: "Footer. Do not translate `device` (a JWT claim name). %@ is an example value such as iphone (not translated).")
        }

        Section {
            if model.devicePublicKeyPEM.isEmpty {
                Button {
                    model.ensureDeviceKey()
                } label: {
                    Label("Create Secure Enclave Key", systemImage: "key.badge.plus")
                }
            } else {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Secure Enclave Key Ready")
                            .font(.subheadline.weight(.medium))
                        Text(verbatim: "sha256:\(model.deviceFingerprint)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(BaoTheme.active)
                }

                Text(model.devicePublicKeyPEM)
                    .baoCaption2Font(monospaced: true)
                    .textSelection(.enabled)

                Button {
                    copyToClipboard(model.devicePublicKeyPEM)
                    copiedPEM = true
                    BaoHaptics.notify(.success)
                } label: {
                    Label(
                        copiedPEM ? "Copied P-256 Public Key" : "Copy P-256 Public Key PEM",
                        systemImage: copiedPEM ? "checkmark" : "doc.on.doc"
                    )
                }

                ShareLink(item: model.devicePublicKeyPEM) {
                    Label("Share Public Key…", systemImage: "square.and.arrow.up")
                }
            }
        } header: {
            Text("Hardware Identity")
        } footer: {
            if model.devicePublicKeyPEM.isEmpty {
                if let name = model.profile?.displayName {
                    Text("This key is dedicated to \(name) and never reused across deployments.", comment: "Footer. %@ is the server's name.")
                } else {
                    Text("This key is dedicated to this server and never reused across deployments.")
                }
            } else if let active = model.profile {
                let regCmd = BaoServerAdmin.renderDeviceAddCommand(
                    address: active.openbao.address,
                    namespace: active.openbao.namespace,
                    caCertPath: active.openbao.isTLSPinned ? "<ca.pem>" : "",
                    mtlsClientIdentity: active.openbao.mtlsClientIdentity,
                    mount: active.openbao.jwtAuth.mount
                )
                Text("Register this PEM on OpenBao with `pbpaste | \(regCmd)`, or expand the raw OpenBao CLI commands below.", comment: "Footer. %@ is a Terminal command; do not translate anything inside backticks. PEM is a key file format.")
            } else {
                Text("Register this PEM on OpenBao with `pbpaste | bao-buddy device add --mount jwt-user`, or expand the raw OpenBao CLI commands below.", comment: "Footer. Do not translate the Terminal command inside backticks. PEM is a key file format.")
            }
        }

        if !model.devicePublicKeyPEM.isEmpty {
            Section {
                DisclosureGroup("OpenBao CLI Setup Commands", isExpanded: $showSetupSnippet) {
                    Text(model.openBaoSetupSnippet())
                        .baoCaption2Font(monospaced: true)
                        .textSelection(.enabled)
                }
            }
        }
    }

    // MARK: - Step 2: Server Profile

    @ViewBuilder
    private var serverSections: some View {
        Section {
            Button {
                showQRScanner = true
            } label: {
                Label("Scan QR Code from Mac or Terminal…", systemImage: "qrcode.viewfinder")
                    .font(.subheadline.weight(.semibold))
            }
        } header: {
            Text("Option 1: Scan Pairing QR Code (Recommended)")
        } footer: {
            Text("In BaoBuddy on Mac, open Settings → Share & Export → Pair iPhone (QR Code), or run `bao-buddy export-profile --qr`.")
        }

        Section {
            Button {
                pasteProfileFromClipboard()
            } label: {
                Label("Paste Profile JSON from Clipboard", systemImage: "doc.on.clipboard")
            }

            TextEditor(text: $profileDraft)
                .font(.caption.monospaced())
                .frame(minHeight: 120)
                .accessibilityLabel("BaoBuddy Profile JSON")
                .onChange(of: profileDraft) { _, _ in
                    importError = nil
                }

            if let preview = parsedDraftProfile {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(preview.displayName)
                            .font(.subheadline.weight(.medium))
                        Text(preview.openbao.address)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        if preview.hasRemoteTarget {
                            Text("Remote target: \(preview.targetDisplayName) (\(preview.t3Granter.host))", comment: "%1$@ is the remote host's name; %2$@ is its address.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                } icon: {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(BaoTheme.active)
                }
            }

            if let importError {
                Label(importError, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        } header: {
            Text("Option 2: Paste a Profile JSON")
        } footer: {
            Text("A profile JSON bundles your OpenBao URL, TLS certificate, JWT auth settings, and optional SSH target (`bao-buddy export-profile --copy`).")
        }

        Section {
            Button {
                showManualSheet = true
            } label: {
                Label("Enter Server Details Manually…", systemImage: "slider.horizontal.3")
            }
        } header: {
            Text("Option 3: Configure Manually")
        } footer: {
            Text("Best if you're connecting your own OpenBao or HashiCorp Vault server and defining custom policies.")
        }
    }

    // MARK: - Step 3: Optional SSH Key

    @ViewBuilder
    private var sshKeySections: some View {
        Section {
            if model.sshPublicKey.isEmpty {
                Button {
                    model.ensureSSHKey()
                } label: {
                    Label("Create Secure Enclave SSH Key", systemImage: "terminal")
                }
            } else {
                Label("SSH Key Ready", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(BaoTheme.active)

                Text(model.sshPublicKey)
                    .baoCaption2Font(monospaced: true)
                    .textSelection(.enabled)

                Button {
                    copyToClipboard(model.sshPublicKey)
                    copiedSSH = true
                    BaoHaptics.notify(.success)
                } label: {
                    Label(
                        copiedSSH ? "Copied SSH Public Key" : "Copy SSH Public Key",
                        systemImage: copiedSSH ? "checkmark" : "doc.on.doc"
                    )
                }

                ShareLink(item: model.sshPublicKey) {
                    Label("Share SSH Public Key…", systemImage: "square.and.arrow.up")
                }
            }
        } header: {
            Text("Remote SSH Delivery Key")
        } footer: {
            if let profile = model.profile {
                Text("Authorize this public key on \(profile.t3Granter.user)@\(profile.t3Granter.host) in its `authorized_keys`.", comment: "Footer. %1$@@%2$@ is an SSH login (user@host). Do not translate `authorized_keys` (a file name).")
            }
        }
    }

    // MARK: - Step 4: Verify

    @ViewBuilder
    private var verifySections: some View {
        if let profile = model.profile {
            Section("Summary") {
                LabeledContent("Server", value: profile.displayName)
                LabeledContent("Address", value: profile.openbao.address)
                if !model.deviceFingerprint.isEmpty {
                    LabeledContent("Device Key") {
                        Text(verbatim: "sha256:\(model.deviceFingerprint.prefix(16))…")
                    }
                }
                if profile.hasRemoteTarget {
                    LabeledContent("Remote Target", value: "\(profile.targetDisplayName) (\(profile.t3Granter.host))")
                }
            }

            Section {
                Button {
                    Task { await runHealthCheck() }
                } label: {
                    HStack {
                        Label("Test OpenBao Connection", systemImage: "network")
                        Spacer()
                        if isTestingHealth {
                            ProgressView()
                        }
                    }
                }
                .disabled(isTestingHealth)

                if let healthMessage {
                    Label(healthMessage, systemImage: healthSucceeded ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(healthSucceeded ? BaoTheme.active : .red)
                }

                if profile.hasRemoteTarget {
                    Button {
                        Task { await model.refreshVMStatus() }
                    } label: {
                        HStack {
                            Label("Test \(profile.targetDisplayName) SSH", systemImage: "terminal")
                            Spacer()
                            if model.isLoadingStatus {
                                ProgressView()
                            }
                        }
                    }
                    .disabled(model.isLoadingStatus)

                    if let status = model.targetStatus {
                        if let unavailable = status.unavailableReason {
                            Label(unavailable, systemImage: "exclamationmark.triangle.fill")
                                .font(.footnote)
                                .foregroundStyle(BaoTheme.elevated)
                        } else {
                            Label("Connected to \(profile.targetDisplayName).", systemImage: "checkmark.circle.fill")
                                .font(.footnote)
                                .foregroundStyle(BaoTheme.active)
                        }
                    }
                }
            } header: {
                Text("Connection Test")
            } footer: {
                Text("Make sure you are on your private network or VPN before testing.")
            }
        }
    }

    // MARK: - Bottom Bar

    private var bottomActionBar: some View {
        VStack(spacing: 0) {
            Divider()
            Button {
                BaoHaptics.impact(.medium)
                handlePrimaryAction()
            } label: {
                Text(primaryButtonTitle)
                    .font(.headline)
                    .frame(maxWidth: .infinity, minHeight: 46, alignment: .center)
                    .multilineTextAlignment(.center)
            }
            .primaryBaoButton(tint: BaoTheme.brand)
            .disabled(!canContinue)
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
        .background(.bar)
    }

    private var primaryButtonTitle: LocalizedStringKey {
        switch step {
        case .deviceKey: "Continue"
        case .server: model.profile != nil && profileDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "Continue"
            : "Save Server & Continue"
        case .sshKey: "Continue"
        case .verify: "Start Using BaoBuddy"
        }
    }

    private var canContinue: Bool {
        switch step {
        case .deviceKey:
            return !model.devicePublicKeyPEM.isEmpty
        case .server:
            return parsedDraftProfile != nil || model.profile != nil
        case .sshKey:
            return !model.sshPublicKey.isEmpty
        case .verify:
            return true
        }
    }

    // MARK: - Actions

    private func handlePrimaryAction() {
        switch step {
        case .server:
            let trimmed = profileDraft.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                model.importProfileJSON(trimmed)
                if let err = model.errorMessage {
                    importError = err
                    return
                }
            }
            advanceAfterServerSaved()
        case .deviceKey:
            step = needsSSHStep ? .sshKey : .verify
        case .sshKey:
            step = .verify
        case .verify:
            dismiss()
        }
    }

    private func advanceAfterServerSaved() {
        healthMessage = nil
        healthSucceeded = false
        model.refreshKeyDisplay()
        step = .deviceKey
    }

    private func goBack() {
        guard let idx = visibleSteps.firstIndex(of: step), idx > 0 else { return }
        step = visibleSteps[idx - 1]
    }

    private func pasteProfileFromClipboard() {
        #if canImport(UIKit)
        guard let text = UIPasteboard.general.string, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            importError = String(localized: "Your clipboard is empty. Copy a profile JSON first, or configure manually below.", comment: "Error in setup when pasting from an empty clipboard.")
            BaoHaptics.notify(.warning)
            return
        }
        profileDraft = text
        if parsedDraftProfile == nil {
            do {
                _ = try BaoProfile.decode(from: Data(text.utf8))
            } catch {
                importError = error.localizedDescription
                BaoHaptics.notify(.error)
            }
        } else {
            importError = nil
            BaoHaptics.notify(.success)
        }
        #endif
    }

    private func runHealthCheck() async {
        isTestingHealth = true
        defer { isTestingHealth = false }
        switch await model.checkServerHealth() {
        case let .success(health):
            if health.sealed {
                healthSucceeded = false
                healthMessage = String(localized: "Reachable over TLS, but OpenBao is currently sealed.", comment: "Connection test result. Sealed means the OpenBao server is locked and can't serve secrets until an operator unseals it.")
                BaoHaptics.notify(.warning)
            } else {
                healthSucceeded = true
                healthMessage = health.version.isEmpty
                    ? String(localized: "Connected — OpenBao is unsealed and certificate matches.", comment: "Connection test result. Unsealed means the server is unlocked and serving secrets.")
                    : String(localized: "Connected — OpenBao (v\(health.version)) is unsealed and certificate matches.", comment: "Connection test result. %@ is the server's version number. Unsealed means the server is unlocked and serving secrets.")
                BaoHaptics.notify(.success)
            }
        case let .failure(error):
            healthSucceeded = false
            healthMessage = error.localizedDescription
            BaoHaptics.notify(.error)
        }
    }

    private func copyToClipboard(_ text: String) {
        #if canImport(UIKit)
        UIPasteboard.general.string = text
        #endif
    }
}
