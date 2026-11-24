import BaoBuddyCore
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

struct DashboardView: View {
    @Bindable var model: AppModel
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    /// Row icons' column, 20 pt at the default text size, growing with the text beside it.
    @ScaledMetric(relativeTo: .subheadline) private var iconColumnWidth: CGFloat = 20

    @State private var hours: Int = 2
    @State private var write: Bool = false
    @State private var push: Bool = false
    @State private var selectedKeys: Set<String> = []
    @State private var selectedHosts: Set<String> = []
    @State private var selectedCustomPolicies: Set<String> = []
    @State private var selectedExtensions: Set<String> = []
    @State private var revealedArtifacts: Set<String> = []
    @State private var why: String = ""
    @State private var showRevokeConfirm: Bool = false
    @State private var revealDirectToken: Bool = false
    @State private var copiedDirectToken: Bool = false
    @State private var showAddServerSheet: Bool = false
    @State private var showSetupWizard: Bool = false
    @State private var showQRScanner: Bool = false
    @State private var showActivitySheet: Bool = false
    @State private var showHelpSheet: Bool = false
    @State private var demoDeliveryTarget: GrantTarget = .t3
    @State private var isTestingHealth: Bool = false
    @State private var healthResult: (ok: Bool, message: String)?

    private func isElevated(profile: BaoProfile) -> Bool {
        if write || push || !selectedKeys.isEmpty || !selectedHosts.isEmpty {
            return true
        }
        if profile.openbao.enabledExtensions.contains(where: { selectedExtensions.contains($0.id) && $0.elevated }) {
            return true
        }
        return profile.openbao.grantPolicies.contains {
            selectedCustomPolicies.contains($0.name) && $0.elevated
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if let profile = model.profile {
                    configuredList(profile: profile)
                        .baoReadableWidth()
                } else {
                    onboardingView
                        .baoReadableWidth()
                }
            }
            .navigationTitle(model.profile == nil ? Text(verbatim: "BaoBuddy") : Text("Grants"))
            .navigationBarTitleDisplayMode(horizontalSizeClass == .regular ? .inline : .large)
            .toolbar {
                ToolbarItemGroup(placement: .topBarLeading) {
                    Button {
                        showHelpSheet = true
                    } label: {
                        Label("Help", systemImage: "questionmark.circle")
                    }
                    if model.profile != nil {
                        Button {
                            showActivitySheet = true
                        } label: {
                            Label("Activity", systemImage: "clock.arrow.circlepath")
                        }
                        .accessibilityIdentifier("activityButton")
                    }
                }
                if !model.profiles.isEmpty {
                    ToolbarItem(placement: .topBarTrailing) {
                        Menu {
                            ForEach(model.profiles) { item in
                                Button {
                                    BaoHaptics.impact()
                                    model.selectProfile(id: item.id)
                                } label: {
                                    if item.id == model.profile?.id {
                                        Label(item.displayName, systemImage: "checkmark")
                                    } else {
                                        Text(item.displayName)
                                    }
                                }
                            }
                            if !model.areProfilesLocked {
                                Divider()
                                Button {
                                    showQRScanner = true
                                } label: {
                                    Label("Scan Pairing QR Code…", systemImage: "qrcode.viewfinder")
                                }
                                Button {
                                    showAddServerSheet = true
                                } label: {
                                    Label("Add Server Manually…", systemImage: "plus")
                                }
                            }
                        } label: {
                            Label("Switch Server", systemImage: "server.rack")
                        }
                    }
                }
            }
            .sheet(isPresented: $showAddServerSheet) {
                ManualProfileSheetView(model: model, existing: nil)
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
            .sheet(isPresented: $showHelpSheet) {
                HelpSheetView(model: model)
                    .presentationSizing(.form)
            }
            .task(id: model.profile?.id) {
                healthResult = nil
                syncComposerDefaults(for: model.profile)
                if let profile = model.profile, profile.hasRemoteTarget, model.targetStatus == nil {
                    await model.refreshVMStatus()
                }
            }
        }
    }

    private func configuredList(profile: BaoProfile) -> some View {
        let durationOptions = [1, 2, 4, 8, 12].filter { $0 <= profile.openbao.maxHours }
        let elevated = isElevated(profile: profile)
        let canReview = !profile.openbao.usesCustomPolicies || !selectedCustomPolicies.isEmpty

        return List {
            BaoRegularColumnTitle(title: "Grants")

            if model.isDemoMode {
                Section {
                    BaoDemoBanner {
                        model.exitDemoMode()
                    }
                }
            }

            if let banner = model.bannerMessage {
                Section {
                    HStack(spacing: 10) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(BaoTheme.active)
                            .accessibilityHidden(true)
                        Text(banner)
                            .font(.subheadline)
                        Spacer()
                        Button {
                            model.bannerMessage = nil
                        } label: {
                            Image(systemName: "xmark")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .frame(minWidth: 44, minHeight: 44)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Dismiss")
                        .accessibilityIdentifier("dismissBanner")
                    }
                }
            }

            if let error = model.errorMessage {
                Section {
                    HStack(spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                            .accessibilityHidden(true)
                        Text(error)
                            .font(.subheadline)
                            .foregroundStyle(.red)
                        Spacer()
                        Button {
                            model.errorMessage = nil
                        } label: {
                            Image(systemName: "xmark")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .frame(minWidth: 44, minHeight: 44)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Dismiss")
                    }
                }
            }

            if let token = model.directToken {
                directTokenSection(token: token)
            }

            serverSummarySection(profile: profile)

            if profile.hasRemoteTarget {
                remoteStatusSection(profile: profile)
            }

            Section {
                if profile.isDemoProfile {
                    Picker("Demo Delivery", selection: $demoDeliveryTarget) {
                        Text("Remote Host").tag(GrantTarget.t3)
                        Text("Direct Token").tag(GrantTarget.mac)
                    }
                    .baoSegmentedPicker()
                    .accessibilityIdentifier("demoDeliveryPicker")
                    .listRowInsets(EdgeInsets(top: 10, leading: 16, bottom: 4, trailing: 16))
                }

                Picker("Duration", selection: $hours) {
                    ForEach(durationOptions.isEmpty ? [1] : durationOptions, id: \.self) { option in
                        Text("\(option)h", comment: "Grant duration option: a number of hours, abbreviated (h = hours).").tag(option)
                    }
                }
                .baoSegmentedPicker()
                .listRowInsets(EdgeInsets(top: 10, leading: 16, bottom: 10, trailing: 16))

                if profile.openbao.usesCustomPolicies {
                    ForEach(profile.openbao.grantPolicies) { policy in
                        Toggle(isOn: Binding(
                            get: { selectedCustomPolicies.contains(policy.name) },
                            set: { isOn in
                                BaoHaptics.impact()
                                if isOn {
                                    selectedCustomPolicies.insert(policy.name)
                                } else {
                                    selectedCustomPolicies.remove(policy.name)
                                }
                            }
                        )) {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Text(policy.displayLabel)
                                    if policy.elevated {
                                        Image(systemName: "exclamationmark.triangle.fill")
                                            .baoCaption2Font()
                                            .foregroundStyle(BaoTheme.elevated)
                                            .accessibilityLabel("Elevated")
                                    }
                                }
                                Text(policy.description.isEmpty ? policy.name : "\(policy.name) — \(policy.description)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .tint(policy.elevated ? BaoTheme.elevated : BaoTheme.brand)
                        .accessibilityIdentifier("policy-\(policy.name)")
                    }
                } else {
                    Toggle(isOn: $write) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Allow Secret Writes")
                            Text(profile.openbao.policies.write)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                    .tint(BaoTheme.elevated)

                    if profile.hasRemoteTarget && profile.supportsPushTokens {
                        Toggle(isOn: $push) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("GitHub Push Token")
                                Text("1-hour scoped Contents write")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .tint(BaoTheme.elevated)
                    }
                }
            } header: {
                Text(profile.hasRemoteTarget ? "New Grant for \(profile.targetDisplayName)" : "New Scoped Token")
            } footer: {
                if !profile.isDemoProfile && !profile.openbao.isTLSPinned {
                    Label("TLS not pinned: this server is trusted through the system certificate store.", systemImage: "lock.trianglebadge.exclamationmark")
                }
            }

            if !profile.openbao.usesCustomPolicies && !profile.openbao.keys.isEmpty {
                Section("Restricted Keys") {
                    ForEach(profile.openbao.keys) { item in
                        let selected = selectedKeys.contains(item.name)
                        Button {
                            BaoHaptics.impact()
                            if selected {
                                selectedKeys.remove(item.name)
                            } else {
                                selectedKeys.insert(item.name)
                            }
                        } label: {
                            HStack {
                                Label(item.name, systemImage: "key")
                                    .foregroundStyle(.primary)
                                Spacer()
                                if selected {
                                    Image(systemName: "checkmark")
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(BaoTheme.elevated)
                                        .accessibilityHidden(true)
                                }
                            }
                            .frame(minHeight: 36)
                        }
                        .accessibilityAddTraits(selected ? [.isSelected] : [])
                    }
                }
            }

            if profile.hasRemoteTarget && !profile.openbao.ssh.hosts.isEmpty {
                Section("SSH Certificates") {
                    ForEach(profile.openbao.ssh.hosts) { host in
                        let selected = selectedHosts.contains(host.name)
                        Button {
                            BaoHaptics.impact()
                            if selected {
                                selectedHosts.remove(host.name)
                            } else {
                                selectedHosts.insert(host.name)
                            }
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(host.name)
                                        .foregroundStyle(.primary)
                                    Text(verbatim: "\(host.user)@\(host.name)")
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if selected {
                                    Image(systemName: "checkmark")
                                        .font(.body.weight(.semibold))
                                        .foregroundStyle(BaoTheme.elevated)
                                        .accessibilityHidden(true)
                                }
                            }
                            .frame(minHeight: 36)
                        }
                        .accessibilityAddTraits(selected ? [.isSelected] : [])
                    }
                }
            }

            if !profile.openbao.enabledExtensions.isEmpty {
                Section {
                    ForEach(profile.openbao.enabledExtensions) { ext in
                        Toggle(isOn: Binding(
                            get: { selectedExtensions.contains(ext.id) },
                            set: { isOn in
                                BaoHaptics.impact()
                                if isOn {
                                    selectedExtensions.insert(ext.id)
                                } else {
                                    selectedExtensions.remove(ext.id)
                                }
                            }
                        )) {
                            HStack(alignment: .center, spacing: 10) {
                                Image(systemName: ext.icon)
                                    .font(.subheadline)
                                    .foregroundStyle(ext.elevated ? BaoTheme.elevated : BaoTheme.brand)
                                    .frame(width: iconColumnWidth, alignment: .center)
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack(spacing: 6) {
                                        Text(ext.displayLabel)
                                            .font(.subheadline)
                                        // Elevated is marked by shape as well as colour, as policies are.
                                        if ext.elevated {
                                            Image(systemName: "exclamationmark.triangle.fill")
                                                .baoCaption2Font()
                                                .foregroundStyle(BaoTheme.elevated)
                                                .accessibilityLabel("Elevated")
                                        }
                                    }
                                    Text(ext.endpoint)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .tint(ext.elevated ? BaoTheme.elevated : BaoTheme.brand)
                        .accessibilityIdentifier("extension-\(ext.id)")
                    }
                } header: {
                    Text("Credentials")
                } footer: {
                    Text(profile.hasRemoteTarget
                         ? "Minted with the grant and delivered to \(profile.targetDisplayName). They end when the grant is revoked or expires."
                         : "Minted with the grant and shown here. They end when the grant is revoked or expires.")
                }
            }

            Section("Audit Reason") {
                BaoTextField("Why is this grant needed?", text: $why)
            }

            Section {
                Button {
                    BaoHaptics.impact(.medium)
                    let orderedHosts = profile.openbao.ssh.hosts.map(\.name).filter { selectedHosts.contains($0) }
                    let orderedKeys = profile.openbao.keys.map(\.name).filter { selectedKeys.contains($0) }
                    let orderedPolicies = profile.openbao.grantPolicies.map(\.name).filter { selectedCustomPolicies.contains($0) }
                    let orderedExtensions = profile.openbao.enabledExtensions.map(\.id).filter { selectedExtensions.contains($0) }
                    let effectiveTarget: GrantTarget = profile.isDemoProfile
                        ? demoDeliveryTarget
                        : (profile.hasRemoteTarget ? .t3 : .mac)
                    let request = GrantRequest(
                        target: effectiveTarget,
                        hours: min(hours, profile.openbao.maxHours),
                        write: profile.openbao.usesCustomPolicies ? false : write,
                        keys: profile.openbao.usesCustomPolicies ? [] : orderedKeys,
                        sshHosts: effectiveTarget == .t3 ? orderedHosts : [],
                        push: effectiveTarget == .t3 && !profile.openbao.usesCustomPolicies ? push : false,
                        customPolicies: profile.openbao.usesCustomPolicies ? orderedPolicies : [],
                        why: why,
                        extensions: orderedExtensions
                    )
                    model.presentApproval(for: request)
                } label: {
                    HStack(spacing: 8) {
                        // With Differentiate Without Color, an elevated grant is marked by shape, not only orange.
                        Image(systemName: elevated && differentiateWithoutColor
                              ? "exclamationmark.triangle.fill"
                              : model.biometry.systemImage)
                            .accessibilityHidden(true)
                        Text("Review & Approve")
                            .font(.headline)
                    }
                    .frame(maxWidth: .infinity, minHeight: 46, alignment: .center)
                    .multilineTextAlignment(.center)
                }
                .primaryBaoButton(tint: elevated ? BaoTheme.elevated : BaoTheme.brand)
                .accessibilityValue(elevated ? Text("Elevated") : Text(verbatim: ""))
                .disabled(!canReview)
                .accessibilityIdentifier("reviewAndApprove")
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
            }
        }
        .listStyle(.insetGrouped)
        .listSectionSpacing(.compact)
        .refreshable {
            await model.refreshVMStatus()
        }
    }

    private func serverSummarySection(profile: BaoProfile) -> some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                BaoAdaptiveStack(spacing: 12) {
                    BaoIconBadge(symbol: profile.isDemoProfile ? "flask.fill" : "server.rack", tint: BaoTheme.brand)
                    VStack(alignment: .leading, spacing: 2) {
                        BaoAdaptiveStack(spacing: 6) {
                            Text(profile.displayName)
                                .font(.headline)
                                .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 1)
                            Spacer(minLength: 4)
                            if profile.isDemoProfile {
                                BaoStatusPill(title: "Demo", tint: BaoTheme.brand, symbol: "flask.fill")
                            } else if model.isManaged(profileID: profile.id) {
                                BaoStatusPill(title: "Managed", tint: .secondary, symbol: "building.2.fill")
                            } else {
                                BaoStatusPill(title: "Active", tint: BaoTheme.active, symbol: "checkmark.circle.fill")
                            }
                        }
                        Text(verbatim: profile.openbao.address)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(dynamicTypeSize.isAccessibilitySize ? nil : 1)
                            .minimumScaleFactor(0.8)
                            // VoiceOver names the field, then reads the address.
                            .accessibilityLabel("Address")
                            .accessibilityValue(Text(verbatim: profile.openbao.address))
                    }
                }
            }
            .padding(.vertical, 2)

            BaoAdaptiveStack(spacing: 6) {
                if profile.isDemoProfile {
                    BaoStatusPill(title: "Simulated · Local", tint: BaoTheme.brand, symbol: "cpu")
                } else if profile.openbao.isTLSPinned {
                    BaoStatusPill(title: "Pinned TLS", tint: BaoTheme.active, symbol: "lock.fill")
                } else {
                    BaoStatusPill(title: "System CAs", tint: BaoTheme.elevated, symbol: "lock.trianglebadge.exclamationmark")
                }
                if !profile.openbao.mtlsClientIdentity.isEmpty {
                    BaoStatusPill(title: "mTLS", tint: BaoTheme.brand, symbol: nil)
                }
                BaoStatusPill(title: "Max \(profile.openbao.maxHours)h", tint: .secondary, symbol: "clock")
                Spacer()
                Button {
                    Task { await runHealthCheck() }
                } label: {
                    if isTestingHealth {
                        ProgressView().controlSize(.small)
                    } else {
                        // One line at its natural width, so long pill labels beside it (Japanese,
                        // for one) can't squeeze it into a column of single letters.
                        HStack(spacing: 4) {
                            Image(systemName: "network")
                                .accessibilityHidden(true)
                            Text("Test")
                        }
                        .font(.caption.weight(.medium))
                        .lineLimit(1)
                        .fixedSize()
                    }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(isTestingHealth)
            }

            if let healthResult {
                Label(
                    healthResult.message,
                    systemImage: healthResult.ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
                )
                .font(.caption)
                .foregroundStyle(healthResult.ok ? BaoTheme.active : .red)
            }
        }
    }

    private func runHealthCheck() async {
        isTestingHealth = true
        defer { isTestingHealth = false }
        switch await model.checkServerHealth() {
        case let .success(health):
            if health.sealed {
                healthResult = (false, String(localized: "Reachable over TLS, but OpenBao is sealed.", comment: "Connection test result. Sealed means the OpenBao server is locked and can't serve secrets until an operator unseals it."))
                BaoHaptics.notify(.warning)
            } else {
                healthResult = (true, health.version.isEmpty
                    ? String(localized: "Connected — OpenBao (unsealed).", comment: "Connection test result. OpenBao is a product name. Unsealed means the server is unlocked and serving secrets.")
                    : String(localized: "Connected — OpenBao v\(health.version) (unsealed).", comment: "Connection test result. %@ is the server's version number. Unsealed means the server is unlocked and serving secrets."))
                BaoHaptics.notify(.success)
            }
        case let .failure(error):
            healthResult = (false, error.localizedDescription)
            BaoHaptics.notify(.error)
        }
    }

    private func remoteStatusSection(profile: BaoProfile) -> some View {
        let headerState = model.targetStatus?.headerState ?? .inactive
        let active = model.targetStatus?.hasActiveGrant ?? false
        let showWarningHeader = headerState == .unknown
        let showActiveHeader = headerState == .active
        return Section {
            HStack {
                Label {
                    Text(showWarningHeader ? "Status Unknown" : (showActiveHeader ? "Active Grant" : "No Active Grant"))
                        .font(.subheadline.weight(.semibold))
                } icon: {
                    if showWarningHeader {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.subheadline)
                            .foregroundStyle(BaoTheme.elevated)
                            .accessibilityHidden(true)
                    } else {
                        Image(showActiveHeader ? "BaoBuddyGlyphUnlocked" : "BaoBuddyGlyph")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 22, height: 18)
                            .foregroundStyle(showActiveHeader ? BaoTheme.active : .secondary)
                            .accessibilityHidden(true)
                    }
                }
                Spacer()
                if model.isLoadingStatus {
                    ProgressView()
                }
            }

            if let status = model.targetStatus {
                if let unavailable = status.unavailableReason {
                    Label(unavailable, systemImage: "wifi.exclamationmark")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(status.entries) { entry in
                        let statusColor: Color = switch entry.state {
                        case .active: BaoTheme.active
                        case .unknown: BaoTheme.elevated
                        case .inactive: .secondary
                        }
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Image(systemName: entry.systemImage)
                                .font(.subheadline)
                                .foregroundStyle(entry.state == .unknown ? BaoTheme.elevated : (entry.isActive ? BaoTheme.brand : .secondary))
                                .frame(width: iconColumnWidth, alignment: .center)
                                .accessibilityHidden(true)

                            VStack(alignment: .leading, spacing: 3) {
                                BaoAdaptiveStack(spacing: 8) {
                                    Text(entry.label)
                                        .font(.subheadline)
                                        .foregroundStyle(entry.state == .inactive ? .secondary : .primary)
                                    Spacer(minLength: 8)
                                    Text(entry.statusText)
                                        .font(.subheadline.weight(entry.state == .inactive ? .regular : .medium))
                                        .foregroundStyle(statusColor)
                                        .multilineTextAlignment(dynamicTypeSize.isAccessibilitySize ? .leading : .trailing)
                                }
                                if !entry.detail.isEmpty {
                                    Text(entry.detail)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                        .padding(.vertical, 1)
                    }
                }
            }

            Button {
                BaoHaptics.impact()
                Task { await model.refreshVMStatus() }
            } label: {
                Label("Refresh Status", systemImage: "arrow.clockwise")
            }
            .disabled(model.isLoadingStatus)

            if active {
                Button(role: .destructive) {
                    BaoHaptics.impact(.medium)
                    showRevokeConfirm = true
                } label: {
                    Label("Revoke Grant", systemImage: "xmark.shield")
                }
                .confirmationDialog(
                    "Revoke active grant on \(profile.targetDisplayName)?",
                    isPresented: $showRevokeConfirm,
                    titleVisibility: .visible
                ) {
                    Button("Revoke Grant", role: .destructive) {
                        Task { await model.revokeVMGrant() }
                    }
                    Button("Cancel", role: .cancel) {}
                }
            }
        } header: {
            Text(profile.targetDisplayName)
        }
    }

    private func directTokenSection(token: String) -> some View {
        Section {
            if !model.directTokenSummary.isEmpty {
                Text(model.directTokenSummary)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            HStack {
                // No text selection: copying must go through the button below, which applies the
                // 2-minute, this-device-only clipboard and the MDM clipboard setting.
                Text(revealDirectToken ? token : String(repeating: "•", count: min(token.count, 28)))
                    .font(.footnote.monospaced())
                    .privacySensitive()
                Spacer()
                Button(revealDirectToken ? "Hide" : "Reveal") {
                    revealDirectToken.toggle()
                }
                .font(.subheadline)
                .accessibilityIdentifier("revealDirectToken")
            }

            if !model.isClipboardDisabled {
                Button {
                    #if canImport(UIKit)
                    // `.localOnly` keeps the token off Universal Clipboard (other Apple devices).
                    UIPasteboard.general.setItems(
                        [[UIPasteboard.typeAutomatic: token]],
                        options: [
                            .expirationDate: Date().addingTimeInterval(120),
                            .localOnly: true
                        ]
                    )
                    #endif
                    copiedDirectToken = true
                    BaoHaptics.notify(.success)
                } label: {
                    Label(
                        copiedDirectToken ? "Copied (Expires in 2m)" : "Copy Token",
                        systemImage: copiedDirectToken ? "checkmark" : "doc.on.doc"
                    )
                }
            }

            ForEach(model.directArtifacts, id: \.name) { artifact in
                artifactRow(artifact)
            }

            Button(role: .destructive) {
                Task { await model.revokeDirectToken() }
            } label: {
                Label(model.directArtifacts.isEmpty ? "Revoke Token" : "Revoke Token and Credentials", systemImage: "trash")
            }
        } header: {
            Text("Minted Token")
        } footer: {
            if model.isClipboardDisabled {
                Text("Clipboard copy is disabled by your organization's MDM policy.")
            }
        }
    }

    private func artifactRow(_ artifact: MintedExtensionArtifact) -> some View {
        let revealed = revealedArtifacts.contains(artifact.name)
        return VStack(alignment: .leading, spacing: 6) {
            HStack {
                Label(artifact.name, systemImage: "doc.badge.ellipsis")
                    .font(.subheadline)
                Spacer()
                Button(revealed ? "Hide" : "Reveal") {
                    if revealed {
                        revealedArtifacts.remove(artifact.name)
                    } else {
                        revealedArtifacts.insert(artifact.name)
                    }
                }
                .font(.subheadline)
                .accessibilityIdentifier("revealArtifact-\(artifact.name)")
            }
            if revealed {
                Text(artifact.content)
                    .baoCaption2Font(monospaced: true)
                    .lineLimit(12)
                    .privacySensitive()
            }
            if let expiresAt = artifact.expiresAt {
                Text("Expires \(Date(timeIntervalSince1970: TimeInterval(expiresAt)).formatted(date: .omitted, time: .shortened))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if !model.isClipboardDisabled {
                Button {
                    #if canImport(UIKit)
                    UIPasteboard.general.setItems(
                        [[UIPasteboard.typeAutomatic: artifact.content]],
                        options: [
                            .expirationDate: Date().addingTimeInterval(120),
                            .localOnly: true
                        ]
                    )
                    #endif
                    BaoHaptics.notify(.success)
                } label: {
                    Label("Copy \(artifact.name) (expires from clipboard in 2m)", systemImage: "doc.on.doc")
                        .font(.footnote)
                }
            }
        }
    }

    private var onboardingView: some View {
        ScrollView {
            VStack(spacing: 22) {
                Spacer(minLength: 28)

                VStack(spacing: 14) {
                    BaoBuddyEmblem(tint: BaoTheme.brand, size: 76)
                    Text("Connect OpenBao or Vault")
                        .font(.title2.weight(.bold))
                        .multilineTextAlignment(.center)
                    Text("Sign short-lived ES256 JWTs in Apple's Secure Enclave with \(model.biometry.nameInSentence) — no passwords stored or typed.", comment: "Welcome screen. %@ is Face ID, Touch ID or the word biometrics. ES256, JWT and Secure Enclave are technical/product names.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                VStack(spacing: 10) {
                    if !model.areProfilesLocked {
                        Button {
                            BaoHaptics.impact(.medium)
                            showQRScanner = true
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "qrcode.viewfinder")
                                Text("Scan QR Code from Mac")
                                    .font(.headline)
                            }
                            .frame(maxWidth: .infinity, minHeight: 46, alignment: .center)
                            .multilineTextAlignment(.center)
                        }
                        .primaryBaoButton(tint: BaoTheme.brand)

                        Button {
                            BaoHaptics.impact()
                            showSetupWizard = true
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "wand.and.stars")
                                Text("Guided Server Setup")
                                    .font(.subheadline.weight(.semibold))
                            }
                            .frame(maxWidth: .infinity, minHeight: 42, alignment: .center)
                            .multilineTextAlignment(.center)
                        }
                        .buttonStyle(.bordered)
                        .buttonBorderShape(.capsule)
                    }

                    Button {
                        BaoHaptics.impact()
                        model.enterDemoMode()
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "flask")
                            Text("Try Demo")
                                .font(.subheadline.weight(.semibold))
                        }
                        .frame(maxWidth: .infinity, minHeight: 42, alignment: .center)
                        .multilineTextAlignment(.center)
                    }
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .tint(BaoTheme.brand)

                    Button {
                        showHelpSheet = true
                    } label: {
                        Text("How BaoBuddy Works")
                            .frame(minHeight: 44)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.borderless)
                    .font(.subheadline)
                }
                .frame(maxWidth: 340)

                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .top, spacing: 10) {
                        BaoIconBadge(symbol: "desktopcomputer", tint: BaoTheme.brand, size: 30)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Fastest setup with BaoBuddy on Mac")
                                .font(.footnote.weight(.semibold))
                            Text("Open BaoBuddy Settings → Share & Export → Pair iPhone (QR Code), or run `bao-buddy export-profile --qr` in Terminal.", comment: "Welcome screen. 'Settings → Share & Export → Pair iPhone (QR Code)' names screens in BaoBuddy for Mac, which is in English only. Do not translate the command in backticks.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .padding(14)
                .frame(maxWidth: 420, alignment: .leading)
                .background(Color(.secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
            .frame(maxWidth: .infinity)
        }
        .background(Color(.systemGroupedBackground))
    }

    private func syncComposerDefaults(for profile: BaoProfile?) {
        write = false
        push = false
        selectedKeys = []
        selectedHosts = []
        selectedExtensions = []
        if let profile {
            hours = min(max(hours, 1), profile.openbao.maxHours)
            if profile.isDemoProfile, let sample = model.demoComposerReason {
                why = sample
            }
            selectedCustomPolicies = Set(profile.openbao.grantPolicies.filter(\.defaultSelected).map(\.name))
        } else {
            selectedCustomPolicies = []
        }
    }
}
