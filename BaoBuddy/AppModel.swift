#if os(iOS) && canImport(ActivityKit)
import ActivityKit
#endif
import BaoBuddyCore
import BaoBuddySSH
import Foundation
import Observation
#if canImport(UIKit)
import UIKit
#endif

/// Shared remote status parser type from `BaoBuddyCore`.
typealias TargetStatusSummary = RemoteStatusSummary

/// A direct token, bound to the profile (server address and TLS pin) it was minted on, so revoking
/// it always goes to the server that issued it, even after the user switches or edits profiles.
struct DirectTokenGrant: Equatable {
    let profile: BaoProfile
    let token: String
    let accessor: String
    let summary: String
    /// Credential-extension output minted with the token; leased ones end when it's revoked.
    var artifacts: [MintedExtensionArtifact] = []
}

/// Guided first-server setup order: configure and validate the server deployment first so the
/// Secure Enclave key is created and exported for that exact server + JWT mount.
enum SetupWizardStep: Int, CaseIterable, Equatable {
    case server
    case deviceKey
    case sshKey
    case verify

    static func steps(hasRemoteTarget: Bool) -> [SetupWizardStep] {
        hasRemoteTarget ? [.server, .deviceKey, .sshKey, .verify] : [.server, .deviceKey, .verify]
    }
}

/// A request waiting for approval, bound to the profile it was parsed against.
struct PendingApproval: Equatable {
    let id: UUID = UUID()
    let profileID: String
    /// The profile as the link selected it (focused on the link's remote target, if any).
    let profile: BaoProfile
    let request: GrantRequest
}

@MainActor
@Observable
final class AppModel {
    private static let deviceNameDefaultsKey = "com.northcutt.baogrant.deviceName"

    var profiles: [BaoProfile] = []
    var activeProfileID: String?
    var managedProfiles: [BaoProfile] = []
    var managedProfileIDs: Set<String> = []
    var isClipboardDisabled: Bool = false
    var areProfilesLocked: Bool = false
    var enforceTLSPinning: Bool = false
    var requireReasonForElevated: Bool = false

    var profile: BaoProfile? {
        if let id = activeProfileID, let match = profiles.first(where: { $0.id == id }) {
            return match
        }
        return profiles.first
    }

    /// Default JWT `device` claim derived from the actual hardware class (`ipad`, `iphone`, etc.).
    static var defaultDeviceName: String {
        #if canImport(UIKit)
        switch UIDevice.current.userInterfaceIdiom {
        case .pad: return "ipad"
        case .mac: return "mac"
        case .vision: return "vision"
        default: return "iphone"
        }
        #else
        return "mac"
        #endif
    }

    var deviceName: String {
        didSet {
            guard !persistenceDisabled else { return }
            let cleaned = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
            UserDefaults.standard.set(cleaned.isEmpty ? Self.defaultDeviceName : cleaned, forKey: Self.deviceNameDefaultsKey)
        }
    }
    /// In-memory device claim shown and signed during Demo Mode so it always matches the current
    /// device class without modifying the user's saved `deviceName` preference.
    var demoDeviceName: String = AppModel.defaultDeviceName
    var devicePublicKeyPEM: String = ""
    var deviceFingerprint: String = ""
    var sshPublicKey: String = ""
    /// False when the SSH key is a legacy software key from an older install.
    var sshKeyIsHardwareBacked: Bool = false

    var targetStatus: TargetStatusSummary?
    var isLoadingStatus: Bool = false

    /// Ephemeral in-memory token for Direct Token mode (never persisted to disk).
    var directGrant: DirectTokenGrant?
    var directToken: String? { directGrant?.token }
    var directTokenSummary: String { directGrant?.summary ?? "" }
    var directArtifacts: [MintedExtensionArtifact] { directGrant?.artifacts ?? [] }

    var pending: PendingApproval?
    var pendingImportedProfile: BaoProfile?
    /// What accepting `pendingImportedProfile` would do (replace which profile, what changes).
    var pendingImport: ProfileImportPlan?
    var pendingRequest: GrantRequest? { pending?.request }
    /// The profile the pending request was parsed against (not necessarily the active one).
    var pendingProfile: BaoProfile? {
        guard let pending, profiles.contains(where: { $0.id == pending.profileID }) else { return nil }
        return pending.profile
    }
    var runningTasks: RunningTasksResult?
    var isCheckingTasks: Bool = false
    var isApproving: Bool = false

    var bannerMessage: String?
    var errorMessage: String?
    var selectedTab: Int = 0
    var isDemoMode: Bool = false
    /// Recent Activity while in Demo Mode: sample entries plus this session's demo grants.
    /// In memory only; demo grants never reach the on-disk activity log.
    var demoActivity: [GrantActivityEntry] = []
    /// Reason the Demo Mode composer starts with, set only by the `-BaoBuddyDemoSampleReason`
    /// launch argument (App Store screenshots): UI tests can't type every language reliably.
    var demoComposerReason: String?

    /// The sample reason Demo Mode screenshots show, in the user's language.
    /// Reasons accept only ASCII letters, digits and a few symbols (`GrantRequest.sanitizeWhy`), so
    /// translations stay within them, and the result is sanitized like any typed reason.
    static var demoSampleReason: String {
        GrantRequest.sanitizeWhy(String(localized: "Run the staging migration check", comment: "Demo mode: sample reason for a grant request, as a user would type it. Grant reasons accept only unaccented letters A-Z, digits, spaces and . , : ; ( ) / _ + - # (other characters are removed), so write it in your language with only those characters if that reads naturally, or else use: CHG-1042 db-migration-check"))
    }
    /// True when Demo Mode is signing with an in-memory software P-256 key
    /// (Simulator or `-BaoBuddyDemo` test mode) rather than a hardware Secure Enclave key.
    var isUsingDemoSoftwareKey: Bool { isDemoMode && demoFallbackSigner != nil }
    var demoSoftwareKeyFingerprint: String = ""

    let biometry = BiometryDescriptor.current
    /// When true (e.g. under `#if DEBUG` `-BaoBuddyEmptyOnboarding` UI tests), all writes to
    /// disk stores, `UserDefaults` and the keychain (device and SSH keys) are suppressed so saved
    /// user profiles and keys can never be overwritten.
    let persistenceDisabled: Bool
    static let persistenceDisabledMessage = String(localized: "Key changes are disabled in UI test isolation mode.", comment: "Error shown only in automated UI tests.")

    private let profileStore: MultiProfileStore
    private let sshKeyStore = SSHKeyStore()
    private let accessorStore: GrantAccessorStore
    private let activityStore: GrantActivityStore
    private var demoOpenBaoTransport: DemoOpenBaoTransport?
    private var demoGranterTransport: DemoGranterTransport?
    private var demoFallbackSigner: EphemeralP256Signer?

    private var effectiveDeviceName: String {
        let name = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? Self.defaultDeviceName : name
    }

    private func keyStore(for target: BaoProfile?) -> SecureEnclaveKeyStore? {
        guard let target else { return nil }
        return SecureEnclaveKeyStore.scoped(for: target, deviceName: effectiveDeviceName)
    }

    private var keyStore: SecureEnclaveKeyStore? {
        keyStore(for: profile)
    }

    init(
        launchArguments: [String] = ProcessInfo.processInfo.arguments,
        profileStore: MultiProfileStore = MultiProfileStore(),
        accessorStore: GrantAccessorStore = GrantAccessorStore(),
        activityStore: GrantActivityStore = GrantActivityStore()
    ) {
        self.profileStore = profileStore
        self.accessorStore = accessorStore
        self.activityStore = activityStore
        #if DEBUG
        let emptyOnboarding = launchArguments.contains("-BaoBuddyEmptyOnboarding")
        #else
        let emptyOnboarding = false
        #endif
        self.persistenceDisabled = emptyOnboarding
        let saved = emptyOnboarding
            ? Self.defaultDeviceName
            : (UserDefaults.standard.string(forKey: Self.deviceNameDefaultsKey) ?? Self.defaultDeviceName)
        self.deviceName = saved
        if emptyOnboarding {
            profiles = []
            activeProfileID = nil
            selectedTab = 0
        } else {
            loadSavedState()
            if launchArguments.contains("-BaoBuddyDemo") {
                enterDemoMode(useSoftwareSigner: true)
                if launchArguments.contains("-BaoBuddyDemoSampleReason") {
                    demoComposerReason = Self.demoSampleReason
                }
                applyDemoScreenArgument(launchArguments)
            }
        }
    }

    private func applyDemoScreenArgument(_ arguments: [String]) {
        guard let idx = arguments.firstIndex(of: "-BaoBuddyDemoScreen"),
              idx + 1 < arguments.count else {
            return
        }
        switch arguments[idx + 1] {
        case "02_Approve":
            if let demoProfile = profile {
                // A standard grant: the default read-only policy plus the demo database credentials.
                let sample = GrantRequest(
                    target: .t3,
                    hours: 2,
                    customPolicies: ["db-readonly"],
                    why: Self.demoSampleReason,
                    extensions: ["db-demo"]
                )
                presentApproval(for: sample, profile: demoProfile)
            }
        case "03_Settings":
            selectedTab = 1
        default:
            selectedTab = 0
        }
    }

    /// Starts built-in Demo Mode with an in-memory simulated OpenBao server and remote host.
    /// On physical devices this uses the real Secure Enclave key and biometric prompt; on the
    /// simulator (or under `-BaoBuddyDemo` UI tests) it falls back to an ephemeral P-256 key.
    func enterDemoMode(useSoftwareSigner: Bool = false) {
        errorMessage = nil
        // With profiles locked by MDM, only managed servers may appear, including fake ones.
        guard !areProfilesLocked else {
            errorMessage = String(localized: "Demo mode is unavailable because your organization manages this app's servers.", comment: "Error. The organization manages server settings through MDM (device management).")
            return
        }
        demoDeviceName = Self.defaultDeviceName
        let pubPEM: String
        // Test isolation never creates a real Secure Enclave key; demo signs with an in-memory key.
        let demoProfile = BaoDemo.makeProfile(remoteTarget: true)
        if !useSoftwareSigner, !persistenceDisabled,
           let demoStore = keyStore(for: demoProfile),
           let realPEM = try? demoStore.ensureKey() {
            pubPEM = realPEM
            demoFallbackSigner = nil
            demoSoftwareKeyFingerprint = ""
            refreshKeyDisplay()
        } else {
            let fallback = EphemeralP256Signer(deviceName: demoDeviceName)
            guard let pem = try? fallback.publicKeyPEM() else {
                errorMessage = String(localized: "Could not initialize demo signing key.", comment: "Error starting demo mode.")
                return
            }
            demoFallbackSigner = fallback
            demoSoftwareKeyFingerprint = (try? BaoServerAdmin.validateP256PEM(pem).fingerprint) ?? ""
            pubPEM = pem
        }

        do {
            let transport = try DemoOpenBaoTransport(trustedPublicKeyPEMs: [pubPEM])
            let granter = DemoGranterTransport(openbao: transport)
            demoOpenBaoTransport = transport
            demoGranterTransport = granter
            isDemoMode = true

            profiles.removeAll { $0.isDemoProfile }
            profiles.insert(demoProfile, at: 0)
            activeProfileID = demoProfile.id
            demoActivity = BaoDemo.sampleActivity(profile: demoProfile)
            targetStatus = nil
            bannerMessage = nil
            selectedTab = 0
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Exits Demo Mode and deletes every in-memory demo profile, grant, and transport.
    func exitDemoMode() {
        isDemoMode = false
        demoDeviceName = Self.defaultDeviceName
        demoOpenBaoTransport = nil
        demoGranterTransport = nil
        demoFallbackSigner = nil
        demoSoftwareKeyFingerprint = ""
        demoActivity = []
        profiles.removeAll { $0.isDemoProfile }
        if activeProfileID == BaoDemo.profileID {
            activeProfileID = profiles.first?.id
        }
        if directGrant?.profile.isDemoProfile == true {
            directGrant = nil
        }
        if pending?.profile.isDemoProfile == true {
            pending = nil
            runningTasks = nil
        }
        targetStatus = nil
        if !persistenceDisabled {
            try? accessorStore.remove(profileID: BaoDemo.profileID)
        }
        Task { await endLiveActivities() }
        bannerMessage = String(localized: "Exited Demo mode.", comment: "Banner.")
    }

    private func signer(for target: BaoProfile) -> any BiometricSigner {
        if isDemoMode, target.isDemoProfile, let fallback = demoFallbackSigner {
            return fallback
        }
        return SecureEnclaveKeyStore.scoped(for: target, deviceName: effectiveDeviceName)
    }

    private func makeOpenBaoClient(for target: BaoProfile) throws -> OpenBaoClient {
        if isDemoMode, target.isDemoProfile, let transport = demoOpenBaoTransport {
            return try OpenBaoClient.forDemo(profile: target, transport: transport)
        }
        return try OpenBaoClient(profile: target)
    }

    /// Converts raw ISO-8601 timestamps in receiver responses (`Granted until 2026-11-23T00:45:24Z ...`)
    /// into a readable local time (`Granted until 6:45 PM ...`) for UI banners.
    nonisolated static func humanizeGrantBanner(_ raw: String) -> String {
        let prefix = "Granted until "
        guard raw.hasPrefix(prefix) else { return raw }
        let rest = raw.dropFirst(prefix.count)
        let parts = rest.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        guard let isoToken = parts.first else { return raw }
        let formatter = ISO8601DateFormatter()
        guard let date = formatter.date(from: String(isoToken)) else { return raw }
        let localTime = date.formatted(date: .omitted, time: .shortened)
        if parts.count > 1 {
            return String(localized: "Granted until \(localTime) \(parts[1])", comment: "Banner after a grant is delivered. %1$@ is a time of day; %2$@ is a note from the remote host in parentheses, as the host wrote it.")
        }
        return String(localized: "Granted until \(localTime)", comment: "Banner after a grant is delivered. %@ is a time of day.")
    }

    func loadSavedState() {
        let managed = ManagedAppConfig.load()
        isClipboardDisabled = managed.disableClipboard
        areProfilesLocked = managed.lockProfiles
        enforceTLSPinning = managed.enforceTLSPinning
        requireReasonForElevated = managed.requireReasonForElevated
        managedProfiles = managed.profiles
        managedProfileIDs = Set(managed.profiles.map(\.id))

        let local = profileStore.load()
        profiles = managed.effectiveProfiles(local: local.profiles)

        if let activeID = local.activeProfileID,
           profiles.contains(where: { $0.id == activeID }) {
            activeProfileID = activeID
        } else {
            activeProfileID = profiles.first?.id
        }
        refreshKeyDisplay()
    }

    func isManaged(profileID: String) -> Bool {
        managedProfileIDs.contains(profileID)
    }

    /// Switching profiles never drops a live direct token: it stays visible (labeled with its
    /// server) until it's revoked or the app quits.
    func selectProfile(id: String) {
        guard profiles.contains(where: { $0.id == id }) else { return }
        activeProfileID = id
        targetStatus = nil
        errorMessage = nil
        refreshKeyDisplay()
        persistLocalProfiles()
    }

    func refreshKeyDisplay() {
        if let store = keyStore,
           let pem = try? store.publicKeyPEM(),
           let fp = try? store.publicKeyFingerprint() {
            devicePublicKeyPEM = pem
            deviceFingerprint = fp
        } else {
            devicePublicKeyPEM = ""
            deviceFingerprint = ""
        }
        if let identity = try? sshKeyStore.loadIdentity() {
            sshPublicKey = identity.openSSHPublicKey(comment: sshKeyComment)
            sshKeyIsHardwareBacked = identity.isHardwareBacked
        } else {
            sshPublicKey = ""
            sshKeyIsHardwareBacked = false
        }
    }

    private var sshKeyComment: String {
        let cleanName = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        return "baobuddy-\(cleanName.isEmpty ? Self.defaultDeviceName : cleanName)"
    }

    func ensureDeviceKey(overwrite: Bool = false) {
        errorMessage = nil
        guard !persistenceDisabled else {
            errorMessage = Self.persistenceDisabledMessage
            return
        }
        guard let store = keyStore else {
            errorMessage = String(localized: "Add or select an OpenBao/Vault server first so BaoBuddy can create a dedicated key for it.", comment: "Error when creating a key with no server set up.")
            BaoHaptics.notify(.error)
            return
        }
        do {
            devicePublicKeyPEM = try store.ensureKey(overwrite: overwrite)
            deviceFingerprint = try store.publicKeyFingerprint()
            if isDemoMode {
                try? demoOpenBaoTransport?.updateTrustedPublicKeyPEM(devicePublicKeyPEM)
                demoFallbackSigner = nil
                demoSoftwareKeyFingerprint = ""
            }
            bannerMessage = String(localized: "Secure Enclave key ready (sha256:\(deviceFingerprint)).", comment: "Banner. %@ is the key's fingerprint; keep sha256: as is.")
            BaoHaptics.notify(.success)
        } catch {
            errorMessage = error.localizedDescription
            BaoHaptics.notify(.error)
        }
    }

    /// Creates the Secure Enclave SSH key. A legacy software key, if any, is replaced.
    func ensureSSHKey(overwrite: Bool = false) {
        errorMessage = nil
        guard !persistenceDisabled else {
            errorMessage = Self.persistenceDisabledMessage
            return
        }
        do {
            let identity = try sshKeyStore.ensureSecureEnclaveIdentity(overwrite: overwrite)
            sshPublicKey = identity.openSSHPublicKey(comment: sshKeyComment)
            sshKeyIsHardwareBacked = identity.isHardwareBacked
            bannerMessage = String(localized: "SSH key ready. Add it to your remote target's authorized_keys.", comment: "Banner. Do not translate authorized_keys (a file name).")
            BaoHaptics.notify(.success)
        } catch {
            errorMessage = error.localizedDescription
            BaoHaptics.notify(.error)
        }
    }

    private var organizationPolicy: ManagedAppConfig {
        ManagedAppConfig(
            profiles: managedProfiles,
            disableClipboard: isClipboardDisabled,
            lockProfiles: areProfilesLocked,
            enforceTLSPinning: enforceTLSPinning,
            requireReasonForElevated: requireReasonForElevated,
            isManaged: !managedProfiles.isEmpty || isClipboardDisabled || areProfilesLocked || enforceTLSPinning || requireReasonForElevated
        )
    }

    private func importPlan(for incoming: BaoProfile) throws -> ProfileImportPlan {
        try ProfileImportPlan.make(
            importing: incoming,
            existing: profiles,
            managedIDs: managedProfileIDs,
            organizationPolicy: organizationPolicy
        )
    }

    /// Saves pasted profile JSON. The user typed or pasted it here, so no extra confirmation;
    /// the organization's lock and pinning rules still apply, and the JSON's `id` is never trusted.
    func importProfileJSON(_ text: String) {
        errorMessage = nil
        do {
            let decoded = try ProfileTransferCodec.decode(
                text: text,
                requireHostKey: true,
                requireTLSPinning: enforceTLSPinning
            )
            try upsertProfile(try importPlan(for: decoded).profile)
        } catch {
            errorMessage = error.localizedDescription
            BaoHaptics.notify(.error)
        }
    }

    /// Queues a profile from a QR code or `baobuddy://import` link for the confirmation sheet.
    func stageImport(_ incoming: BaoProfile) {
        errorMessage = nil
        do {
            let plan = try importPlan(for: incoming)
            pendingImport = plan
            pendingImportedProfile = plan.profile
        } catch {
            pendingImport = nil
            pendingImportedProfile = nil
            errorMessage = error.localizedDescription
            BaoHaptics.notify(.error)
        }
    }

    func confirmPendingImportedProfile() {
        guard let plan = pendingImport else { return }
        pendingImport = nil
        pendingImportedProfile = nil
        do {
            // Re-plan against the current list in case it changed while the sheet was open.
            try upsertProfile(try importPlan(for: plan.profile).profile)
        } catch {
            errorMessage = error.localizedDescription
            BaoHaptics.notify(.error)
        }
    }

    func cancelPendingImport() {
        pendingImport = nil
        pendingImportedProfile = nil
    }

    func upsertProfile(_ newProfile: BaoProfile) throws {
        errorMessage = nil
        guard !newProfile.isDemoProfile else {
            throw ProfileError.invalidField("id", String(localized: "demo profile cannot be saved", comment: "Error detail after: Invalid profile field id:"))
        }
        guard !areProfilesLocked else {
            throw ProfileTransferError.lockedByOrganization
        }
        guard !managedProfileIDs.contains(newProfile.id) else {
            throw ProfileError.invalidField("id", String(localized: "managed profiles can't be changed on this device", comment: "Error detail after: Invalid profile field id:. Managed profiles are set by the organization (MDM)."))
        }
        var savedProfile = newProfile
        if requireReasonForElevated {
            savedProfile.openbao.auditPolicy.requireReasonForElevated = true
        }
        try savedProfile.validate(requireHostKey: true, requireTLSPinning: enforceTLSPinning)
        if let index = profiles.firstIndex(where: { $0.id == savedProfile.id }) {
            profiles[index] = savedProfile
        } else {
            profiles.append(savedProfile)
        }
        activeProfileID = savedProfile.id
        try saveLocalProfiles()
        refreshKeyDisplay()
        targetStatus = nil
        bannerMessage = String(localized: "Saved \(newProfile.displayName).", comment: "Banner after saving a server. %@ is the server's name.")
        BaoHaptics.notify(.success)
    }

    func deleteProfile(id: String) {
        guard !managedProfileIDs.contains(id) else { return }
        profiles.removeAll { $0.id == id }
        if activeProfileID == id {
            activeProfileID = profiles.first?.id
            targetStatus = nil
        }
        if pending?.profileID == id {
            dismissApproval()
        }
        if !persistenceDisabled {
            try? accessorStore.remove(profileID: id)
        }
        persistLocalProfiles()
        bannerMessage = String(localized: "Removed server profile.", comment: "Banner.")
    }

    /// Opens the approval sheet for a `baobuddy://grant` link.
    /// - The link's `profile=` selects which server the request is parsed against, for this
    ///   approval only; it never changes or saves the active profile.
    /// - A `profile=` that matches nothing is an error, never a silent fallback to another server.
    /// - Links are ignored while an approval is in progress, so the request being signed can't
    ///   change under the user.
    func handleIncomingURL(_ url: URL) {
        guard !isApproving else {
            errorMessage = String(localized: "Finish the approval in progress before opening another grant link.", comment: "Error.")
            return
        }
        errorMessage = nil

        if ProfileTransferCodec.isImportURL(url) {
            guard !areProfilesLocked else {
                errorMessage = String(localized: "Server profiles are locked by your organization's MDM policy.", comment: "Error. MDM = mobile device management.")
                return
            }
            do {
                stageImport(try ProfileTransferCodec.decode(
                    url: url,
                    requireHostKey: true,
                    requireTLSPinning: enforceTLSPinning
                ))
            } catch {
                errorMessage = error.localizedDescription
            }
            return
        }

        do {
            let target = try GrantRequest.resolveProfile(from: url, in: profiles, active: profile)
            let focused = try GrantRequest.linkProfile(url: url, base: target)
            let request = try GrantRequest.parse(url: url, profile: focused)
            presentApproval(for: request, profile: focused)
        } catch {
            errorMessage = error.localizedDescription
            if profiles.isEmpty {
                selectedTab = 1
            }
        }
    }

    func presentApproval(for request: GrantRequest, profile requested: BaoProfile? = nil) {
        guard !isApproving, let target = requested ?? profile else { return }
        errorMessage = nil
        let approval = PendingApproval(profileID: target.id, profile: target, request: request)
        pending = approval
        runningTasks = nil
        guard let target = pendingProfile, target.hasRemoteTarget, request.target == .t3 else { return }
        let approvalID = approval.id
        Task {
            await loadRunningTasks(for: target, approvalID: approvalID)
        }
    }

    func dismissApproval() {
        guard !isApproving else { return }
        pending = nil
        runningTasks = nil
    }

    func loadRunningTasks(for target: BaoProfile, approvalID: UUID? = nil) async {
        guard let client = makeGranterClient(for: target) else {
            if approvalID == nil || pending?.id == approvalID {
                runningTasks = RunningTasksResult(tasks: [], brokerUnavailable: true)
            }
            return
        }
        isCheckingTasks = true
        defer { isCheckingTasks = false }
        let result = await client.runningTasks()
        if approvalID == nil || pending?.id == approvalID {
            runningTasks = result
        }
    }

    func approvePendingGrant() async {
        guard !isApproving, let approval = pending, let profile = pendingProfile else { return }
        let request = approval.request
        errorMessage = nil
        isApproving = true
        defer { isApproving = false }

        do {
            let openbao = try makeOpenBaoClient(for: profile)
            let activeSigner = signer(for: profile)
            if profile.hasRemoteTarget && request.target == .t3 {
                guard let granter = makeGranterClient(for: profile) else {
                    errorMessage = String(localized: "Create an SSH key in Settings and authorize it on \(profile.targetDisplayName) first.", comment: "Error. %@ is the remote host's name.")
                    BaoHaptics.notify(.error)
                    return
                }
                let store = accessorStore
                let suppressPersistence = persistenceDisabled || profile.isDemoProfile
                let orchestrator = GrantOrchestrator(
                    profile: profile,
                    signer: activeSigner,
                    openbao: openbao,
                    t3Granter: granter,
                    via: profile.isDemoProfile ? "demo" : "app",
                    organizationPolicy: organizationPolicy,
                    onRemoteGrantMinted: { accessor, expiresAt in
                        guard !suppressPersistence else { return }
                        try store.record(for: profile, accessor: accessor, expiresAt: expiresAt)
                    },
                    onRemoteGrantRolledBack: { accessor in
                        guard !suppressPersistence else { return }
                        try? store.remove(for: profile, accessor: accessor)
                    }
                )
                let outcome = try await orchestrator.execute(request)
                recordActivity(GrantActivityEntry(
                    action: .granted,
                    serverName: profile.displayName,
                    namespace: profile.openbao.namespace,
                    targetName: profile.targetDisplayName,
                    policies: request.openBaoPolicies(profile: profile),
                    hours: request.hours,
                    why: request.why,
                    elevated: request.isElevated(profile: profile),
                    via: profile.isDemoProfile ? "demo" : "app"
                ), for: profile)
                bannerMessage = Self.humanizeGrantBanner(outcome.message)
                pending = nil
                runningTasks = nil
                BaoHaptics.notify(.success)
                await startLiveActivity(profile: profile, request: request)
                await refreshVMStatus()
            } else {
                let orchestrator = GrantOrchestrator(
                    profile: profile,
                    signer: activeSigner,
                    openbao: openbao,
                    via: profile.isDemoProfile ? "demo" : "app",
                    organizationPolicy: organizationPolicy
                )
                let outcome = try await orchestrator.mintDirectToken(request)
                if let token = outcome.mintedToken {
                    directGrant = DirectTokenGrant(
                        profile: profile,
                        token: token,
                        accessor: outcome.accessor ?? "",
                        summary: "\(profile.displayName): \(request.summary(profile: profile))",
                        artifacts: outcome.artifacts
                    )
                }
                recordActivity(GrantActivityEntry(
                    action: .directToken,
                    serverName: profile.displayName,
                    namespace: profile.openbao.namespace,
                    targetName: String(localized: "Direct Token", comment: "Where a grant goes when it has no remote host: a token shown in this app."),
                    policies: request.openBaoPolicies(profile: profile),
                    hours: request.hours,
                    why: request.why,
                    elevated: request.isElevated(profile: profile),
                    via: profile.isDemoProfile ? "demo" : "app"
                ), for: profile)
                bannerMessage = Self.humanizeGrantBanner(outcome.message)
                pending = nil
                runningTasks = nil
                BaoHaptics.notify(.success)
                await startLiveActivity(profile: profile, request: request)
            }
        } catch {
            errorMessage = error.localizedDescription
            BaoHaptics.notify(.error)
        }
    }

    /// Demo grants go to the in-memory demo log; real ones to the on-disk log (unless isolated).
    private func recordActivity(_ entry: GrantActivityEntry, for profile: BaoProfile) {
        if profile.isDemoProfile {
            demoActivity.insert(entry, at: 0)
        } else if !persistenceDisabled {
            activityStore.record(entry)
        }
    }

    /// Revokes the direct token on the server that minted it. The token stays in memory if the
    /// server doesn't confirm, so the user can retry.
    func revokeDirectToken() async {
        guard let grant = directGrant else { return }
        errorMessage = nil
        do {
            let openbao = try makeOpenBaoClient(for: grant.profile)
            try await openbao.revokeSelf(token: grant.token)
            directGrant = nil
            bannerMessage = String(localized: "Revoked token.", comment: "Banner.")
            BaoHaptics.notify(.success)
            await endLiveActivities()
        } catch {
            errorMessage = error.localizedDescription
            BaoHaptics.notify(.error)
        }
    }

    func refreshVMStatus() async {
        guard let profile, profile.hasRemoteTarget else {
            targetStatus = nil
            return
        }
        guard let granter = makeGranterClient(for: profile) else {
            targetStatus = .unavailable(String(localized: "Create an SSH key in Settings and authorize it on \(profile.targetDisplayName).", comment: "Remote host status. %@ is the remote host's name."))
            return
        }
        isLoadingStatus = true
        defer { isLoadingStatus = false }
        do {
            let raw = try await granter.status()
            var parsed = TargetStatusSummary.parse(raw)
            // The simulated host answers in the real (English) wire format; Demo Mode knows the
            // grant's expiry, so it shows the time left in the user's language.
            if profile.isDemoProfile, let expiry = demoGranterTransport?.activeGrantExpiry {
                parsed = parsed.localizingTimeLeft(until: expiry)
            }
            targetStatus = parsed
            if !parsed.hasActiveGrant {
                await endLiveActivities()
            }
        } catch {
            targetStatus = .unavailable(error.localizedDescription)
        }
    }

    /// Revokes the remote grant through OpenBao by accessor (with a biometric sign-in), so a
    /// compromised or unreachable host can't keep it by claiming it was revoked. The host is
    /// then asked to delete its copies; that part depends on the host.
    func revokeVMGrant() async {
        guard let profile, profile.hasRemoteTarget else { return }
        errorMessage = nil
        var revokedOnServer = false
        let recorded: [GrantAccessorStore.Entry]
        if persistenceDisabled || profile.isDemoProfile {
            recorded = []
        } else {
            do {
                recorded = try accessorStore.entries(for: profile)
            } catch {
                errorMessage = error.localizedDescription
                BaoHaptics.notify(.error)
                return
            }
        }
        if !recorded.isEmpty {
            do {
                let orchestrator = GrantOrchestrator(
                    profile: profile,
                    signer: signer(for: profile),
                    openbao: try makeOpenBaoClient(for: profile),
                    via: profile.isDemoProfile ? "demo" : "app",
                    organizationPolicy: organizationPolicy
                )
                for entry in recorded {
                    try await orchestrator.revokeRemoteGrant(accessor: entry.accessor)
                    try accessorStore.remove(for: profile, accessor: entry.accessor)
                }
                revokedOnServer = true
            } catch {
                errorMessage = error.localizedDescription
                BaoHaptics.notify(.error)
                return
            }
        }
        guard let granter = makeGranterClient(for: profile) else {
            if revokedOnServer {
                bannerMessage = String(localized: "Revoked the grant through OpenBao. Couldn't reach \(profile.targetDisplayName) to delete its copies.", comment: "Banner. %@ is the remote host's name.")
                await endLiveActivities()
            } else {
                errorMessage = String(localized: "Create an SSH key in Settings and authorize it on \(profile.targetDisplayName) first.", comment: "Error. %@ is the remote host's name.")
            }
            return
        }
        do {
            let message = try await granter.revoke()
            recordActivity(GrantActivityEntry(
                action: .revoked,
                serverName: profile.displayName,
                namespace: profile.openbao.namespace,
                targetName: profile.targetDisplayName,
                via: profile.isDemoProfile ? "demo" : "app"
            ), for: profile)
            bannerMessage = revokedOnServer
                ? String(localized: "Revoked the grant through OpenBao. \(message)", comment: "Banner. %@ is the remote host's own message (not translated).")
                : String(localized: "\(message) (Only \(profile.targetDisplayName) confirmed this; no accessor was recorded for this grant.)", comment: "Banner. %1$@ is the remote host's own message; %2$@ is the remote host's name. An accessor is the OpenBao ID of a token.")
            BaoHaptics.notify(.success)
            await endLiveActivities()
            await refreshVMStatus()
        } catch {
            if revokedOnServer {
                bannerMessage = String(localized: "Revoked the grant through OpenBao, but \(profile.targetDisplayName) didn't confirm deleting its copies.", comment: "Banner. %@ is the remote host's name.")
                await endLiveActivities()
            } else {
                errorMessage = error.localizedDescription
                BaoHaptics.notify(.error)
            }
        }
    }

    func checkServerHealth() async -> Result<ServerHealth, Error> {
        guard let profile else {
            return .failure(OpenBaoError.invalidBaseURL(String(localized: "No server configured", comment: "Error detail after: Invalid OpenBao URL:")))
        }
        do {
            let client = try makeOpenBaoClient(for: profile)
            let health = try await client.checkHealth()
            return .success(health)
        } catch {
            return .failure(error)
        }
    }

    /// Manual server setup matching what `bao-buddy server-setup` writes. Use one mount per person:
    /// every key on a mount can sign in as that mount's subject.
    func openBaoSetupSnippet() -> String {
        let subject = profile?.openbao.jwtAuth.subject.isEmpty == false ? (profile?.openbao.jwtAuth.subject ?? "user") : "user"
        let mount = profile?.openbao.jwtAuth.mount ?? BaoServerAdmin.defaultMount(subject: subject)
        let role = profile?.openbao.jwtAuth.role ?? "granter"
        let issuer = profile?.openbao.jwtAuth.issuer ?? "bao-granter"
        let audience: String
        if let profile, !profile.openbao.jwtAuth.audience.isEmpty {
            audience = profile.openbao.jwtAuth.audience
        } else {
            audience = BaoOpenBaoConfig.defaultAudience(
                address: profile?.openbao.address ?? "https://openbao.example.com:8200",
                namespace: profile?.openbao.namespace ?? "",
                mount: mount,
                caPEM: profile?.openbao.caPEM ?? "",
                mtlsClientIdentity: profile?.openbao.mtlsClientIdentity ?? ""
            )
        }
        let granterPolicy = BaoServerAdmin.defaultGranterPolicy(mount: mount, subject: subject)
        return """
        bao auth enable -path=\(mount) jwt
        bao write auth/\(mount)/config \\
          bound_issuer="\(issuer)" \\
          jwt_supported_algs="ES256" \\
          jwt_validation_pubkeys=@device.pem
        bao write auth/\(mount)/role/\(role) \\
          role_type="jwt" user_claim="sub" \\
          bound_subject="\(subject)" \\
          bound_audiences="\(audience)" \\
          token_policies="\(granterPolicy)" token_no_default_policy=true \\
          token_ttl=2m token_max_ttl=2m \\
          expiration_leeway=5 not_before_leeway=5 clock_skew_leeway=5 \\
          claim_mappings="device=device" claim_mappings="scope=scope"
        """
    }

    private func startLiveActivity(profile: BaoProfile, request: GrantRequest) async {
        #if os(iOS) && canImport(ActivityKit)
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        await endLiveActivities()
        let expiresAt = Date().addingTimeInterval(TimeInterval(request.hours * 3600))
        let attributes = GrantActivityAttributes(
            serverName: profile.displayName,
            targetName: profile.hasRemoteTarget && request.target == .t3
                ? profile.targetDisplayName
                : String(localized: "Direct Token", comment: "Where a grant goes when it has no remote host: a token shown in this app."),
            reason: request.why
        )
        let state = GrantActivityAttributes.ContentState(
            scopeSummary: request.scopeDescription(profile: profile),
            expiresAt: expiresAt,
            isElevated: request.isElevated(profile: profile)
        )
        let content = ActivityContent(state: state, staleDate: expiresAt)
        _ = try? Activity<GrantActivityAttributes>.request(attributes: attributes, content: content, pushType: nil)
        #endif
    }

    private func endLiveActivities() async {
        #if os(iOS) && canImport(ActivityKit)
        for activity in Activity<GrantActivityAttributes>.activities {
            await activity.end(nil, dismissalPolicy: .immediate)
        }
        #endif
    }

    private func saveLocalProfiles() throws {
        guard !persistenceDisabled else { return }
        let localOnly = profiles.filter { !managedProfileIDs.contains($0.id) && !$0.isDemoProfile }
        let savedActive = localOnly.contains(where: { $0.id == activeProfileID }) ? activeProfileID : localOnly.first?.id
        try profileStore.save(ProfileCollection(activeProfileID: savedActive, profiles: localOnly))
    }

    private func persistLocalProfiles() {
        try? saveLocalProfiles()
    }

    private func makeGranterClient(for target: BaoProfile) -> (any T3GranterTransport)? {
        if isDemoMode, target.isDemoProfile, let demoGranterTransport {
            return demoGranterTransport
        }
        guard target.hasRemoteTarget, let identity = try? sshKeyStore.loadIdentity() else {
            return nil
        }
        return NIOSSHGranterClient(config: target.t3Granter, identity: identity)
    }
}
