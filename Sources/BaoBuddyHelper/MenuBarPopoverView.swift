#if os(macOS)
import AppKit
import BaoBuddyCore
import Foundation
import LocalAuthentication
import Observation
import SwiftUI

/// Adaptive BaoBuddy palette matching `Branding/README.md` for the macOS popover.
enum MacBaoTheme {
    static let brand = Color(nsColor: NSColor(name: nil) { appearance in
        let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        return isDark
            ? NSColor(srgbRed: 0.078, green: 0.722, blue: 0.651, alpha: 1) // #14B8A6
            : NSColor(srgbRed: 0.059, green: 0.463, blue: 0.431, alpha: 1) // #0F766E
    })
    static let elevated = Color.orange
    static let active = Color.green
    static let cream = Color(red: 1.0, green: 0.965, blue: 0.898)
}

/// Shared remote status row type from `BaoBuddyCore`.
typealias RemoteStatusRow = RemoteStatusSummary.Entry

/// Pending confirmation when active workloads are detected on a remote target.
/// Bound to the exact focused `profile` (and remote target) that was checked so switching
/// profiles or targets can never deliver an approval to a different host.
struct PendingRemoteTaskWarning: Equatable {
    let profile: BaoProfile
    let request: GrantRequest
    let tasks: [String]
    let brokerUnavailable: Bool
}

/// Incoming `baobuddy://` grant request bound to the exact profile and remote target it was validated against.
struct PendingMacApproval: Equatable {
    let id: UUID = UUID()
    let profile: BaoProfile
    let request: GrantRequest
    var runningTasks: RunningTasksResult?
    var isCheckingTasks: Bool = false
}

@MainActor
@Observable
final class MenuBarState {
    private struct RefreshScope: Equatable {
        let profileID: String
        let issuerBindingKey: String
        let remoteTargetScopeKey: String?
    }

    private let deps: MenuBarDependencies
    private var refreshGeneration: UInt64 = 0
    private var activeRefreshTask: Task<Void, Never>?
    private var activeRefreshScope: RefreshScope?
    /// Tracks local tokens already confirmed revoked at OpenBao whose Keychain deletion failed,
    /// keyed by `profile.openbao.issuerBindingKey`, so retry skips `revokeSelf` for that exact token.
    var pendingLocalCleanupByIssuer: [String: String] = [:]

    var profiles: [BaoProfile] = []
    var activeProfileID: String?
    var selectedRemoteTargetID: String?
    var profile: BaoProfile? {
        let base: BaoProfile?
        if let id = activeProfileID, let match = profiles.first(where: { $0.id == id }) {
            base = match
        } else {
            base = profiles.first
        }
        guard let base else { return nil }
        if let targetID = selectedRemoteTargetID,
           let matchedTarget = base.configuredRemoteTargets.first(where: { $0.id == targetID }) {
            return base.focusing(remoteTarget: matchedTarget)
        }
        return base
    }

    func selectRemoteTarget(id: String) {
        guard !isMutating else { return }
        selectedRemoteTargetID = id
        pendingWarning = nil
        remoteRows = []
        remoteUnavailable = nil
        recordedRemoteAccessors = []
        remoteAccessorError = nil
        hasLoadedRemote = false
        scheduleRefresh(force: true)
    }

    var localGrantStatus: LocalGrantStatus = .inactive
    var macGrantInfo: TokenLookupInfo? {
        localGrantStatus.activeInfo
    }
    var remoteRows: [RemoteStatusRow] = []
    var remoteUnavailable: String?
    var recordedRemoteAccessors: [GrantAccessorStore.Entry] = []
    var remoteAccessorError: String?
    var hasLoadedRemote: Bool = false

    // Composer state
    var target: GrantTarget = .mac
    var hours: Int = 2
    var write: Bool = false
    var push: Bool = false
    var selectedKeys: Set<String> = []
    var selectedHosts: Set<String> = []
    var selectedPolicies: Set<String> = []
    var selectedExtensions: Set<String> = []
    var why: String = ""
    var showComposer: Bool = false

    // Transient UI state
    var isRefreshing: Bool = false
    var isMutating: Bool = false
    var bannerMessage: String?
    var errorMessage: String?
    var pendingWarning: PendingRemoteTaskWarning?
    var pendingDeepLink: PendingMacApproval?
    var lastRefresh: Date?

    var isManagedByMDM: Bool = false
    var managedProfiles: [BaoProfile] = []
    var managedProfileIDs: Set<String> = []
    var areProfilesLocked: Bool = false
    var isClipboardDisabled: Bool = false
    var enforceTLSPinning: Bool = false
    var requireReasonForElevated: Bool = false

    let biometryLabel: String
    let biometrySymbol: String

    var onStatusChange: (() -> Void)?

    init(dependencies: MenuBarDependencies = .live) {
        self.deps = dependencies
        let bio = dependencies.detectBiometry()
        self.biometryLabel = bio.label
        self.biometrySymbol = bio.symbol
        loadProfilesFromDisk()
    }

    nonisolated static func detectSystemBiometry() -> (label: String, symbol: String) {
        let context = LAContext()
        var err: NSError?
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
        switch context.biometryType {
        case .touchID: return ("Touch ID", "touchid")
        case .opticID: return ("Optic ID", "opticid")
        default: return ("Biometrics", "lock.shield")
        }
    }

    func loadProfilesFromDisk() {
        let managed = deps.loadManagedConfig()
        isManagedByMDM = managed.isManaged
        managedProfiles = managed.profiles
        areProfilesLocked = managed.lockProfiles
        isClipboardDisabled = managed.disableClipboard
        enforceTLSPinning = managed.enforceTLSPinning
        requireReasonForElevated = managed.requireReasonForElevated

        let collection = deps.loadProfileCollection()
        let previousID = activeProfileID
        managedProfileIDs = Set(managed.profiles.map(\.id))
        profiles = managed.effectiveProfiles(local: collection.profiles)
        if let activeID = collection.activeProfileID,
           profiles.contains(where: { $0.id == activeID }) {
            activeProfileID = activeID
        } else {
            activeProfileID = profiles.first?.id
        }
        if previousID != activeProfileID {
            selectedRemoteTargetID = nil
            syncComposerDefaults(for: profile)
        } else if let targetID = selectedRemoteTargetID,
                  let currentBase = profiles.first(where: { $0.id == activeProfileID }),
                  !currentBase.configuredRemoteTargets.contains(where: { $0.id == targetID }) {
            selectedRemoteTargetID = nil
        }
    }

    func selectProfile(id: String) {
        guard !isMutating, profiles.contains(where: { $0.id == id }) else { return }
        let previousID = activeProfileID
        activeProfileID = id
        selectedRemoteTargetID = nil
        pendingWarning = nil
        localGrantStatus = .inactive
        remoteRows = []
        remoteUnavailable = nil
        recordedRemoteAccessors = []
        remoteAccessorError = nil
        hasLoadedRemote = false
        bannerMessage = nil
        errorMessage = nil
        do {
            try saveProfiles()
        } catch {
            activeProfileID = previousID
            errorMessage = "Could not save active server selection: \(error.localizedDescription)"
            return
        }
        syncComposerDefaults(for: profile)
        scheduleRefresh(force: true)
    }

    var organizationPolicy: ManagedAppConfig {
        ManagedAppConfig(
            profiles: managedProfiles,
            disableClipboard: isClipboardDisabled,
            lockProfiles: areProfilesLocked,
            enforceTLSPinning: enforceTLSPinning,
            requireReasonForElevated: requireReasonForElevated,
            isManaged: isManagedByMDM
        )
    }

    func isManaged(profileID: String) -> Bool {
        managedProfileIDs.contains(profileID)
    }

    /// Adds an imported profile under the shared import rules (lock, pinning, no ID takeover).
    func importProfile(_ incoming: BaoProfile) throws {
        let plan = try ProfileImportPlan.make(
            importing: incoming,
            existing: profiles,
            managedIDs: managedProfileIDs,
            organizationPolicy: organizationPolicy
        )
        try upsertProfile(plan.profile)
    }

    func upsertProfile(_ newProfile: BaoProfile) throws {
        guard !areProfilesLocked else {
            throw ProfileTransferError.lockedByOrganization
        }
        guard !managedProfileIDs.contains(newProfile.id) else {
            throw ProfileError.invalidField("id", "managed profiles can't be changed on this Mac")
        }
        var newProfile = newProfile
        if requireReasonForElevated {
            newProfile.openbao.auditPolicy.requireReasonForElevated = true
        }
        try newProfile.validate(requireHostKey: true, requireTLSPinning: enforceTLSPinning)
        let previousProfiles = profiles
        let previousActiveID = activeProfileID
        if let idx = profiles.firstIndex(where: { $0.id == newProfile.id }) {
            profiles[idx] = newProfile
        } else {
            profiles.append(newProfile)
        }
        activeProfileID = newProfile.id
        do {
            try saveProfiles()
        } catch {
            profiles = previousProfiles
            activeProfileID = previousActiveID
            throw error
        }
        selectedRemoteTargetID = nil
        pendingWarning = nil
        syncComposerDefaults(for: newProfile)
        localGrantStatus = .inactive
        remoteRows = []
        remoteUnavailable = nil
        recordedRemoteAccessors = []
        remoteAccessorError = nil
        hasLoadedRemote = false
        bannerMessage = "Saved \(newProfile.displayName)."
        scheduleRefresh(force: true)
    }

    func deleteProfile(id: String) {
        guard !isMutating, !areProfilesLocked, !managedProfileIDs.contains(id) else { return }
        let previousProfiles = profiles
        let previousActiveID = activeProfileID
        profiles.removeAll { $0.id == id }
        if activeProfileID == id {
            activeProfileID = profiles.first?.id
            selectedRemoteTargetID = nil
        }
        do {
            try saveProfiles()
        } catch {
            profiles = previousProfiles
            activeProfileID = previousActiveID
            errorMessage = "Could not delete server profile: \(error.localizedDescription)"
            return
        }
        pendingWarning = nil
        syncComposerDefaults(for: profile)
        localGrantStatus = .inactive
        remoteRows = []
        remoteUnavailable = nil
        recordedRemoteAccessors = []
        remoteAccessorError = nil
        hasLoadedRemote = false
        scheduleRefresh(force: true)
    }

    private func saveProfiles() throws {
        let localOnly = profiles.filter { !managedProfileIDs.contains($0.id) }
        let collection = ProfileCollection(activeProfileID: activeProfileID, profiles: localOnly)
        try deps.saveProfileCollection(collection)
        if let active = profile, !managedProfileIDs.contains(active.id) {
            try? deps.saveLegacyProfile(active)
        }
    }

    var isBusy: Bool { isRefreshing || isMutating }

    var isMacActive: Bool {
        localGrantStatus.isActive
    }

    var isRemoteActive: Bool {
        remoteRows.contains(where: \.isActive)
    }

    var hasRecordedRemoteAccessor: Bool {
        !recordedRemoteAccessors.isEmpty
    }

    var canRevokeRemote: Bool {
        isRemoteActive
            || hasRecordedRemoteAccessor
            || remoteUnavailable != nil
            || remoteRows.contains(where: \.isUnknown)
            || remoteAccessorError != nil
    }

    var isComposerElevated: Bool {
        guard let profile else { return false }
        let targetingRemote = target == .t3 && profile.hasRemoteTarget
        if profile.openbao.enabledExtensions.contains(where: { selectedExtensions.contains($0.id) && $0.elevated }) {
            return true
        }
        if profile.openbao.usesCustomPolicies {
            if targetingRemote && !selectedHosts.isEmpty { return true }
            return profile.openbao.grantPolicies.contains {
                selectedPolicies.contains($0.name) && $0.elevated
            }
        }
        if write || !selectedKeys.isEmpty { return true }
        if targetingRemote && (push || !selectedHosts.isEmpty) { return true }
        return false
    }

    func quickMacGrantLabel(for profile: BaoProfile) -> String {
        if profile.openbao.usesCustomPolicies {
            let defaults = profile.openbao.grantPolicies.filter(\.defaultSelected)
            if defaults.count == 1, let first = defaults.first {
                return "1h \(first.displayLabel)"
            }
            return "1h Quick"
        }
        return "1h Read"
    }

    private func refreshScope(for loaded: BaoProfile?) -> RefreshScope? {
        guard let loaded else { return nil }
        return RefreshScope(
            profileID: loaded.id,
            issuerBindingKey: loaded.openbao.issuerBindingKey,
            remoteTargetScopeKey: loaded.hasRemoteTarget ? loaded.t3Granter.canonicalScopeKey : nil
        )
    }

    /// Schedules a status refresh with generation + scope tracking.
    /// - Background/timer refreshes (`force == false`) never interrupt an active mutation or cancel an
    ///   in-flight refresh for the same profile/target scope, preventing slow polls from starving.
    /// - Explicit/post-mutation/profile-switch refreshes (`force == true`) supersede older in-flight
    ///   refreshes so user-initiated updates are never dropped or overwritten by stale responses.
    @discardableResult
    func scheduleRefresh(force: Bool = false) -> Task<Void, Never>? {
        let currentScope = refreshScope(for: profile)
        if !force {
            if isMutating {
                return nil
            }
            if let existing = activeRefreshTask, !existing.isCancelled, activeRefreshScope == currentScope {
                return existing
            }
        }

        activeRefreshTask?.cancel()
        refreshGeneration &+= 1
        let generation = refreshGeneration
        activeRefreshScope = currentScope
        let task = Task { @MainActor [weak self] in
            guard let self else { return }
            await self.performRefresh(generation: generation)
        }
        activeRefreshTask = task
        return task
    }

    func refreshAll(force: Bool = false) async {
        guard let task = scheduleRefresh(force: force) else { return }
        await task.value
    }

    private func performRefresh(generation: UInt64) async {
        isRefreshing = true
        defer {
            if refreshGeneration == generation {
                isRefreshing = false
                activeRefreshTask = nil
                activeRefreshScope = nil
                lastRefresh = Date()
                onStatusChange?()
            }
        }

        loadProfilesFromDisk()
        guard refreshGeneration == generation, !Task.isCancelled else { return }
        activeRefreshScope = refreshScope(for: profile)

        guard let loaded = profile else {
            localGrantStatus = .inactive
            remoteRows = []
            remoteUnavailable = nil
            recordedRemoteAccessors = []
            remoteAccessorError = nil
            hasLoadedRemote = false
            return
        }

        let expectedProfileID = loaded.id
        let expectedIssuer = loaded.openbao.issuerBindingKey
        let expectedTargetScope = loaded.hasRemoteTarget ? loaded.t3Granter.canonicalScopeKey : nil

        func isCurrentScope() -> Bool {
            guard refreshGeneration == generation, !Task.isCancelled else { return false }
            guard let current = profile else { return false }
            let currentTargetScope = current.hasRemoteTarget ? current.t3Granter.canonicalScopeKey : nil
            return current.id == expectedProfileID
                && current.openbao.issuerBindingKey == expectedIssuer
                && currentTargetScope == expectedTargetScope
        }

        // 1. Local Keychain grant status (distinguish absence vs Keychain error vs OpenBao error).
        let localResult: LocalGrantStatus
        do {
            if let token = try deps.readLocalGrant(loaded), !token.isEmpty {
                if pendingLocalCleanupByIssuer[expectedIssuer] == token {
                    localResult = .unknown("Revoked at OpenBao; local Keychain cleanup incomplete — retry Revoke.")
                } else {
                    do {
                        let info = try await deps.lookupSelf(loaded, token)
                        if info.ttlSeconds > 0 {
                            localResult = .active(info)
                        } else {
                            localResult = .unknown("OpenBao returned ambiguous TTL 0.")
                        }
                    } catch {
                        if OpenBaoErrorClassification.isConfirmedInvalidToken(error) {
                            localResult = .inactive
                        } else {
                            localResult = .unknown("Couldn't verify with OpenBao: \(error.localizedDescription)")
                        }
                    }
                }
            } else {
                pendingLocalCleanupByIssuer[expectedIssuer] = nil
                localResult = .inactive
            }
        } catch {
            localResult = .unknown("Keychain unavailable: \(error.localizedDescription)")
        }
        guard isCurrentScope() else { return }
        localGrantStatus = localResult

        // 2. Remote target status + local recorded accessor availability.
        if loaded.hasRemoteTarget {
            let accessorsResult: Result<[GrantAccessorStore.Entry], Error> = Result {
                try deps.recordedRemoteAccessors(loaded)
            }
            let statusResult: Result<RemoteStatusSummary, Error>
            do {
                let raw = try await deps.remoteStatus(loaded)
                statusResult = .success(RemoteStatusSummary.parse(raw))
            } catch {
                statusResult = .failure(error)
            }
            guard isCurrentScope() else { return }
            switch accessorsResult {
            case let .success(entries):
                recordedRemoteAccessors = entries
                remoteAccessorError = nil
            case let .failure(err):
                recordedRemoteAccessors = []
                remoteAccessorError = err.localizedDescription
            }
            switch statusResult {
            case let .success(parsed):
                remoteRows = parsed.entries
                remoteUnavailable = parsed.unavailableReason
            case .failure:
                remoteRows = []
                remoteUnavailable = "Unavailable"
            }
            hasLoadedRemote = true
        } else {
            remoteRows = []
            remoteUnavailable = nil
            recordedRemoteAccessors = []
            remoteAccessorError = nil
            hasLoadedRemote = false
        }
    }

    func refreshIfStale(maxAge: TimeInterval = 15) async {
        guard !isMutating else { return }
        if let lastRefresh, Date().timeIntervalSince(lastRefresh) < maxAge {
            return
        }
        await refreshAll(force: false)
    }

    func submitComposerGrant() async {
        guard !isMutating, let snapshotProfile = profile else { return }
        isMutating = true
        errorMessage = nil
        bannerMessage = nil
        pendingWarning = nil

        let orderedKeys = snapshotProfile.openbao.keys.map(\.name).filter { selectedKeys.contains($0) }
        let orderedHosts = snapshotProfile.openbao.ssh.hosts.map(\.name).filter { selectedHosts.contains($0) }
        let orderedPolicies = snapshotProfile.openbao.grantPolicies.map(\.name).filter { selectedPolicies.contains($0) }
        let orderedExtensions = snapshotProfile.openbao.enabledExtensions.map(\.id).filter { selectedExtensions.contains($0) }
        let effectiveTarget: GrantTarget = (target == .t3 && snapshotProfile.hasRemoteTarget) ? .t3 : .mac

        let request = GrantRequest(
            target: effectiveTarget,
            hours: min(hours, snapshotProfile.openbao.maxHours),
            write: snapshotProfile.openbao.usesCustomPolicies ? false : write,
            keys: snapshotProfile.openbao.usesCustomPolicies ? [] : orderedKeys,
            sshHosts: effectiveTarget == .t3 ? orderedHosts : [],
            push: effectiveTarget == .t3 && !snapshotProfile.openbao.usesCustomPolicies ? push : false,
            customPolicies: snapshotProfile.openbao.usesCustomPolicies ? orderedPolicies : [],
            why: why,
            extensions: orderedExtensions
        )

        if effectiveTarget == .t3 {
            let running = await deps.remoteRunningTasks(snapshotProfile)
            if running.brokerUnavailable || !running.tasks.isEmpty {
                pendingWarning = PendingRemoteTaskWarning(
                    profile: snapshotProfile,
                    request: request,
                    tasks: running.tasks,
                    brokerUnavailable: running.brokerUnavailable
                )
                isMutating = false
                onStatusChange?()
                return
            }
        }

        await executeGrantHoldingMutationLock(request, profile: snapshotProfile)
    }

    func confirmPendingGrant() async {
        guard !isMutating, let warning = pendingWarning else { return }
        pendingWarning = nil
        isMutating = true
        await executeGrantHoldingMutationLock(warning.request, profile: warning.profile)
    }

    /// Validates an incoming `baobuddy://grant?r=...` URL without changing the saved active profile
    /// or auto-approving. Mirrors iOS `AppModel.handleIncomingURL` security rules.
    func handleIncomingURL(_ url: URL) {
        guard !isMutating else {
            errorMessage = "Another grant operation is already in progress. Try opening the link again once it finishes."
            return
        }
        guard pendingDeepLink == nil else {
            errorMessage = "Approve or decline the current incoming grant request before opening another link."
            return
        }
        loadProfilesFromDisk()
        errorMessage = nil
        bannerMessage = nil

        do {
            let targetProfile = try GrantRequest.resolveProfile(from: url, in: profiles, active: profile)
            let focused = try GrantRequest.linkProfile(url: url, base: targetProfile)
            let request = try GrantRequest.parse(url: url, profile: focused)
            let approval = PendingMacApproval(
                profile: focused,
                request: request,
                runningTasks: nil,
                isCheckingTasks: focused.hasRemoteTarget && request.target == .t3
            )
            pendingDeepLink = approval
            if focused.hasRemoteTarget && request.target == .t3 {
                let approvalID = approval.id
                let fetchTasks = deps.remoteRunningTasks
                Task { [weak self] in
                    let running = await fetchTasks(focused)
                    guard let self, var current = self.pendingDeepLink, current.id == approvalID else { return }
                    current.runningTasks = running
                    current.isCheckingTasks = false
                    self.pendingDeepLink = current
                }
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func approvePendingDeepLink() async {
        guard !isMutating, let pending = pendingDeepLink else { return }
        pendingDeepLink = nil
        isMutating = true
        await executeGrantHoldingMutationLock(pending.request, profile: pending.profile)
    }

    func dismissPendingDeepLink() {
        pendingDeepLink = nil
    }

    func runQuickMacGrant() async {
        guard !isMutating, let snapshotProfile = profile else { return }
        let request: GrantRequest
        if snapshotProfile.openbao.usesCustomPolicies {
            let defaults = snapshotProfile.openbao.grantPolicies.filter(\.defaultSelected).map(\.name)
            let chosen = defaults.isEmpty ? Array(snapshotProfile.openbao.grantPolicies.prefix(1).map(\.name)) : defaults
            request = GrantRequest(target: .mac, hours: 1, customPolicies: chosen, why: "menu bar grant")
        } else {
            request = GrantRequest(target: .mac, hours: 1, write: false, why: "menu bar grant")
        }
        isMutating = true
        await executeGrantHoldingMutationLock(request, profile: snapshotProfile)
    }

    private func executeGrantHoldingMutationLock(_ request: GrantRequest, profile: BaoProfile) async {
        errorMessage = nil
        bannerMessage = nil
        defer {
            isMutating = false
            onStatusChange?()
        }

        do {
            let outcome = try await deps.executeGrant(profile, request, organizationPolicy)
            if request.target == .mac {
                pendingLocalCleanupByIssuer[profile.openbao.issuerBindingKey] = nil
            }
            let targetLabel = request.target == .t3 ? profile.targetDisplayName : "This Mac"
            let entry = GrantActivityEntry(
                action: .granted,
                serverName: profile.displayName,
                namespace: profile.openbao.namespace,
                targetName: targetLabel,
                policies: request.openBaoPolicies(profile: profile),
                hours: request.hours,
                why: request.why,
                elevated: request.isElevated(profile: profile),
                via: "mac"
            )
            deps.recordActivity(entry)
            deps.emitTelemetry(profile, entry)
            let notifID = "\(profile.id).\(request.target == .t3 ? profile.targetDisplayName : "mac")"
            deps.scheduleExpiryNotification(
                notifID,
                profile.displayName,
                targetLabel,
                outcome.effectiveTTLSeconds ?? (request.hours * 3600)
            )
            bannerMessage = outcome.message
            why = ""
            showComposer = false
            await refreshAll(force: true)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func revokeMacGrant() async {
        guard !isMutating, let snapshotProfile = profile else { return }
        isMutating = true
        errorMessage = nil
        bannerMessage = nil
        defer {
            isMutating = false
            onStatusChange?()
        }

        let issuerKey = snapshotProfile.openbao.issuerBindingKey
        do {
            guard let token = try deps.readLocalGrant(snapshotProfile), !token.isEmpty else {
                pendingLocalCleanupByIssuer[issuerKey] = nil
                deps.cancelExpiryNotification("\(snapshotProfile.id).mac")
                localGrantStatus = .inactive
                bannerMessage = "No grant saved on this Mac for \(snapshotProfile.displayName)."
                return
            }

            let alreadyConfirmed = (pendingLocalCleanupByIssuer[issuerKey] == token)
            if !alreadyConfirmed {
                // Only proceed to local cleanup after OpenBao explicitly confirms revocation.
                try await deps.revokeSelf(snapshotProfile, token)
                pendingLocalCleanupByIssuer[issuerKey] = token
                deps.cancelExpiryNotification("\(snapshotProfile.id).mac")
                let entry = GrantActivityEntry(
                    action: .revoked,
                    serverName: snapshotProfile.displayName,
                    namespace: snapshotProfile.openbao.namespace,
                    targetName: "This Mac",
                    via: "mac"
                )
                deps.recordActivity(entry)
            }

            do {
                try deps.deleteRevokedLocalGrant(snapshotProfile, token)
            } catch {
                let cleanupError = LocalGrantCleanupError(underlying: error)
                localGrantStatus = .unknown(cleanupError.localizedDescription)
                bannerMessage = "Revoked at OpenBao."
                errorMessage = "\(cleanupError.localizedDescription) Retry Revoke to finish local cleanup."
                return
            }

            pendingLocalCleanupByIssuer[issuerKey] = nil
            localGrantStatus = .inactive
            bannerMessage = "Revoked Mac grant."
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func revokeRemoteGrant() async {
        guard !isMutating, let snapshotProfile = profile else { return }
        isMutating = true
        errorMessage = nil
        bannerMessage = nil
        defer {
            isMutating = false
            onStatusChange?()
        }

        do {
            let recorded = try deps.recordedRemoteAccessors(snapshotProfile)
            var revokedCount = 0
            var serverRevokeError: Error?
            var accessorCleanupError: Error?

            for entry in recorded {
                do {
                    try await deps.revokeRemoteAccessor(snapshotProfile, entry.accessor, organizationPolicy)
                    revokedCount += 1
                    do {
                        try deps.removeRecordedRemoteAccessor(snapshotProfile, entry.accessor)
                    } catch {
                        accessorCleanupError = error
                    }
                } catch {
                    serverRevokeError = error
                    break
                }
            }

            if let serverRevokeError {
                if revokedCount > 0 {
                    bannerMessage = "Revoked \(revokedCount) of \(recorded.count) recorded grants through OpenBao."
                }
                var details = [serverRevokeError.localizedDescription]
                if let accessorCleanupError {
                    details.append("Local accessor cleanup failed: \(accessorCleanupError.localizedDescription)")
                }
                errorMessage = details.joined(separator: " ")
                await refreshAll(force: true)
                return
            }

            let revokedOnServer = !recorded.isEmpty
            var hostMessage: String?
            var hostCleanupError: Error?
            do {
                hostMessage = try await deps.remoteRevokeHost(snapshotProfile)
            } catch {
                hostCleanupError = error
            }

            if !revokedOnServer, let hostCleanupError {
                throw hostCleanupError
            }

            deps.cancelExpiryNotification("\(snapshotProfile.id).\(snapshotProfile.targetDisplayName)")
            let entry = GrantActivityEntry(
                action: .revoked,
                serverName: snapshotProfile.displayName,
                namespace: snapshotProfile.openbao.namespace,
                targetName: snapshotProfile.targetDisplayName,
                via: "mac"
            )
            deps.recordActivity(entry)

            if revokedOnServer {
                var cleanupIssues: [String] = []
                if let hostCleanupError {
                    cleanupIssues.append("\(snapshotProfile.targetDisplayName) didn't confirm deleting its local copies: \(hostCleanupError.localizedDescription)")
                }
                if let accessorCleanupError {
                    cleanupIssues.append("Local accessor record cleanup failed: \(accessorCleanupError.localizedDescription)")
                }
                if cleanupIssues.isEmpty {
                    let suffix = hostMessage.map { $0.isEmpty ? "" : " \($0)" } ?? ""
                    bannerMessage = "Revoked through OpenBao.\(suffix)"
                } else {
                    bannerMessage = "Revoked through OpenBao."
                    errorMessage = cleanupIssues.joined(separator: " ") + " Retry Revoke to finish cleanup."
                }
            } else {
                let msg = hostMessage ?? "Revoked on \(snapshotProfile.targetDisplayName)."
                bannerMessage = msg
                errorMessage = "No accessor was recorded locally, so only \(snapshotProfile.targetDisplayName) confirmed revocation."
            }
            await refreshAll(force: true)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func syncComposerDefaults(for profile: BaoProfile?) {
        write = false
        push = false
        selectedKeys = []
        selectedHosts = []
        selectedExtensions = []
        pendingWarning = nil
        if let profile {
            hours = min(max(hours, 1), profile.openbao.maxHours)
            selectedPolicies = Set(profile.openbao.grantPolicies.filter(\.defaultSelected).map(\.name))
            if !profile.hasRemoteTarget {
                target = .mac
            }
        } else {
            selectedPolicies = []
            target = .mac
        }
    }

    nonisolated static func formatTTL(_ seconds: Int) -> String {
        let hrs = seconds / 3600
        let mins = (seconds % 3600) / 60
        if hrs > 0 {
            return "\(hrs)h \(mins)m"
        }
        return "\(max(1, mins))m"
    }
}

// MARK: - Popover View

struct MenuBarPopoverView: View {
    @Bindable var state: MenuBarState
    let onOpenSettings: (MacSettingsTab) -> Void
    let onQuit: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            headerBar
            Divider()

            ScrollView(.vertical) {
                VStack(spacing: 10) {
                    if let banner = state.bannerMessage {
                        statusBanner(banner, isError: false) { state.bannerMessage = nil }
                    }
                    if let error = state.errorMessage {
                        statusBanner(error, isError: true) { state.errorMessage = nil }
                    }

                    if let pending = state.pendingDeepLink {
                        incomingApprovalCard(pending: pending)
                    }

                    if let profile = state.profile {
                        macGrantCard(profile: profile)
                        if profile.hasRemoteTarget {
                            remoteGrantCard(profile: profile)
                        }
                        if let warning = state.pendingWarning {
                            runningTasksWarningCard(warning: warning)
                        }
                        composerCard(profile: profile)
                    } else {
                        unconfiguredCard
                    }
                }
                .padding(12)
            }
            .scrollIndicators(.automatic)
            .frame(maxHeight: 540)
            .fixedSize(horizontal: false, vertical: true)

            Divider()
            footerBar
        }
        .frame(width: 344)
    }

    // MARK: - Header & Footer

    private var headerBar: some View {
        HStack(spacing: 10) {
            brandIconView
                .frame(width: 32, height: 32)

            VStack(alignment: .leading, spacing: 1) {
                Text("BaoBuddy")
                    .font(.headline)
                Menu {
                    ForEach(state.profiles) { item in
                        Button {
                            state.selectProfile(id: item.id)
                        } label: {
                            if item.id == state.profile?.id {
                                Label(item.displayName, systemImage: "checkmark")
                            } else {
                                Text(item.displayName)
                            }
                        }
                    }
                    if !state.profiles.isEmpty {
                        Divider()
                    }
                    Button {
                        onOpenSettings(.servers)
                    } label: {
                        Label("Manage Servers & Targets…", systemImage: "server.rack")
                    }
                    Button {
                        onOpenSettings(.keys)
                    } label: {
                        Label("Hardware Keys…", systemImage: "key")
                    }
                    Button {
                        onOpenSettings(.help)
                    } label: {
                        Label("Help & About…", systemImage: "info.circle")
                    }
                } label: {
                    Text(state.profile?.displayName ?? "Not Configured")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.visible)
                .fixedSize()
                .disabled(state.isMutating)
            }

            Spacer()

            HStack(spacing: 4) {
                headerIconButton(
                    symbol: "info.circle",
                    help: "Help & About",
                    isSpinning: false,
                    disabled: false
                ) {
                    onOpenSettings(.help)
                }

                headerIconButton(
                    symbol: "arrow.clockwise",
                    help: "Refresh grant status (⌘R)",
                    isSpinning: state.isRefreshing,
                    disabled: state.isBusy
                ) {
                    Task { await state.refreshAll(force: true) }
                }
                .keyboardShortcut("r", modifiers: .command)

                headerIconButton(
                    symbol: "gearshape",
                    help: "Manage Servers & Keys (⌘,)",
                    isSpinning: false,
                    disabled: false
                ) {
                    onOpenSettings(.servers)
                }
                .keyboardShortcut(",", modifiers: .command)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    private func headerIconButton(
        symbol: String,
        help: String,
        isSpinning: Bool,
        disabled: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Group {
                if isSpinning {
                    ProgressView()
                        .controlSize(.small)
                } else {
                    Image(systemName: symbol)
                        .font(.system(size: 13, weight: .medium))
                }
            }
            .frame(width: 26, height: 26)
            .contentShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
        .buttonStyle(.borderless)
        .disabled(disabled)
        .help(help)
    }

    @ViewBuilder
    private var brandIconView: some View {
        if let appIcon = NSApp.applicationIconImage {
            Image(nsImage: appIcon)
                .resizable()
                .scaledToFit()
        } else {
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .fill(MacBaoTheme.brand.gradient)
                .overlay {
                    Image(systemName: "lock.shield.fill")
                        .foregroundStyle(MacBaoTheme.cream)
                }
        }
    }

    private var footerBar: some View {
        HStack {
            if let address = state.profile?.openbao.address {
                Text(address)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            } else {
                Text("Secure Enclave Companion")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Quit") {
                onQuit()
            }
            .buttonStyle(.borderless)
            .font(.caption)
            .foregroundStyle(.secondary)
            .keyboardShortcut("q", modifiers: .command)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: - Status Cards (Unified Grammar)

    private func macGrantCard(profile: BaoProfile) -> some View {
        let active = state.isMacActive
        let unknownReason = state.localGrantStatus.unknownReason
        let ttlText = state.macGrantInfo.flatMap { $0.ttlSeconds > 0 ? MenuBarState.formatTTL($0.ttlSeconds) : nil }

        return cardContainer {
            HStack(spacing: 9) {
                brandGlyphView(unlocked: active)
                    .foregroundStyle(active ? MacBaoTheme.active : (unknownReason != nil ? MacBaoTheme.elevated : .secondary))
                VStack(alignment: .leading, spacing: 1) {
                    Text("This Mac")
                        .font(.subheadline.weight(.semibold))
                    if let ttlText {
                        Text("Active • \(ttlText) left")
                            .font(.caption)
                            .foregroundStyle(MacBaoTheme.active)
                    } else if unknownReason != nil {
                        Text("Status Unknown")
                            .font(.caption)
                            .foregroundStyle(MacBaoTheme.elevated)
                    } else {
                        Text("No Active Grant")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 6)
                if active || unknownReason != nil {
                    Button(role: .destructive) {
                        Task { await state.revokeMacGrant() }
                    } label: {
                        Text("Revoke")
                            .font(.caption.weight(.medium))
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(state.isMutating)
                } else {
                    Button {
                        Task { await state.runQuickMacGrant() }
                    } label: {
                        Label(state.quickMacGrantLabel(for: profile), systemImage: state.biometrySymbol)
                            .font(.caption.weight(.medium))
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .tint(MacBaoTheme.brand)
                    .disabled(state.isBusy)
                }
            }

            if let unknownReason {
                Divider()
                Label(unknownReason, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2)
                    .foregroundStyle(MacBaoTheme.elevated)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let info = state.macGrantInfo, info.ttlSeconds > 0 {
                let policies = info.policies.filter { $0 != "default" }
                if !policies.isEmpty || !info.why.isEmpty {
                    Divider()
                    VStack(spacing: 4) {
                        if !policies.isEmpty {
                            labeledRow("Policies", value: policies.joined(separator: ", "), systemImage: "checkmark.shield")
                        }
                        if !info.why.isEmpty {
                            labeledRow("Reason", value: info.why, systemImage: "text.alignleft")
                        }
                    }
                }
            }
        }
    }

    private func remoteGrantCard(profile: BaoProfile) -> some View {
        let active = state.isRemoteActive
        return cardContainer {
            HStack(spacing: 9) {
                brandGlyphView(unlocked: active)
                    .foregroundStyle(active ? MacBaoTheme.active : (state.hasRecordedRemoteAccessor ? MacBaoTheme.elevated : .secondary))
                VStack(alignment: .leading, spacing: 1) {
                    if profile.configuredRemoteTargets.count > 1 {
                        Menu {
                            ForEach(profile.configuredRemoteTargets) { target in
                                Button {
                                    state.selectRemoteTarget(id: target.id)
                                } label: {
                                    if target.id == profile.t3Granter.id {
                                        Label("\(target.displayName) (\(target.host))", systemImage: "checkmark")
                                    } else {
                                        Text("\(target.displayName) (\(target.host))")
                                    }
                                }
                            }
                        } label: {
                            Text(profile.targetDisplayName)
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(.primary)
                        }
                        .menuStyle(.borderlessButton)
                        .menuIndicator(.visible)
                        .fixedSize()
                        .disabled(state.isMutating)
                    } else {
                        Text(profile.targetDisplayName)
                            .font(.subheadline.weight(.semibold))
                    }
                    if !state.hasLoadedRemote {
                        Text("Checking…")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else if let unavailable = state.remoteUnavailable {
                        Text(state.hasRecordedRemoteAccessor ? "\(unavailable) • Revoke via OpenBao" : unavailable)
                            .font(.caption)
                            .foregroundStyle(state.hasRecordedRemoteAccessor ? MacBaoTheme.elevated : .secondary)
                    } else if state.remoteRows.contains(where: \.isUnknown) {
                        Text("Status Unknown")
                            .font(.caption)
                            .foregroundStyle(MacBaoTheme.elevated)
                    } else if active {
                        Text("Active Grant")
                            .font(.caption)
                            .foregroundStyle(MacBaoTheme.active)
                    } else if state.hasRecordedRemoteAccessor {
                        Text("Recorded Grant • Revoke via OpenBao")
                            .font(.caption)
                            .foregroundStyle(MacBaoTheme.elevated)
                    } else {
                        Text("No Active Grant")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer(minLength: 6)
                if state.canRevokeRemote {
                    Button(role: .destructive) {
                        Task { await state.revokeRemoteGrant() }
                    } label: {
                        Text("Revoke")
                            .font(.caption.weight(.medium))
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(state.isMutating)
                }
            }

            if let accessorErr = state.remoteAccessorError {
                Divider()
                Label(accessorErr, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2)
                    .foregroundStyle(MacBaoTheme.elevated)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if !state.remoteRows.isEmpty {
                Divider()
                VStack(spacing: 4) {
                    ForEach(state.remoteRows) { row in
                        let valueText = row.detail.isEmpty ? row.statusText : "\(row.statusText) · \(row.detail)"
                        labeledRow(
                            row.label,
                            value: valueText,
                            systemImage: row.systemImage,
                            emphasized: row.isActive || row.isUnknown
                        )
                    }
                }
            }
        }
    }

    // MARK: - Composer Card

    private func composerCard(profile: BaoProfile) -> some View {
        let durationOptions = [1, 2, 4, 8, 12].filter { $0 <= profile.openbao.maxHours }
        let elevated = state.isComposerElevated
        let accent = elevated ? MacBaoTheme.elevated : MacBaoTheme.brand
        let canApprove = !state.isBusy && (!profile.openbao.usesCustomPolicies || !state.selectedPolicies.isEmpty)

        return cardContainer {
            Button {
                withAnimation(.snappy(duration: 0.18)) {
                    state.showComposer.toggle()
                }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "plus.circle.fill")
                        .foregroundStyle(MacBaoTheme.brand)
                        .font(.system(size: 15))
                    Text("New Grant")
                        .font(.subheadline.weight(.semibold))
                    Spacer()
                    Image(systemName: state.showComposer ? "chevron.up" : "chevron.down")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if state.showComposer {
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    if profile.hasRemoteTarget {
                        Picker("Target", selection: $state.target) {
                            Text("This Mac").tag(GrantTarget.mac)
                            Text(profile.targetDisplayName).tag(GrantTarget.t3)
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                    }

                    Picker("Duration", selection: $state.hours) {
                        ForEach(durationOptions.isEmpty ? [1] : durationOptions, id: \.self) { opt in
                            Text("\(opt)h").tag(opt)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()

                    if profile.openbao.usesCustomPolicies {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(profile.openbao.grantPolicies) { policy in
                                alignedSwitchRow(
                                    accessibilityLabel: policy.displayLabel,
                                    isOn: Binding(
                                        get: { state.selectedPolicies.contains(policy.name) },
                                        set: { isOn in
                                            if isOn {
                                                state.selectedPolicies.insert(policy.name)
                                            } else {
                                                state.selectedPolicies.remove(policy.name)
                                            }
                                        }
                                    ),
                                    tint: policy.elevated ? MacBaoTheme.elevated : MacBaoTheme.brand
                                ) {
                                    HStack(spacing: 5) {
                                        Text(policy.displayLabel)
                                            .font(.subheadline)
                                        if policy.elevated {
                                            Image(systemName: "exclamationmark.triangle.fill")
                                                .font(.caption2)
                                                .foregroundStyle(MacBaoTheme.elevated)
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        alignedSwitchRow(
                            accessibilityLabel: "Allow Secret Writes",
                            isOn: $state.write,
                            tint: MacBaoTheme.elevated
                        ) {
                            Text("Allow Secret Writes")
                                .font(.subheadline)
                        }

                        if state.target == .t3 && profile.hasRemoteTarget && profile.supportsPushTokens {
                            alignedSwitchRow(
                                accessibilityLabel: "GitHub Push Token (1h)",
                                isOn: $state.push,
                                tint: MacBaoTheme.elevated
                            ) {
                                Text("GitHub Push Token (1h)")
                                    .font(.subheadline)
                            }
                        }

                        if !profile.openbao.keys.isEmpty {
                            chipSelector(
                                title: "Restricted Keys",
                                items: profile.openbao.keys.map(\.name),
                                selection: $state.selectedKeys
                            )
                        }
                    }

                    if state.target == .t3 && profile.hasRemoteTarget && !profile.openbao.ssh.hosts.isEmpty {
                        chipSelector(
                            title: "SSH Certificates",
                            items: profile.openbao.ssh.hosts.map(\.name),
                            selection: $state.selectedHosts
                        )
                    }

                    ForEach(profile.openbao.enabledExtensions) { ext in
                        alignedSwitchRow(
                            accessibilityLabel: ext.displayLabel,
                            isOn: Binding(
                                get: { state.selectedExtensions.contains(ext.id) },
                                set: { isOn in
                                    if isOn {
                                        state.selectedExtensions.insert(ext.id)
                                    } else {
                                        state.selectedExtensions.remove(ext.id)
                                    }
                                }
                            ),
                            tint: ext.elevated ? MacBaoTheme.elevated : MacBaoTheme.brand
                        ) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(ext.displayLabel)
                                    .font(.subheadline)
                                Text(state.target == .t3 && profile.hasRemoteTarget
                                     ? "\(ext.endpoint) → \(ext.deliverAs) on \(profile.targetDisplayName)"
                                     : "\(ext.endpoint) → Keychain (\(ext.deliverAs))")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    let audit = profile.openbao.auditPolicy
                    let reasonNeeded = audit.requireReason || (audit.requireReasonForElevated && elevated)
                    let reasonHint: String = {
                        let custom = audit.reasonPlaceholder.trimmingCharacters(in: .whitespacesAndNewlines)
                        if !custom.isEmpty { return custom }
                        return reasonNeeded ? "Audit reason / ticket ID (required)" : "Audit reason (optional)"
                    }()
                    TextField(reasonHint, text: $state.why)
                        .textFieldStyle(.roundedBorder)
                        .font(.subheadline)

                    if reasonNeeded && state.why.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        Label("Reason required by server audit policy.", systemImage: "doc.text.magnifyingglass")
                            .font(.caption2)
                            .foregroundStyle(MacBaoTheme.elevated)
                    }

                    if elevated {
                        Label("Elevated scope — verify permissions before approving.", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption2)
                            .foregroundStyle(MacBaoTheme.elevated)
                    }

                    Button {
                        Task { await state.submitComposerGrant() }
                    } label: {
                        HStack(spacing: 6) {
                            if state.isMutating {
                                ProgressView()
                                    .controlSize(.small)
                            } else {
                                Image(systemName: state.biometrySymbol)
                            }
                            Text(state.isMutating ? "Authenticating…" : "Approve with \(state.biometryLabel)")
                                .font(.subheadline.weight(.semibold))
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 3)
                    }
                    .macPrimaryBaoButton(tint: accent)
                    .disabled(!canApprove)
                }
            }
        }
    }

    private func alignedSwitchRow<LabelContent: View>(
        accessibilityLabel: String,
        isOn: Binding<Bool>,
        tint: Color,
        @ViewBuilder label: () -> LabelContent
    ) -> some View {
        HStack(alignment: .center, spacing: 8) {
            label()
            Spacer(minLength: 8)
            Toggle(accessibilityLabel, isOn: isOn)
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
                .tint(tint)
        }
    }

    private func incomingApprovalCard(pending: PendingMacApproval) -> some View {
        let elevated = pending.request.isElevated(profile: pending.profile)
        let accent = elevated ? MacBaoTheme.elevated : MacBaoTheme.brand
        let duration = pending.request.hours == 1 ? "1 hour" : "\(pending.request.hours) hours"
        let targetName = pending.profile.hasRemoteTarget && pending.request.target == .t3
            ? pending.profile.targetDisplayName
            : "This Mac"

        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: elevated ? "exclamationmark.triangle.fill" : "link.badge.plus")
                    .foregroundStyle(accent)
                    .font(.subheadline)
                VStack(alignment: .leading, spacing: 1) {
                    Text(elevated ? "Elevated Grant Request" : "Incoming Grant Request")
                        .font(.subheadline.weight(.semibold))
                    Text("\(pending.profile.displayName) → \(targetName) • \(duration)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            Divider()

            VStack(spacing: 4) {
                if !pending.profile.openbao.namespace.isEmpty {
                    labeledRow("Namespace", value: pending.profile.openbao.namespace, systemImage: "folder.badge.gearshape")
                }
                labeledRow(
                    "Scope",
                    value: pending.request.scopeDescription(profile: pending.profile),
                    systemImage: "checkmark.shield"
                )
                if !pending.request.why.isEmpty {
                    labeledRow("Reason", value: pending.request.why, systemImage: "text.alignleft")
                }
            }

            if pending.isCheckingTasks {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Checking running tasks on \(targetName)…")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            } else if let running = pending.runningTasks {
                if running.brokerUnavailable {
                    Label("Couldn't check running tasks on \(targetName).", systemImage: "exclamationmark.circle")
                        .font(.caption2)
                        .foregroundStyle(MacBaoTheme.elevated)
                } else if !running.tasks.isEmpty {
                    VStack(alignment: .leading, spacing: 2) {
                        Label(
                            running.tasks.count == 1
                                ? "Will reach 1 running task:"
                                : "Will reach \(running.tasks.count) running tasks:",
                            systemImage: "exclamationmark.triangle.fill"
                        )
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(MacBaoTheme.elevated)
                        ForEach(running.tasks, id: \.self) { task in
                            Text(task)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            HStack(spacing: 8) {
                Button("Decline") {
                    state.dismissPendingDeepLink()
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(state.isMutating)

                Spacer()

                Button {
                    Task { await state.approvePendingDeepLink() }
                } label: {
                    Label("Approve with \(state.biometryLabel)", systemImage: state.biometrySymbol)
                        .font(.caption.weight(.semibold))
                }
                .macPrimaryBaoButton(tint: accent)
                .controlSize(.small)
                .disabled(state.isMutating)
            }
            .padding(.top, 2)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(accent.opacity(0.09), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(accent.opacity(0.45), lineWidth: 1)
        )
    }

    private func runningTasksWarningCard(warning: PendingRemoteTaskWarning) -> some View {
        let targetName = warning.profile.targetDisplayName
        return cardContainer {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(MacBaoTheme.elevated)
                VStack(alignment: .leading, spacing: 4) {
                    Text(
                        warning.brokerUnavailable
                            ? "Couldn't check running tasks on \(targetName)."
                            : (warning.tasks.count == 1
                                ? "1 task is running on \(targetName):"
                                : "\(warning.tasks.count) tasks are running on \(targetName):")
                    )
                    .font(.caption.weight(.semibold))

                    ForEach(warning.tasks, id: \.self) { task in
                        Text(task)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
            HStack {
                Button("Cancel") {
                    state.pendingWarning = nil
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(state.isMutating)
                Spacer()
                Button("Grant Anyway") {
                    Task { await state.confirmPendingGrant() }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .tint(MacBaoTheme.elevated)
                .disabled(state.isMutating)
            }
        }
    }

    private var unconfiguredCard: some View {
        cardContainer {
            VStack(alignment: .leading, spacing: 8) {
                Text("No server configured yet")
                    .font(.subheadline.weight(.semibold))
                Text("Connect an OpenBao or HashiCorp Vault server by importing a profile JSON or entering your server details.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button {
                    onOpenSettings(.servers)
                } label: {
                    Label("Add Server…", systemImage: "plus.circle.fill")
                        .font(.subheadline.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 2)
                }
                .macPrimaryBaoButton(tint: MacBaoTheme.brand)
            }
        }
    }

    // MARK: - Small Components

    private func chipSelector(title: String, items: [String], selection: Binding<Set<String>>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 74), spacing: 6)], alignment: .leading, spacing: 6) {
                ForEach(items, id: \.self) { item in
                    let isSelected = selection.wrappedValue.contains(item)
                    Button {
                        if isSelected {
                            selection.wrappedValue.remove(item)
                        } else {
                            selection.wrappedValue.insert(item)
                        }
                    } label: {
                        Text(item)
                            .font(.caption2.weight(isSelected ? .semibold : .regular).monospaced())
                            .lineLimit(1)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .frame(maxWidth: .infinity)
                            .background(
                                isSelected ? MacBaoTheme.elevated.opacity(0.18) : Color.primary.opacity(0.06),
                                in: Capsule()
                            )
                            .overlay(
                                Capsule().strokeBorder(
                                    isSelected ? MacBaoTheme.elevated : Color.primary.opacity(0.1),
                                    lineWidth: 1
                                )
                            )
                            .foregroundStyle(isSelected ? MacBaoTheme.elevated : .primary)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private func statusBanner(_ text: String, isError: Bool, onDismiss: @escaping () -> Void) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(isError ? .red : MacBaoTheme.active)
                .font(.caption)
            Text(text)
                .font(.caption)
                .foregroundStyle(isError ? .red : .primary)
                .textSelection(.enabled)
            Spacer(minLength: 4)
            Button {
                onDismiss()
            } label: {
                Image(systemName: "xmark")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
        }
        .padding(10)
        .background(
            (isError ? Color.red : MacBaoTheme.active).opacity(0.10),
            in: RoundedRectangle(cornerRadius: 10, style: .continuous)
        )
    }

    private func labeledRow(
        _ label: String,
        value: String,
        systemImage: String,
        emphasized: Bool = true
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Label(label, systemImage: systemImage)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer(minLength: 8)
            Text(value)
                .font(.caption.monospaced())
                .foregroundStyle(emphasized ? .primary : .secondary)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
        }
    }

    private func cardContainer<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            content()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color.primary.opacity(0.08), lineWidth: 0.75)
        )
    }

    @ViewBuilder
    private func brandGlyphView(unlocked: Bool) -> some View {
        let name = unlocked ? "MenuBarGlyphUnlocked" : "MenuBarGlyph"
        if let nsImage = Bundle.main.image(forResource: name) {
            let template: NSImage = {
                let copy = nsImage.copy() as? NSImage ?? nsImage
                copy.isTemplate = true
                return copy
            }()
            Image(nsImage: template)
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: 22, height: 18)
        } else {
            Image(systemName: unlocked ? "lock.open.fill" : "lock.shield.fill")
                .font(.system(size: 16))
        }
    }
}

private struct MacPrimaryBaoButtonModifier: ViewModifier {
    let tint: Color

    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
                .buttonStyle(.glassProminent)
                .tint(tint)
        } else {
            content
                .buttonStyle(.borderedProminent)
                .tint(tint)
        }
    }
}

private extension View {
    func macPrimaryBaoButton(tint: Color) -> some View {
        modifier(MacPrimaryBaoButtonModifier(tint: tint))
    }
}
#endif
