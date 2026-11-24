#if os(macOS)
import BaoBuddyCore
import Foundation
import XCTest
@testable import BaoBuddyHelper

@MainActor
final class MacHelperUITests: XCTestCase {
    private func makeProfile(
        id: String,
        name: String,
        address: String,
        mount: String = "jwt-alice",
        caPEM: String = "",
        targets: [BaoT3GranterConfig] = []
    ) -> BaoProfile {
        BaoProfile(
            id: id,
            version: 1,
            name: name,
            openbao: BaoOpenBaoConfig(
                address: address,
                caPEM: caPEM,
                jwtAuth: BaoJWTAuthConfig(
                    mount: mount,
                    role: "granter",
                    issuer: "bao-granter",
                    audience: BaoOpenBaoConfig.defaultAudience(address: address, mount: mount, caPEM: caPEM),
                    subject: "alice"
                ),
                tokenRoles: BaoTokenRolesConfig(mac: "grant", t3: "grant"),
                grantPolicies: [
                    BaoBuddyPolicy(name: "app-read", label: "Read", elevated: false, defaultSelected: true),
                    BaoBuddyPolicy(name: "app-write", label: "Write", elevated: true, defaultSelected: false)
                ],
                maxHours: 8,
                keys: [],
                ssh: BaoSSHConfig(role: "", hosts: []),
                githubAppItem: ""
            ),
            remoteTargets: targets
        )
    }

    private func makeTarget(name: String, host: String, key: String = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockHostKey") -> BaoT3GranterConfig {
        BaoT3GranterConfig(name: name, host: host, port: 22, user: "granter", hostKey: key)
    }

    private func baseDeps(collection: ProfileCollection) -> MenuBarDependencies {
        var stored = collection
        return MenuBarDependencies(
            loadManagedConfig: { .empty },
            loadProfileCollection: { stored },
            saveProfileCollection: { stored = $0 },
            saveLegacyProfile: { _ in },
            readLocalGrant: { _ in nil },
            deleteRevokedLocalGrant: { _, _ in },
            lookupSelf: { _, _ in TokenLookupInfo(ttlSeconds: 3600, policies: ["app-read"], displayName: "grant", why: "test") },
            revokeSelf: { _, _ in },
            remoteStatus: { _ in "Secrets: no grant\nSSH: no certificate\nPush: no token" },
            remoteRunningTasks: { _ in RunningTasksResult(tasks: [], brokerUnavailable: false) },
            remoteRevokeHost: { _ in "Revoked the grant at OpenBao and removed local credentials." },
            recordedRemoteAccessors: { _ in [] },
            revokeRemoteAccessor: { _, _, _ in },
            removeRecordedRemoteAccessor: { _, _ in },
            executeGrant: { _, _, _ in GrantOutcome(message: "Granted.") },
            recordActivity: { _ in },
            emitTelemetry: { _, _ in },
            scheduleExpiryNotification: { _, _, _, _ in },
            cancelExpiryNotification: { _ in },
            detectBiometry: { ("Touch ID", "touchid") }
        )
    }

    // MARK: - 1. Local read / issuer errors & local revoke cleanup retry

    func testRefreshReportsUnknownOnKeychainReadErrorAndIssuerOutage() async {
        let profile = makeProfile(id: "srv-a", name: "Server A", address: "https://a.example:8200")
        var deps = baseDeps(collection: ProfileCollection(activeProfileID: profile.id, profiles: [profile]))
        deps.readLocalGrant = { _ in throw MacKeychainError.writeFailed(errSecInteractionNotAllowed) }

        let state = MenuBarState(dependencies: deps)
        await state.refreshAll()
        XCTAssertTrue(state.localGrantStatus.isUnknown)
        XCTAssertFalse(state.isMacActive)
        XCTAssertTrue(state.localGrantStatus.unknownReason?.contains("Keychain unavailable") == true)

        // Now Keychain returns a live token, but OpenBao is unreachable / returns generic 403 permission denied.
        var deps2 = baseDeps(collection: ProfileCollection(activeProfileID: profile.id, profiles: [profile]))
        deps2.readLocalGrant = { _ in "s.live-local" }
        deps2.lookupSelf = { _, _ in throw OpenBaoError.httpError(403, "permission denied") }

        let state2 = MenuBarState(dependencies: deps2)
        await state2.refreshAll()
        XCTAssertTrue(state2.localGrantStatus.isUnknown)
        XCTAssertTrue(state2.localGrantStatus.unknownReason?.contains("Couldn't verify") == true)

        // Generic HTTP 403 (even with text like "bad token") remains unknown unless OpenBaoClient maps it to .inactiveToken.
        var deps2b = baseDeps(collection: ProfileCollection(activeProfileID: profile.id, profiles: [profile]))
        deps2b.readLocalGrant = { _ in "s.ambiguous" }
        deps2b.lookupSelf = { _, _ in throw OpenBaoError.httpError(403, "bad token") }

        let state2b = MenuBarState(dependencies: deps2b)
        await state2b.refreshAll()
        XCTAssertTrue(state2b.localGrantStatus.isUnknown)

        // Confirmed invalid token (`.inactiveToken`) transitions cleanly to `.inactive`.
        var deps3 = baseDeps(collection: ProfileCollection(activeProfileID: profile.id, profiles: [profile]))
        deps3.readLocalGrant = { _ in "s.expired" }
        deps3.lookupSelf = { _, _ in throw OpenBaoError.inactiveToken }

        let state3 = MenuBarState(dependencies: deps3)
        await state3.refreshAll()
        XCTAssertEqual(state3.localGrantStatus, .inactive)
    }

    func testRevokeMacGrantFailsHonestlyOnKeychainReadError() async {
        let profile = makeProfile(id: "srv-a", name: "Server A", address: "https://a.example:8200")
        var recordedActivities: [GrantActivityEntry] = []
        var revokeCalled = false
        var cancelCalled = false

        var deps = baseDeps(collection: ProfileCollection(activeProfileID: profile.id, profiles: [profile]))
        deps.readLocalGrant = { _ in throw MacKeychainError.writeFailed(errSecAuthFailed) }
        deps.revokeSelf = { _, _ in revokeCalled = true }
        deps.recordActivity = { recordedActivities.append($0) }
        deps.cancelExpiryNotification = { _ in cancelCalled = true }

        let state = MenuBarState(dependencies: deps)
        await state.revokeMacGrant()

        XCTAssertNotNil(state.errorMessage)
        XCTAssertNil(state.bannerMessage)
        XCTAssertFalse(revokeCalled)
        XCTAssertFalse(cancelCalled)
        XCTAssertTrue(recordedActivities.isEmpty)
    }

    func testRevokeMacGrantRetriesLocalCleanupWithoutCallingOpenBaoAgain() async {
        let profile = makeProfile(id: "srv-a", name: "Server A", address: "https://a.example:8200")
        var revokeCalls = 0
        var deleteCalls = 0
        var deleteShouldFail = true
        var telemetryCalls = 0
        var storedToken: String? = "s.local-retry"

        var deps = baseDeps(collection: ProfileCollection(activeProfileID: profile.id, profiles: [profile]))
        deps.readLocalGrant = { _ in storedToken }
        deps.revokeSelf = { _, _ in revokeCalls += 1 }
        deps.deleteRevokedLocalGrant = { _, matching in
            deleteCalls += 1
            if deleteShouldFail {
                throw MacKeychainError.writeFailed(errSecInteractionNotAllowed)
            }
            if storedToken == matching {
                storedToken = nil
            }
        }
        deps.emitTelemetry = { _, _ in telemetryCalls += 1 }

        let state = MenuBarState(dependencies: deps)

        // First attempt: OpenBao confirms revoke, local Keychain cleanup fails.
        await state.revokeMacGrant()
        XCTAssertEqual(revokeCalls, 1)
        XCTAssertEqual(deleteCalls, 1)
        XCTAssertEqual(telemetryCalls, 0, "revoke must not add telemetry emission")
        XCTAssertEqual(state.bannerMessage, "Revoked at OpenBao.")
        XCTAssertTrue(state.errorMessage?.contains("Local Keychain cleanup is incomplete") == true)
        XCTAssertTrue(state.localGrantStatus.isUnknown)
        XCTAssertEqual(state.pendingLocalCleanupByIssuer[profile.openbao.issuerBindingKey], "s.local-retry")

        // Second attempt (retry): skips OpenBao revokeSelf and finishes local Keychain deletion.
        deleteShouldFail = false
        await state.revokeMacGrant()
        XCTAssertEqual(revokeCalls, 1, "same-grant cleanup retry must not call revokeSelf again")
        XCTAssertEqual(deleteCalls, 2)
        XCTAssertNil(state.errorMessage)
        XCTAssertEqual(state.bannerMessage, "Revoked Mac grant.")
        XCTAssertEqual(state.localGrantStatus, .inactive)
        XCTAssertNil(state.pendingLocalCleanupByIssuer[profile.openbao.issuerBindingKey])
    }

    // MARK: - 2. Remote accessor availability & partial revoke result

    func testRemoteRevokeAvailableWhenHostUnavailableAndReportsPartialCleanup() async {
        let target = makeTarget(name: "Bastion", host: "bastion.example")
        let profile = makeProfile(id: "srv-a", name: "Server A", address: "https://a.example:8200", targets: [target])

        var accessors = [GrantAccessorStore.Entry(accessor: "acc-1", expiresAt: Date().addingTimeInterval(3600))]
        var revokedAccessors: [String] = []
        var activities: [GrantActivityEntry] = []
        var cancelledNotifs: [String] = []
        var telemetryCalls = 0

        var deps = baseDeps(collection: ProfileCollection(activeProfileID: profile.id, profiles: [profile]))
        deps.remoteStatus = { _ in throw T3GranterError.timedOut("status") }
        deps.recordedRemoteAccessors = { _ in accessors }
        deps.revokeRemoteAccessor = { _, acc, _ in revokedAccessors.append(acc) }
        deps.removeRecordedRemoteAccessor = { _, acc in accessors.removeAll { $0.accessor == acc } }
        deps.remoteRevokeHost = { _ in throw T3GranterError.timedOut("revoke") }
        deps.recordActivity = { activities.append($0) }
        deps.cancelExpiryNotification = { cancelledNotifs.append($0) }
        deps.emitTelemetry = { _, _ in telemetryCalls += 1 }

        let state = MenuBarState(dependencies: deps)
        await state.refreshAll()

        XCTAssertEqual(state.remoteUnavailable, "Unavailable")
        XCTAssertTrue(state.hasRecordedRemoteAccessor)
        XCTAssertTrue(state.canRevokeRemote, "Revoke must stay available when host is unreachable and accessor exists")

        await state.revokeRemoteGrant()
        XCTAssertEqual(revokedAccessors, ["acc-1"])
        XCTAssertTrue(accessors.isEmpty)
        XCTAssertEqual(state.bannerMessage, "Revoked through OpenBao.")
        XCTAssertTrue(state.errorMessage?.contains("didn't confirm deleting its local copies") == true)
        XCTAssertEqual(activities.count, 1)
        XCTAssertEqual(activities.first?.action, .revoked)
        XCTAssertEqual(cancelledNotifs, ["srv-a.Bastion"])
        XCTAssertEqual(telemetryCalls, 0, "revoke must not add telemetry emission")
    }

    // MARK: - 3. Stale refresh protection & timer non-cancellation

    func testStaleRefreshDoesNotOverwriteSwitchedProfileAndTimerDoesNotCancelMutation() async {
        let profileA = makeProfile(id: "srv-a", name: "Server A", address: "https://a.example:8200")
        let profileB = makeProfile(id: "srv-b", name: "Server B", address: "https://b.example:8200")

        let (started, signal) = AsyncStream<Void>.makeStream()
        var releaseLookupA: CheckedContinuation<TokenLookupInfo, Error>?
        var lookupACalls = 0
        var lookupBCalls = 0

        var deps = baseDeps(collection: ProfileCollection(activeProfileID: profileA.id, profiles: [profileA, profileB]))
        deps.readLocalGrant = { p in p.id == "srv-a" ? "s.token-a" : nil }
        deps.lookupSelf = { p, _ in
            if p.id == "srv-a" {
                lookupACalls += 1
                return try await withCheckedThrowingContinuation { cont in
                    releaseLookupA = cont
                    signal.yield(())
                    signal.finish()
                }
            } else {
                lookupBCalls += 1
                return TokenLookupInfo(ttlSeconds: 100, policies: ["app-read"], displayName: "b", why: "")
            }
        }

        let state = MenuBarState(dependencies: deps)
        let firstTask = state.scheduleRefresh(force: true)
        for await _ in started { break }
        XCTAssertEqual(lookupACalls, 1)

        // A non-forced timer refresh while same-scope refresh is already running coalesces (does not cancel/re-invoke).
        let coalesced = state.scheduleRefresh(force: false)
        XCTAssertEqual(coalesced, firstTask)
        XCTAssertEqual(lookupACalls, 1)

        // Switch to Server B while Server A's lookup is still in flight.
        state.selectProfile(id: profileB.id)
        await Task.yield()

        // Complete Server A's stale lookup with an active grant.
        releaseLookupA?.resume(returning: TokenLookupInfo(ttlSeconds: 3600, policies: ["app-read"], displayName: "a", why: "stale"))
        await firstTask?.value
        // Allow Server B's refresh to settle.
        await state.refreshAll(force: false)

        XCTAssertEqual(state.activeProfileID, profileB.id)
        XCTAssertEqual(state.localGrantStatus, .inactive, "Server A's stale result must never overwrite Server B")
        XCTAssertEqual(lookupBCalls, 0)

        // While a mutation is in flight, non-forced timer refresh is skipped and does not cancel work.
        state.isMutating = true
        XCTAssertNil(state.scheduleRefresh(force: false))
        state.isMutating = false
    }

    // MARK: - 4. PendingRemoteTaskWarning binding & mutation re-entrancy

    func testPendingRemoteTaskWarningStaysBoundAndClearsOnTargetSwitch() async {
        let targetA = makeTarget(name: "Host A", host: "a.internal")
        let targetB = makeTarget(name: "Host B", host: "b.internal", key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockHostKeyB")
        let profile = makeProfile(id: "srv-a", name: "Server A", address: "https://a.example:8200", targets: [targetA, targetB])

        var executedTargets: [String] = []
        var deps = baseDeps(collection: ProfileCollection(activeProfileID: profile.id, profiles: [profile]))
        deps.remoteRunningTasks = { p in
            RunningTasksResult(tasks: ["deploy on \(p.targetDisplayName)"], brokerUnavailable: false)
        }
        deps.executeGrant = { p, _, _ in
            executedTargets.append(p.targetDisplayName)
            return GrantOutcome(message: "Granted on \(p.targetDisplayName).")
        }

        let state = MenuBarState(dependencies: deps)
        state.target = .t3
        state.selectedPolicies = ["app-read"]

        await state.submitComposerGrant()
        XCTAssertEqual(state.pendingWarning?.profile.targetDisplayName, "Host A")

        // Switching remote targets clears the warning so it cannot be confirmed for Host B.
        state.selectRemoteTarget(id: targetB.id)
        XCTAssertNil(state.pendingWarning)

        // Confirming a bound warning delivers to the bound profile even if active profile changed underneath.
        await state.submitComposerGrant()
        XCTAssertEqual(state.pendingWarning?.profile.targetDisplayName, "Host B")
        state.selectedRemoteTargetID = targetA.id
        await state.confirmPendingGrant()
        XCTAssertEqual(executedTargets, ["Host B"])
    }

    // MARK: - 5. MacSettingsLogic: scoped builder key, collector headers, derived audience

    func testMacSettingsLogicScopedKeyHeadersAndAudience() {
        let pemA = "-----BEGIN PUBLIC KEY-----\nKEY_A\n-----END PUBLIC KEY-----"
        let pemB = "-----BEGIN PUBLIC KEY-----\nKEY_B\n-----END PUBLIC KEY-----"
        let profileA = makeProfile(id: "a", name: "A", address: "https://a.example:8200")
        let profileB = makeProfile(id: "b", name: "B", address: "https://b.example:8200")

        let keyForB = MacSettingsLogic.scopedPublicKeyPEM(for: profileB) { p, _ in
            p.id == "a" ? pemA : pemB
        }
        XCTAssertEqual(keyForB, pemB, "Builder must load the key scoped to the selected card's profile, not the active one")
        XCTAssertEqual(MacSettingsLogic.scopedPublicKeyPEM(for: nil) { _, _ in pemA }, "")

        // Collector headers preserved only for canonical equivalent OTLP endpoint.
        let existingTelemetry = BaoTelemetryConfig(
            otlpEndpoint: "https://otel-a.corp.example:443/v1/",
            serviceName: "baobuddy-client",
            headers: ["Authorization": "Bearer collector-a-secret"]
        )
        let sameEndpoint = MacSettingsLogic.resolvedTelemetry(
            existing: existingTelemetry,
            newEndpoint: "https://OTEL-A.CORP.EXAMPLE/v1"
        )
        XCTAssertEqual(sameEndpoint.headers, existingTelemetry.headers)

        let changedHost = MacSettingsLogic.resolvedTelemetry(
            existing: existingTelemetry,
            newEndpoint: "https://otel-b.corp.example:4318"
        )
        XCTAssertTrue(changedHost.headers.isEmpty, "Changing OTLP collector must clear prior auth headers")

        for changed in ["https://otel-a.corp.example:443/another", "https://otel-a.corp.example:443/v1/#different"] {
            XCTAssertTrue(MacSettingsLogic.resolvedTelemetry(existing: existingTelemetry, newEndpoint: changed).headers.isEmpty)
        }

        let clearedEndpoint = MacSettingsLogic.resolvedTelemetry(
            existing: existingTelemetry,
            newEndpoint: "   "
        )
        XCTAssertTrue(clearedEndpoint.headers.isEmpty)

        // Derived baobuddy:// audience re-derives cleanly when rotating CA PEM without touching Advanced Settings.
        let origExpected = profileA.openbao.expectedOriginMountAudience
        let rederived = MacSettingsLogic.resolvedAudience(
            rawAudience: origExpected,
            originalExpectedAudience: origExpected,
            derivedAudience: BaoOpenBaoConfig.defaultAudience(
                address: profileA.openbao.address,
                namespace: profileA.openbao.namespace,
                mount: profileA.openbao.jwtAuth.mount,
                caPEM: "-----BEGIN CERTIFICATE-----\nNEW_CA\n-----END CERTIFICATE-----",
                mtlsClientIdentity: ""
            )
        )
        XCTAssertNotEqual(rederived, origExpected)
        XCTAssertTrue(rederived.contains("pin="))

        // Deliberate custom IdP audience is preserved verbatim.
        let customAud = MacSettingsLogic.resolvedAudience(
            rawAudience: "https://idp.corp.example/openbao",
            originalExpectedAudience: origExpected,
            derivedAudience: BaoOpenBaoConfig.defaultAudience(
                address: profileA.openbao.address,
                namespace: "",
                mount: "jwt-alice",
                caPEM: "",
                mtlsClientIdentity: ""
            )
        )
        XCTAssertEqual(customAud, "https://idp.corp.example/openbao")
    }
}
#endif
