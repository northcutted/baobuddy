import BaoBuddyCore
import BaoBuddySSH
import CryptoKit
import XCTest
@testable import BaoBuddy

final class BaoBuddyTests: XCTestCase {
    func testGrantRequestCanonicalRoundTrip() throws {
        let profile = BaoProfile(
            version: 1,
            openbao: .init(
                address: "https://openbao.example.com:8200",
                caPEM: "",
                jwtAuth: .init(
                    mount: "jwt-granter",
                    role: "operator",
                    issuer: "bao-granter",
                    audience: "openbao-granter",
                    subject: "operator"
                ),
                tokenRoles: .init(mac: "grant", t3: "grant-remote"),
                maxHours: 12,
                keys: [.init(name: "cluster", item: "cluster")],
                ssh: .init(role: "ops", hosts: [.init(name: "docker", user: "root", principal: "root-docker")]),
                githubAppItem: "ci/github-app"
            ),
            t3Granter: .init(name: "Build Host", host: "bastion.example.com", port: 22, user: "granter", hostKey: "")
        )
        let url = try XCTUnwrap(URL(string: "baobuddy://grant?r=HOURS%3D2%20SSH%3Ddocker%20WHY%3Dtest"))
        let req = try GrantRequest.parse(url: url, profile: profile)
        XCTAssertEqual(req.canonicalText, "HOURS=2 SSH=docker WHY=test")
        XCTAssertEqual(req.summary(profile: profile), "Grant to Build Host on openbao.example.com:8200 (2 hours): Read secrets; SSH (role ops): root@docker [principal: root-docker] — test")
    }

    private func profile(id: String, name: String) -> BaoProfile {
        BaoProfile(
            id: id,
            version: 1,
            name: name,
            openbao: .init(
                address: "https://\(id).example:8200",
                caPEM: "",
                jwtAuth: .init(mount: "jwt-a", role: "a", issuer: "i", audience: "aud", subject: "a"),
                tokenRoles: .init(mac: "grant", t3: "grant"),
                grantPolicies: [.init(name: "db-read", defaultSelected: true)],
                maxHours: 4,
                keys: [],
                ssh: .init(role: "", hosts: []),
                githubAppItem: ""
            )
        )
    }

    @MainActor
    func testDeepLinkBindsApprovalToItsProfileWithoutSwitchingActiveServer() throws {
        let model = AppModel()
        model.profiles = [profile(id: "home", name: "Home"), profile(id: "prod", name: "Prod")]
        model.activeProfileID = "home"

        model.handleIncomingURL(try XCTUnwrap(URL(string: "baobuddy://grant?profile=Prod&r=HOURS%3D1")))
        XCTAssertEqual(model.pending?.profileID, "prod")
        XCTAssertEqual(model.pendingProfile?.name, "Prod")
        XCTAssertEqual(model.activeProfileID, "home", "a link must not switch the saved active server")
    }

    @MainActor
    func testDeepLinkForUnknownProfileDoesNotFallBackToActiveServer() throws {
        let model = AppModel()
        model.profiles = [profile(id: "home", name: "Home")]
        model.activeProfileID = "home"
        model.handleIncomingURL(try XCTUnwrap(URL(string: "baobuddy://grant?profile=Prod&r=HOURS%3D1")))
        XCTAssertNil(model.pending)
        XCTAssertNotNil(model.errorMessage)
    }

    @MainActor
    func testDeepLinkIsIgnoredWhileApproving() throws {
        let model = AppModel()
        model.profiles = [profile(id: "home", name: "Home"), profile(id: "prod", name: "Prod")]
        model.activeProfileID = "home"
        model.presentApproval(for: GrantRequest(target: .mac, hours: 1), profile: model.profiles[0])
        model.isApproving = true
        model.handleIncomingURL(try XCTUnwrap(URL(string: "baobuddy://grant?profile=Prod&r=HOURS%3D4")))
        XCTAssertEqual(model.pending?.profileID, "home")
        XCTAssertEqual(model.pendingRequest?.hours, 1)
    }

    func testTargetStatusSummaryParsesActiveAndIdleLines() {
        let active = TargetStatusSummary.parse("""
        Secrets: read until 08:42 AM, why: deploy.
        SSH: docker until 08:42 AM.
        Push: no token.
        """)
        XCTAssertTrue(active.hasActiveGrant)
        XCTAssertEqual(active.entries.count, 3)
        XCTAssertTrue(active.entries[0].isActive)
        XCTAssertTrue(active.entries[1].isActive)
        XCTAssertFalse(active.entries[2].isActive)

        let idle = TargetStatusSummary.parse("""
        Secrets: no grant.
        SSH: no certificate.
        Push: no token.
        """)
        XCTAssertFalse(idle.hasActiveGrant)
        XCTAssertEqual(idle.entries.map(\.statusText), ["None", "None", "None"])

        let demoActive = TargetStatusSummary.parse("""
        Secrets: active (59m left; demo • files: db-creds.json).
        SSH: ops@staging-web (59m left).
        Push: no token.
        """)
        XCTAssertTrue(demoActive.hasActiveGrant)
        XCTAssertEqual(demoActive.entries[0].statusText, "Active · 59m left")
        XCTAssertEqual(demoActive.entries[0].detail, "demo • files: db-creds.json")
        XCTAssertEqual(demoActive.entries[1].statusText, "Active · 59m left")
        XCTAssertEqual(demoActive.entries[1].detail, "ops@staging-web", "Unix usernames must keep exact case")

        let unknownStatus = TargetStatusSummary.parse("""
        Secrets: unknown (couldn't reach OpenBao).
        SSH: certificate present
        Push: no token.
        """)
        XCTAssertEqual(unknownStatus.headerState, .unknown)
        XCTAssertTrue(unknownStatus.hasUnknownStatus)
        XCTAssertEqual(unknownStatus.entries[0].state, .unknown)
        XCTAssertEqual(unknownStatus.entries[0].statusText, "Unknown")
        XCTAssertEqual(unknownStatus.entries[0].detail, "couldn't reach OpenBao")
        XCTAssertEqual(unknownStatus.entries[1].statusText, "Active")
        XCTAssertEqual(unknownStatus.entries[1].detail, "")

        let humanized = AppModel.humanizeGrantBanner("Granted until 2026-11-23T00:45:24Z (demo · 1 credential file)")
        XCTAssertTrue(humanized.hasPrefix("Granted until "))
        XCTAssertFalse(humanized.contains("T00:45:24Z"))
        XCTAssertTrue(humanized.contains("1 credential file"))
    }

    func testOpenSSHPublicKeyFormat() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let line = SSHKeyStore.openSSHPublicKey(for: privateKey.publicKey, comment: "test-device")
        let parts = line.split(separator: " ")
        XCTAssertEqual(parts.count, 3)
        XCTAssertEqual(parts[0], "ssh-ed25519")
        XCTAssertEqual(parts[2], "test-device")

        let blob = try XCTUnwrap(Data(base64Encoded: String(parts[1])))
        // RFC 8709: uint32(11) + "ssh-ed25519" + uint32(32) + 32-byte pubkey = 51 bytes
        XCTAssertEqual(blob.count, 4 + 11 + 4 + 32)
        XCTAssertEqual(Array(blob.prefix(4)), [0, 0, 0, 11])
        XCTAssertEqual(String(data: blob.subdata(in: 4..<15), encoding: .utf8), "ssh-ed25519")
        XCTAssertEqual(Array(blob.subdata(in: 15..<19)), [0, 0, 0, 32])
        XCTAssertEqual(blob.subdata(in: 19..<51), privateKey.publicKey.rawRepresentation)
    }

    @MainActor
    func testDemoModeLaunchArgumentAndFullApprovalRevokeCycle() async throws {
        let model = AppModel(launchArguments: ["BaoBuddy", "-BaoBuddyDemo", "-BaoBuddyDemoScreen", "02_Approve"])
        XCTAssertTrue(model.isDemoMode)
        XCTAssertEqual(model.profile?.id, BaoDemo.profileID)
        XCTAssertNotNil(model.pendingRequest)

        // The screenshot sample is a standard grant with the db-demo extension.
        XCTAssertEqual(model.pendingRequest?.isElevated(profile: try XCTUnwrap(model.pendingProfile)), false)
        XCTAssertEqual(model.pendingRequest?.why, AppModel.demoSampleReason)
        let sampleHistory = model.demoActivity.count

        // Approve the simulated remote grant with the db-demo extension.
        await model.approvePendingGrant()
        XCTAssertNil(model.errorMessage)
        XCTAssertNil(model.pending)
        XCTAssertEqual(model.targetStatus?.hasActiveGrant, true)
        // Demo grants go to the in-memory demo log only.
        XCTAssertEqual(model.demoActivity.count, sampleHistory + 1)
        XCTAssertEqual(model.demoActivity.first?.action, .granted)

        // Revoke the simulated remote grant (re-runs ES256 JWT login + revoke-accessor).
        await model.revokeVMGrant()
        XCTAssertNil(model.errorMessage)
        XCTAssertEqual(model.targetStatus?.hasActiveGrant, false)

        // Also test Direct Token flow in Demo Mode.
        let demoProfile = try XCTUnwrap(model.profile)
        model.presentApproval(
            for: GrantRequest(target: .mac, hours: 1, customPolicies: ["db-readonly"], why: "demo direct", extensions: ["db-demo"]),
            profile: demoProfile
        )
        await model.approvePendingGrant()
        XCTAssertNotNil(model.directToken)
        XCTAssertEqual(model.directArtifacts.map(\.name), ["db-creds.json"])

        await model.revokeDirectToken()
        XCTAssertNil(model.directToken)

        // Exit demo removes all demo state cleanly.
        model.exitDemoMode()
        XCTAssertFalse(model.isDemoMode)
        XCTAssertFalse(model.profiles.contains(where: \.isDemoProfile))
        XCTAssertTrue(model.demoActivity.isEmpty)
    }

    @MainActor
    func testEmptyOnboardingDisablesPersistenceAndPreservesSavedProfiles() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("baobuddy-empty-onboarding-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        addTeardownBlock {
            try? FileManager.default.removeItem(at: tempDir)
        }

        let profilesURL = tempDir.appendingPathComponent("profiles.json")
        let legacyURL = tempDir.appendingPathComponent("legacy-profile.json")
        let accessorsURL = tempDir.appendingPathComponent("remote-grants.json")
        let profileStore = MultiProfileStore(url: profilesURL, legacyStore: FileProfileStore(url: legacyURL))
        let accessorStore = GrantAccessorStore(url: accessorsURL)

        let existing = profile(id: "prod", name: "Production Vault")
        try profileStore.save(ProfileCollection(activeProfileID: existing.id, profiles: [existing]))
        try accessorStore.record(
            profileID: existing.id,
            accessor: "acc-existing",
            expiresAt: Date().addingTimeInterval(3600)
        )
        let originalProfilesData = try Data(contentsOf: profilesURL)
        let originalAccessorsData = try Data(contentsOf: accessorsURL)
        let deviceDefaultsKey = "com.northcutt.baogrant.deviceName"
        let originalDeviceDefault = UserDefaults.standard.string(forKey: deviceDefaultsKey)

        let model = AppModel(
            launchArguments: ["BaoBuddy", "-BaoBuddyEmptyOnboarding"],
            profileStore: profileStore,
            accessorStore: accessorStore
        )
        XCTAssertTrue(model.persistenceDisabled)
        XCTAssertTrue(model.profiles.isEmpty)
        XCTAssertNil(model.activeProfileID)

        // Mutate profiles and deviceName in memory: none of these may touch disk or UserDefaults.
        let transient = profile(id: "staging", name: "Staging Vault")
        try model.upsertProfile(transient)
        XCTAssertEqual(model.profiles.map(\.id), ["staging"])
        model.selectProfile(id: transient.id)
        model.deviceName = "transient-ui-test-device"
        model.deleteProfile(id: transient.id)
        model.deleteProfile(id: existing.id)

        XCTAssertEqual(try Data(contentsOf: profilesURL), originalProfilesData)
        let reloaded = profileStore.load()
        XCTAssertEqual(reloaded.activeProfileID, "prod")
        XCTAssertEqual(reloaded.profiles.map(\.id), ["prod"])
        XCTAssertEqual(try Data(contentsOf: accessorsURL), originalAccessorsData)
        XCTAssertEqual(accessorStore.entry(profileID: "prod")?.accessor, "acc-existing")
        XCTAssertEqual(UserDefaults.standard.string(forKey: deviceDefaultsKey), originalDeviceDefault)

        // Keychain keys are off limits too: regenerating either key is refused, not performed.
        model.ensureDeviceKey(overwrite: true)
        XCTAssertEqual(model.errorMessage, AppModel.persistenceDisabledMessage)
        XCTAssertTrue(model.devicePublicKeyPEM.isEmpty)
        model.ensureSSHKey(overwrite: true)
        XCTAssertEqual(model.errorMessage, AppModel.persistenceDisabledMessage)
        XCTAssertTrue(model.sshPublicKey.isEmpty)
    }

    @MainActor
    func testDeepLinkFocusesSecondaryRemoteTargetWithoutMutatingBaseProfile() throws {
        let targetA = BaoT3GranterConfig(name: "Staging", host: "10.0.0.10", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA")
        let targetB = BaoT3GranterConfig(name: "Prod", host: "10.0.0.20", port: 22, user: "granter", hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB")
        var multi = profile(id: "multi", name: "Multi")
        multi.remoteTargets = [targetA, targetB]

        let model = AppModel(launchArguments: ["BaoBuddy", "-BaoBuddyEmptyOnboarding"])
        model.profiles = [multi]
        model.activeProfileID = multi.id

        let url = try XCTUnwrap(URL(string: "baobuddy://grant?profile=Multi&target=remote&remote_target=Prod&r=HOURS%3D1"))
        model.handleIncomingURL(url)

        XCTAssertEqual(model.pendingProfile?.t3Granter.host, "10.0.0.20")
        XCTAssertEqual(model.pendingProfile?.targetDisplayName, "Prod")
        XCTAssertEqual(model.profile?.t3Granter.host, "10.0.0.10", "base profile target order must remain unchanged")
    }

    @MainActor
    func testDeepLinkRejectsAmbiguousNamesAndConflictingHintsAndResolvesCrossDevice() throws {
        var prodUS = profile(id: "prod-us", name: "Prod")
        prodUS.openbao.address = "https://us.vault.example:8200"
        prodUS.openbao.namespace = ""
        prodUS.openbao.jwtAuth.mount = "jwt-alice"

        var prodEU = profile(id: "prod-eu", name: "Prod")
        prodEU.openbao.address = "https://eu.vault.example:8200"
        prodEU.openbao.namespace = "eu"
        prodEU.openbao.jwtAuth.mount = "jwt-alice"

        let model = AppModel(launchArguments: ["BaoBuddy", "-BaoBuddyEmptyOnboarding"])
        model.profiles = [prodUS, prodEU]
        model.activeProfileID = prodUS.id

        // Ambiguous display name must fail closed.
        model.handleIncomingURL(try XCTUnwrap(URL(string: "baobuddy://grant?profile=Prod&r=HOURS%3D1")))
        XCTAssertNil(model.pending)
        XCTAssertNotNil(model.errorMessage)

        // Exact profile_id with conflicting server hint must be rejected.
        model.errorMessage = nil
        model.handleIncomingURL(try XCTUnwrap(URL(string: "baobuddy://grant?profile_id=prod-us&server=https%3A%2F%2Feu.vault.example%3A8200&mount=jwt-alice&namespace=&r=HOURS%3D1")))
        XCTAssertNil(model.pending)
        XCTAssertNotNil(model.errorMessage)

        // Cross-device link with unknown profile_id resolves by exact (server, mount, namespace).
        model.errorMessage = nil
        model.handleIncomingURL(try XCTUnwrap(URL(string: "baobuddy://grant?profile_id=mac-other-id&profile=Prod&server=https%3A%2F%2Feu.vault.example%3A8200&mount=jwt-alice&namespace=eu&r=HOURS%3D1")))
        XCTAssertNil(model.errorMessage)
        XCTAssertEqual(model.pending?.profileID, "prod-eu")
    }

    @MainActor
    func testSetupWizardOrdersServerBeforeDeviceKeyAndScopesKeyAndSnippetPerServer() throws {
        // Fresh onboarding must configure Server BEFORE creating the server-scoped Device Key.
        XCTAssertEqual(SetupWizardStep.steps(hasRemoteTarget: false), [.server, .deviceKey, .verify])
        XCTAssertEqual(SetupWizardStep.steps(hasRemoteTarget: true), [.server, .deviceKey, .sshKey, .verify])

        // Without any server configured, ensureDeviceKey refuses cleanly (outside persistenceDisabled).
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("baobuddy-wizard-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: tempDir) }
        let store = MultiProfileStore(
            url: tempDir.appendingPathComponent("profiles.json"),
            legacyStore: FileProfileStore(url: tempDir.appendingPathComponent("legacy.json"))
        )
        let model = AppModel(
            launchArguments: ["BaoBuddy"],
            profileStore: store,
            accessorStore: GrantAccessorStore(url: tempDir.appendingPathComponent("accessors.json"))
        )
        model.profiles = []
        model.activeProfileID = nil
        model.ensureDeviceKey()
        XCTAssertNotNil(model.errorMessage)
        XCTAssertTrue(model.errorMessage?.contains("Add or select an OpenBao") == true)

        // Switching servers changes the scoped key identity and generates deployment-bound snippets.
        var serverA = profile(id: "srv-a", name: "Vault A")
        serverA.openbao.address = "https://proxy.example/vault-a"
        serverA.openbao.jwtAuth.mount = "jwt-alice"
        serverA.openbao.jwtAuth.subject = "alice"
        serverA.openbao.jwtAuth.audience = serverA.openbao.expectedOriginMountAudience

        var serverB = serverA
        serverB.id = "srv-b"
        serverB.name = "Vault B"
        serverB.openbao.address = "https://proxy.example/vault-b"
        serverB.openbao.jwtAuth.audience = serverB.openbao.expectedOriginMountAudience

        model.profiles = [serverA, serverB]
        model.activeProfileID = serverA.id
        let snippetA = model.openBaoSetupSnippet()
        XCTAssertTrue(snippetA.contains("granter-alice"))
        XCTAssertTrue(snippetA.contains("baobuddy://proxy.example/auth/jwt-alice?base=%2Fvault-a"))
        XCTAssertNotEqual(
            SecureEnclaveKeyStore.accountName(for: serverA),
            SecureEnclaveKeyStore.accountName(for: serverB)
        )
    }

    @MainActor
    func testImportPreservesDistinctSameURLDeploymentsWhileExplicitEditUpdatesInPlaceAndRejectsBadBoundAudience() throws {
        let model = AppModel(launchArguments: ["BaoBuddy", "-BaoBuddyEmptyOnboarding"])

        let jsonA = """
        {
          "version": 1,
          "name": "Gateway A",
          "openbao": {
            "address": "https://gateway.corp.example:8200",
            "namespace": "prod",
            "ca_pem": "-----BEGIN CERTIFICATE-----\\nCA-A\\n-----END CERTIFICATE-----",
            "mtls_client_identity": "client-a",
            "jwt_auth": { "mount": "jwt-alice", "role": "granter", "issuer": "bao-granter", "audience": "", "subject": "alice" },
            "token_roles": { "local": "grant-alice", "remote": "grant-alice" },
            "grant_policies": [{ "name": "db-readonly", "default_selected": true }]
          }
        }
        """
        let jsonB = jsonA
            .replacingOccurrences(of: "Gateway A", with: "Gateway B")
            .replacingOccurrences(of: "client-a", with: "client-b")

        model.importProfileJSON(jsonA)
        XCTAssertNil(model.errorMessage)
        XCTAssertEqual(model.profiles.count, 1)
        let firstID = try XCTUnwrap(model.profiles.first?.id)
        XCTAssertTrue(model.profiles[0].openbao.usesBoundAudience)
        XCTAssertTrue(model.profiles[0].openbao.jwtAuth.audience.contains("mtls="))
        XCTAssertTrue(model.profiles[0].openbao.jwtAuth.audience.contains("pin="))

        // Importing second same-URL deployment with different mTLS identity adds side-by-side instead of replacing.
        model.importProfileJSON(jsonB)
        XCTAssertNil(model.errorMessage)
        XCTAssertEqual(model.profiles.count, 2)
        XCTAssertEqual(model.profiles[0].id, firstID)
        XCTAssertNotEqual(model.profiles[1].id, firstID)

        // Explicit reviewed edit via upsertProfile updates firstID in-place even when changing CA/mTLS.
        var edited = model.profiles[0]
        edited.openbao.caPEM = "-----BEGIN CERTIFICATE-----\nCA-ROTATED\n-----END CERTIFICATE-----"
        edited.openbao.jwtAuth.audience = edited.openbao.expectedOriginMountAudience
        try model.upsertProfile(edited)
        XCTAssertEqual(model.profiles.count, 2)
        XCTAssertEqual(model.profiles.first(where: { $0.id == firstID })?.openbao.caPEM, edited.openbao.caPEM)

        // Importing a profile with an explicitly mismatched baobuddy:// audience fails at import time.
        let badAudJSON = jsonA.replacingOccurrences(
            of: #""audience": """#,
            with: #""audience": "baobuddy://gateway.corp.example:8200/ns/prod/auth/jwt-alice""#
        )
        model.importProfileJSON(badAudJSON)
        XCTAssertNotNil(model.errorMessage)
        XCTAssertEqual(model.profiles.count, 2)
    }
}
