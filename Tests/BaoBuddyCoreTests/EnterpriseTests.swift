@testable import BaoBuddyCore
import Foundation
import XCTest

final class EnterpriseTests: XCTestCase {
    private func makeProfile(
        namespace: String = "",
        caPEM: String = "",
        mtlsIdentity: String = "",
        auditPolicy: BaoAuditPolicy = .none,
        catalog: [BaoBuddyPolicy] = [
            .init(name: "db-readonly", label: "DB Read-Only", elevated: false, defaultSelected: true),
            .init(name: "k8s-deploy", label: "K8s Deploy", elevated: true, defaultSelected: false)
        ]
    ) -> BaoProfile {
        BaoProfile(
            version: 1,
            name: "Enterprise Prod",
            openbao: .init(
                address: "https://vault.corp.example:8200",
                namespace: namespace,
                caPEM: caPEM,
                mtlsClientIdentity: mtlsIdentity,
                jwtAuth: .init(
                    mount: "jwt-alice",
                    role: "granter",
                    issuer: "bao-granter",
                    audience: "openbao-granter",
                    subject: "alice"
                ),
                tokenRoles: .init(mac: "grant", t3: "grant"),
                grantPolicies: catalog,
                auditPolicy: auditPolicy,
                maxHours: 8,
                keys: [],
                ssh: .init(role: "", hosts: []),
                githubAppItem: ""
            )
        )
    }

    // MARK: - Namespaces (X-Vault-Namespace)

    func testOpenBaoClientSendsNamespaceHeaderOnAPICalls() async throws {
        var seenNamespaces: [String: String?] = [:]
        let transport = MockHTTPTransport { req in
            let path = req.url?.path ?? ""
            seenNamespaces[path] = req.value(forHTTPHeaderField: "X-Vault-Namespace")
            switch path {
            case "/v1/sys/health":
                let data = try JSONSerialization.data(withJSONObject: ["initialized": true, "sealed": false, "version": "2.7.2"])
                return (200, data)
            case "/v1/auth/jwt-alice/login":
                let data = try JSONSerialization.data(withJSONObject: ["auth": ["client_token": "s.signin123"]])
                return (200, data)
            case "/v1/auth/token/lookup-self":
                let data = try JSONSerialization.data(withJSONObject: ["data": ["ttl": 120, "policies": ["db-readonly"], "display_name": "grant", "meta": [:]]])
                return (200, data)
            case "/v1/auth/token/revoke-self":
                return (204, Data())
            default:
                return (404, Data())
            }
        }

        let client = OpenBaoClient(
            baseURL: URL(string: "https://vault.corp.example:8200")!,
            transport: transport,
            namespace: "admin/prod-us-east"
        )

        _ = try await client.checkHealth()
        let token = try await client.loginJWT(mount: "jwt-alice", role: "granter", jwt: "a.b.c")
        _ = try await client.lookupSelf(token: token)
        try await client.revokeSelf(token: token)

        // /v1/sys/health runs at root; all other API calls carry X-Vault-Namespace.
        XCTAssertNil(seenNamespaces["/v1/sys/health"] ?? .none)
        XCTAssertEqual(seenNamespaces["/v1/auth/jwt-alice/login"] ?? .none, "admin/prod-us-east")
        XCTAssertEqual(seenNamespaces["/v1/auth/token/lookup-self"] ?? .none, "admin/prod-us-east")
        XCTAssertEqual(seenNamespaces["/v1/auth/token/revoke-self"] ?? .none, "admin/prod-us-east")
    }

    func testNamespaceValidationAcceptsNestedAndRejectsTraversal() throws {
        try makeProfile(namespace: "admin/prod-us-east").validate()
        try makeProfile(namespace: "finance").validate()
        try makeProfile(namespace: "").validate()

        for bad in ["/admin", "admin/", "admin//prod", "admin/../root", "prod space"] {
            XCTAssertThrowsError(try makeProfile(namespace: bad).validate(), "Expected '\(bad)' to fail")
        }
    }

    // MARK: - Audit & Change-Ticket Policy Enforcement

    func testAuditPolicyRequiresReasonForElevatedOnly() throws {
        let profile = makeProfile(
            auditPolicy: .init(requireReason: false, requireReasonForElevated: true)
        )
        let standard = GrantRequest(target: .mac, hours: 1, customPolicies: ["db-readonly"], why: "")
        try standard.validate(against: profile)

        let elevatedNoWhy = GrantRequest(target: .mac, hours: 1, customPolicies: ["k8s-deploy"], why: "")
        XCTAssertThrowsError(try elevatedNoWhy.validate(against: profile)) { error in
            XCTAssertEqual(error as? GrantRequestError, .reasonRequired(elevatedOnly: true))
        }

        let elevatedWithWhy = GrantRequest(target: .mac, hours: 1, customPolicies: ["k8s-deploy"], why: "CHG-1042 deploy")
        try elevatedWithWhy.validate(against: profile)
    }

    func testAuditPolicyRequiresReasonAndTicketPattern() throws {
        let profile = makeProfile(
            auditPolicy: .init(
                requireReason: true,
                requireReasonForElevated: true,
                reasonPattern: "^(INC|CHG|JIRA)-[0-9]+",
                reasonPlaceholder: "INC-12345 — summary"
            )
        )

        let empty = GrantRequest(target: .mac, hours: 1, customPolicies: ["db-readonly"], why: "")
        XCTAssertThrowsError(try empty.validate(against: profile)) { error in
            XCTAssertEqual(error as? GrantRequestError, .reasonRequired(elevatedOnly: false))
        }

        let mismatch = GrantRequest(target: .mac, hours: 1, customPolicies: ["db-readonly"], why: "quick debug")
        XCTAssertThrowsError(try mismatch.validate(against: profile)) { error in
            XCTAssertEqual(error as? GrantRequestError, .reasonPatternMismatch("INC-12345 — summary"))
        }

        let valid = GrantRequest(target: .mac, hours: 1, customPolicies: ["db-readonly"], why: "INC-4821 investigate timeout #12")
        try valid.validate(against: profile)
    }

    func testProfileValidationRejectsInvalidAuditRegex() {
        let badRegex = makeProfile(auditPolicy: .init(reasonPattern: "[unclosed"))
        XCTAssertThrowsError(try badRegex.validate())
    }

    // MARK: - MDM Governance Controls

    func testMDMEnforceTLSPinningAndElevatedReason() throws {
        let unpinned = makeProfile(caPEM: "")
        let pinned = makeProfile(caPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
        let data = try JSONEncoder().encode([unpinned, pinned])
        let jsonString = try XCTUnwrap(String(data: data, encoding: .utf8))

        let managed = ManagedAppConfig.parse(dictionary: [
            "profiles_json": jsonString,
            "lock_profiles": true,
            "disable_clipboard": true,
            "enforce_tls_pinning": true,
            "require_reason_for_elevated": true
        ])

        XCTAssertTrue(managed.isManaged)
        XCTAssertTrue(managed.lockProfiles)
        XCTAssertTrue(managed.disableClipboard)
        XCTAssertTrue(managed.enforceTLSPinning)
        XCTAssertTrue(managed.requireReasonForElevated)
        XCTAssertEqual(managed.profiles.count, 1)
        XCTAssertTrue(managed.profiles[0].openbao.isTLSPinned)
        XCTAssertTrue(managed.profiles[0].openbao.auditPolicy.requireReasonForElevated)
    }

    // MARK: - JSON Round-Trip Cleanliness

    func testEnterpriseFieldsRoundTripAndOmitWhenEmpty() throws {
        let minimal = makeProfile()
        let minimalData = try JSONEncoder().encode(minimal)
        let minimalJSON = try XCTUnwrap(String(data: minimalData, encoding: .utf8))
        XCTAssertFalse(minimalJSON.contains("\"namespace\""))
        XCTAssertFalse(minimalJSON.contains("\"mtls_client_identity\""))
        XCTAssertFalse(minimalJSON.contains("\"audit_policy\""))

        let full = makeProfile(
            namespace: "org/payments",
            mtlsIdentity: "alice.vault.corp.example",
            auditPolicy: .init(
                requireReason: true,
                requireReasonForElevated: true,
                reasonPattern: "^CHG-[0-9]+",
                reasonPlaceholder: "CHG-0001"
            )
        )
        let fullData = try JSONEncoder().encode(full)
        let decoded = try BaoProfile.decode(from: fullData)
        XCTAssertEqual(decoded.openbao.namespace, "org/payments")
        XCTAssertEqual(decoded.openbao.mtlsClientIdentity, "alice.vault.corp.example")
        XCTAssertEqual(decoded.openbao.auditPolicy, full.openbao.auditPolicy)
    }
}
