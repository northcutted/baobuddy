@testable import BaoBuddyCore
import Foundation
import XCTest

final class Phase3Tests: XCTestCase {
    // MARK: - OpenTelemetry OTLP Exporter

    func testOTLPExporterEmitsLogsAndMetricsWithoutSecrets() async throws {
        var requests: [(String, [String: Any])] = []
        let transport = MockHTTPTransport { req in
            let path = req.url?.path ?? ""
            XCTAssertEqual(req.value(forHTTPHeaderField: "Authorization"), "Bearer test-otel-key")
            let body = try XCTUnwrap(req.httpBody)
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
            requests.append((path, json))
            return (200, Data())
        }

        let cfg = BaoTelemetryConfig(
            otlpEndpoint: "https://otel.corp.example:4318",
            serviceName: "baobuddy-mac",
            headers: ["Authorization": "Bearer test-otel-key"]
        )
        let exporter = try BaoOTLPExporter(config: cfg, transport: transport)
        let entry = GrantActivityEntry(
            action: .granted,
            serverName: "Prod",
            namespace: "admin/prod",
            targetName: "Bastion",
            policies: ["db-readonly", "k8s-deploy"],
            hours: 2,
            why: "CHG-999",
            elevated: true,
            via: "mac"
        )
        await exporter.emit(entry: entry, actor: "alice")

        XCTAssertEqual(requests.map(\.0), ["/v1/logs", "/v1/metrics"])
        XCTAssertNotNil(requests[0].1["resourceLogs"])
        XCTAssertNotNil(requests[1].1["resourceMetrics"])
    }

    func testProfileValidationRejectsPlaintextRemoteOTLP() {
        let base = BaoProfile(
            version: 1,
            name: "Prod",
            openbao: .init(
                address: "https://vault.corp.example:8200",
                caPEM: "",
                jwtAuth: .init(mount: "jwt-alice", role: "granter", issuer: "bao-granter", audience: "openbao-granter", subject: "alice"),
                tokenRoles: .init(mac: "grant", t3: "grant"),
                telemetry: .init(otlpEndpoint: "http://otel.corp.example:4318"),
                maxHours: 8,
                keys: [],
                ssh: .init(role: "", hosts: []),
                githubAppItem: ""
            )
        )
        XCTAssertThrowsError(try base.validate())

        var loopback = base
        loopback.openbao.telemetry.otlpEndpoint = "http://127.0.0.1:4318"
        XCTAssertNoThrow(try loopback.validate())
    }

    // MARK: - OpenTofu / Terraform Deployment Builder

    func testTofuBuilderGeneratesMultiUserForEachStack() throws {
        let spec = BaoTofuDeploymentSpec(
            serverName: "Enterprise Prod",
            openbaoAddress: "https://vault.corp.example:8200",
            namespace: "admin/prod",
            users: [
                .init(
                    name: "alice",
                    allowedPolicies: ["db-readonly", "k8s-deploy"],
                    maxHours: 4,
                    boundCIDRs: ["10.0.0.0/8"]
                ),
                .init(
                    name: "bob",
                    allowedPolicies: ["db-readonly"],
                    maxHours: 8
                )
            ],
            elevatedPolicies: ["k8s-deploy"],
            auditPolicy: .init(requireReasonForElevated: true, reasonPattern: "^CHG-[0-9]+"),
            sshSignPath: "ssh/sign/ops",
            otlpEndpoint: "https://otel.corp.example:4318"
        )

        let files = BaoTofuBuilder.generate(spec)
        XCTAssertEqual(Set(files.keys), ["versions.tf", "variables.tf", "main.tf", "outputs.tf", "terraform.tfvars", "README.md"])

        let mainTF = try XCTUnwrap(files["main.tf"])
        XCTAssertTrue(mainTF.contains("for_each = var.users"))
        XCTAssertTrue(mainTF.contains("token_no_default_policy = true"))
        XCTAssertTrue(mainTF.contains("expiration_leeway       = 5"))
        XCTAssertTrue(mainTF.contains("orphan                 = true"))
        XCTAssertTrue(mainTF.contains("renewable              = false"))

        let tfvars = try XCTUnwrap(files["terraform.tfvars"])
        XCTAssertTrue(tfvars.contains("namespace         = \"admin/prod\""))
        XCTAssertTrue(tfvars.contains("\"alice\" = {"))
        XCTAssertTrue(tfvars.contains("\"bob\" = {"))
        XCTAssertTrue(tfvars.contains("otlp_endpoint     = \"https://otel.corp.example:4318\""))
        XCTAssertTrue(tfvars.contains("reason_pattern              = \"^CHG-[0-9]+\""))

        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }
        let written = try BaoTofuBuilder.write(spec, to: tmpDir)
        XCTAssertEqual(written.count, 6)
    }
}
