@testable import BaoBuddyCore
import Foundation
import XCTest

final class ExtensionTests: XCTestCase {
    func testBuiltInTemplatesAreDisabledByDefaultAndValid() throws {
        XCTAssertGreaterThanOrEqual(BaoCredentialExtension.builtInTemplates.count, 5)
        for template in BaoCredentialExtension.builtInTemplates {
            XCTAssertFalse(template.enabled, "Built-in template '\(template.id)' should be disabled by default")
        }

        let profile = BaoProfile(
            version: 1,
            name: "Extensions Test",
            openbao: .init(
                address: "https://vault.corp.example:8200",
                caPEM: "",
                jwtAuth: .init(mount: "jwt-alice", role: "granter", issuer: "bao-granter", audience: "openbao-granter", subject: "alice"),
                tokenRoles: .init(mac: "grant", t3: "grant"),
                extensions: BaoCredentialExtension.builtInTemplates,
                maxHours: 8,
                keys: [],
                ssh: .init(role: "", hosts: []),
                githubAppItem: ""
            )
        )
        try profile.validate()
        XCTAssertTrue(profile.openbao.enabledExtensions.isEmpty)
    }

    func testValidationRejectsUnsafeExtensionEndpointOrFilename() {
        let baseOpenBao = BaoOpenBaoConfig(
            address: "https://vault.corp.example:8200",
            caPEM: "",
            jwtAuth: .init(mount: "jwt-alice", role: "granter", issuer: "bao-granter", audience: "openbao-granter", subject: "alice"),
            tokenRoles: .init(mac: "grant", t3: "grant"),
            maxHours: 8,
            keys: [],
            ssh: .init(role: "", hosts: []),
            githubAppItem: ""
        )

        var badEndpoint = BaoProfile(version: 1, name: "Bad", openbao: baseOpenBao)
        badEndpoint.openbao.extensions = [
            .init(id: "bad", label: "Bad", endpoint: "aws/../sys/raw", deliverAs: "out.json")
        ]
        XCTAssertThrowsError(try badEndpoint.validate())

        var badFile = BaoProfile(version: 1, name: "Bad", openbao: baseOpenBao)
        badFile.openbao.extensions = [
            .init(id: "bad", label: "Bad", endpoint: "aws/sts/deploy", deliverAs: ".hidden")
        ]
        XCTAssertThrowsError(try badFile.validate())
    }

    func testOpenBaoClientInvokesGetAndPostExtensions() async throws {
        let transport = MockHTTPTransport { req in
            switch (req.httpMethod, req.url?.path) {
            case ("POST", "/v1/aws/sts/deploy"):
                let payload: [String: Any] = [
                    "lease_duration": 3600,
                    "data": [
                        "access_key": "ASIAEXAMPLE",
                        "secret_key": "secret123",
                        "security_token": "tok123"
                    ]
                ]
                return (200, try JSONSerialization.data(withJSONObject: payload))
            case ("POST", "/v1/github/token/push"):
                let payload: [String: Any] = [
                    "data": [
                        "token": "ghs_example123",
                        "expires_at": "2030-01-01T00:00:00Z"
                    ]
                ]
                return (200, try JSONSerialization.data(withJSONObject: payload))
            default:
                return (404, Data())
            }
        }

        let client = OpenBaoClient(
            baseURL: URL(string: "https://vault.corp.example:8200")!,
            transport: transport,
            namespace: "admin/prod"
        )

        let awsTemplate = try XCTUnwrap(BaoCredentialExtension.builtInTemplates.first(where: { $0.id == "aws-sts" }))
        let awsArtifact = try await client.invokeExtension(awsTemplate, authToken: "s.signin")
        XCTAssertEqual(awsArtifact.name, "aws-creds.json")
        XCTAssertTrue(awsArtifact.content.contains("ASIAEXAMPLE"))
        XCTAssertNotNil(awsArtifact.expiresAt)

        let ghTemplate = try XCTUnwrap(BaoCredentialExtension.builtInTemplates.first(where: { $0.id == "git-push" }))
        let ghArtifact = try await client.invokeExtension(ghTemplate, authToken: "s.signin")
        XCTAssertEqual(ghArtifact.name, "push-token")
        XCTAssertEqual(ghArtifact.content, "ghs_example123")
        XCTAssertNotNil(ghArtifact.expiresAt)
    }
}
