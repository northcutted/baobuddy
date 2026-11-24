import Foundation

/// HTTP method used when invoking an OpenBao / Vault secrets engine extension endpoint.
public enum BaoExtensionMethod: String, Codable, Equatable, CaseIterable, Sendable {
    case get = "GET"
    case post = "POST"
}

/// A workflow-agnostic OpenBao / HashiCorp Vault dynamic credential extension.
///
/// Any secrets engine endpoint (AWS STS, Kubernetes tokens, Database dynamic creds,
/// PKI TLS certificates, GitHub App installation tokens, etc.) can be declared here
/// without hardcoding cloud- or workflow-specific logic into BaoBuddy.
public struct BaoCredentialExtension: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    public var label: String
    public var description: String
    public var icon: String
    /// OpenBao / Vault path relative to `v1/` (for example `aws/sts/deploy` or `github/token/push`).
    public var endpoint: String
    public var method: BaoExtensionMethod
    /// Optional static JSON body parameters sent on POST requests (for example `{"ttl": "1h"}`).
    public var requestBody: [String: String]
    /// Optional key inside `response.data` to extract as the primary token/secret.
    /// Leave empty to deliver the entire `response.data` JSON object.
    public var tokenField: String
    /// Optional ISO-8601 expiry field inside `response.data` (for example `expires_at`).
    public var expiryField: String
    /// Safe filename written under the receiver's artifact directory (for example `aws-creds.json`).
    public var deliverAs: String
    /// Optional OpenBao policy that allows `endpoint`. Selecting the extension adds this policy to
    /// the grant (it must be in the token role's `allowed_policies`), so approving the extension is
    /// approving that policy. Leave empty when the grant's other policies already cover the path.
    public var policy: String
    /// Highlights approvals in orange and triggers elevated audit-reason policies.
    public var elevated: Bool
    /// Disabled by default for shipped example templates; only enabled extensions appear in grant UIs.
    public var enabled: Bool

    public var displayLabel: String {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? id : trimmed
    }

    enum CodingKeys: String, CodingKey {
        case id
        case label
        case description
        case icon
        case endpoint
        case method
        case requestBody = "request_body"
        case tokenField = "token_field"
        case expiryField = "expiry_field"
        case deliverAs = "deliver_as"
        case policy
        case elevated
        case enabled
    }

    public init(
        id: String,
        label: String,
        description: String = "",
        icon: String = "puzzlepiece.extension",
        endpoint: String,
        method: BaoExtensionMethod = .post,
        requestBody: [String: String] = [:],
        tokenField: String = "",
        expiryField: String = "",
        deliverAs: String,
        policy: String = "",
        elevated: Bool = false,
        enabled: Bool = true
    ) {
        self.policy = policy
        self.id = id
        self.label = label
        self.description = description
        self.icon = icon
        self.endpoint = endpoint
        self.method = method
        self.requestBody = requestBody
        self.tokenField = tokenField
        self.expiryField = expiryField
        self.deliverAs = deliverAs
        self.elevated = elevated
        self.enabled = enabled
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(String.self, forKey: .id)
        self.label = try container.decodeIfPresent(String.self, forKey: .label) ?? ""
        self.description = try container.decodeIfPresent(String.self, forKey: .description) ?? ""
        self.icon = try container.decodeIfPresent(String.self, forKey: .icon) ?? "puzzlepiece.extension"
        self.endpoint = try container.decode(String.self, forKey: .endpoint)
        self.method = try container.decodeIfPresent(BaoExtensionMethod.self, forKey: .method) ?? .post
        self.requestBody = try container.decodeIfPresent([String: String].self, forKey: .requestBody) ?? [:]
        self.tokenField = try container.decodeIfPresent(String.self, forKey: .tokenField) ?? ""
        self.expiryField = try container.decodeIfPresent(String.self, forKey: .expiryField) ?? ""
        self.deliverAs = try container.decode(String.self, forKey: .deliverAs)
        self.policy = try container.decodeIfPresent(String.self, forKey: .policy) ?? ""
        self.elevated = try container.decodeIfPresent(Bool.self, forKey: .elevated) ?? false
        self.enabled = try container.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }

    /// Example extension templates shipped disabled by default so operators can enable
    /// and customize common OpenBao / Vault dynamic-secret workflows with one click.
    public static let builtInTemplates: [BaoCredentialExtension] = [
        BaoCredentialExtension(
            id: "aws-sts",
            label: String(localized: "AWS STS Credentials", table: "BaoBuddyCore", comment: "Name of a built-in credential extension template (an example that mints extra credentials with a grant). AWS STS, PKI and GitHub App are product/technical names."),
            description: String(localized: "Mint temporary AWS access key, secret key, and session token via the AWS secrets engine.", table: "BaoBuddyCore", comment: "Description of a built-in credential extension template. A secrets engine is an OpenBao/Vault component."),
            icon: "cloud",
            endpoint: "aws/sts/deploy",
            method: .post,
            requestBody: ["ttl": "1h"],
            tokenField: "",
            expiryField: "",
            deliverAs: "aws-creds.json",
            elevated: true,
            enabled: false
        ),
        BaoCredentialExtension(
            id: "k8s-token",
            label: String(localized: "Kubernetes Ephemeral Token", table: "BaoBuddyCore", comment: "Name of a built-in credential extension template (an example that mints extra credentials with a grant)."),
            description: String(localized: "Generate a short-lived Kubernetes ServiceAccount token via the Kubernetes secrets engine.", table: "BaoBuddyCore", comment: "Description of a built-in credential extension template. A secrets engine is an OpenBao/Vault component."),
            icon: "cube",
            endpoint: "kubernetes/creds/deploy",
            method: .post,
            requestBody: ["kubernetes_namespace": "default", "ttl": "1h"],
            tokenField: "service_account_token",
            expiryField: "",
            deliverAs: "k8s-token",
            elevated: true,
            enabled: false
        ),
        BaoCredentialExtension(
            id: "db-creds",
            label: String(localized: "Database Dynamic Credentials", table: "BaoBuddyCore", comment: "Name of a built-in credential extension template (an example that mints extra credentials with a grant)."),
            description: String(localized: "Issue short-lived database username and password via the Database secrets engine.", table: "BaoBuddyCore", comment: "Description of a built-in credential extension template. A secrets engine is an OpenBao/Vault component."),
            icon: "cylinder.split.1x2",
            endpoint: "database/creds/readonly",
            method: .get,
            requestBody: [:],
            tokenField: "",
            expiryField: "",
            deliverAs: "db-creds.json",
            elevated: false,
            enabled: false
        ),
        BaoCredentialExtension(
            id: "pki-cert",
            label: String(localized: "Short-Lived PKI Certificate", table: "BaoBuddyCore", comment: "Name of a built-in credential extension template (an example that mints extra credentials with a grant). AWS STS, PKI and GitHub App are product/technical names."),
            description: String(localized: "Issue an ephemeral TLS certificate and private key via the PKI secrets engine.", table: "BaoBuddyCore", comment: "Description of a built-in credential extension template. A secrets engine is an OpenBao/Vault component."),
            icon: "lock.doc",
            endpoint: "pki/issue/service",
            method: .post,
            requestBody: ["common_name": "workstation.internal", "ttl": "1h"],
            tokenField: "",
            expiryField: "",
            deliverAs: "tls-cert.json",
            elevated: false,
            enabled: false
        ),
        BaoCredentialExtension(
            id: "git-push",
            label: String(localized: "GitHub App Push Token", table: "BaoBuddyCore", comment: "Name of a built-in credential extension template (an example that mints extra credentials with a grant). AWS STS, PKI and GitHub App are product/technical names."),
            description: String(localized: "Mint a 1-hour GitHub installation token via vault-plugin-secrets-github.", table: "BaoBuddyCore", comment: "Description of a built-in credential extension template. Do not translate vault-plugin-secrets-github (a plugin name)."),
            icon: "arrow.up.circle",
            endpoint: "github/token/push",
            method: .post,
            requestBody: [:],
            tokenField: "token",
            expiryField: "expires_at",
            deliverAs: "push-token",
            elevated: true,
            enabled: false
        )
    ]
}

/// Output produced by invoking a `BaoCredentialExtension` against OpenBao / Vault.
public struct MintedExtensionArtifact: Codable, Equatable, Sendable {
    public let name: String
    public let content: String
    public let expiresAt: Int64?

    enum CodingKeys: String, CodingKey {
        case name
        case content
        case expiresAt = "expires_at"
    }

    public init(name: String, content: String, expiresAt: Int64? = nil) {
        self.name = name
        self.content = content
        self.expiresAt = expiresAt
    }
}
