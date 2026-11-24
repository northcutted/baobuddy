import Foundation

/// An OpenBao policy generated for a credential extension: `capabilities` on `path`.
public struct BaoTofuExtensionPolicy: Equatable, Sendable {
    public var name: String
    public var path: String
    public var capabilities: [String]

    public init(name: String, path: String, capabilities: [String]) {
        self.name = name
        self.path = path
        self.capabilities = capabilities
    }
}

/// Per-operator configuration rendered into `for_each` maps in the generated OpenTofu project.
public struct BaoTofuUserSpec: Equatable, Identifiable, Sendable {
    public var id: String { name }
    public var name: String
    public var mount: String
    public var subject: String
    public var devicePublicKeysPEM: [String]
    public var allowedPolicies: [String]
    public var maxHours: Int
    public var boundCIDRs: [String]

    public init(
        name: String,
        mount: String = "",
        subject: String = "",
        devicePublicKeysPEM: [String] = [],
        allowedPolicies: [String] = ["read"],
        maxHours: Int = 12,
        boundCIDRs: [String] = []
    ) {
        self.name = name
        self.mount = mount.isEmpty ? "jwt-\(name)" : mount
        self.subject = subject.isEmpty ? name : subject
        self.devicePublicKeysPEM = devicePublicKeysPEM
        self.allowedPolicies = allowedPolicies
        self.maxHours = max(1, min(maxHours, 24))
        self.boundCIDRs = boundCIDRs
    }
}

/// Complete input specification for generating a variablized OpenTofu / Terraform deployment.
public struct BaoTofuDeploymentSpec: Equatable, Sendable {
    public var serverName: String
    public var openbaoAddress: String
    public var namespace: String
    public var caPEM: String
    public var mtlsClientIdentity: String
    public var issuer: String
    public var audience: String
    public var tokenRolePrefix: String
    public var users: [BaoTofuUserSpec]
    public var elevatedPolicies: [String]
    public var auditPolicy: BaoAuditPolicy
    public var sshSignPath: String
    public var githubTokenPath: String
    public var otlpEndpoint: String
    /// Policies for credential extensions (name, path, capabilities).
    public var extensionPolicies: [BaoTofuExtensionPolicy]

    public init(
        serverName: String = "OpenBao",
        openbaoAddress: String = "https://openbao.example.com:8200",
        namespace: String = "",
        caPEM: String = "",
        mtlsClientIdentity: String = "",
        issuer: String = "bao-granter",
        audience: String = "",
        tokenRolePrefix: String = "grant",
        users: [BaoTofuUserSpec],
        elevatedPolicies: [String] = [],
        auditPolicy: BaoAuditPolicy = .none,
        sshSignPath: String = "",
        githubTokenPath: String = "",
        otlpEndpoint: String = "",
        extensionPolicies: [BaoTofuExtensionPolicy] = []
    ) {
        self.extensionPolicies = extensionPolicies
        self.serverName = serverName
        self.openbaoAddress = openbaoAddress
        self.namespace = namespace
        self.caPEM = caPEM
        self.mtlsClientIdentity = mtlsClientIdentity
        self.issuer = issuer
        self.audience = audience
        self.tokenRolePrefix = tokenRolePrefix
        self.users = users
        self.elevatedPolicies = elevatedPolicies
        self.auditPolicy = auditPolicy
        self.sshSignPath = sshSignPath
        self.githubTokenPath = githubTokenPath
        self.otlpEndpoint = otlpEndpoint
    }

    /// Seeds a deployment spec directly from an existing `BaoProfile` and optional device public key PEM.
    public static func from(profile: BaoProfile, devicePEM: String = "") -> BaoTofuDeploymentSpec {
        let policies: [String]
        let elevated: [String]
        if profile.openbao.usesCustomPolicies {
            policies = profile.openbao.grantPolicies.map(\.name)
            elevated = profile.openbao.grantPolicies.filter(\.elevated).map(\.name)
        } else {
            policies = [profile.openbao.policies.read, profile.openbao.policies.write]
                .filter { !$0.isEmpty }
            elevated = [profile.openbao.policies.write].filter { !$0.isEmpty }
        }
        // Each enabled extension that names a policy gets that policy generated, and the user may
        // carry it in grants.
        var extensionPolicies: [BaoTofuExtensionPolicy] = []
        for ext in profile.openbao.enabledExtensions where !ext.policy.isEmpty {
            guard !extensionPolicies.contains(where: { $0.name == ext.policy }) else { continue }
            extensionPolicies.append(BaoTofuExtensionPolicy(
                name: ext.policy,
                path: ext.endpoint,
                capabilities: ext.method == .get ? ["read"] : ["create", "update"]
            ))
        }
        let grantable = (policies.isEmpty ? ["read"] : policies)
            + extensionPolicies.map(\.name).filter { !policies.contains($0) }
        let subject = profile.openbao.jwtAuth.subject.isEmpty ? "operator" : profile.openbao.jwtAuth.subject
        let user = BaoTofuUserSpec(
            name: subject,
            mount: profile.openbao.jwtAuth.mount,
            subject: subject,
            devicePublicKeysPEM: devicePEM.isEmpty ? [] : [devicePEM],
            allowedPolicies: grantable,
            maxHours: profile.openbao.maxHours
        )
        return BaoTofuDeploymentSpec(
            serverName: profile.displayName,
            openbaoAddress: profile.openbao.address,
            namespace: profile.openbao.namespace,
            caPEM: profile.openbao.caPEM,
            mtlsClientIdentity: profile.openbao.mtlsClientIdentity,
            issuer: profile.openbao.jwtAuth.issuer,
            audience: profile.openbao.usesBoundAudience ? "" : profile.openbao.jwtAuth.audience,
            tokenRolePrefix: profile.openbao.tokenRoles.mac,
            users: [user],
            elevatedPolicies: elevated,
            auditPolicy: profile.openbao.auditPolicy,
            sshSignPath: profile.openbao.ssh.role.isEmpty ? "" : "ssh/sign/\(profile.openbao.ssh.role)",
            githubTokenPath: profile.openbao.githubTokenPath,
            otlpEndpoint: profile.openbao.telemetry.otlpEndpoint,
            extensionPolicies: extensionPolicies
        )
    }
}

/// Generates a clean, variablized, `for_each`-driven OpenTofu / Terraform project for BaoBuddy.
/// Every operator gets an isolated JWT auth mount (`auth/jwt-<user>/`), least-privilege granter ACL
/// policy (no `sudo`, `token_no_default_policy=true`, 5s leeways), and orphan non-renewable token role.
public enum BaoTofuBuilder {
    public static func generate(_ spec: BaoTofuDeploymentSpec) -> [String: String] {
        [
            "versions.tf": renderVersions(),
            "variables.tf": renderVariables(),
            "main.tf": renderMain(),
            "outputs.tf": renderOutputs(),
            "terraform.tfvars": renderTFVars(spec),
            "README.md": renderReadme(spec)
        ]
    }

    /// Writes all generated `.tf` / `.tfvars` / `README.md` files into `directory`.
    public static func write(_ spec: BaoTofuDeploymentSpec, to directory: URL) throws -> [String] {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let files = generate(spec)
        let sortedNames = files.keys.sorted()
        for name in sortedNames {
            guard let content = files[name] else { continue }
            try content.write(to: directory.appendingPathComponent(name), atomically: true, encoding: .utf8)
        }
        return sortedNames
    }

    private static func renderVersions() -> String {
        """
        terraform {
          required_version = ">= 1.6.0"

          required_providers {
            vault = {
              source  = "hashicorp/vault"
              version = ">= 4.4.0"
            }
          }
        }

        provider "vault" {
          address   = var.openbao_address
          namespace = var.namespace != "" ? var.namespace : null
        }
        """
    }

    private static func renderVariables() -> String {
        """
        variable "server_name" {
          description = "Display name shown in BaoBuddy on macOS and iOS."
          type        = string
          default     = "OpenBao"
        }

        variable "openbao_address" {
          description = "OpenBao or HashiCorp Vault server URL."
          type        = string
        }

        variable "namespace" {
          description = "Optional Vault Enterprise / HCP Vault / OpenBao 2.x namespace."
          type        = string
          default     = ""
        }

        variable "ca_pem" {
          description = "Optional pinned CA or leaf certificate PEM embedded into output profiles and trust-bound JWT audiences."
          type        = string
          default     = ""
        }

        variable "mtls_client_identity" {
          description = "Optional mTLS client identity label embedded into output profiles and trust-bound JWT audiences."
          type        = string
          default     = ""
        }

        variable "issuer" {
          description = "Bound JWT issuer (iss) expected from BaoBuddy devices."
          type        = string
          default     = "bao-granter"
        }

        variable "audience" {
          description = "Bound JWT audience (aud) expected from BaoBuddy devices. Leave empty to derive an origin- and mount-bound baobuddy:// audience per operator."
          type        = string
          default     = ""
        }

        variable "token_role_prefix" {
          description = "Prefix for per-user scoped orphan token roles."
          type        = string
          default     = "grant"
          validation {
            condition     = can(regex("^[A-Za-z0-9._@:-]+$", var.token_role_prefix))
            error_message = "token_role_prefix may only contain letters, digits, and . _ - @ : (no quotes, spaces, '*', '+', or '..'), because it is written into policy text."
          }
        }

        variable "ssh_sign_path" {
          description = "Optional OpenBao SSH CA signing path (for example ssh/sign/ops)."
          type        = string
          default     = ""
          validation {
            condition     = var.ssh_sign_path == "" || (can(regex("^[A-Za-z0-9._@:-]+(/[A-Za-z0-9._@:-]+)*$", var.ssh_sign_path)) && !can(regex("(^|/)[.][.]?(/|$)", var.ssh_sign_path)))
            error_message = "ssh_sign_path may only contain letters, digits, and . _ - @ : and / (no quotes, spaces, '*', '+', or '..'), because it is written into policy text."
          }
        }

        variable "github_token_path" {
          description = "Optional server-side GitHub token endpoint (for example github/token/push)."
          type        = string
          default     = ""
          validation {
            condition     = var.github_token_path == "" || (can(regex("^[A-Za-z0-9._@:-]+(/[A-Za-z0-9._@:-]+)*$", var.github_token_path)) && !can(regex("(^|/)[.][.]?(/|$)", var.github_token_path)))
            error_message = "github_token_path may only contain letters, digits, and . _ - @ : and / (no quotes, spaces, '*', '+', or '..'), because it is written into policy text."
          }
        }

        variable "elevated_policies" {
          description = "Policies highlighted in orange in BaoBuddy UIs."
          type        = list(string)
          default     = []
        }

        variable "audit_policy" {
          description = "Optional audit and change-ticket requirements embedded into exported profiles."
          type = object({
            require_reason              = optional(bool, false)
            require_reason_for_elevated = optional(bool, false)
            reason_pattern              = optional(string, "")
            reason_placeholder          = optional(string, "")
          })
          default = {}
        }

        variable "otlp_endpoint" {
          description = "Optional OpenTelemetry OTLP/HTTP endpoint for client SIEM ingestion."
          type        = string
          default     = ""
        }

        variable "users" {
          description = "Map of operators. Each user receives an isolated JWT auth mount so keys cannot impersonate another person."
          type = map(object({
            mount                  = string
            subject                = string
            device_public_keys_pem = list(string)
            allowed_policies       = list(string)
            max_hours              = optional(number, 12)
            bound_cidrs            = optional(list(string), [])
          }))
          validation {
            condition = alltrue([
              for name, u in var.users :
              can(regex("^[A-Za-z0-9._@:-]+$", name)) &&
              can(regex("^[A-Za-z0-9._@:-]+$", u.subject)) &&
              can(regex("^[A-Za-z0-9._@:-]+(/[A-Za-z0-9._@:-]+)*$", u.mount)) && !can(regex("(^|/)[.][.]?(/|$)", u.mount)) &&
              length(u.allowed_policies) > 0 &&
              !contains(u.allowed_policies, "root") &&
              alltrue([for p in u.allowed_policies : can(regex("^[A-Za-z0-9._@:-]+$", p))]) &&
              length(u.device_public_keys_pem) > 0
            ])
            error_message = "Each user needs a safe name, subject, and mount, at least one device public key, and a non-empty allowed_policies list without root. An empty allowed_policies list would let the granter mint any policy."
          }
        }
        variable "extension_policies" {
          description = "Policies for BaoBuddy credential extensions, keyed by policy name. Add each name to the users' allowed_policies; selecting the extension adds the policy to the grant."
          type = map(object({
            path         = string
            capabilities = list(string)
          }))
          default = {}

          validation {
            condition = alltrue([
              for name, p in var.extension_policies :
              can(regex("^[A-Za-z0-9._@:-]+$", name)) && name != "root" &&
              can(regex("^[A-Za-z0-9._@:-]+(/[A-Za-z0-9._@:-]+)*$", p.path)) && !can(regex("(^|/)[.][.]?(/|$)", p.path)) &&
              !contains(["sys", "auth", "identity", "cubbyhole"], split("/", p.path)[0]) &&
              length(p.capabilities) > 0 &&
              alltrue([for c in p.capabilities : contains(["read", "create", "update"], c)])
            ])
            error_message = "Each extension policy needs a safe name, a secrets engine path (not under sys/, auth/, identity/, or cubbyhole/), and capabilities from read, create, update."
          }
        }
        """
    }

    private static func renderMain() -> String {
        """
        locals {
          extra_paths   = compact([var.ssh_sign_path, var.github_token_path])
          addr_trimmed  = trimspace(var.openbao_address)
          addr_is_https = startswith(lower(local.addr_trimmed), "https://")
          addr_is_http  = startswith(lower(local.addr_trimmed), "http://")
          addr_no_scheme = trimsuffix(
            local.addr_is_https ? substr(local.addr_trimmed, 8, length(local.addr_trimmed) - 8) : (
              local.addr_is_http ? substr(local.addr_trimmed, 7, length(local.addr_trimmed) - 7) : local.addr_trimmed
            ),
            "/"
          )
          addr_parts         = split("/", local.addr_no_scheme)
          addr_authority_raw = lower(local.addr_parts[0])
          addr_authority = (
            local.addr_is_https && endswith(local.addr_authority_raw, ":443") ? trimsuffix(local.addr_authority_raw, ":443") : (
              local.addr_is_http && endswith(local.addr_authority_raw, ":80") ? trimsuffix(local.addr_authority_raw, ":80") : local.addr_authority_raw
            )
          )
          addr_base_path = length(local.addr_parts) > 1 ? "/${join("/", slice(local.addr_parts, 1, length(local.addr_parts)))}" : ""
          base_param     = local.addr_base_path != "" ? "base=${urlencode(local.addr_base_path)}" : ""
          mtls_param     = trimspace(var.mtls_client_identity) != "" ? "mtls=${substr(sha256(trimspace(var.mtls_client_identity)), 0, 16)}" : ""
          pin_param      = trimspace(var.ca_pem) != "" ? "pin=${substr(sha256(trimspace(var.ca_pem)), 0, 16)}" : ""
          query_parts    = compact([local.base_param, local.mtls_param, local.pin_param])
          query_suffix   = length(local.query_parts) > 0 ? "?${join("&", local.query_parts)}" : ""
          ns_segment     = trim(var.namespace, "/") != "" ? "/ns/${trim(var.namespace, "/")}" : ""
          operator_audience = {
            for name, user in var.users :
            name => (var.audience != "" ? var.audience : "baobuddy://${local.addr_authority}${local.ns_segment}/auth/${trim(user.mount, "/")}${local.query_suffix}")
          }
        }

        # Isolated JWT auth mount per operator (one identity per mount).
        resource "vault_jwt_auth_backend" "operator" {
          for_each = var.users

          path                   = each.value.mount
          type                   = "jwt"
          description            = "BaoBuddy hardware-backed device keys for ${each.value.subject}"
          bound_issuer           = var.issuer
          jwt_validation_pubkeys = each.value.device_public_keys_pem
        }

        # Scoped, orphan, non-renewable token role per operator.
        resource "vault_token_auth_backend_role" "grant" {
          for_each = var.users

          role_name              = "${var.token_role_prefix}-${each.key}"
          allowed_policies       = each.value.allowed_policies
          disallowed_policies    = ["root"]
          orphan                 = true
          renewable              = false
          token_explicit_max_ttl = each.value.max_hours * 3600
        }

        # Least-privilege granter ACL policy (never uses sudo, no secret read access).
        resource "vault_policy" "granter" {
          for_each = var.users

          name = "baobuddy-granter-${each.key}"
          policy = join("\\n\\n", concat(
            [
              <<-EOT
                path "auth/token/create/${vault_token_auth_backend_role.grant[each.key].role_name}" {
                  capabilities = ["create", "update"]
                }
              EOT
              ,
              <<-EOT
                path "auth/token/revoke" {
                  capabilities = ["update"]
                }
              EOT
              ,
              <<-EOT
                path "auth/token/revoke-accessor" {
                  capabilities = ["update"]
                }
              EOT
              ,
              <<-EOT
                path "auth/token/revoke-self" {
                  capabilities = ["update"]
                }
              EOT
            ],
            [
              for p in local.extra_paths : <<-EOT
                path "${p}" {
                  capabilities = ["create", "update"]
                }
              EOT
            ]
          ))
        }

        # Short-lived (2m) JWT login role with tight 5s leeways and no default policy.
        resource "vault_jwt_auth_backend_role" "operator" {
          for_each = var.users

          backend                 = vault_jwt_auth_backend.operator[each.key].path
          role_name               = "granter"
          role_type               = "jwt"
          user_claim              = "sub"
          bound_subject           = each.value.subject
          bound_audiences         = [local.operator_audience[each.key]]
          token_policies          = [vault_policy.granter[each.key].name]
          token_no_default_policy = true
          token_ttl               = 120
          token_max_ttl           = 120
          expiration_leeway       = 5
          not_before_leeway       = 5
          clock_skew_leeway       = 5
          token_bound_cidrs       = length(each.value.bound_cidrs) > 0 ? each.value.bound_cidrs : null
          claim_mappings = {
            device = "device"
            scope  = "scope"
          }
        }

        # One policy per credential extension. A grant carries it only when the user selects the
        # extension, and the extension is called with the grant token, so its leases end with the grant.
        resource "vault_policy" "extension" {
          for_each = var.extension_policies

          name   = each.key
          policy = <<-EOT
            path "${each.value.path}" {
              capabilities = ${jsonencode(each.value.capabilities)}
            }
          EOT
        }
        """
    }

    private static func renderOutputs() -> String {
        """
        output "baobuddy_profiles" {
          description = "Non-secret BaoBuddy v1 profile JSON per operator (ready for `bao-buddy import-profile` or iPhone paste)."
          value = {
            for name, user in var.users : name => jsonencode({
              version = 1
              name    = var.server_name
              openbao = merge(
                {
                  address              = var.openbao_address
                  ca_pem               = trimspace(var.ca_pem)
                  mtls_client_identity = trimspace(var.mtls_client_identity)
                  jwt_auth = {
                    mount    = user.mount
                    role     = "granter"
                    issuer   = var.issuer
                    audience = local.operator_audience[name]
                    subject  = user.subject
                  }
                  token_roles = {
                    local  = vault_token_auth_backend_role.grant[name].role_name
                    remote = vault_token_auth_backend_role.grant[name].role_name
                  }
                  grant_policies = [
                    for idx, p in user.allowed_policies : {
                      name             = p
                      elevated         = contains(var.elevated_policies, p)
                      default_selected = idx == 0 && !contains(var.elevated_policies, p)
                    }
                  ]
                  max_hours = user.max_hours
                  keys      = []
                  ssh = {
                    role  = ""
                    hosts = []
                  }
                  github_app_item = ""
                },
                var.namespace != "" ? { namespace = var.namespace } : {},
                var.github_token_path != "" ? { github_token_path = var.github_token_path } : {},
                var.otlp_endpoint != "" ? { telemetry = { otlp_endpoint = var.otlp_endpoint } } : {},
                (
                  try(var.audit_policy.require_reason, false) ||
                  try(var.audit_policy.require_reason_for_elevated, false) ||
                  try(var.audit_policy.reason_pattern, "") != ""
                ) ? { audit_policy = var.audit_policy } : {}
              )
            })
          }
        }
        """
    }

    private static func renderTFVars(_ spec: BaoTofuDeploymentSpec) -> String {
        var lines: [String] = [
            "server_name       = \(hclString(spec.serverName))",
            "openbao_address   = \(hclString(spec.openbaoAddress))",
            "namespace         = \(hclString(spec.namespace))",
            "issuer            = \(hclString(spec.issuer))",
            "audience          = \(hclString(spec.audience))",
            "token_role_prefix = \(hclString(spec.tokenRolePrefix))",
            "ssh_sign_path     = \(hclString(spec.sshSignPath))",
            "github_token_path = \(hclString(spec.githubTokenPath))",
            "elevated_policies = \(hclStringList(spec.elevatedPolicies))",
            "otlp_endpoint     = \(hclString(spec.otlpEndpoint))"
        ]
        if !spec.caPEM.isEmpty {
            lines.append("ca_pem            = \(hclString(spec.caPEM))")
        }
        if !spec.mtlsClientIdentity.isEmpty {
            lines.append("mtls_client_identity = \(hclString(spec.mtlsClientIdentity))")
        }
        lines += [
            "",
            "extension_policies = {"
        ] + spec.extensionPolicies.map { policy in
            "  \(hclString(policy.name)) = { path = \(hclString(policy.path)), capabilities = \(hclStringList(policy.capabilities)) }"
        } + [
            "}",
            "",
            "audit_policy = {",
            "  require_reason              = \(spec.auditPolicy.requireReason)",
            "  require_reason_for_elevated = \(spec.auditPolicy.requireReasonForElevated)",
            "  reason_pattern              = \(hclString(spec.auditPolicy.reasonPattern))",
            "  reason_placeholder          = \(hclString(spec.auditPolicy.reasonPlaceholder))",
            "}",
            "",
            "users = {"
        ]

        for user in spec.users {
            lines.append("  \(hclString(user.name)) = {")
            lines.append("    mount            = \(hclString(user.mount))")
            lines.append("    subject          = \(hclString(user.subject))")
            lines.append("    allowed_policies = \(hclStringList(user.allowedPolicies))")
            lines.append("    max_hours        = \(user.maxHours)")
            lines.append("    bound_cidrs      = \(hclStringList(user.boundCIDRs))")
            if user.devicePublicKeysPEM.isEmpty {
                lines.append("    device_public_keys_pem = [")
                lines.append("      # Paste output of `bao-buddy pubkey` (Mac) or Copy Public Key (iPhone)")
                lines.append("    ]")
            } else {
                lines.append("    device_public_keys_pem = [")
                // Only keys that parse as P-256 public keys are written: the heredoc ends at a line
                // reading EOT, so unvalidated text could inject HCL.
                for pem in user.devicePublicKeysPEM {
                    guard let key = try? BaoServerAdmin.validateP256PEM(pem) else {
                        lines.append("      # Skipped a device key that isn't a valid P-256 public key PEM")
                        continue
                    }
                    let trimmed = key.pem.trimmingCharacters(in: .whitespacesAndNewlines)
                    lines.append("      <<-EOT")
                    for pemLine in trimmed.split(separator: "\n", omittingEmptySubsequences: false) {
                        lines.append("        \(pemLine)")
                    }
                    lines.append("      EOT")
                }
                lines.append("    ]")
            }
            lines.append("  }")
        }
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    private static func renderReadme(_ spec: BaoTofuDeploymentSpec) -> String {
        """
        # BaoBuddy OpenTofu / Terraform Deployment (\(spec.serverName))

        Generated by **BaoBuddy** for `\(spec.openbaoAddress)`\(spec.namespace.isEmpty ? "" : " (namespace `\(spec.namespace)`)").

        ## Apply
        ```bash
        export VAULT_TOKEN="<admin-token>"
        tofu init
        tofu plan
        tofu apply
        ```

        ## Export Operator Profile
        ```bash
        tofu output -json baobuddy_profiles | jq -r '.["\(spec.users.first?.name ?? "operator")"]' | bao-buddy import-profile
        ```
        """
    }

    private static func hclString(_ value: String) -> String {
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\t", with: "\\t")
            // `${` and `%{` start template sequences in HCL strings; doubling the sigil escapes them.
            .replacingOccurrences(of: "${", with: "$${")
            .replacingOccurrences(of: "%{", with: "%%{")
        return "\"\(escaped)\""
    }

    private static func hclStringList(_ values: [String]) -> String {
        let items = values.map(hclString).joined(separator: ", ")
        return "[\(items)]"
    }
}
