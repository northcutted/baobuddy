variable "server_name" {
  description = "Friendly display name shown in BaoBuddy."
  type        = string
  default     = "OpenBao"
}

variable "openbao_address" {
  description = "OpenBao or HashiCorp Vault URL embedded in output profiles."
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
  description = "Bound JWT issuer (iss)."
  type        = string
  default     = "bao-granter"
}

variable "audience" {
  description = "Optional override for bound JWT audience (aud). Leave empty to derive an endpoint-, base-path-, namespace-, and mount-bound audience per operator."
  type        = string
  default     = ""
}

variable "token_role_prefix" {
  description = "Prefix for per-operator scoped orphan token roles."
  type        = string
  default     = "grant"
  validation {
    condition     = can(regex("^[A-Za-z0-9._@:-]+$", var.token_role_prefix))
    error_message = "token_role_prefix may only contain letters, digits, and . _ - @ : (no quotes, spaces, '*', '+', or '..'), because it is written into policy text."
  }
}

variable "ssh_sign_path" {
  description = "Optional SSH CA signing path (e.g., ssh/sign/ops)."
  type        = string
  default     = ""
  validation {
    condition     = var.ssh_sign_path == "" || (can(regex("^[A-Za-z0-9._@:-]+(/[A-Za-z0-9._@:-]+)*$", var.ssh_sign_path)) && !can(regex("(^|/)[.][.]?(/|$)", var.ssh_sign_path)))
    error_message = "ssh_sign_path may only contain letters, digits, and . _ - @ : and / (no quotes, spaces, '*', '+', or '..'), because it is written into policy text."
  }
}

variable "github_token_path" {
  description = "Optional server-side GitHub token endpoint (e.g., github/token/push)."
  type        = string
  default     = ""
  validation {
    condition     = var.github_token_path == "" || (can(regex("^[A-Za-z0-9._@:-]+(/[A-Za-z0-9._@:-]+)*$", var.github_token_path)) && !can(regex("(^|/)[.][.]?(/|$)", var.github_token_path)))
    error_message = "github_token_path may only contain letters, digits, and . _ - @ : and / (no quotes, spaces, '*', '+', or '..'), because it is written into policy text."
  }
}

variable "elevated_policies" {
  description = "Policy names highlighted in orange in BaoBuddy."
  type        = list(string)
  default     = []
}

variable "audit_policy" {
  description = "Optional audit reason and ticket regex rules."
  type = object({
    require_reason              = optional(bool, false)
    require_reason_for_elevated = optional(bool, false)
    reason_pattern              = optional(string, "")
    reason_placeholder          = optional(string, "")
  })
  default = {}
}

variable "otlp_endpoint" {
  description = "Optional OTLP/HTTP endpoint for client SIEM ingestion."
  type        = string
  default     = ""
}

variable "users" {
  description = "Map of operators; each receives an isolated JWT auth mount."
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
