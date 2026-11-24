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

resource "vault_jwt_auth_backend" "operator" {
  for_each = var.users

  path                   = each.value.mount
  type                   = "jwt"
  description            = "BaoBuddy hardware-backed device keys for ${each.value.subject}"
  bound_issuer           = var.issuer
  jwt_validation_pubkeys = each.value.device_public_keys_pem
}

resource "vault_token_auth_backend_role" "grant" {
  for_each = var.users

  role_name              = "${var.token_role_prefix}-${each.key}"
  allowed_policies       = each.value.allowed_policies
  disallowed_policies    = ["root"]
  orphan                 = true
  renewable              = false
  token_explicit_max_ttl = each.value.max_hours * 3600
}

resource "vault_policy" "granter" {
  for_each = var.users

  name = "baobuddy-granter-${each.key}"
  policy = join("\n\n", concat(
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
