output "baobuddy_profiles" {
  description = "Ready-to-import BaoBuddy v1 profile JSON per operator."
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
          max_hours       = user.max_hours
          keys            = []
          ssh             = { role = "", hosts = [] }
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
