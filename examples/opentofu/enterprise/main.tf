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
  address   = "https://vault.corp.example:8200"
  namespace = "admin/prod"
}

# Each list holds the output of `bao-buddy pubkey` (Mac) or Copy Public Key (iPhone), for example
# in terraform.tfvars:  alice_device_keys = [file("keys/alice-mac.pem")]
variable "alice_device_keys" {
  type = list(string)
}

variable "bob_device_keys" {
  type = list(string)
}

module "baobuddy" {
  source = "../modules/baobuddy"

  server_name       = "Enterprise Prod"
  openbao_address   = "https://vault.corp.example:8200"
  namespace         = "admin/prod"
  elevated_policies = ["k8s-deploy", "db-admin"]
  otlp_endpoint     = "https://otel-collector.corp.example:4318"

  audit_policy = {
    require_reason              = false
    require_reason_for_elevated = true
    reason_pattern              = "^(INC|CHG|JIRA)-[0-9]+"
    reason_placeholder          = "CHG-12345 — brief change summary"
  }

  users = {
    alice = {
      mount            = "jwt-alice"
      subject          = "alice"
      allowed_policies = ["db-readonly", "k8s-deploy"]
      max_hours        = 4
      bound_cidrs      = ["10.0.0.0/8"]
      device_public_keys_pem = var.alice_device_keys
    }
    bob = {
      mount            = "jwt-bob"
      subject          = "bob"
      allowed_policies = ["db-readonly", "db-admin"]
      max_hours        = 2
      bound_cidrs      = ["10.0.0.0/8"]
      device_public_keys_pem = var.bob_device_keys
    }
  }
}

output "profiles" {
  value = module.baobuddy.baobuddy_profiles
}
