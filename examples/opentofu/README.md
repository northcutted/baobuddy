# OpenTofu / Terraform Examples for BaoBuddy

BaoBuddy ships both a reusable OpenTofu/Terraform module (`modules/baobuddy/`) and an interactive project generator in the CLI (`bao-buddy tofu-init`) and macOS Settings (**Export OpenTofu…**).

## Reusable Module
- `modules/baobuddy/` provisions per-operator isolated JWT auth mounts (`auth/jwt-<user>/`), least-privilege granter ACL policies (no `sudo`, `token_no_default_policy=true`, 5s leeways), and orphan non-renewable token roles via `for_each`.
- Outputs ready-to-import `baobuddy_profiles` JSON for every operator.

## Generate a Custom Deployment from CLI
```bash
# Seed from your active BaoBuddy server profile + Mac Secure Enclave public key:
bao-buddy tofu-init --from-profile --out ./baobuddy-tofu

# Or define a multi-user enterprise deployment directly:
bao-buddy tofu-init \
  --name "Enterprise Prod" \
  --addr https://vault.corp.example:8200 \
  --namespace admin/prod \
  --users alice,bob \
  --policies db-readonly,k8s-deploy \
  --elevated k8s-deploy \
  --cidrs 10.0.0.0/8 \
  --require-reason-elevated \
  --reason-pattern '^(INC|CHG|JIRA)-[0-9]+' \
  --otlp https://otel-collector.corp.example:4318 \
  --out ./baobuddy-tofu
```
