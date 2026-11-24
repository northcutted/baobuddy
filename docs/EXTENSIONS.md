# Credential Extensions

Credential Extensions let a team describe OpenBao or HashiCorp Vault **dynamic secrets engines**
(AWS STS, Kubernetes, database, PKI, GitHub tokens) declaratively, instead of BaoBuddy hard-coding
each provider. When you select an extension for a grant, BaoBuddy mints its credential with the
grant and delivers it next to the grant token.

## How a grant uses extensions

1. **You select it.** Enabled extensions appear as toggles in the iOS app and the Mac menu bar,
   as `--ext ID1,ID2` on `bao-buddy grant`, as `EXT=ID1,ID2` in `baobuddy://grant` links, and as
   `extensions` in the MCP `baobuddy_request_grant` tool. Only the profile's enabled extensions
   can be named.
2. **You approve it.** The approval sheet, the biometric prompt, and the JWT `scope` claim list
   each extension with its endpoint, for example
   `Credentials: AWS STS [aws/sts/deploy, policy aws-deploy]`. An `elevated` extension makes the
   grant elevated, which triggers `require_reason_for_elevated`.
3. **BaoBuddy mints the grant**, adding each selected extension's `policy` to the grant's
   policies, and checks the result as usual.
4. **BaoBuddy calls each endpoint with the grant token**, never the sign-in token. The grant's
   policies decide what the extension can reach, and any lease the call creates belongs to the
   grant: revoking the grant (directly or by accessor) or letting it expire revokes the lease.
   Each artifact's expiry is capped at the grant's.
5. **BaoBuddy delivers the artifacts:**

| Grant target | Where artifacts go |
| --- | --- |
| Remote (`--on remote`) | `baobuddy-receiver` writes them to `<state_dir>/artifacts/<deliver_as>` (the v2 install envelope). Granter hosts that only accept the original three-line format still work for grants without extensions. |
| This Mac (`--on local`) | The login keychain, service `openbao-grant-artifact.<binding>` (scoped per server trust domain; `bao-buddy status` prints the exact service name), account `<deliver_as>`. Read one inside the command that needs it: `security find-generic-password -s openbao-grant-artifact.<binding> -a db-creds.json -w`. `bao-buddy status` lists them; revoking the local grant deletes them. |
| Direct token (iOS app) | Shown under the minted token with Reveal and Copy (2-minute, this-device-only clipboard). |
| `bao-buddy grant --on direct` | Not supported: use `--on local`, so credentials don't land in a terminal or an agent's transcript. |

If any extension call fails, BaoBuddy revokes the grant (which revokes leases already created)
and delivers nothing. A `403` names the extension and the path the grant's policies don't allow.

**Limits.** Some engines issue credentials that OpenBao can't revoke: AWS STS sessions, and PKI
certificates without `generate_lease`. Those stay valid until their own TTL, so set `request_body`
`ttl` no longer than the grants you approve. The receiver and the Keychain hold copies until the
grant is revoked or (on the receiver) the artifact expires.

---

## 1. Built-In Example Templates (Disabled by Default)

BaoBuddy ships 5 example templates in **Server Settings → Credential Extensions (Optional)** — all **disabled by default** so new users start with a clean UI:

| Template ID | OpenBao / Vault Endpoint | Method | Delivered File | Typical Use Case |
| --- | --- | --- | --- | --- |
| `aws-sts` | `aws/sts/deploy` | `POST` | `aws-creds.json` | Short-lived AWS STS access key + session token |
| `k8s-token` | `kubernetes/creds/deploy` | `POST` | `k8s-token` | Ephemeral Kubernetes ServiceAccount JWT |
| `db-creds` | `database/creds/readonly` | `GET` | `db-creds.json` | Dynamic Postgres / MySQL username & password |
| `pki-cert` | `pki/issue/service` | `POST` | `tls-cert.json` | Short-lived mTLS / TLS certificate & key |
| `git-push` | `github/token/push` | `POST` | `push-token` | 1-hour GitHub App installation token (`vault-plugin-secrets-github`) |

Enable any template in **Settings → Servers → Edit… → Credential Extensions**, adjust its OpenBao endpoint path to match your mount/role name, and save.

---

## 2. Creating a Custom Extension

Add an entry to `openbao.extensions` in your server profile JSON (or create one directly in **Edit Server → Credential Extensions**):

```json
{
  "id": "aws-sts-prod",
  "label": "AWS Prod STS",
  "description": "1-hour STS session for production Terraform runs.",
  "icon": "cloud",
  "endpoint": "aws/sts/prod-deploy",
  "method": "POST",
  "request_body": {
    "ttl": "1h"
  },
  "token_field": "",
  "expiry_field": "",
  "deliver_as": "aws-creds.json",
  "elevated": true,
  "enabled": true
}
```

### Field Reference

| Field | Required | Description |
| --- | --- | --- |
| `id` | Yes | Unique ASCII identifier (`a-z`, `0-9`, `-`, `_`). |
| `label` | Yes | Friendly checkbox label shown when approving grants. |
| `description` | No | Short explanation shown in Settings and the Approval sheet. |
| `icon` | No | SF Symbol name (e.g. `cloud`, `cube`, `cylinder.split.1x2`, `lock.doc`, `arrow.up.circle`). |
| `endpoint` | Yes | OpenBao/Vault secrets engine path relative to `v1/` (no leading `/`, `..`, `*`, or `+`; not under `sys/`, `auth/`, `identity/`, or `cubbyhole/`). |
| `method` | No | `POST` (default) or `GET`. |
| `request_body` | No | Optional JSON key/value parameters sent on `POST` requests (e.g. `{"ttl": "1h"}`). |
| `token_field` | No | Key inside `response.data` to extract as plain text (e.g. `"token"`). Leave empty `""` to deliver the `response.data` object as formatted JSON. A response without `data` is an error. |
| `expiry_field` | No | Optional ISO-8601 expiry timestamp key inside `response.data` (e.g. `"expires_at"`). Falls back to Vault's `lease_duration`. |
| `policy` | No | OpenBao policy that allows `endpoint`. Selecting the extension adds it to the grant, so it must be in the token role's `allowed_policies`. Leave empty when the grant's other policies already cover the path. Can't be `root`. |
| `deliver_as` | Yes | Unique filename of letters, digits, `.`, `_`, `-` (64 characters at most), written under `<state_dir>/artifacts/` by `baobuddy-receiver` with the configured `file_mode`. |
| `elevated` | No | If `true`, highlights the approval sheet in orange and enforces `require_reason_for_elevated`. |
| `enabled` | No | Set `false` to keep a template saved without showing it in the approval UI. |

---

## 3. Server-Side OpenBao / Vault Policy Setup

Give each extension a policy that allows its path, list that policy in the token role's
`allowed_policies`, and set it as the extension's `policy`. Never add extension paths to the
`granter` policy: the `granter` token exists for two minutes after every sign-in, and extensions
don't use it.

```hcl
# policy "aws-deploy", listed in the token role's allowed_policies
path "aws/sts/deploy" {
  capabilities = ["create", "update"]   # POST endpoints; use ["read"] for GET endpoints
}
```

`bao-buddy tofu-init --from-profile` and the Mac OpenTofu builder generate these policies for
every enabled extension that names one, and add them to the user's `allowed_policies`. The module
accepts them as `extension_policies`:

```hcl
extension_policies = {
  "aws-deploy" = { path = "aws/sts/deploy", capabilities = ["create", "update"] }
}
```

---

## 4. Receiving Extension Artifacts on Remote Hosts (`baobuddy-receiver`)

`baobuddy-receiver` supports both the legacy 3-line `v1` stdin format and the `v2` JSON envelope:

```json
{
  "version": 2,
  "token": "hvs.xxxxx",
  "artifacts": [
    {
      "name": "aws-creds.json",
      "content": "{\"access_key\":\"ASIA...\",\"secret_key\":\"...\",\"security_token\":\"...\"}",
      "expires_at": 1795382400
    }
  ]
}
```

- Every artifact filename is validated (`[A-Za-z0-9._-]`, no leading `.`, no `..`, unique, at most 16 files of 64 KiB each).
- Artifacts are staged in a new directory and swapped in under a lock, so one grant's files never mix with another's.
- `cleanup` (and `status`) delete each artifact after its `expires_at`, and every artifact once the grant's token is gone.
- `revoke` revokes the grant at OpenBao, which revokes the leases its extensions created, and deletes the local copies. Credentials without a lease (STS sessions, unleased PKI certificates) stay valid until their own TTL.
