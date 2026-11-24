<p align="center"><img src="Branding/png/baobuddy-app-icon-256.png" width="128" alt="BaoBuddy app icon"></p>

# BaoBuddy

> **Status: beta (v0.1.0).** Core signing, verification, and receiver flows have end-to-end tests that run against live OpenBao and HashiCorp Vault dev servers in CI; the macOS approval key requires a provisioned Developer ID helper. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before using it in production.

Hardware-backed biometric companion app (iOS) and Hardened Runtime CLI helper (macOS) for **OpenBao** and **HashiCorp Vault**.

BaoBuddy replaces passwords and long-lived tokens with non-exportable **EC P-256 keys stored inside the Apple Secure Enclave**, gated by Face ID, Touch ID, or Optic ID. You can connect multiple OpenBao/Vault servers, define your own custom policies for a dynamic approval UI, and either mint short-lived tokens directly on your device or deliver tokens and ephemeral SSH certificates to a remote host over SSH.

---

## 5-minute quickstart

**On iPhone**, open BaoBuddy and tap **Try Demo**. The demo runs in memory and can use Face ID to sign a sample request. The simulator uses a software key.

**On Mac**, follow the [local OpenBao quickstart](examples/quickstart/README.md) to build the helper from source, create a read-only policy, approve a one-hour grant with Touch ID, and revoke it. Docker runs OpenBao on the Mac’s loopback interface.

---

## Top three limitations (read before relying on it)

Every security tool has boundaries. These are BaoBuddy's top three — full details and mitigations are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md):

1. **The server can't verify the app-displayed scope beyond `allowed_policies`.** OpenBao/Vault only sees that a registered device key signed a 30-second JWT and returns a 2-minute `granter` token. The app enforces the exact policy subset and checks the minted token (`verify`), so the token role's `allowed_policies` and `token_explicit_max_ttl` are the true server-side ceiling.
2. **macOS Keychain.** The provisioned helper saves new approval keys in its private data-protection Keychain group. Existing installations must register a new Mac public key with each issuer, verify a grant, then retire the previous public key at that issuer. The helper leaves old Keychain items available for deliberate recovery. Local bearer grants and extension credentials still use the login Keychain so authorized scripts can consume them.
3. **Local shell agents can request `--on direct` or revoke grants.** An agent with shell access on your Mac can run `bao-buddy grant --on direct` (which prints the token to stdout; the Touch ID prompt explicitly warns the token goes to "the program that asked") or call `bao-buddy revoke` (denial of service, not a secret leak). Use `--on local` or a remote host running `baobuddy-receiver` for agent workflows.

---

## Why not X?

These tools are good, and some are stronger than BaoBuddy where it matters most: they're enforced
by the server. BaoBuddy's approved scope is enforced by the app (see the threat model).

| Alternative | Where it's stronger | Where BaoBuddy differs |
| --- | --- | --- |
| **OpenBao / Vault login MFA (TOTP, Duo, Okta)** | The server enforces the second factor at login. | Login MFA proves who signed in, not what they're about to mint. BaoBuddy shows each request (policies, target, duration, reason) in a prompt before signing, and delivers the grant to a remote host or agent without a password on that host. |
| **OIDC with passkeys (`vault login -method=oidc`)** | Phishing-resistant, standard, centrally managed through your IdP. | Needs an IdP and a browser on the machine that logs in, which is awkward for headless VMs and agents. BaoBuddy uses only the built-in JWT auth method with device keys. |
| **Teleport / Boundary** | A full access plane: session recording, RBAC, audit, many protocols. | Much more to deploy and run. BaoBuddy adds no server of its own to your existing OpenBao or Vault. |
| **Secretive / 1Password SSH agent** | Mature, hardware-backed SSH keys with Touch ID per use. | They cover SSH authentication. BaoBuddy mints scoped, time-boxed OpenBao/Vault tokens, SSH certificates, and dynamic credentials, and can revoke them. |

---

## How it works

1. **You review the request:** server, target, duration, policies (or read/write, restricted keys, and SSH hosts), and an audit reason. BaoBuddy shows it before asking for biometrics.
2. **The Secure Enclave signs a 30-second ES256 JWT** (`iss`, `sub`, `aud`, `device`, `iat`, `exp`, `jti`, `scope`) only after a fresh biometric check (`.biometryCurrentSet`, no reuse window).
3. **OpenBao or Vault verifies the JWT** against the P-256 public keys registered on a JWT auth mount and returns a **2-minute `granter` token**.
4. **BaoBuddy mints the approved grant and checks it:** exact policies, orphan, non-renewable, and no longer than approved. A token that doesn't match is revoked. It can add an OpenBao SSH user certificate and a 1-hour GitHub push token.
5. **Cleanup:** BaoBuddy revokes the `granter` token right away. If delivery fails, it also revokes the new grant and any push token.

> **What the server can't check.** OpenBao only learns that a registered device key signed in. It
> can't see what you approved, so the scope is enforced by the app, and the token role's
> `allowed_policies` is the server-side limit. Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
> before you rely on BaoBuddy.

```text
iPhone / Mac (Secure Enclave P-256 + Face ID / Touch ID)
  │
  │  1. Sign 30s ES256 JWT (never leaves hardware)
  ▼
OpenBao / Vault  (auth/jwt-<you>/ → 2m least-privilege `granter` token)
  │  2. Mint scoped orphan grant token (+ optional SSH user cert)
  │  3. Revoke temporary `granter` sign-in token
  ▼
Delivery
  ├─ Direct Token mode: shown in-app (2-minute, this-device-only clipboard + 1-tap revoke)
  ├─ macOS Helper mode: stored in the macOS login keychain for local terminal scripts
  └─ Remote SSH Target: installed over pinned-host-key SSH onto a VM / bastion / runner
```

No server addresses, TLS certificates, or secrets are checked into this repository.

---

## Suggested use cases

### 1. AI coding agents & autonomous VMs
Keep coding agents and background VMs locked out of your secrets and SSH access by default. When an agent needs temporary access, it hands you a `baobuddy://grant?r=...` link. Tapping it opens BaoBuddy, displays the requested scope alongside any active workloads on the host, and lets you approve a time-boxed grant with Face ID.

Agents can ask for a grant, through the `bao-buddy mcp` server or a link, but can't approve one: every grant needs your biometric approval, and the approval sheet shows the real scope. Two limits to know:

- An agent with shell access on your Mac can run `bao-buddy grant --on direct` or `bao-buddy personal-token`, which print a token to the caller. The Touch ID prompt says the token goes to "the program that asked"; don't approve that for an agent, because the token would land in its context and transcript. Use `--on local` or a remote target instead.
- Any agent that can run `bao-buddy` can revoke your grants without asking. That's denial of service, not a leak.

### 2. Break-glass & production deployments
Eliminate standing privileges for high-impact operations. Define custom policies in BaoBuddy (for example `k8s-deploy`, `terraform-apply`, `db-write`, `pki-issue`), mark them **Elevated** (highlighted in orange), and mint a 1-hour audited token with a required reason only when deploying or responding to an incident.

### 3. Ephemeral OpenBao SSH user certificates
Use OpenBao's SSH secrets engine to sign short-lived Ed25519 user certificates scoped to specific hosts and principals (e.g., `root@docker`, `ops@bastion`). Certificates expire automatically with the grant — no permanent SSH private keys left sitting on remote machines.

### 4. Multi-environment Vault operations
Configure separate profiles for **Development**, **Staging**, and **Production** OpenBao/Vault servers — each with its own TLS pin, JWT auth mount, and dynamic policy catalog — and switch between them from the top bar or via `baobuddy://grant?profile=<name>&r=...`.

### 5. Dynamic credentials alongside the grant
Describe AWS STS, Kubernetes, database, PKI, or GitHub secrets engines as [credential extensions](docs/EXTENSIONS.md). Selecting one adds it to the approval, mints it with the grant token (so its lease ends with the grant), and delivers it to the remote host, this Mac's Keychain, or the iOS app.

### 6. Touch ID terminal workflows on macOS
Install `bao-buddy` (`BaoBuddyHelper.app`) on your Mac so local scripts and `make` targets prompt for Touch ID instead of asking for your OpenBao password.

---

## Prerequisites & server setup (OpenBao / HashiCorp Vault)

BaoBuddy works with any OpenBao or HashiCorp Vault server reachable over HTTPS (plain `http://` is accepted only for loopback addresses). Self-signed leaf certificates and private CAs are supported through a pinned PEM. Without a PEM, the system certificate store is trusted and the app labels the server "TLS not pinned".

### Fast path: use the built-in `bao-buddy` CLI (no `make` or `bao` CLI needed)

Point `BAO_ADDR` and `BAO_TOKEN` (or `VAULT_ADDR` / `VAULT_TOKEN`) at your server once, then let `bao-buddy` configure everything over OpenBao's HTTP API. The admin token is read from the environment or from stdin (`--token-stdin`), never from a command-line flag, because flags show up in `ps` and shell history.

```bash
export BAO_ADDR=https://openbao.example.com:8200
export BAO_TOKEN=<admin-token>
# Optional for self-signed or private CA certs:
# export BAO_CACERT=/path/to/ca.crt

# 1. Bootstrap per-operator granter policy (`granter-alice`), token role (`grant-alice`),
#    ES256 JWT mount (`jwt-alice`), deployment-bound audience (`baobuddy://...`),
#    and register this Mac's server-scoped Secure Enclave key in one shot.
#    Use one mount per person: every key on a mount can sign in as its subject.
bao-buddy server-setup --mount jwt-alice --subject alice \
  --policies db-readonly,k8s-deploy,terraform-apply --add-self

# 2. Export a ready-to-import profile JSON (copied for iPhone + saved for this Mac):
bao-buddy export-profile \
  --name "Production OpenBao" \
  --mount jwt-alice \
  --subject alice \
  --policies db-readonly,k8s-deploy,terraform-apply \
  --elevated k8s-deploy,terraform-apply \
  --copy --save

# 3. On iPhone: open BaoBuddy -> Set Up First Server -> Paste Profile JSON from Clipboard,
#    then create its server-scoped Hardware Approval Key and copy its PEM.
#    Register that iPhone key on OpenBao (preserving BAO_ADDR, BAO_NAMESPACE, BAO_CACERT,
#    or passing --addr / --namespace / --cacert / --mtls-identity if not in env):
pbpaste | bao-buddy device add --mount jwt-alice
```

Every server deployment uses its own Secure Enclave signing key, JWT audience, and local Keychain slot scoped to `(server, base path, namespace, TLS CA pin, mTLS client identity, mount)`, so adding a server first ensures the device key is bound to that exact trust domain. Deliberate trust changes (rotating a pinned leaf certificate, changing `ca_pem`, or changing `mtls_client_identity`) start a new trust domain and require re-enrolling the new scoped device key (`bao-buddy device add --self` or iOS **Settings → Hardware Approval Key**) and updating `bound_audiences`.

Manage registered devices anytime:

```bash
bao-buddy device list   --mount jwt-alice                  # SHA-256 fingerprints registered on OpenBao
bao-buddy device remove --mount jwt-alice <sha256-prefix>  # stop a lost device from signing in
```

Removing a device key stops new sign-ins only. It doesn't revoke grants that device already minted, and it doesn't remove its SSH key from a remote host. The command prints both follow-up steps.

### Manual OpenBao / Vault CLI setup (Linux or without `bao-buddy`)

#### 1. Create a least-privilege per-operator `granter-<you>` policy

The device sign-in token should **only** be able to mint grants through your per-operator token role, revoke grants, and revoke itself (and optionally sign SSH keys or mint GitHub tokens server-side). It needs no `sudo`, and never `root`, `admin`, or read access to your secrets. The JWT role below sets `token_no_default_policy`, so every path the token needs is listed here.

```hcl
# granter-alice.hcl
path "auth/token/create/grant-alice" {
  capabilities = ["create", "update"]
}

path "auth/token/revoke" {
  capabilities = ["update"]
}

path "auth/token/revoke-accessor" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}

# Optional: sign ephemeral SSH user certificates
# path "ssh/sign/ops" {
#   capabilities = ["create", "update"]
# }

# Optional: mint GitHub push tokens on the server (vault-plugin-secrets-github permission set)
# path "github/token/push" {
#   capabilities = ["create", "update"]
# }
```

```bash
bao policy write granter-alice granter-alice.hcl
```

### 2. Create a per-operator scoped token role

Configure the token role that restricts which policies and TTLs BaoBuddy is allowed to mint for this operator:

```bash
bao write auth/token/roles/grant-alice \
  allowed_policies="db-readonly,k8s-deploy,terraform-apply" \
  disallowed_policies="root" \
  orphan=true \
  renewable=false \
  token_explicit_max_ttl=12h
```

### 3. Generate your server-scoped Secure Enclave public key

- **iPhone / iPad**: First add or import your server profile in **BaoBuddy** (**Setup Wizard** or **Settings → OpenBao / Vault Servers**), then tap **Create Server-Scoped Key** and **Copy P-256 Public Key PEM** and save it as `device.pem`.
- **macOS**: Run `bao-buddy init --addr https://openbao.example.com:8200 --mount jwt-alice` (or `bao-buddy init` after importing a profile) to print the server-scoped PEM to stdout.

### 4. Enable ES256 JWT auth on OpenBao / Vault

Use one mount per person and a deployment-bound audience (`baobuddy://<host[:port]>[/ns/<ns>]/auth/<mount>[?base=<path>]`): Vault trusts every key on a mount equally, and the device chooses the `sub` claim. Register that person's device public keys (`jwt_validation_pubkeys`) and bind the role to the expected claims and trusted network CIDRs:

```bash
bao auth enable -path=jwt-alice jwt

bao write auth/jwt-alice/config \
  bound_issuer="bao-granter" \
  jwt_supported_algs="ES256" \
  jwt_validation_pubkeys=@device.pem

bao write auth/jwt-alice/role/alice \
  role_type="jwt" \
  user_claim="sub" \
  bound_subject="alice" \
  bound_audiences="baobuddy://openbao.example.com:8200/auth/jwt-alice" \
  token_policies="granter-alice" \
  token_no_default_policy=true \
  token_ttl=2m \
  token_max_ttl=2m \
  expiration_leeway=5 \
  not_before_leeway=5 \
  clock_skew_leeway=5 \
  token_bound_cidrs="10.20.0.0/16" \
  claim_mappings="device=device" \
  claim_mappings="scope=scope"
```

The leeway settings matter: Vault's defaults add 150 seconds to `exp` and 60 seconds of clock skew, which would let a 30-second JWT be used for about 3 minutes. `device` and `scope` are copied into the sign-in token's metadata for your audit log. Both are claims the device chose, so treat them as a record, not proof.

> **Revoking a lost device:** remove its PEM from `jwt_validation_pubkeys` (or run `bao-buddy device remove`). That stops new sign-ins. Then revoke grants it already minted, and remove its SSH key from any remote granter host.

---

## Setting up the iOS app

Open [BaoBuddy.xcodeproj](BaoBuddy.xcodeproj) in Xcode, select your iPhone or iPad, and run (`⌘R`).

### Option A: Manual setup in the app (no scripts needed)

1. Open **Settings → OpenBao / Vault Servers → Add Manually**.
2. Enter your server display name, HTTPS URL, JWT auth mount/role/subject/issuer/audience, and token role.
3. Choose **Custom Policies** and add each OpenBao/Vault policy you want in your UI:
   - Exact OpenBao policy name (e.g., `k8s-deploy`)
   - Friendly display label (e.g., `Kubernetes Deploy`)
   - Optional short description
   - **Elevated** toggle (highlights the policy and approval CTA in orange)
   - **Selected by default** toggle
4. Paste a custom CA or self-signed server certificate PEM to pin TLS. Without one, the system certificate store is trusted.
5. Leave **Deliver Grants Over SSH** off for **Direct Token** mode, or turn it on to deliver grants to a remote SSH granter host. A pinned host key is required.

The **Grants** tab immediately adapts to your server and renders interactive controls for your exact policies.

### Option B: Import a profile JSON

Open **Settings → Import JSON** and paste a version 1 profile. You can import multiple profiles and switch between them from the top-right server menu on the **Grants** tab.

#### Minimal standalone profile (custom dynamic policies, Direct Token mode)

```json
{
  "version": 1,
  "name": "Production OpenBao",
  "openbao": {
    "address": "https://openbao.example.com:8200",
    "ca_pem": "",
    "jwt_auth": {
      "mount": "jwt-alice",
      "role": "alice",
      "issuer": "bao-granter",
      "audience": "baobuddy://openbao.example.com:8200/auth/jwt-alice",
      "subject": "alice"
    },
    "token_roles": {
      "local": "grant-alice"
    },
    "grant_policies": [
      {
        "name": "db-readonly",
        "label": "Database Read-Only",
        "description": "Read replica credentials",
        "default_selected": true
      },
      {
        "name": "k8s-deploy",
        "label": "Kubernetes Deploy",
        "description": "Deploy workloads to production",
        "elevated": true
      },
      {
        "name": "terraform-apply",
        "label": "Terraform State Write",
        "elevated": true
      }
    ],
    "max_hours": 12
  }
}
```

#### Full profile with remote SSH delivery, SSH certificates, and restricted keys

```json
{
  "version": 1,
  "name": "Team Lab",
  "openbao": {
    "address": "https://openbao.example.com:8200",
    "ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "jwt_auth": {
      "mount": "jwt-alice",
      "role": "granter",
      "issuer": "bao-granter",
      "audience": "",
      "subject": "alice"
    },
    "token_roles": {
      "local": "grant-alice",
      "remote": "grant-alice-remote"
    },
    "policies": {
      "read": "secrets-read",
      "write": "secrets-write",
      "key_prefix": "secrets-key-",
      "key_write_suffix": "-write"
    },
    "max_hours": 12,
    "keys": [
      { "name": "cluster", "item": "cluster" }
    ],
    "ssh": {
      "role": "ops",
      "hosts": [
        { "name": "docker", "user": "root", "principal": "root-docker" }
      ]
    },
    "github_token_path": "github/token/push"
  },
  "remote_target": {
    "name": "Agent VM",
    "host": "agent-vm.example.com",
    "port": 22,
    "user": "granter",
    "host_key": "ssh-ed25519 AAAA..."
  }
}
```

*(Leaving `"audience": ""` — or omitting it — automatically derives the trust-domain-bound `baobuddy://...` audience from `address`, `namespace`, `mount`, `ca_pem`, and `mtls_client_identity`, matching `bao-buddy server-setup` and OpenTofu so you never have to hand-compute `?pin=` or `?mtls=` hashes; `bao-buddy export-profile` also writes the exact derived value. Non-`baobuddy://` custom audiences are preserved verbatim for external JWT roles. Legacy `t3_granter` and `token_roles.mac` / `token_roles.t3` keys are still read. Imported profiles are validated: `https://` only, plain-text names and labels, unique policy/key/host names, and a pinned `host_key` for any remote target.)*

`github_token_path` points at a server-side GitHub token endpoint, such as a [vault-plugin-secrets-github](https://github.com/martinbaillie/vault-plugin-secrets-github) permission set, so the GitHub App private key never leaves the server. The older `github_app_item` setting still works but reads the App private key into the client. See the threat model before using it.

---

## Deep links (`baobuddy://`)

External tools, chat bots, or scripts can open the BaoBuddy approval sheet directly with a pre-filled request:

```text
baobuddy://grant?r=HOURS%3D2%20POLICIES%3Ddb-readonly,k8s-deploy%20WHY%3Drelease%20v1.4
```

Query parameters:
- `profile_id` *(optional)* — exact saved server profile ID (preferred; takes precedence over `profile`).
- `profile` *(optional)* — matches a saved server profile by `id` or unambiguous case-insensitive `name`. Defaults to the currently active server.
- `server`, `mount`, `namespace` *(optional)* — verified against the resolved profile (conflicting hints are rejected; used for exact cross-device matching when a link generated on Mac opens on iPhone).
- `target` *(optional)* — `local` or `remote`. Defaults to `remote` when the profile has a remote target.
- `remote_target_id` / `remote_target` *(optional)* — exact remote target ID or unambiguous name; an unknown or ambiguous target is an error.
- `r` — space-separated canonical grant parameters:
  - `HOURS=<1..max_hours>`
  - `POLICIES=<p1,p2>` (must be listed in the profile's `grant_policies`; links can't name policies for a profile without that catalog)
  - `WRITE=1` (standard read/write mode)
  - `KEYS=<k1,k2>` (restricted keys in standard mode)
  - `SSH=<host1,host2>` (hosts defined in `openbao.ssh.hosts`)
  - `PUSH=1` (1-hour GitHub App push token when `github_token_path` or `github_app_item` is configured)
  - `EXT=<id1,id2>` (enabled [credential extensions](docs/EXTENSIONS.md) to mint with the grant)
  - `WHY=<reason>` (sanitized, max 120 chars, recorded in OpenBao token metadata & audit log)

Every link is validated against the local profile and shown in the **Approve Grant** sheet. BaoBuddy never approves on its own or asks for biometrics until you tap **Approve**. A link's `profile` applies to that approval only: it never changes your active server, and a `profile` that isn't set up is an error rather than a fallback to another server. Links that arrive while an approval is in progress are ignored.

---

## Remote SSH target protocol (optional)

When a profile defines `remote_target`, BaoBuddy connects over SSH (`apple/swift-nio-ssh`) using:
- A P-256 client key in the Secure Enclave (`ecdsa-sha2-nistp256`; **Settings → Remote SSH Delivery Key** on iOS, `bao-buddy ssh-key` on macOS). It can't be copied off the device. It isn't biometric-gated, because status checks run without a prompt.
- Host-key pinning against `remote_target.host_key`. BaoBuddy refuses to connect without a pin.
- A 30-second limit per command. A command that ends without an exit status counts as a failure.

The device that approved a remote grant records its accessor and revokes it through OpenBao (`auth/token/revoke-accessor`), so revoking doesn't depend on the remote host cooperating.

Your remote host's `authorized_keys` can lock that SSH key to a forced-command script implementing five simple commands:

| Command | Stdin | Expected stdout |
| --- | --- | --- |
| `status` | *(none)* | Human-readable status lines (`Secrets: ...`, `SSH: ...`, `Push: ...`) |
| `tasks` | *(none)* | Zero or more active workload lines, or `!` if the task broker is unreachable |
| `pubkey` | *(none)* | `ssh-ed25519 AAAA...` (the remote host's ephemeral SSH key to sign via OpenBao) |
| `install` | 3 lines: `<token>\n<ssh_cert>\n<push_token>\n`, or, when the grant includes [credential extensions](docs/EXTENSIONS.md), one line of JSON: `{"version":2,"token":...,"ssh_cert":...,"push_token":...,"artifacts":[{"name":...,"content":...,"expires_at":...}]}` | `Granted until ...` on success (any other result revokes the minted token, its extension leases, and the push token) |
| `revoke` | *(none)* | Confirmation message after revoking the active grant and deleting local copies |

---

## macOS helper (`bao-buddy`)

### Install via Homebrew (packaged release)

Once a macOS release is published to GitHub Releases and `northcutted/homebrew-tap`:

```bash
brew install --cask northcutted/tap/baobuddy
```

This installs `/Applications/BaoBuddyHelper.app` and puts `bao-buddy` on your `PATH`. You can also download the notarized `.dmg` or `.zip` directly from GitHub Releases.

### Build from source

Build and install the signed Hardened Runtime macOS helper locally:

```bash
export MAC_HELPER_PROFILE="/path/to/BaoBuddy Helper Developer ID.provisionprofile"
make build-mac     # builds & signs build/BaoBuddyHelper.app (Developer ID + Hardened Runtime)
make install-mac   # installs /Applications/BaoBuddyHelper.app & symlinks ~/.local/bin/bao-buddy
make dist-mac      # creates local .zip, .dmg, SHA256SUMS.txt & rendered Homebrew Cask
```

For local UI and CLI development without a provisioning profile, use ad-hoc signing. Biometric enrollment and signing require the provisioned build.

```bash
make build-mac SIGN_IDENTITY="-"
```

One-time setup:

```bash
bao-buddy import-profile < profile.json # saves profile to ~/.config/baobuddy/profiles.json
bao-buddy init                          # creates server-scoped Secure Enclave P-256 key, prints PEM
bao-buddy pubkey                        # prints server-scoped PEM public key for OpenBao JWT auth
bao-buddy ssh-key                       # Secure Enclave SSH key for remote delivery (optional)
```

Commands:

```bash
bao-buddy grant --on local --hours 2 --why "terraform plan"
bao-buddy grant --on remote --hours 2 --ssh docker --why "inspect logs"
bao-buddy grant --on local --hours 1 --ext db-creds --why "migration"   # credential lands in the Keychain
bao-buddy revoke --on remote            # revokes through OpenBao by accessor, then cleans up the host
bao-buddy personal-token --why "quick check"   # prints a 15-minute token: for you, never for an agent
bao-buddy status
open /Applications/BaoBuddyHelper.app   # or `bao-buddy menubar` for the live menu bar icon
```

When opened without CLI arguments (from Finder, Spotlight, or Login Items), `BaoBuddyHelper.app` runs in the macOS menu bar with the BaoBuddy template glyph (locked when idle, unlocked with remaining TTL when a grant is active), one-click 1-hour Touch ID Mac grants, and instant revoke.

---

## Security & privacy model

The full threat model, including what BaoBuddy doesn't protect against, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). To report a vulnerability, see [SECURITY.md](SECURITY.md). In short:

- **Hardware-bound signing keys:** the sign-in key lives in the Secure Enclave with `[.privateKeyUsage, .biometryCurrentSet]`, so adding or changing enrolled biometrics invalidates it. Every signature needs a fresh biometric check.
- **The server can't see your approval:** the scope you approve is enforced by the app. The server-side limit is the token role's `allowed_policies` and maximum TTL, so keep both small. Every minted token is checked against the approval and revoked if it doesn't match.
- **One identity per JWT mount:** every device key on a mount can sign in as that mount's subject.
- **TLS:** pinned to `ca_pem` when you provide one (exact leaf or private CA). Otherwise the system certificate store is trusted, and the app says so. Plain `http://` is refused except on loopback.
- **SSH:** the host key must be pinned. The client key lives in the Secure Enclave.
- **No vendor cloud:** BaoBuddy talks to your OpenBao or Vault server and your SSH host. It has no analytics or relays. It sends grant events (who, policies, reason) to an OpenTelemetry collector only if a profile sets `telemetry.otlp_endpoint`; importing such a profile shows the endpoint first.
- **Clipboard:** a copied direct token expires after 2 minutes and stays off Universal Clipboard. MDM can disable copying.
- **macOS limits:** A process allowed to read an issued bearer token from the login Keychain can use it until revocation or expiry.

---

## Repository structure

- `Sources/BaoBuddyCore` — Shared Swift 6 library: Secure Enclave key store, ES256 JWT signer, pinned TLS client, OpenBao API client, multi-profile store, dynamic policy/request parser, GitHub App push token client, Mac Keychain store, and orchestrator.
- `Sources/BaoBuddySSH` — Pure-Swift SSH client on [`apple/swift-nio-ssh`](https://github.com/apple/swift-nio-ssh) with Secure Enclave P-256 client keys (legacy Ed25519 Keychain keys still work), host-key pinning, and half-close stdin delivery.
- `Sources/BaoBuddyHelper` — macOS Hardened Runtime CLI helper and menu bar app (`BaoBuddyHelper.app` / `bao-buddy`).
- `BaoBuddy/` + `BaoBuddy.xcodeproj` — Native SwiftUI iOS companion app with Liquid Glass styling, context-aware biometrics, Dynamic Type, 44pt touch targets, VoiceOver labels, and the BaoBuddy identity (`BaoTheme`).
- `BaoBuddyLiveActivity/` — WidgetKit Live Activity & Dynamic Island extension showing active grants and remaining time.
- `Branding/` — Single source of truth (`Branding/generate.py`) for the flat-vector logo, Liquid Glass `AppIcon.icon`, in-app template glyphs, and macOS menu bar PNGs. See [Branding/README.md](Branding/README.md).
- `Tests/BaoBuddyCoreTests` & `BaoBuddyTests` — SwiftPM and iOS Simulator unit test suites.
- `.github/` — CI and release configuration for [`northcutted/ios-release-workflows`](https://github.com/northcutted/ios-release-workflows).

---

## Development & CI

```bash
make brand       # Regenerate AppIcon.icon, XCAssets, menu bar PNGs & SVGs from Branding/generate.py
make test-core   # SwiftPM unit tests (BaoBuddyCoreTests)
make test-ios    # iOS Simulator tests (BaoBuddyTests)
make build-mac   # Release macOS helper app + Liquid Glass icon + codesign --verify --strict
make lint        # SwiftLint
```

### Release workflows

- **iOS**: built and shipped by [`northcutted/ios-release-workflows`](https://github.com/northcutted/ios-release-workflows) from `.github/ios-release.json`. **Release Prep** (`main.yml`) builds a verified candidate on every push to `main`; **Release** (`ios-release.yml`) promotes a chosen candidate to TestFlight or the App Store; **App Store Deploy** and **Release Maintenance** handle submission and status. Metadata and review notes live in `app-store/metadata/`. One-time setup: [docs/RELEASE_SETUP.md](docs/RELEASE_SETUP.md).
- **macOS**: `.github/workflows/release-mac.yml` runs on `helper-v*` tags (or manual dispatch from `main`) in two jobs; `v*` tags belong to the iOS release platform. The signing job uses a `helper-release` environment with required reviewers and the signing secrets (`scripts/provision-repo.sh` sets it up). The `build` job tests and builds a universal (`arm64` + `x86_64`) `BaoBuddyHelper.app` with read-only permissions and no secrets. The `release` job never builds code: it signs with Hardened Runtime, notarizes the `.zip` and `.dmg`, attests build provenance, and publishes them with `SHA256SUMS.txt`, a CycloneDX SBOM, and a rendered Homebrew cask. Verify a download with `gh attestation verify <file> --repo northcutted/baobuddy`. Required GitHub Actions secrets:
  - `DEVELOPER_ID_CERT_P12` (base64-encoded Developer ID Application `.p12`)
  - `DEVELOPER_ID_CERT_PASSWORD`
  - `DEVELOPER_ID_IDENTITY` (e.g., `Developer ID Application: Edward Northcutt (BDQ47H73HH)`)
  - `APP_STORE_CONNECT_API_KEY_P8` (base64-encoded `.p8` key for `notarytool`)
  - `APP_STORE_CONNECT_KEY_ID` and `APP_STORE_CONNECT_ISSUER_ID`

- **Receiver** releases use `receiver-v*` tags or a manual **Release Receiver** run from `main`. The dedicated `receiver-release` environment publishes five Go binaries and their checksums with GitHub build attestations. See the [receiver install instructions](receiver/README.md#quick-install).

## License

MIT — see [LICENSE](LICENSE).
