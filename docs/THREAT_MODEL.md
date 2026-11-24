# BaoBuddy threat model

This document states what BaoBuddy protects, what it relies on, and where its protection ends.
Each limitation below is a known gap, not something on a hidden roadmap. If you find something
that isn't listed here, please report it as described in [SECURITY.md](../SECURITY.md).

## What BaoBuddy does

BaoBuddy replaces a long-lived OpenBao or HashiCorp Vault credential with short grants that a
person approves on an Apple device:

1. The app shows the request: server, target, policies, duration, and reason.
2. After a fresh Face ID or Touch ID check, the Secure Enclave signs a 30-second ES256 JWT.
3. OpenBao verifies the JWT against the device public keys registered on a JWT auth mount and
   returns a 2-minute `granter` token.
4. The app uses the `granter` token to mint the approved grant through a token role, checks the
   result, and revokes the `granter` token.
5. The grant is shown once in the app, saved to the macOS Keychain, or delivered over SSH to a
   remote host.

## Trust anchors

| Component | Trusted for |
| --- | --- |
| Apple Secure Enclave and biometrics | Keeping the signing key on the device and requiring a fresh biometric check for every signature |
| The BaoBuddy app or helper binary | Showing the true scope and minting only that scope |
| OpenBao or Vault, and its policy configuration | Enforcing the token role's allowed policies and maximum TTL |
| The registered device keys on a JWT mount | Representing one person |

## What the server enforces and what the app enforces

The most important limit is in this table. OpenBao only learns that a registered device key
signed a JWT. It doesn't learn what the user saw.

| Property | Enforced by |
| --- | --- |
| A registered device key signed the sign-in JWT | Server |
| Policies are within the token role's `allowed_policies` | Server |
| TTL is within the role's `token_explicit_max_ttl` | Server |
| The grant is orphan and non-renewable | Server role settings. The app also checks every minted token and revokes it on a mismatch. |
| The grant has exactly the policies, duration, and target the user approved | **App only** |

**Consequence:** anyone who can make the Secure Enclave key sign with one biometric approval can
mint any policy in `allowed_policies` for up to the role's maximum TTL. Keep `allowed_policies`
small. Give elevated policies their own token role, and their own JWT mount with a separate
device key, if you need the server to tell them apart.

The JWT carries a `scope` claim with the approved request text, and `server-setup` maps it into
the `granter` token's metadata. Audit logs then show the approved scope next to what was minted.
This helps reviewers catch a mismatch after the fact. It isn't enforcement: a compromised client
can write any `scope`.

## Threats

| Threat | Status | Notes |
| --- | --- | --- |
| Stolen phone or Mac (locked) | Mitigated | The key can't leave the Secure Enclave, and signing needs the enrolled biometric. Adding or changing enrolled biometrics invalidates the key. |
| Network attacker between the device and OpenBao | Mitigated when TLS is pinned | With `ca_pem` set, TLS is pinned to that certificate or CA. A CA pin still checks hostname and expiry; an exact leaf-certificate pin is the trust decision by itself (the handshake proves the server holds that key), so hostname and expiry aren't checked and rotation means updating `ca_pem`. With `ca_pem` empty, the system CA store is trusted, and the app shows "TLS not pinned". Plain `http://` is refused except for loopback addresses (including before admin/export requests), and HTTP redirects are never followed, so credentials can't be forwarded to another host. |
| Cross-server JWT replay or bearer disclosure | Mitigated | Every deployment uses a dedicated Secure Enclave key (`signing-key.v3.<hash>`) derived from the full trust-domain binding `(origin, base path, namespace, TLS CA/leaf pin, mTLS client identity)` plus JWT mount with no implicit fallback to an unscoped legacy key, and a matching trust-domain-bound audience (`baobuddy://<host[:port]>[/ns/<ns>]/auth/<mount>[?base=<path>&mtls=<hash>&pin=<hash>]`). BaoBuddy refuses to sign an empty or mismatched `baobuddy://` audience. Local macOS Keychain grants and artifacts use the same trust-domain binding (`openbao-grant.<v3-hash>` / `openbao-grant-artifact.<v3-hash>`), so distinct backends routed by path, TLS pin, or mTLS identity never share signing keys, audiences, or bearer tokens. Deliberate trust changes (rotating a pinned leaf certificate, changing `ca_pem`, or switching `mtls_client_identity`) create a new trust domain and require re-enrolling the new scoped device key and updating `bound_audiences`. |
| Replay of a sniffed sign-in JWT | Partly mitigated | The JWT is valid for 30 seconds, and `server-setup` sets 5 s leeways (Vault's defaults would allow about 3 minutes). OpenBao doesn't check `jti`, so a JWT captured inside TLS could be replayed within that window. TLS pinning makes capture hard. |
| Malicious `baobuddy://` link | Mitigated | Links only pre-fill the approval sheet and never approve. Without a `grant_policies` catalog, a link can't name policies. Links bind exact profile and remote-target IDs (with server/mount/namespace verification), reject ambiguous display names and conflicting endpoint/mount/namespace hints, and never fall back to another server or host. A link never changes the saved active server, and links are ignored while an approval is in progress. |
| Malicious profile import (QR code, `baobuddy://import` link, pasted JSON) | Mitigated | Imports are validated (canonical endpoint URLs without userinfo/query/fragment/percent-escapes), shown for confirmation with the server address, and flagged when they turn on telemetry, leave TLS unpinned, use a non-deployment-bound audience, define SSH principals, or replace an existing profile (listing changed pins, host keys, SSH role/principals, and endpoints). An imported profile's `id` is never trusted, so it can't take over another profile, including a managed one. |
| Misleading profile text (labels, bidi characters) | Mitigated | Imported and MDM profiles reject control and invisible formatting characters, and so do policy names typed into the CLI or sent by an agent. Policy names, server identity/base path/namespace, and SSH signing roles & exact principals are always shown in prompts and signed scopes. Server error text is stripped of formatting characters and never echoes a non-JSON body or URL credentials. |
| Prompt-injected AI agent | Partly mitigated | See "AI agents and the MCP server". |
| Misconfigured token role or SSH CA (renewable, wrong policies, long TTL) | Mitigated | Every minted token is checked for exact policies, orphan status, non-renewal, and TTL. A single conservative grant deadline is anchored before token creation, remaining TTL is recomputed right before SSH signing, and returned SSH certificates are parsed and verified with zero positive grace window (`validBefore <= grantDeadline`); any mismatch revokes the grant before delivery. |
| Compromised remote granter host | Partly mitigated | The host receives the grant and can use it until it expires. Before SSH delivery, the approving device requires a non-empty accessor and atomically persists it under a cross-process file lock scoped to `(profile, issuer, target)` (failing closed and revoking the newly minted token if persistence fails). Revocation revokes all live accessors for that target through OpenBao without trusting the host, never inferring legacy untargeted records onto today's target. SSH command output is bounded and timeouts terminate child processes cleanly. SSH certificates can't be revoked and last at most as long as the grant. |
| Same-user malware on macOS | **Not mitigated** | See "Limitations on macOS". |
| Malware on a jailbroken iPhone, or a compromised OS | Out of scope | |
| Compromised OpenBao server or admin | Out of scope | |
| Coercion of the device owner | Out of scope | |

## Known limitations

### Face ID doesn't display the scope

On iPhone, Face ID shows the app's usage description, not the request. The approval sheet,
which is drawn by the app, is the only place the scope appears. Touch ID on the Mac shows the
scope in the system prompt.

### One mount per person

Every key on a JWT mount can sign in to every role on that mount. A device can also claim any
`sub`, `device`, or `scope` value it likes. `server-setup` refuses to add a second subject to a
mount that already has one, but mounts configured by hand aren't checked. Use one mount per
person (`--mount jwt-<name>`), or per device if you need the audit log to identify the device
reliably.

### The device chooses the JWT expiry

OpenBao's JWT auth has no maximum JWT lifetime. A client that controls the Secure Enclave key
could sign a JWT with a distant `exp` after one biometric approval, and then sign in with it
repeatedly. Grants still follow the token role's limits. Removing the device key from the mount
ends this.

### Limitations on macOS

- New biometric approval handles use the provisioned helper’s explicit data-protection Keychain group. Provisioning and real Touch ID still require signed acceptance on a clean Mac user account. An old login-Keychain handle remains usable under its previous ACL while its public key remains enrolled at an issuer. Register a fresh Mac key, verify approval and cancellation, then retire the old public key at each issuer.
- `bao-buddy grant --on local` saves a bearer token, valid for up to the requested hours, in the
  login keychain for local scripts. Same-user malware that can read it can use it.
- Local state in `~/.config/baobuddy` (profiles, the activity log, and remote-grant accessors,
  which can only revoke) is written 0600 in a 0700 directory, so other users can't read it.
- Without `bao-buddy ssh-key`, remote delivery falls back to `/usr/bin/ssh` with
  `~/.ssh/id_ed25519`. That path ignores your ssh configuration and requires a pinned host key,
  but the key file is your general-purpose key.

### The SSH delivery key isn't presence-gated

New SSH keys live in the Secure Enclave and can't be copied off the device. They aren't gated by
biometrics, because status checks run without a prompt. Code running in the app's context could
call `status`, `tasks`, `revoke`, or `install` on the remote host. Grants it installs must still
come from a biometric sign-in. Installs from older versions may still hold a software Ed25519 key;
Settings offers to replace it.

### Remote revocation needs the accessor

The device that approved a remote grant keeps its accessor and revokes through OpenBao. A grant
approved on another device can only be revoked by that device, by the remote host, or by an
admin.

### Revoking a lost device

`bao-buddy device remove` stops new sign-ins. It doesn't:

1. revoke grants the device already minted (they last up to the token role's maximum TTL), or
2. remove the device's SSH key from a remote host's `authorized_keys`.

Do both. The command prints the steps.

### GitHub push tokens

The recommended setup mints push tokens on the server through a GitHub secrets plugin permission
set (`github_token_path`), so the App private key never leaves OpenBao. The legacy
`github_app_item` mode reads the App private key into the client. Any sign-in can then read a
credential that never expires. Use legacy mode only if you accept that.

### AI agents and the MCP server

`bao-buddy mcp` lets an agent ask for a grant. It can't approve one: the request opens the
approval UI (or returns a link), the human approves with a biometric check, and the MCP server
never returns a token. Requests are validated like deep links (catalogued policies only, exact
targets, strict argument types), and the suggested `cli_command` is shell-quoted.

Limits:

- An agent with shell access can run `bao-buddy grant --on direct` or `bao-buddy personal-token`.
  Both print a token to the caller. The biometric prompt says so ("Print token to the program
  that asked"), and the JWT scope carries `DIRECT=1`, but if the user approves, the token is in
  the agent's context.
- An agent that can run `bao-buddy` can read a local grant from the login keychain once the user
  allows that, like any other same-user process (see "Limitations on macOS").
- Any agent that can run `bao-buddy` can revoke grants without approval. That's denial of
  service only.
- `baobuddy_wait_for_grant` reports a matching active grant; it can't tell whether that grant was
  approved for this request or earlier.
- Remote status text comes from the remote host. The MCP server strips formatting characters and
  labels it `status_reported_by_host`, but a compromised host can still put misleading text in it.

### Organization (MDM) policy is enforced by the client

`lock_profiles`, `enforce_tls_pinning`, `require_reason_for_elevated`, and `disable_clipboard`
are applied by the app, the menu bar, the CLI, and the MCP server, at the point of use. On macOS
only keys forced by an installed configuration profile count, so `defaults write` can't turn them
off. They still aren't a boundary against the device's owner: someone who can run a modified
binary can skip them. The server-side controls are the token role and one JWT mount per person.
`reason_pattern` matching has a time limit, and a pattern that doesn't compile or times out
counts as a mismatch.

### Telemetry

Off by default. A profile with `telemetry.otlp_endpoint` makes the menu bar send grant events
(subject, server, namespace, policies, reason) to that collector, trusting the system CA store.
Importing such a profile shows the endpoint first. Telemetry headers usually hold a collector
API key, so they're removed whenever a profile is shared (QR code, link, clipboard, export) and
should come from MDM. Only the menu bar emits events today; the iOS app, CLI, and MCP server don't.

### The remote receiver

`baobuddy-receiver` checks each token with OpenBao before installing it, never follows
redirects, validates `lookup-self` JSON envelopes and required TTL fields, and keeps the token file
and `.grant.json` expiry metadata whenever OpenBao returns an ambiguous error (`missing client token`,
generic `permission denied`, non-canonical prose, or malformed HTTP 200) instead of confirmed
invalidity. It can't tell where a valid token came from: any key in its `authorized_keys` can
install one. `allowed_policies` and `required_meta` narrow what it accepts, but token metadata is
written by whoever minted the token. Its forced-command sandbox is OpenSSH's `restrict`; the
systemd hardening applies only to the cleanup timer.

### Credential extensions

Selected extensions are part of the approved scope (sheet, biometric prompt, JWT `scope`). They're
called with the grant token, so the server's policy on the grant decides what they reach, and
their leases end with the grant (checked against OpenBao: revoking the sign-in token leaves them,
revoking the grant by token or accessor removes them). Validation rejects control-plane endpoints
(`sys/`, `auth/`, `identity/`, `cubbyhole/`), a `root` policy, and responses that carry a token.
Limits: the server sees only the policies, not which extension the user picked; credentials
without a lease (STS sessions, unleased PKI certificates) outlive a revoked grant until their own
TTL; and local copies sit in the login keychain with the same same-user exposure as the grant.

### Concurrent admin changes

Device-key changes read, merge, and write the JWT mount's config. OpenBao offers no
compare-and-set for auth config, so two admins changing keys at the same moment can overwrite each
other. A failed read never writes.

## Recommended server configuration

`bao-buddy server-setup` applies these settings. If you configure the server by hand, match them:

- `granter` policy: `create`/`update` on `auth/token/create/<role>`; `update` on
  `auth/token/revoke`, `auth/token/revoke-accessor`, and `auth/token/revoke-self`; optionally
  SSH signing and a GitHub token path. No `sudo`, and no access to secrets.
- JWT role: `token_no_default_policy=true`, `token_ttl=2m`, `token_max_ttl=2m`,
  `expiration_leeway=5`, `not_before_leeway=5`, `clock_skew_leeway=5`, `bound_subject`,
  `bound_audiences`, `claim_mappings` for `device` and `scope`, and `token_bound_cidrs` where you can.
- Token role: small `allowed_policies`, `disallowed_policies=root`, `orphan=true`,
  `renewable=false`, and `token_explicit_max_ttl` set to the longest grant you accept.
- One JWT mount per person.
- Put secret paths in the policies a grant can carry, never in the `granter` policy. Give each
  credential extension its own policy and list it in `allowed_policies`.
