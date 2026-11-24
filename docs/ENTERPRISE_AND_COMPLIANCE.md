# Enterprise, Government & Compliance Guide

BaoBuddy is designed so security, platform, and compliance teams can deploy hardware-backed biometric approvals for OpenBao and HashiCorp Vault without introducing any third-party cloud service or SaaS dependency.

---

## 1. Security & Compliance Architecture

| Control | Implementation |
| --- | --- |
| **Hardware Cryptography** | Private signing keys (`EC P-256` / `ES256`) and remote SSH delivery keys (`ecdsa-sha2-nistp256`) are generated inside Apple's Secure Enclave and can't be exported. Apple lists FIPS 140-3 validations for its Secure Key Store module on specific OS releases; check Apple's [security certifications](https://support.apple.com/guide/certifications/welcome/web) for the versions you deploy. BaoBuddy itself isn't FIPS-validated. |
| **Biometric Binding** | Approval keys require `.biometryCurrentSet` (Touch ID / Face ID / Optic ID). Adding or changing enrolled biometrics automatically invalidates the hardware key. |
| **No vendor cloud** | BaoBuddy has no backend server, relay, analytics, or crash-reporting SDK. Traffic goes from the Mac or iPhone to your OpenBao / Vault cluster, your remote SSH target if configured, GitHub if legacy push tokens are used, and an OTLP collector only if a profile sets `telemetry.otlp_endpoint` (off by default; the endpoint is shown when a profile is imported). |
| **Short-lived sign-in** | Each approval signs a 30-second ES256 JWT, exchanges it for a 2-minute `token_no_default_policy=true` granter token (5 s leeways), mints an orphan non-renewable scoped token, checks its policies, TTL, orphan, and renewable flags, and revokes the sign-in token. The JWT carries a unique `jti`, but OpenBao's JWT auth doesn't track it, so a captured JWT can be replayed until it expires (see the threat model). |
| **Transport Pinning & mTLS** | Supports custom CA / leaf TLS certificate pinning (`ca_pem`), optional mutual TLS client certificates (`mtls_client_identity` resolved from the Apple Keychain — never stored in profile JSON), and strict SSH host key pinning (`host_key`). |
| **Supply Chain** | Signed with Developer ID, notarized, published with SHA-256 checksums, a CycloneDX SBOM of the Swift package dependencies, and GitHub build provenance attestations (SLSA provenance format, built on GitHub-hosted runners). |

See [THREAT_MODEL.md](THREAT_MODEL.md) for the complete trust-boundary analysis.

---

## 2. Namespaces (Vault Enterprise, HCP Vault & OpenBao 2.x)

BaoBuddy sends the `X-Vault-Namespace` header automatically on every API request when `openbao.namespace` is set (keeping `/v1/sys/health` at root).

### CLI & Bootstrap
```bash
export BAO_ADDR="https://vault.corp.example:8200"
export BAO_NAMESPACE="admin/prod-us-east"
export BAO_TOKEN="<admin-token>"

bao-buddy server-setup \
  --subject alice \
  --mount jwt-alice \
  --policies db-readonly,k8s-deploy \
  --add-self

bao-buddy export-profile \
  --name "Prod US-East" \
  --subject alice \
  --mount jwt-alice \
  --policies db-readonly,k8s-deploy \
  --elevated k8s-deploy \
  --require-reason-elevated \
  --reason-pattern '^(INC|CHG|JIRA)-[0-9]+' \
  --reason-placeholder 'CHG-12345 — change summary' \
  --save
```

Or pass `--namespace admin/prod-us-east` directly on `server-setup`, `device`, and `export-profile`.

---

## 3. Mutual TLS (mTLS) Client Certificates

For clusters fronted by an mTLS gateway or load balancer:

1. Push the user's client certificate + private key into the macOS/iOS Keychain via your MDM (SCEP / ACME / ADCS) — **never** embed private keys in BaoBuddy profile JSON.
2. Set `openbao.mtls_client_identity` to either:
   - the certificate Common Name / Subject Summary (for example `alice.vault.corp.example`), or
   - the certificate's SHA-256 fingerprint (`sha256:...`).
3. BaoBuddy resolves the matching `SecIdentity` from the Keychain at TLS handshake time and presents it automatically on `NSURLAuthenticationMethodClientCertificate` challenges.

---

## 4. Audit Policy & Change-Ticket Enforcement

Configure `openbao.audit_policy` in your profile (or enforce `require_reason_for_elevated` via MDM):

```json
"audit_policy": {
  "require_reason": false,
  "require_reason_for_elevated": true,
  "reason_pattern": "^(INC|CHG|JIRA)-[0-9]+",
  "reason_placeholder": "CHG-12345 — brief change summary"
}
```

Enforcement happens in `BaoBuddyCore` before biometric signing, so it applies to the macOS menu bar, the iOS approval sheet, `baobuddy://` deep links, the `bao-buddy` CLI, and the MCP server.

**This is a client-side control.** OpenBao can't see the reason rule, so a modified client can skip it. To enforce a reason on the server, give elevated policies their own token role and JWT mount, and alert on grants whose `why` metadata doesn't match your pattern.

---

## 5. OpenBao / Vault Audit Log Reference & SIEM Queries

Every BaoBuddy grant produces two linked events in the OpenBao / Vault audit log:

1. **Biometric sign-in** (`auth/<mount>/login`), recorded by the server:
   - `auth.policies` — `granter` (set by the server from the JWT role)
   - `auth.metadata.device` and `auth.metadata.scope` — copied from JWT claims (`claim_mappings`)
   - `auth.metadata.role`, and the mount in `request.path`, which identify the person (one mount per person)
2. **Scoped grant mint** (`auth/token/create/<role>`):
   - `auth.accessor` and `auth.policies` — the calling `granter` token (server-set)
   - `response.auth.policies`, `response.auth.token_ttl`, `response.auth.accessor` — what was minted (server-set)
   - `response.auth.metadata.by`, `.via` (`mac`, `app`, `cli`, or `mcp`), `.on` (`local`, `remote`, or `direct`), `.why`, `.scope` — written by the client

**Trust the server-set fields for detection.** Everything in `response.auth.metadata`, and the
`device` and `scope` claims, is chosen by the client: a modified client, or anyone holding the
device key, can write any value or leave it out. Use them to explain a grant, not to decide
whether it was legitimate. Key alerts on `request.path`, the calling token's `auth.policies` and
mount, and the minted policies.

### Splunk SPL (Alert on Elevated Grants)
```spl
index=vault_audit type="response" request.path="auth/token/create/*"
| where mvfind('response.auth.policies', "k8s-deploy") >= 0
| table _time, request.namespace.path, response.auth.metadata.by, response.auth.metadata.via, response.auth.metadata.on, response.auth.metadata.why, response.auth.token_ttl, response.auth.accessor
```

### Elastic / Kibana KQL
```kql
type: "response" and request.path: "auth/token/create/*" and auth.policies: "granter"
```

### Datadog Log Explorer
```text
service:openbao @type:response @request.path:auth/token/create/* @auth.policies:granter
```

---

## 6. MDM Deployment (Jamf, Kandji, Intune)

BaoBuddy supports managed configuration on iOS (Managed App Configuration, `com.apple.configuration.managed`) and macOS (a configuration profile whose payload type is the helper's domain, `com.northcutt.BaoBuddy.Helper`). On macOS only keys forced by an installed profile count, so a user can't override them with `defaults write`. Managed profiles always take precedence over local copies and can't be edited or replaced on the device. The app, menu bar, CLI, and MCP server all apply the managed settings.

### Supported Managed Keys

| Key | Type | Effect |
| --- | --- | --- |
| `profiles_json` | `String` | JSON array of `BaoProfile` objects to push to devices. |
| `profile_json` | `String` | Single `BaoProfile` JSON object (alternative to `profiles_json`). |
| `lock_profiles` | `Bool` | Locks the app strictly to MDM-pushed servers; hides Add / Import / Edit / Remove controls. |
| `disable_clipboard` | `Bool` | Disables copying direct tokens or profile JSON to the clipboard. |
| `enforce_tls_pinning` | `Bool` | Rejects any profile that does not pin a TLS certificate / CA (`ca_pem`). |
| `require_reason_for_elevated` | `Bool` | Forces an audit reason on every elevated grant across all profiles. |

See [examples/mdm/baobuddy-macos.mobileconfig](../examples/mdm/baobuddy-macos.mobileconfig) for a ready-to-customize macOS Configuration Profile. Leave `jwt_auth.audience` empty (`""`) — or generate `profiles_json` from `bao-buddy export-profile` or OpenTofu `baobuddy_profiles` — so BaoBuddy derives the exact trust-domain-bound `baobuddy://...` audience (including the `ca_pem` pin and `mtls_client_identity` hashes) from the deployment fields without hand-maintained hashes.
