# Changelog

All notable changes to **BaoBuddy** are documented in this file.

## [0.1.0] - Unreleased (Beta)

### Added
- **Built-in Demo Mode (iOS)**: In-memory simulated OpenBao server and remote host (`demo.baobuddy.invalid`) that cryptographically verifies real Secure Enclave ES256 JWT signatures with Face ID so first-time users and App Review can experience the full approval, credential extension, and revocation workflow without a server.
- **5-Minute Docker Compose Quickstart**: Self-contained OpenBao dev server + `baobuddy-receiver` container stack (`examples/quickstart/compose.yaml`).
- **Hardware-Backed Biometric Approvals (iOS & macOS)**: Non-exportable EC P-256 keys stored inside Apple's Secure Enclave gated by Face ID, Touch ID, or Optic ID (`.biometryCurrentSet`).
- **macOS Menu Bar App & Hardened CLI (`bao-buddy`)**: Native popover with quick approvals, multi-server switcher, deep-link approval (`baobuddy://grant?...`), Launch at Login (`SMAppService`), expiry notifications, and local non-secret activity log.
- **iOS Companion App & Live Activities**: Guided first-server setup wizard, dynamic policy approval sheets, Live Activity countdowns, 2-minute local-only clipboard for direct tokens, and QR code pairing scanner (`baobuddy://import?p=...`).
- **Enterprise & Government Governance**:
  - Vault Enterprise / HCP Vault / OpenBao 2.x **Namespaces** (`X-Vault-Namespace`).
  - **Mutual TLS (mTLS)** client certificate authentication via Apple Keychain (`mtls_client_identity`).
  - **Audit & Change-Ticket Policies** (`require_reason`, `require_reason_for_elevated`, ticket regex validation).
  - **macOS & iOS MDM Managed Configuration** (`lock_profiles`, `disable_clipboard`, `enforce_tls_pinning`, `require_reason_for_elevated`) plus sample `.mobileconfig`.
- **Workflow-Agnostic Credential Extensions**: Declarative OpenBao / Vault dynamic secrets engine extensions (5 built-in templates disabled by default: AWS STS, Kubernetes, Database, PKI, GitHub App) minted with the grant token so leases terminate with the grant.
- **Standalone Go Receiver (`baobuddy-receiver`)**: Zero-dependency static binaries (`linux/amd64`, `linux/arm64`, `darwin/arm64`, `darwin/amd64`, `freebsd/amd64`) with server-side token verification, v2 JSON artifact delivery, structured JSONL audit logs, Prometheus textfile metrics, and native OpenTelemetry OTLP/HTTP export.
- **OpenTofu / Terraform Module & Built-in Builder**: Reusable `for_each` module (`examples/opentofu/modules/baobuddy/`) plus interactive macOS builder and `bao-buddy tofu-init`.
- **AI Agent Integration (`bao-buddy mcp`)**: Zero-dependency stdio MCP server exposing 6 least-privilege tools, 2 resources, and 4 built-in prompts (never leaks raw tokens into LLM context, never bypasses biometrics), plus portable `SKILL.md` and `AGENTS.md` templates.
