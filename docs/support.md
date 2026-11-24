# BaoBuddy Support

Need help setting up BaoBuddy with OpenBao or HashiCorp Vault, troubleshooting a connection, or reporting an issue?

## Quick Troubleshooting

1. **Try Demo Mode first (iOS):** Open BaoBuddy and tap **Try Demo** (on the welcome screen or in **Settings**) to verify Face ID signing, approval sheets, and revocation without needing a live OpenBao server.
2. **Check server health & TLS pin:** In **Settings → Guided Server Setup** (iOS) or **Settings → Servers → Test Connection** (macOS), verify that your device can reach OpenBao over HTTPS and that the pinned CA PEM matches.
3. **Check `baobuddy-receiver` on remote hosts:** Run `baobuddy-receiver doctor` on the target host to verify state directory permissions (`0750`), OpenBao reachability, and metrics/audit paths.
4. **Verify clock skew:** Short-lived ES256 sign-in JWTs use a 30-second lifetime with tight leeway (`5s`). Ensure NTP is synchronized on your OpenBao/Vault server and client device.

## Documentation

- [README & 5-Minute Quickstart](../README.md)
- [Threat Model & Security Architecture](THREAT_MODEL.md)
- [Credential Extensions Guide](EXTENSIONS.md)
- [Enterprise & Compliance Guide](ENTERPRISE_AND_COMPLIANCE.md)
- [Privacy Policy](privacy.md)

## Reporting Bugs & Requesting Features

- **Bug reports & feature requests:** Open an issue on [GitHub Issues](https://github.com/northcutted/baobuddy/issues/new/choose).
- **Diagnostics without secrets:** In the iOS app (**Settings → Help & About → Copy Diagnostics**) or macOS app (**Settings → About → Copy Diagnostics**), you can copy version, OS, and non-secret profile counts to attach to a bug report. Never paste raw tokens, private keys, or internal certificates into public issues.

## Reporting Security Vulnerabilities

Please **do not** report security vulnerabilities in public GitHub issues. Use [GitHub Private Vulnerability Reporting](https://github.com/northcutted/baobuddy/security/advisories/new) as described in [SECURITY.md](../SECURITY.md).
