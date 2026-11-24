# BaoBuddy Privacy Policy

*Effective date: November 2026*

BaoBuddy is a local-first, open-source client for your own **OpenBao** or **HashiCorp Vault** server. **BaoBuddy does not collect, track, sell, or transmit any personal data to the developer or to any third party.**

## Data Collected

**None.** BaoBuddy contains no analytics SDKs, crash-reporting services, advertising identifiers, or third-party tracking libraries.

## Where Your Data Lives

- **Hardware signing keys (Secure Enclave):** Non-exportable EC P-256 private keys are created and stored locally in Apple's Secure Enclave / Keychain on your device and never leave your hardware.
- **Server profiles & local activity log:** Server URLs, TLS pins, policy names, and non-secret grant metadata (timestamps, policy names, target name, duration, audit reason) are stored locally on your device. No raw tokens, passwords, or secrets are written to the activity log.
- **Direct tokens & clipboard (iOS):** Tokens minted in Direct Token mode are held in memory only. When you tap **Copy Token**, BaoBuddy writes to the local-only pasteboard (`localOnly: true`) with a 2-minute expiration so tokens do not sync via Universal Clipboard.
- **Camera permission (iOS):** Used solely on-device to scan `baobuddy://import` pairing QR codes. Images never leave the device.
- **Local network permission (iOS):** Used solely to connect directly to the OpenBao/Vault server and optional SSH target that you configure.
- **Demo mode:** Runs entirely in memory on your device against a simulated server (`demo.baobuddy.invalid`). Nothing leaves your device in Demo mode, and exiting Demo mode deletes all in-memory demo state.

## Optional User-Configured Telemetry (OTLP)

Organizations may optionally configure an OpenTelemetry (OTLP/HTTP) endpoint in a server profile or in `baobuddy-receiver`. When configured by you:

- Telemetry is sent **only** to the endpoint you specify — never to BaoBuddy's maintainers.
- Each event contains: the action (for example "granted" or "revoked"), the OpenBao/Vault subject (user name), server name, namespace, target name, policy names, duration, whether the grant was elevated, where it was approved (Mac, iPhone, CLI), and the audit reason you typed. It **never** includes OpenBao/Vault tokens, private keys, or credential contents.
- The endpoint is shown when you import a profile that sets one, and headers such as collector API keys are removed whenever a profile is shared.

## Contact

Questions or privacy concerns can be opened on [GitHub](https://github.com/northcutted/baobuddy/issues) or reported privately via GitHub Private Vulnerability Reporting on the repository's Security tab.
