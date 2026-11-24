# Contributing to BaoBuddy

Contributions, security reports, and bug fixes are welcome.

## Security Issues
Please **do not** open a public GitHub issue for security vulnerabilities. Follow [SECURITY.md](SECURITY.md) for private disclosure, and review [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before changing authentication, TLS pinning, SSH host-key verification, or profile validation code.

## Local Development

### Prerequisites
- macOS 15+ with Xcode 16+ (Swift 6)
- Optional: Go 1.24+ (for `receiver/`), OpenBao (`bao`) for live E2E tests, OpenTofu (`tofu`) for IaC validation, and SwiftLint (`brew install swiftlint`).

### Running Tests & Checks
```bash
# SwiftPM unit & security regression tests
swift test

# SwiftLint
make lint

# Build macOS menu bar app + CLI (uses ad-hoc signing by default if no Developer ID is installed)
make build-mac

# Go standalone receiver tests
make -C receiver test

# Live OpenBao + receiver + Swift JWT end-to-end integration test
bash scripts/integration-test-openbao.sh
```

### Client and receiver compatibility

On macOS, run `bash scripts/integration-test-openbao.sh --wire` to send the production Swift client's three-line and JSON grant formats to a real receiver against a temporary OpenBao server. The check verifies token delivery, artifact contents, active status and revocation. CI runs this check against the current source even before the first release.

For each product with a published stable release, CI also builds from the most recently published matching tag. It pairs the current receiver with each released Apple client’s encoder and pairs the current encoder with the released receiver. To reproduce a pairing, set `CLIENT_SOURCE_DIR` to a client checkout containing the wire fixture test, or `RECEIVER_SOURCE_DIR` to a checkout's `receiver/` directory.

## Guidelines
- Keep **zero external runtime dependencies** in `receiver/` (Go standard library only) and minimal audited dependencies in SwiftPM.
- Every security-sensitive fix should include a regression test in `Tests/BaoBuddyCoreTests/SecurityRegressionTests.swift` or `receiver/internal/receiver/receiver_test.go`.
- Never log or print raw OpenBao tokens, SSH private keys, or credentials to stdout, stderr, audit logs, or telemetry sinks.
