# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/northcutted/baobuddy/security/advisories/new).
Don't open a public issue for a security problem.

Include the version or commit, the platform (iOS or macOS), and the steps to reproduce. You should
get an acknowledgement within 7 days. Fixes are released as soon as they're ready, and reporters
are credited in the advisory unless they ask not to be.

## Scope

In scope: the iOS app, the macOS helper (`bao-buddy`, including its MCP server), the Live Activity
extension, `baobuddy-receiver`, the profile format, the release workflows, and the server
configuration that `bao-buddy server-setup` and the OpenTofu module write.

Before reporting, check [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). It lists known limitations,
such as the server being unable to enforce the scope approved in the app. A report showing that
one of those limitations is worse than described is welcome.

Out of scope: vulnerabilities in OpenBao, HashiCorp Vault, or Apple platforms themselves (report
those upstream), and attacks that need a jailbroken or otherwise compromised operating system.

## Supported versions

Only the latest release gets security fixes.
