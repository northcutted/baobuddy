# `baobuddy-receiver`

Portable, zero-dependency, statically compiled Go binary (`CGO_ENABLED=0`) for receiving BaoBuddy grants over SSH on any Linux (`amd64`/`arm64`), macOS (`arm64`/`amd64`), or FreeBSD (`amd64`) host.

## Features
- **Zero third-party dependencies**: Go standard library only, so it's easy to audit. (A FIPS build with `GOFIPS140` is possible with Go 1.24+, but the Makefile and CI don't build or test one.)
- **Server-side verification**: Calls OpenBao/Vault `/v1/auth/token/lookup-self` (with optional `X-Vault-Namespace`, and an optional `ca_cert_path` that replaces the system roots) before accepting any token. It refuses renewable, non-orphan, batch, and over-TTL tokens, and optionally tokens whose policies aren't in `allowed_policies` or whose metadata doesn't match `required_meta` (for example `{"on": "remote"}`). Redirects are never followed, so a token can't be forwarded to another host.
- **Revocation and cleanup.** A successful `revoke` requires local cleanup to finish. If OpenBao confirms revocation and a credential file cannot be removed, the command exits with an error. Correct the filesystem problem and rerun `revoke`. The receiver can recognize a confirmed revocation for the same token.
- **Grant replacement.** The receiver stages the new token, SSH certificate, push token, artifacts and expiry record before replacing the active grant. A failed install restores the previous files. If the process exits during publication, the next locked receiver command recovers the grant. If a delivery mount is unavailable, restore it at its original path and retry. Revoke the active grant before changing its delivery paths. Workloads reading several paths independently can observe a replacement in progress.
- **Enterprise SIEM & Observability**:
  - Native **OpenTelemetry OTLP/HTTP JSON** exporter (`/v1/logs` and `/v1/metrics`) for Splunk, Datadog, Grafana Alloy, Elastic, or any OTel Collector.
  - Structured JSONL audit log (`audit_log_path`, zero secrets).
  - Prometheus `node_exporter` textfile gauge metrics (`metrics_file_path`).

## Quick Install

1. Download the binary for your operating system and architecture from a `receiver-v*` release. For example, to install a published Linux amd64 build, set `version` to the receiver version you want and run these commands in an empty directory:
   ```bash
   version=0.1.0
   asset="baobuddy-receiver-${version}-linux-amd64"
   repo=northcutted/baobuddy
   workflow="$repo/.github/workflows/release-receiver.yml"
   gh release download "receiver-v${version}" --repo "$repo" --pattern "$asset" --pattern SHA256SUMS.txt &&
     gh attestation verify SHA256SUMS.txt --repo "$repo" --signer-workflow "$workflow" &&
     gh attestation verify "$asset" --repo "$repo" --signer-workflow "$workflow" &&
     shasum -a 256 "$asset" | grep -Fx -f SHA256SUMS.txt &&
     sudo install -m 0755 "$asset" /usr/local/bin/baobuddy-receiver
   ```
   To build from source in the `receiver` directory instead:
   ```bash
   make build
   sudo install -m 0755 baobuddy-receiver /usr/local/bin/baobuddy-receiver
   ```
2. Create a dedicated `granter` user and `/etc/baobuddy/receiver.json` from `deploy/config.example.json`. The file may hold OTLP auth headers, so make it `root:granter` mode `0640`. Unknown keys are rejected; give `file_mode` as a quoted octal string (`"0600"` or `"0640"`).
3. Create the state directory. On Linux, install `deploy/baobuddy-receiver.tmpfiles.conf` as `/etc/tmpfiles.d/baobuddy-receiver.conf` and run `sudo systemd-tmpfiles --create`; `/run` is cleared at every boot. On macOS or FreeBSD, set `state_dir` to a directory owned by `granter` with mode `0750`.
4. Authorize your Mac/iPhone BaoBuddy Secure Enclave SSH key (`bao-buddy ssh-key`) with an OpenSSH forced command in `~granter/.ssh/authorized_keys`:
   ```text
   command="/usr/local/bin/baobuddy-receiver --config /etc/baobuddy/receiver.json",restrict ecdsa-sha2-nistp256 AAAA... baobuddy-mac
   ```
5. Verify connectivity:
   ```bash
   sudo -u granter /usr/local/bin/baobuddy-receiver --config /etc/baobuddy/receiver.json doctor
   ```
6. Optionally install the `systemd` timer from `deploy/` to sweep expired files every minute.

## Receiver configuration

The example accepts the quickstart’s `app-read` policy and the issuer’s `default` policy. Set `allowed_policies` to the policy names intended for this workload before installation. The receiver checks direct and identity policies. With an allowlist, it rejects grants that carry policies in another namespace. Existing configurations that omit the list continue to use issuer-side policy restrictions.

Use base URLs for `openbao_addr` and `otlp_endpoint`. A reverse-proxy path is supported. Put collector authentication in `otlp_headers`. User information, query strings and fragments are rejected. `doctor` displays the endpoint origin and expects an initialized, unsealed, active issuer.

The example leaves telemetry disabled. To enable the local audit log or Prometheus textfile, provision a receiver-writable parent directory and set `audit_log_path` or `metrics_file_path`. Set `otlp_endpoint` for remote export. Run `doctor` as the receiver account to check local sink access. The audit check opens the configured regular file for append and creates an empty file if needed. If a sink fails during a grant command, its response includes a warning and retains the grant operation’s exit status.

An install must finish reading SSH input within the receiver’s 20-second command budget. The optional `tasks_command` has five seconds and a 64 KiB output limit. On timeout or excess output the receiver returns `! task check unavailable`.

## Share credentials with a workload

Use separate accounts for the receiver and the workload. Create a dedicated group for credential readers and add both accounts to it. Set `file_mode` to `"0640"` and `file_owner_gid` to that group’s numeric GID. Give the group traversal through the delivery path. On Linux, for a group named `app-readers`, the tmpfiles entry is `d /run/baobuddy 0750 granter app-readers -`. Keep the configuration file in the receiver’s private group.

Use receiver-owned directories, or root-owned directories that grant write access specifically to the receiver. The receiver owns the credential files. Workload accounts need read access to credentials and traverse access to their directories. Keep parent directories and any inherited ACLs under administrator or receiver control. The receiver writes its grant metadata with mode `0600`.

Earlier builds accepted `0620` and `0660`. Change either setting to `0600` or `0640` before upgrading. If workloads could write an existing token or grant record, revoke the original grant by its OpenBao accessor and retire the old delivery files before installing a fresh grant. Changing the mode alone cannot establish who last wrote the file.

## Limits

- The forced-command path runs outside systemd, so the unit's sandboxing applies only to the `cleanup` timer. The `restrict` option in `authorized_keys` is what limits the SSH session.
- The receiver can delete its copies of SSH certificates, push tokens, and artifacts, but it can't revoke those credentials. They stay valid until they expire.
- Any key in `authorized_keys` can install a token. `allowed_policies` and `required_meta` narrow what's accepted, but metadata is set by whoever minted the token.
