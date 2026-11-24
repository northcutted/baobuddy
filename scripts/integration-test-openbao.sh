#!/usr/bin/env bash
# Real end-to-end integration test against a live ephemeral OpenBao (`bao server -dev`)
# or HashiCorp Vault (`VAULT_BIN=vault`) and the standalone Go `baobuddy-receiver` binary,
# plus the Swift live ES256 JWT + extension + accessor-revoke E2E test when Swift is present.
set -euo pipefail

case "${1:-}" in ""|--wire) ;; *) echo "usage: $0 [--wire]" >&2; exit 2 ;; esac
umask 077
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
VAULT_BIN="${VAULT_BIN:-bao}"
SERVER_PID=""

cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

command -v "${VAULT_BIN}" >/dev/null || { echo "error: ${VAULT_BIN} CLI not installed" >&2; exit 1; }
command -v go >/dev/null || { echo "error: go not installed" >&2; exit 1; }

PORT=$((18200 + RANDOM % 1000))
BAO_ADDR="http://127.0.0.1:${PORT}"
ROOT_TOKEN="$(openssl rand -hex 32)"
export BAO_ADDR
export BAO_TOKEN="${ROOT_TOKEN}"
export VAULT_ADDR="${BAO_ADDR}"
export VAULT_TOKEN="${ROOT_TOKEN}"

echo "==> Starting ephemeral ${VAULT_BIN} dev server on ${BAO_ADDR}"
"${VAULT_BIN}" server -dev -dev-no-store-token -dev-root-token-id="${ROOT_TOKEN}" -dev-listen-address="127.0.0.1:${PORT}" \
  >"${TMP_DIR}/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS "${BAO_ADDR}/v1/sys/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl -fsS "${BAO_ADDR}/v1/sys/health" >/dev/null

echo "==> Bootstrapping least-privilege policy, token role, and JWT auth"
"${VAULT_BIN}" policy write app-read - <<'EOF'
path "secret/data/app/*" {
  capabilities = ["read"]
}
EOF

"${VAULT_BIN}" policy write granter - <<'EOF'
path "auth/token/create/grant" {
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
EOF

"${VAULT_BIN}" write auth/token/roles/grant \
  allowed_policies="app-read" \
  disallowed_policies="root" \
  orphan=true \
  renewable=false \
  token_explicit_max_ttl=2h

echo "==> Minting a grant the way BaoBuddy does: with a short-lived granter token, not root"
GRANTER_TOKEN="$("${VAULT_BIN}" token create -policy=granter -no-default-policy -ttl=2m -field=token)"
MINTED_TOKEN="$(BAO_TOKEN="${GRANTER_TOKEN}" VAULT_TOKEN="${GRANTER_TOKEN}" "${VAULT_BIN}" token create -role=grant -policy=app-read -ttl=1h \
  -metadata="by=e2e" -metadata="via=ci" -metadata="on=remote" -metadata="why=CHG-42" -field=token)"

echo "==> Confirming the granter token can't mint outside the role's allowed_policies"
if BAO_TOKEN="${GRANTER_TOKEN}" VAULT_TOKEN="${GRANTER_TOKEN}" "${VAULT_BIN}" token create -role=grant -policy=root -ttl=1h >/dev/null 2>&1; then
  echo "error: granter minted a root-policy token!" >&2
  exit 1
fi
if BAO_TOKEN="${GRANTER_TOKEN}" VAULT_TOKEN="${GRANTER_TOKEN}" "${VAULT_BIN}" token create -policy=app-read -ttl=1h >/dev/null 2>&1; then
  echo "error: granter minted a token outside the token role!" >&2
  exit 1
fi

echo "==> Building standalone Go baobuddy-receiver"
RECEIVER_BIN="${TMP_DIR}/baobuddy-receiver"
(cd "${RECEIVER_SOURCE_DIR:-${ROOT_DIR}/receiver}" && CGO_ENABLED=0 go build -o "${RECEIVER_BIN}" ./cmd/baobuddy-receiver)

cat >"${TMP_DIR}/receiver.json" <<EOF
{
  "openbao_addr": "${BAO_ADDR}",
  "state_dir": "${TMP_DIR}/state",
  "audit_log_path": "${TMP_DIR}/audit.jsonl",
  "metrics_file_path": "${TMP_DIR}/baobuddy.prom",
  "allowed_policies": ["app-read"],
  "required_meta": {"on": "remote"}
}
EOF

mkdir -p "${TMP_DIR}/state"
chmod 0750 "${TMP_DIR}/state"

if [[ "${1:-}" == --wire ]]; then
  printf '%s' "${MINTED_TOKEN}" >"${TMP_DIR}/input-token"
  BAOBUDDY_WIRE_FIXTURE_DIR="${TMP_DIR}" swift test --package-path "${CLIENT_SOURCE_DIR:-${ROOT_DIR}}" \
    --force-resolved-versions --filter ReceiverWireFixtureTests
  for format in v1 v2; do
    "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" install <"${TMP_DIR}/${format}"
    [[ "$(cat "${TMP_DIR}/state/token")" == "${MINTED_TOKEN}" ]]
    "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" status | grep -F 'Secrets: active'
  done
  [[ "$(cat "${TMP_DIR}/state/artifacts/fixture.txt")" == "wire fixture" ]]
  "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" revoke
  [[ ! -e "${TMP_DIR}/state/token" && ! -e "${TMP_DIR}/state/artifacts/fixture.txt" ]]
  if BAO_TOKEN="${MINTED_TOKEN}" VAULT_TOKEN="${MINTED_TOKEN}" "${VAULT_BIN}" token lookup >/dev/null 2>&1; then
    echo "receiver revoke left the token active" >&2
    exit 1
  fi
  echo "PASS: Swift v1 and v2 grants installed, read and revoked"
  exit 0
fi

echo "==> Running baobuddy-receiver doctor / install / status / revoke against live ${VAULT_BIN}"
"${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" doctor

echo "==> Confirming the receiver refuses a token that isn't a BaoBuddy remote grant"
OTHER_TOKEN="$("${VAULT_BIN}" token create -policy=app-read -ttl=1h -field=token)"
if printf '%s\n\n\n' "${OTHER_TOKEN}" | "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" install >/dev/null 2>&1; then
  echo "error: receiver accepted a non-orphan token without on=remote metadata!" >&2
  exit 1
fi

INSTALL_OUT="$(printf '%s\n\n\n' "${MINTED_TOKEN}" | "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" install)"
echo "    install: ${INSTALL_OUT}"
[[ "${INSTALL_OUT}" == Granted\ until* ]]

STATUS_OUT="$("${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" status)"
echo "    status:  ${STATUS_OUT}"
echo "${STATUS_OUT}" | grep -q "Secrets: active"
echo "${STATUS_OUT}" | grep -q "CHG-42"
grep -q "baobuddy_receiver_grant_active 1" "${TMP_DIR}/baobuddy.prom"

echo "==> Verifying an audit write failure is visible on a successful install"
# Obstruct only the temporary test audit path. The active grant must remain usable.
mv "${TMP_DIR}/audit.jsonl" "${TMP_DIR}/saved-audit.jsonl"
mkdir "${TMP_DIR}/audit.jsonl"
AUDIT_OUT="$(printf '%s\n\n\n' "${MINTED_TOKEN}" | "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" install)"
[[ "${AUDIT_OUT}" == Granted\ until* ]]
grep -Fq "Warning: could not append to the configured audit log" <<<"${AUDIT_OUT}"
if "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" doctor >"${TMP_DIR}/doctor.log" 2>&1; then
  echo "error: doctor reported an unusable audit destination as ready" >&2
  exit 1
fi
grep -Fq "audit_log_path" "${TMP_DIR}/doctor.log"
rmdir "${TMP_DIR}/audit.jsonl"
mv "${TMP_DIR}/saved-audit.jsonl" "${TMP_DIR}/audit.jsonl"

echo "==> Delivering a credential-extension artifact with the v2 envelope (as BaoBuddy does)"
V2_PAYLOAD="$(printf '{"version":2,"token":"%s","ssh_cert":"","push_token":"","artifacts":[{"name":"db-creds.json","content":"{\\"username\\":\\"u\\"}","expires_at":%s}]}' \
  "${MINTED_TOKEN}" "$(( $(date +%s) + 600 ))")"
V2_OUT="$(printf '%s\n' "${V2_PAYLOAD}" | "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" install)"
echo "    install v2: ${V2_OUT}"
[[ "${V2_OUT}" == Granted\ until* ]]
grep -q '"username"' "${TMP_DIR}/state/artifacts/db-creds.json"
[[ "$(stat -c %a "${TMP_DIR}/state/artifacts/db-creds.json" 2>/dev/null || stat -f %Lp "${TMP_DIR}/state/artifacts/db-creds.json")" == "600" ]]

echo "==> Verifying a delivery error preserves the active grant"
NEXT_TOKEN="$(BAO_TOKEN="${GRANTER_TOKEN}" VAULT_TOKEN="${GRANTER_TOKEN}" "${VAULT_BIN}" token create -role=grant -policy=app-read -ttl=1h \
  -metadata="on=remote" -field=token)"
mkdir "${TMP_DIR}/state/push-token"
if printf '%s\n\n\n' "${NEXT_TOKEN}" | "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" install >"${TMP_DIR}/failed-install.log" 2>&1; then
  echo "error: install succeeded despite an unusable credential path" >&2
  exit 1
fi
[[ "$(cat "${TMP_DIR}/state/token")" == "${MINTED_TOKEN}" ]]
grep -q '"username"' "${TMP_DIR}/state/artifacts/db-creds.json"
BAO_TOKEN="${MINTED_TOKEN}" VAULT_TOKEN="${MINTED_TOKEN}" "${VAULT_BIN}" token lookup >/dev/null

echo "==> Verifying revoke reports a local cleanup error after OpenBao revokes the token"
if "${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" revoke >"${TMP_DIR}/failed-revoke.log" 2>&1; then
  echo "error: revoke reported success despite a local cleanup failure" >&2
  exit 1
fi
grep -qi 'local cleanup failed' "${TMP_DIR}/failed-revoke.log"
if BAO_TOKEN="${MINTED_TOKEN}" VAULT_TOKEN="${MINTED_TOKEN}" "${VAULT_BIN}" token lookup >/dev/null 2>&1; then
  echo "error: grant remained active after the first revoke" >&2
  exit 1
fi
rmdir "${TMP_DIR}/state/push-token"
REVOKE_OUT="$("${RECEIVER_BIN}" --config "${TMP_DIR}/receiver.json" revoke)"
echo "    revoke retry:  ${REVOKE_OUT}"
[[ "${REVOKE_OUT}" == *"at OpenBao"* ]]
[[ ! -e "${TMP_DIR}/state/token" && ! -e "${TMP_DIR}/state/.grant.json" ]]
grep -q "baobuddy_receiver_grant_active 0" "${TMP_DIR}/baobuddy.prom"

if [[ -e "${TMP_DIR}/state/artifacts/db-creds.json" ]]; then
  echo "error: revoke left the artifact behind!" >&2
  exit 1
fi

echo "==> Confirming revoked token is truly rejected by ${VAULT_BIN}"
if BAO_TOKEN="${MINTED_TOKEN}" VAULT_TOKEN="${MINTED_TOKEN}" "${VAULT_BIN}" token lookup >/dev/null 2>&1; then
  echo "error: token should have been revoked by ${VAULT_BIN}!" >&2
  exit 1
fi

echo "==> Confirming audit log never leaked the raw token"
if grep -qF "${MINTED_TOKEN}" "${TMP_DIR}/audit.jsonl"; then
  echo "error: audit.jsonl leaked the raw token!" >&2
  exit 1
fi

if [[ "$(uname -s)" == Darwin ]] && command -v swift >/dev/null 2>&1; then
  echo "==> Running Swift live ES256 JWT + extension + accessor-revoke E2E test"
  (cd "${ROOT_DIR}" && BAO_E2E_ADDR="${BAO_ADDR}" BAO_E2E_TOKEN="${ROOT_TOKEN}" swift test --filter LiveOpenBaoE2ETests)
fi

echo "PASS: live ${VAULT_BIN} + baobuddy-receiver end-to-end test succeeded."
