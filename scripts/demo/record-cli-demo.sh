#!/usr/bin/env bash
# Records docs/media/cli-demo.{gif,mp4} from scripts/demo/cli-demo.tape.
#
# Starts a throwaway `bao server -dev` on 127.0.0.1:18200, registers this Mac's
# Secure Enclave key with it, and points BaoBuddy at a temporary profile
# directory (CFFIXED_USER_HOME), so your saved profiles and grants are not
# touched. The tape pauses for one Touch ID approval.
#
# Requires: bao, bao-buddy, vhs, jq.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"

for tool in bao bao-buddy vhs jq; do
  command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }
done

work=$(mktemp -d)
server_pid=""
cleanup() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

export BAO_ADDR=http://127.0.0.1:18200
export CFFIXED_USER_HOME="$work/home"
mkdir -p "$CFFIXED_USER_HOME"

bao server -dev -dev-root-token-id=demo-root -dev-listen-address=127.0.0.1:18200 -dev-no-store-token \
  >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do
  BAO_TOKEN=demo-root bao status >/dev/null 2>&1 && break
  sleep 0.2
done

(
  export BAO_TOKEN=demo-root
  printf 'path "secret/data/staging/db/*" { capabilities = ["read"] }\n' | bao policy write db-readonly - >/dev/null
  printf 'path "secret/data/staging/app/*" { capabilities = ["read"] }\n' | bao policy write app-read - >/dev/null
  bao kv put secret/staging/db/postgres username=app_ro password=demo-only-not-real >/dev/null
  bao kv put secret/staging/app/config feature_flags=on >/dev/null
  bao-buddy server-setup --subject demo --policies db-readonly,app-read --add-self >/dev/null
  bao-buddy export-profile --name Staging --subject demo --policies db-readonly,app-read --save \
    >/dev/null 2>&1
)

unset BAO_TOKEN VAULT_TOKEN
mkdir -p docs/media
vhs scripts/demo/cli-demo.tape
echo "Wrote docs/media/cli-demo.gif and docs/media/cli-demo.mp4"
