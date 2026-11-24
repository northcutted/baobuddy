# BaoBuddy 5-Minute Quickstart

This Docker Compose stack starts a local **OpenBao** dev server (`http://127.0.0.1:8200`) so you can try BaoBuddy's Touch ID sign-in, scoped grant, and revocation on your Mac in about five minutes. It also starts a `baobuddy-receiver` container that checks it can reach OpenBao; it isn't wired up for SSH delivery (see [receiver/README.md](../../receiver/README.md) for a real remote host).

Use a Mac with Touch ID, Xcode and Docker Compose. Run these commands from the root of the BaoBuddy source checkout in the same terminal. The dev server listens on the Mac’s loopback interface. To try BaoBuddy on an iPhone without configuring a reachable server, choose **Try Demo**.

## 1. Build the Mac helper and start OpenBao

```bash
make build-mac SIGN_IDENTITY=-
helper="$PWD/build/BaoBuddyHelper.app/Contents/MacOS/BaoBuddyHelper"
docker compose -f examples/quickstart/compose.yaml up -d --build --wait
```

Verify `baobuddy-receiver` can reach OpenBao:

```bash
docker compose -f examples/quickstart/compose.yaml exec receiver \
  baobuddy-receiver --config /etc/baobuddy/receiver.json doctor
```

## 2. Bootstrap OpenBao with `bao-buddy`

```bash
quickstart_addr=http://127.0.0.1:8200

# Create two example policies on OpenBao:
docker compose -f examples/quickstart/compose.yaml exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=baobuddy-quickstart-root openbao \
  sh -ec '
    bao kv put secret/app/demo greeting="hello-from-baobuddy"
    printf "path \"secret/data/app/*\" { capabilities = [\"read\"] }\n" | bao policy write app-read -
    printf "path \"secret/data/db/*\"  { capabilities = [\"read\"] }\n" | bao policy write db-readonly -
  '

# Register this Mac's Secure Enclave key and create the least-privilege JWT mount + token role:
BAO_TOKEN=baobuddy-quickstart-root "$helper" server-setup --addr "$quickstart_addr" \
  --mount jwt-demo \
  --subject demo \
  --policies app-read,db-readonly \
  --max-hours 1 \
  --add-self

# Save a local BaoBuddy profile:
"$helper" export-profile --addr "$quickstart_addr" \
  --name "Quickstart" \
  --mount jwt-demo \
  --subject demo \
  --policies app-read,db-readonly \
  --max-hours 1 \
  --save
```

## 3. Mint and inspect a Touch ID–approved grant

```bash
# Prompts Touch ID, signs a 30s ES256 JWT in the Secure Enclave, mints a 1h orphan grant:
"$helper" grant --profile Quickstart --on local --hours 1 --policies app-read --why "quickstart check"

# Verify status and revoke when finished:
"$helper" status --profile Quickstart --on local
"$helper" revoke --profile Quickstart --on local
"$helper" status --profile Quickstart --on local
```

## 4. Clean up

```bash
docker compose -f examples/quickstart/compose.yaml down -v
```
