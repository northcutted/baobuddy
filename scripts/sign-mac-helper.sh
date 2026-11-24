#!/bin/bash
set -euo pipefail
app=${1:?app path required}
identity=${2:?Developer ID identity required}
profile=${3:?Set MAC_HELPER_PROFILE to the helper Developer ID provisioning profile}
entitlements="$(dirname "$0")/../MacHelper/Signing.entitlements"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

security cms -D -i "$profile" -o "$work/profile.plist"
python3 -I - "$work/profile.plist" "$entitlements" "$app/Contents/Info.plist" <<'PY'
import datetime, fnmatch, plistlib, sys
def read(path):
    with open(path, "rb") as stream:
        return plistlib.load(stream)
profile, requested, info = map(read, sys.argv[1:])
authorized = profile["Entitlements"]
group, = requested["keychain-access-groups"]
team = requested["com.apple.developer.team-identifier"]
if not (profile["ExpirationDate"] > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        and profile.get("ProvisionsAllDevices") is True and "OSX" in profile.get("Platform", [])
        and team in profile["TeamIdentifier"] and group == team + "." + info["CFBundleIdentifier"]
        and authorized.get("com.apple.application-identifier") == group
        and any(fnmatch.fnmatchcase(group, pattern) for pattern in authorized.get("keychain-access-groups", []))):
    sys.exit("Expected a current Developer ID profile authorizing this helper and its private Keychain group.")
PY
cp "$profile" "$app/Contents/embedded.provisionprofile"
codesign --force --options runtime --timestamp --entitlements "$entitlements" --sign "$identity" "$app"
codesign --verify --strict "$app"
codesign -d --extract-certificates="$work/cert" "$app"
python3 -I - "$work/profile.plist" "$work/cert0" <<'PY'
import pathlib, plistlib, sys
profile = plistlib.loads(pathlib.Path(sys.argv[1]).read_bytes())
if pathlib.Path(sys.argv[2]).read_bytes() not in profile["DeveloperCertificates"]:
    sys.exit("Signing certificate is absent from the helper provisioning profile.")
PY
