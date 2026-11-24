# Release setup (Phase 0)

What has to exist before the first release, in order. Steps marked **script** are done by
[`scripts/provision-repo.sh`](../scripts/provision-repo.sh); the rest need Apple's portals or
GitHub's web UI. Save every secret you create (`.p12` password, `.p8` key, match password,
GitHub App private key) in Bitwarden as you go; nothing here keeps a copy.

Expect about an hour, most of it in Apple's portals.

## 1. Repositories, settings, environments (script)

```sh
brew install gh jq gitleaks   # if missing
gh auth login                  # as northcutted
scripts/provision-repo.sh
```

It asks before each step that's public or hard to undo, and skips anything that already exists:

- creates `northcutted/baobuddy` (public), `northcutted/homebrew-tap` (public), and
  `northcutted/baobuddy-certs` (private);
- scans the files for secrets with gitleaks, makes the initial commit, and pushes `main`;
- turns on private vulnerability reporting, secret scanning with push protection, and Dependabot;
- creates the environments, each limited to the ref it may deploy from:

| Environment | Deploys from | Approval | Used by |
| --- | --- | --- | --- |
| `helper-release` | tags `helper-v*`, branch `main` | you | Mac helper and CLI (`release-mac.yml`) |
| `receiver-release` | tags `receiver-v*`, branch `main` | you | Receiver binaries and provenance (`release-receiver.yml`) |
| `signing` | `main` | | iOS: build and sign the candidate |
| `testflight` | `main` | | iOS: TestFlight upload |
| `release-publishing`, `screenshot-publishing` | `main` | | iOS: publisher App actions |
| `app-store-staging` | tags `v*` | | iOS: stage the App Store version |
| `production` | tags `v*` | you | iOS: request App Review |
| `app-store-observe` | `main` | | iOS: scheduled status checks |

- adds a `Casks/` folder to the tap.

`scripts/provision-repo.sh status` shows what exists without changing anything.

**Tag namespaces.** The iOS app releases as `v0.1.0` (created by the publisher App). The Mac
helper and CLI use `helper-v0.1.0`. The receiver uses `receiver-v0.1.0`. Each product can advance its version independently.

## 2. Apple Developer: identifiers, certificate, provisioning profile

At [developer.apple.com/account](https://developer.apple.com/account) → Certificates, Identifiers
& Profiles:

1. **Identifiers → +** → App IDs → App. Register three explicit IDs, with no extra capabilities:
   - `com.northcutt.BaoBuddy` (iOS app)
   - `com.northcutt.BaoBuddy.LiveActivity` (iOS widget extension)
   - `com.northcutt.BaoBuddy.Helper` (macOS)
2. **Developer ID Application certificate.** You already have one (`make install-mac` found
   it). Export it from Keychain Access with its private key: My Certificates → right-click
   "Developer ID Application: …" → Export → `.p12`, with a new password. Keep the file outside
   the repository.
3. **Developer ID provisioning profile (for Phase 4).** Profiles → + → Developer ID → App ID
   `com.northcutt.BaoBuddy.Helper` → your Developer ID certificate → name it
   `BaoBuddy Helper Developer ID`. Set `MAC_HELPER_PROFILE` to its path for local Developer ID builds. Release CI reads the same file from the base64-encoded environment secret `MAC_HELPER_PROFILE_BASE64`. An ad-hoc build can exercise the CLI but cannot enroll or use an approval key.

## 3. App Store Connect: API key and app record

1. **API key.** [appstoreconnect.apple.com](https://appstoreconnect.apple.com) → Users and
   Access → Integrations → App Store Connect API → Team Keys → +. Name `BaoBuddy release`, role
   **App Manager**. Download the `.p8` (only possible once) and note the **Key ID** and
   **Issuer ID**. One key serves Mac notarization and iOS uploads.
2. **App record.** Apps → + → New App: platform iOS, name `BaoBuddy`, language English (U.S.),
   bundle ID `com.northcutt.BaoBuddy`, SKU `baobuddy-ios`, full access. Then:
   - App Privacy → Get Started → **Data Not Collected**.
   - Pricing and Availability → Free.
   - App Information → category Developer Tools, secondary Utilities; complete the age rating
     questionnaire (all "None").
   - The store listings use the [companion site](https://northcutted.github.io/baobuddy/)
     for marketing. Before submitting, verify that the homepage,
     [support page](https://northcutted.github.io/baobuddy/support/), and
     [privacy policy](https://northcutted.github.io/baobuddy/privacy/) are publicly accessible on GitHub Pages.

   The platform uploads metadata and review notes from `app-store/metadata/` and screenshots
   from `app-store/screenshots/`; you don't type those in. To regenerate the screenshots (6
   screens, 2 devices, 17 locales), run `make platform-sync platform-gems platform-images`
   once, then `make screenshots process-screenshots verify-screenshots`. Headlines are in
   `app-store/MarketingHeadlines.xcstrings`; the screens come from
   `BaoBuddyUITests/ScreenshotTests.swift` (scheme `BaoBuddyScreenshots`).

## 4. iOS signing assets (fastlane match)

The release workflow reads App Store certificates and profiles from `baobuddy-certs` with
fastlane match (the same layout as `picstrip-certs`). Seed it once from your Mac:

```sh
brew install fastlane
umask 077
cat > /tmp/asc-key.json <<EOF
{"key_id": "KEY_ID", "issuer_id": "ISSUER_ID", "key_filepath": "$HOME/Downloads/AuthKey_KEY_ID.p8"}
EOF
fastlane match appstore \
  --app_identifier com.northcutt.BaoBuddy,com.northcutt.BaoBuddy.LiveActivity \
  --git_url git@github.com:northcutted/baobuddy-certs.git \
  --team_id BDQ47H73HH \
  --api_key_path /tmp/asc-key.json
rm /tmp/asc-key.json
```

match asks for a passphrase: that's `MATCH_PASSWORD`, so pick a new one and save it. It creates
an Apple Distribution certificate and the two App Store profiles (`match AppStore
com.northcutt.BaoBuddy` and `…LiveActivity`), which is what `.github/ios-release.json` expects.
If Apple says you've reached the distribution certificate limit, revoke an unused one, or reuse
picstrip's with `fastlane match import`.

## 5. Publisher GitHub App

The iOS platform creates `v*` tags and releases through a GitHub App, not your account. Reuse
the App that publishes picstrip: GitHub → Settings → Developer settings → GitHub Apps → that App
→ Install App → your account → Only select repositories → add `baobuddy`. Note the **App ID**
on the App's General page. If you don't have its private key saved, generate a new one there
(Private keys → Generate) and save the `.pem`.

## 6. Secrets (script)

With the files from steps 2–5 at hand:

```sh
scripts/provision-repo.sh secrets
```

It asks for the `.p8` path, Key ID, Issuer ID, the `.p12` path and password, your signing
identity (detected from the keychain), `MATCH_PASSWORD`, and the publisher App ID and `.pem`.
It generates a write deploy key for `baobuddy-certs` (`MATCH_SSH_PRIVATE_KEY`) itself and
deletes its local copy. Values go to `gh secret set` on stdin and are never printed.

| Environment | Secrets |
| --- | --- |
| `helper-release` | `MAC_HELPER_PROFILE_BASE64`, `DEVELOPER_ID_CERT_P12`, `DEVELOPER_ID_CERT_PASSWORD`, `DEVELOPER_ID_IDENTITY`, `APP_STORE_CONNECT_API_KEY_P8`, `APP_STORE_CONNECT_KEY_ID`, `APP_STORE_CONNECT_ISSUER_ID` |
| `receiver-release` | No custom secrets. Publishing uses the workflow token and GitHub OIDC. |
| `signing` | `MATCH_PASSWORD`, `MATCH_SSH_PRIVATE_KEY` |
| `testflight`, `app-store-staging`, `production`, `app-store-observe` | `APP_STORE_CONNECT_API_KEY_ID`, `APP_STORE_CONNECT_API_KEY_ISSUER_ID`, `APP_STORE_CONNECT_API_KEY_CONTENT` |
| `release-publishing`, `screenshot-publishing` | `RELEASE_APP_ID`, `RELEASE_APP_PRIVATE_KEY` |

## 7. Repository controls (after the first green CI run)

The platform's `controls-configure` adds the `Main` ruleset (pull requests and a passing
**CI Gate** required), the `Release tags` ruleset (only the publisher App creates `v*` tags),
immutable releases, and `RELEASE_DISTRIBUTION_ENABLED=false`. It refuses to run until
**PR Checks** has passed on the current `main` commit.

```sh
git clone https://github.com/northcutted/ios-release-workflows ~/src/ios-release-workflows
git -C ~/src/ios-release-workflows checkout a3c32bcae61a8a174f3c5ea6a4ba0b623aaaf33a
brew install uv
cd ~/Development/BaoBuddy
python3 ~/src/ios-release-workflows/bin/ios-release setup
RUN_ID=$(gh run list --workflow "PR Checks" --branch main --status success --limit 1 --json databaseId --jq '.[0].databaseId')
python3 ~/src/ios-release-workflows/bin/ios-release controls-configure --ci-run "$RUN_ID" --release-app-id APP_ID          # preview
python3 ~/src/ios-release-workflows/bin/ios-release controls-configure --ci-run "$RUN_ID" --release-app-id APP_ID --apply  # apply
```

After the first full **PR Checks** run passes on `main`, enable path-based checks on pull requests:

```sh
gh variable set BAOBUDDY_SCOPED_PR_CI --body true --repo northcutted/baobuddy
```

Main and manual runs always run the full suite. The required **CI Gate** verifies the result of each job against the checks selected for that change.

## 8. First releases

- **Mac helper and CLI:** tag `helper-v0.1.0` on `main` and push it, or run **Release
  macOS Helper** with version `0.1.0`. Approve the `helper-release` deployment. Then commit the
  release's `baobuddy.rb` to `homebrew-tap/Casks/` and check a clean install
  (docs/RELEASE_PLAN.md, Phase 5).
- **Receiver:** push a tag such as `receiver-v0.1.0` on the intended commit, or run **Release Receiver** from `main` with version `0.1.0`. Approve the `receiver-release` deployment. A tag push publishes the release. Manual runs default to a draft and create the tag at the exact build commit. To publish that draft, publish it in GitHub Releases or rerun from the same commit with **Keep the GitHub release as a draft** cleared. Each release contains the five platform binaries and their checksum manifest.
- **iOS:** each push to `main` runs **Release Prep**, which builds a verified candidate. Run
  **Release** with action *Upload to TestFlight* and that run's URL. Set the repository
  variable `RELEASE_DISTRIBUTION_ENABLED=true` only once a TestFlight build has been checked.
  See the platform's [operations guide](https://github.com/northcutted/ios-release-workflows/blob/a3c32bcae61a8a174f3c5ea6a4ba0b623aaaf33a/docs/operations.md).
