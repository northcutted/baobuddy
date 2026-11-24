# Release plan: v0.1.0 (App Store, Homebrew, Show HN)

Goal: a public beta that a skeptical reader can install in five minutes, verify, and attack using
the documentation we give them. Each phase lists its owner and the condition that ends it.
**Maintainer** means a step only you can do (accounts, secrets, Apple). **Code** means changes in
this repository.

## Decisions

| Decision | Choice |
| --- | --- |
| App Review access | Built-in demo mode (no hosted server) |
| First version | 0.1.0, labeled beta |
| App Store vs. HN timing | Independent: post to HN when Homebrew and TestFlight work; App Store release whenever review passes |
| iPad | Open. Recommendation: drop iPad for 0.1 (iPhone only) to avoid iPad screenshots and layout review |
| Price | Free |

## Phase 0: Accounts and infrastructure (Maintainer, start now, runs in parallel)

Step-by-step instructions are in [RELEASE_SETUP.md](RELEASE_SETUP.md); `scripts/provision-repo.sh`
does the GitHub parts.

- [ ] Repositories, settings, and environments: `scripts/provision-repo.sh` (creates
      `baobuddy`, `homebrew-tap`, `baobuddy-certs`; pushes `main`; private vulnerability
      reporting; `helper-release`, `receiver-release`, and the seven iOS platform environments).
- [ ] Apple: register the three App IDs, export the Developer ID `.p12`, and create the
      **Developer ID provisioning profile** for `com.northcutt.BaoBuddy.Helper` (needed for
      Phase 4).
- [ ] App Store Connect: API key (App Manager) and the app record (Developer Tools,
      "Data Not Collected", free, age rating).
- [ ] Seed `baobuddy-certs` with `fastlane match appstore`.
- [ ] Install the publisher GitHub App (picstrip's) on `baobuddy`.
- [ ] Secrets: `scripts/provision-repo.sh secrets`.
- [ ] After the first green **PR Checks** run: the platform's `controls-configure --apply`.
- [x] Privacy policy and support pages: `docs/privacy.md` and `docs/support.md` in the repo.

**Done when** `scripts/provision-repo.sh status` shows every environment with its secrets and the
provisioning profile is downloaded.

## Phase 1: Hygiene and docs (Code)

- [x] Set version 0.1.0 in the iOS project, `MacHelper/Info.plist`, and the receiver Makefile.
- [x] Privacy manifest: declare `NSPrivacyAccessedAPICategoryUserDefaults` (`CA92.1`) for the app
      and the Live Activity extension if it reads defaults.
- [x] Remove leftovers: default policy names `lab-read`/`lab-write`, `192.168.1.5` placeholder,
      "Homelab" examples, personal `SIGN_IDENTITY` default in the Makefile, and the legacy
      `baogrant://` scheme (keep parsing it for one release, stop registering it).
- [x] Add `CHANGELOG.md`, `CONTRIBUTING.md`, issue templates (bug, feature; security goes to the
      advisory link), and a "Status: beta" line at the top of the README.
- [x] README: a five-minute quickstart, a "Why not X?" section (OpenBao/Vault login MFA, OIDC with
      passkeys, Teleport, Secretive, 1Password SSH agent, `vault login -method=oidc`), and the
      top three limitations linked to the threat model.
- [x] Draft `docs/privacy.md` (no data collected; optional telemetry goes only to the user's own
      collector) and `docs/support.md`.

**Done when** the repo can be pushed publicly without anything personal or misleading in it.

## Phase 2: Demo mode (Code)

A demo that runs the real code paths with a simulated server, so App Review, screenshots, and
first-time users all see the product without OpenBao.

- [x] `DemoOpenBaoTransport` (Core): an in-memory `HTTPTransport` that implements the endpoints the
      app uses: `sys/health`, JWT login, `auth/token/create/<role>`, `lookup-self`, `revoke`,
      `revoke-self`, `revoke-accessor`, and one extension endpoint (`database/creds/demo`). The
      login handler **verifies the ES256 JWT** against the device's public key, so the demo
      exercises the real Secure Enclave signature and Face ID prompt.
- [x] `DemoGranterTransport`: a simulated remote host with fake running tasks, status, install
      (accepts the v2 envelope), and revoke.
- [x] A demo profile that exists only in memory: reserved ID and address
      (`https://demo.baobuddy.invalid`). It is never saved, exported, or shared. Imports that use
      the reserved ID or address are rejected. `OpenBaoClient` uses the demo transport only for
      this in-memory profile.
- [x] UI: "Try Demo" on the onboarding screen and in Settings; a persistent "Demo mode: nothing
      leaves this phone" banner; "Exit Demo" removes everything it created.
- [x] Launch argument `-BaoBuddyDemo` for UI tests and screenshots (the six `screens` in
      `.github/ios-release.json`, captured by `BaoBuddyUITests/ScreenshotTests.swift`).
- [x] Tests: the full orchestrator flow (sign-in, mint, extension, deliver, revoke) runs against
      the demo transports in `swift test`; a UI test walks the demo.

**Done when** a fresh install can approve, view, and revoke a demo grant (direct and remote) with
Face ID, and the screenshots generate from the launch argument.

## Phase 3: Proof in CI and release plumbing (Code)

- [x] Live sign-in test: a test harness signs an ES256 JWT with a software P-256 key, then runs
      `server-setup` → login → mint → `verify` → receiver install → revoke-by-accessor against
      `bao server -dev`.
- [x] The same job against `vault server -dev` (HashiCorp Vault), so the "works with Vault" claim
      is tested.
- [x] `examples/quickstart/compose.yaml`: OpenBao dev server plus a receiver container, used by
      the README quickstart.
- [x] Receiver release job: cross-compiled binaries, `SHA256SUMS.txt`, and build provenance
      attestations on a dedicated `receiver-v*` GitHub release.
- [x] Cask: add `livecheck`; note that Keychain items aren't removed by `zap`.
- [x] iOS: add `.github/workflows/main.yml` calling `ios-release-workflows` `prepare.yml`, and
      `app-store/metadata/` (description, keywords without third-party trademarks, review notes
      that say "tap Try Demo").

**Done when** CI is green on GitHub with the live OpenBao and Vault jobs.

## Phase 4: macOS data-protection keychain (Code, after the provisioning profile)

The helper now requires its provisioned private access group for new biometric approval keys. Signed acceptance and retirement of older issuer keys are pending.

- [ ] Sign the helper with the provisioning profile and `keychain-access-groups`; move the key
      handle, local grant, SSH key, and extension artifacts to the data-protection keychain
      (`kSecUseDataProtectionKeychain`), with a one-time migration from the login keychain.
- [ ] Scripts and agents can no longer read the grant with `security find-generic-password`. Add
      `bao-buddy exec -- <command>`, which runs the command with `VAULT_TOKEN`/`BAO_TOKEN` (and
      artifact file paths) in its environment and never prints the token. Update the agent skill,
      AGENTS snippet, and README.
- [ ] Update the threat model and README "macOS limits".

**Done when** a process without the access group can't read or use any BaoBuddy item, verified on
a clean user account.

## Phase 5: v0.1.0 release (Maintainer approves, Code prepares)

- [ ] Mac helper and CLI: tag `helper-v0.1.0` (or run **Release macOS Helper**) and
      approve the `helper-release` environment.
- [ ] Receiver: tag `receiver-v0.1.0` (or run **Release Receiver**) and approve the
      `receiver-release` environment. Verify the downloaded binary’s provenance and checksum.
- [ ] Verify on a clean Mac: `gh attestation verify`, `spctl --assess`, `codesign --verify`,
      `brew install --cask northcutted/tap/baobuddy`, `bao-buddy --help`, menu bar grant.
- [ ] Commit the rendered `baobuddy.rb` to `homebrew-tap`.
- [ ] iOS: run **Release** → *Upload to TestFlight* with a green **Release Prep** run; after
      checking the build, submit for App Review with the demo-mode notes. (The iOS release is
      tagged `v0.1.0` by the publisher App.)

**Done when** Homebrew install works from a clean machine and TestFlight is live.

## Phase 6: Launch

- [ ] Outside review: one security-minded person who didn't write the code, plus
      `/code-review ultra` on the branch. Fix or document every finding.
- [ ] 30–60 second demo video: agent asks → approval sheet → Face ID → grant on the remote host →
      revoke. Also a GIF for the README.
- [ ] Show HN draft: what it is, why (agents need short scoped access, not standing tokens), how it
      works in four lines, the limits up front, quickstart link, threat model link.
- [ ] LinkedIn post: the video, the problem, one paragraph on the design, the link.
- [ ] Post on a weekday morning (US Eastern) and stay available for 4–6 hours to answer
      threat-model questions.

**Done when** the posts are live and the first round of questions has answers in the thread
(and fixes or doc updates in the repo).

## Order and dependencies

```text
Phase 0 (Maintainer) ──────────────┬─────────────────────────────┐
Phase 1 → Phase 2 → Phase 3 (Code) ┤                             │
                                   └→ Phase 4 (needs profile) → Phase 5 → Phase 6
```

App Store approval isn't on the critical path: Phase 6 can go ahead with TestFlight and Homebrew.
