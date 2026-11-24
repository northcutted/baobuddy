#!/usr/bin/env bash
# Provisions GitHub for the BaoBuddy v0.1.0 release (docs/RELEASE_PLAN.md, Phase 0).
#
# Safe to rerun: every step checks what already exists and skips it. Anything public or hard to
# undo (creating repositories, the first commit, pushing) asks first. Secrets are read from
# files or hidden prompts and passed to `gh secret set` on stdin; they never appear in argv,
# the terminal, or shell history.
#
# Usage:
#   scripts/provision-repo.sh            # repos, push, settings, environments, homebrew tap
#   scripts/provision-repo.sh secrets    # environment secrets (asks for files and values)
#   scripts/provision-repo.sh status     # show what exists, change nothing
#
# Steps that need Apple's portals or GitHub's web UI are in docs/RELEASE_SETUP.md.
set -euo pipefail

OWNER="${OWNER:-northcutted}"
REPO="${OWNER}/baobuddy"
TAP="${OWNER}/homebrew-tap"
CERTS="${OWNER}/baobuddy-certs"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Environments used by the iOS release platform (northcutted/ios-release-workflows) and the
# Mac helper and receiver releases, with their permitted deployment refs.
IOS_ENVS=(signing:branch:main testflight:branch:main release-publishing:branch:main
  screenshot-publishing:branch:main app-store-staging:tag:v* production:tag:v*
  app-store-observe:branch:main)
HELPER_ENV="helper-release"
RECEIVER_ENV="receiver-release"

bold() { printf '\n\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
done_() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
skip() { printf '  \033[2m- %s\033[0m\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

confirm() {
  local answer
  read -r -p "  $1 [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" ]]
}

repo_exists() { gh repo view "$1" --json name >/dev/null 2>&1; }

preflight() {
  for tool in gh git jq base64 ssh-keygen security rsync; do
    command -v "$tool" >/dev/null || die "$tool is required"
  done
  gh auth status >/dev/null 2>&1 || die "run 'gh auth login' first"
  ME="$(gh api user --jq .login)"
  ME_ID="$(gh api user --jq .id)"
  [[ "$ME" == "$OWNER" ]] || warn "signed in to gh as $ME, but OWNER is $OWNER"
}

# --- Repositories -----------------------------------------------------------------------------

create_repos() {
  bold "Repositories"
  if repo_exists "$REPO"; then skip "$REPO exists"; else
    if confirm "Create PUBLIC repository $REPO?"; then
      gh repo create "$REPO" --public \
        --description "Biometric, short-lived OpenBao and HashiCorp Vault grants from your iPhone or Mac" \
        --homepage "https://github.com/$REPO" --disable-wiki >/dev/null
      done_ "created $REPO"
    else
      die "the main repository is required"
    fi
  fi

  if repo_exists "$TAP"; then skip "$TAP exists"; else
    if confirm "Create PUBLIC repository $TAP (Homebrew tap)?"; then
      gh repo create "$TAP" --public --description "Homebrew tap for BaoBuddy" --disable-wiki --add-readme >/dev/null
      done_ "created $TAP"
    fi
  fi

  if repo_exists "$CERTS"; then skip "$CERTS exists"; else
    if confirm "Create PRIVATE repository $CERTS (fastlane match signing storage)?"; then
      gh repo create "$CERTS" --private --description "Encrypted iOS signing assets for BaoBuddy (fastlane match)" \
        --disable-wiki --add-readme >/dev/null
      done_ "created $CERTS"
    fi
  fi
}

# --- First commit and push --------------------------------------------------------------------

# Scans exactly the files the first commit would contain (tracked plus untracked, minus
# .gitignore), so ignored build output isn't scanned.
scan_for_secrets() {
  local copy
  copy="$(mktemp -d)"
  git -C "$ROOT_DIR" ls-files -co --exclude-standard -z \
    | rsync -a --from0 --files-from=- "$ROOT_DIR/" "$copy/"
  if command -v gitleaks >/dev/null; then
    if ! gitleaks dir "$copy" --redact --no-banner >/dev/null 2>&1; then
      rm -rf "$copy"
      die "gitleaks found possible secrets; run: gitleaks dir . --redact (after removing build output)"
    fi
    done_ "gitleaks: no secrets in the files to commit"
  else
    warn "gitleaks isn't installed (brew install gitleaks); using a basic pattern scan"
    if grep -rIlE 'BEGIN (EC |RSA |OPENSSH |)PRIVATE KEY|hvs\.[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}' "$copy"; then
      rm -rf "$copy"
      die "possible secrets in the files above"
    fi
    done_ "pattern scan: no secrets in the files to commit"
  fi
  rm -rf "$copy"
}

push_main() {
  bold "Source"
  cd "$ROOT_DIR"
  if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
    info "This checkout has no commits yet. Files that would be committed:"
    git status --short | awk '{print $2}' | cut -d/ -f1 | sort -u | sed 's/^/      /'
    scan_for_secrets
    if confirm "Create the initial commit with everything listed above (respects .gitignore)?"; then
      git add -A
      git commit -q -m "Initial public release candidate (v0.1.0 beta)"
      done_ "committed $(git rev-parse --short HEAD)"
    else
      die "nothing to push without a commit"
    fi
  else
    skip "commits exist ($(git rev-parse --short HEAD))"
  fi

  local url
  if [[ "$(gh config get git_protocol 2>/dev/null)" == "ssh" ]]; then
    url="git@github.com:${REPO}.git"
  else
    url="https://github.com/${REPO}.git"
  fi
  if git remote get-url origin >/dev/null 2>&1; then
    skip "remote origin is $(git remote get-url origin)"
  else
    git remote add origin "$url"
    done_ "added remote origin $url"
  fi

  if git ls-remote --exit-code --heads origin main >/dev/null 2>&1; then
    skip "origin/main exists"
  elif confirm "Push main to $REPO (makes the code public)?"; then
    git push -u origin main
    done_ "pushed main"
  fi
}

# --- Repository settings ----------------------------------------------------------------------

configure_repo() {
  bold "Repository settings"
  gh api -X PATCH "repos/$REPO" --input - >/dev/null <<'JSON'
{"has_wiki": false, "has_projects": false, "delete_branch_on_merge": true,
 "allow_merge_commit": false, "allow_squash_merge": true, "allow_rebase_merge": true,
 "security_and_analysis": {"secret_scanning": {"status": "enabled"},
                           "secret_scanning_push_protection": {"status": "enabled"}}}
JSON
  done_ "squash/rebase merges, delete merged branches, secret scanning with push protection"
  gh api -X PUT "repos/$REPO/private-vulnerability-reporting" >/dev/null
  done_ "private vulnerability reporting (SECURITY.md links to it)"
  gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null
  gh api -X PUT "repos/$REPO/automated-security-fixes" >/dev/null
  done_ "Dependabot alerts and security updates"
}

# --- Environments -----------------------------------------------------------------------------

# put_environment NAME KIND REF REVIEWED
put_environment() {
  local name="$1" kind="$2" ref="$3" reviewed="$4" payload
  if [[ "$reviewed" == "yes" ]]; then
    payload=$(jq -n --argjson id "$ME_ID" '{deployment_branch_policy:{protected_branches:false,custom_branch_policies:true},
      can_admins_bypass:false, prevent_self_review:false, reviewers:[{type:"User",id:$id}]}')
  else
    payload='{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true},"can_admins_bypass":false}'
  fi
  gh api -X PUT "repos/$REPO/environments/$name" --input - >/dev/null <<<"$payload"
  allow_deployment_ref "$name" "$kind" "$ref"
  done_ "$name (deploys from $kind $ref$([[ "$reviewed" == yes ]] && echo ", needs your approval"))"
}

allow_deployment_ref() {
  local name="$1" kind="$2" ref="$3" existing
  existing="$(gh api "repos/$REPO/environments/$name/deployment-branch-policies" \
    --jq ".branch_policies[] | select(.name == \"$ref\" and .type == \"$kind\") | .id")"
  if [[ -z "$existing" ]]; then
    gh api -X POST "repos/$REPO/environments/$name/deployment-branch-policies" \
      -f name="$ref" -f type="$kind" >/dev/null
  fi
}

configure_environments() {
  bold "Environments"
  # Each standalone release uses its own tags and supports manual dispatch from main.
  put_environment "$HELPER_ENV" tag 'helper-v*' yes
  allow_deployment_ref "$HELPER_ENV" branch main
  put_environment "$RECEIVER_ENV" tag 'receiver-v*' yes
  allow_deployment_ref "$RECEIVER_ENV" branch main

  for entry in "${IOS_ENVS[@]}"; do
    IFS=: read -r name kind ref <<<"$entry"
    if [[ "$name" == "production" ]]; then
      put_environment "$name" "$kind" "$ref" yes
    else
      put_environment "$name" "$kind" "$ref" no
    fi
  done
  info "Rulesets, immutable releases, and RELEASE_DISTRIBUTION_ENABLED come later from the"
  info "platform's controls-configure step (docs/RELEASE_SETUP.md, step 6)."
}

# --- Homebrew tap -----------------------------------------------------------------------------

scaffold_tap() {
  bold "Homebrew tap"
  repo_exists "$TAP" || { skip "$TAP doesn't exist"; return; }
  if gh api "repos/$TAP/contents/Casks" >/dev/null 2>&1; then
    skip "Casks/ exists"
    return
  fi
  local body
  body=$(printf '%s\n' "# Casks" "" \
    "Each BaoBuddy for Mac release attaches a rendered \`baobuddy.rb\`; commit it here." | base64)
  gh api -X PUT "repos/$TAP/contents/Casks/README.md" -f message="Add Casks directory" \
    -f content="$body" >/dev/null
  done_ "created Casks/ (install with: brew install --cask $OWNER/tap/baobuddy)"
}

# --- Secrets ----------------------------------------------------------------------------------

# set_secret ENV NAME < value
set_secret() {
  gh secret set "$2" --repo "$REPO" --env "$1" >/dev/null
  done_ "$1: $2"
}

ask_file() {
  local path
  read -r -p "  $1: " path
  path="${path/#\~/$HOME}"
  [[ -f "$path" ]] || die "no such file: $path"
  printf '%s' "$path"
}

ask_value() {
  local value
  read -r -p "  $1: " value
  [[ -n "$value" ]] || die "$1 is required"
  printf '%s' "$value"
}

ask_hidden() {
  local value
  read -r -s -p "  $1: " value
  echo >&2
  [[ -n "$value" ]] || die "$1 is required"
  printf '%s' "$value"
}

secrets() {
  bold "App Store Connect API key (notarization and iOS uploads)"
  info "Use a Team key with the App Manager role. The same key serves both pipelines."
  local p8 key_id issuer
  p8="$(ask_file "Path to AuthKey_XXXXXXXXXX.p8")"
  key_id="$(ask_value "Key ID")"
  issuer="$(ask_value "Issuer ID")"

  bold "Mac helper signing ($HELPER_ENV)"
  local p12 identity helper_profile
  helper_profile="$(ask_file "Path to BaoBuddy Helper Developer ID .provisionprofile")"
  base64 -i "$helper_profile" | set_secret "$HELPER_ENV" MAC_HELPER_PROFILE_BASE64
  p12="$(ask_file "Path to the exported Developer ID Application .p12")"
  identity="$(security find-identity -v -p codesigning | sed -nE 's/.*"(Developer ID Application: [^"]+)".*/\1/p' | head -1)"
  if [[ -n "$identity" ]] && confirm "Use signing identity '$identity'?"; then :; else
    identity="$(ask_value "Signing identity (e.g. Developer ID Application: Name (TEAMID))")"
  fi
  base64 -i "$p12" | set_secret "$HELPER_ENV" DEVELOPER_ID_CERT_P12
  ask_hidden "Password for the .p12" | set_secret "$HELPER_ENV" DEVELOPER_ID_CERT_PASSWORD
  printf '%s' "$identity" | set_secret "$HELPER_ENV" DEVELOPER_ID_IDENTITY
  base64 -i "$p8" | set_secret "$HELPER_ENV" APP_STORE_CONNECT_API_KEY_P8
  printf '%s' "$key_id" | set_secret "$HELPER_ENV" APP_STORE_CONNECT_KEY_ID
  printf '%s' "$issuer" | set_secret "$HELPER_ENV" APP_STORE_CONNECT_ISSUER_ID

  bold "iOS App Store environments"
  for env in testflight app-store-staging production app-store-observe; do
    printf '%s' "$key_id" | set_secret "$env" APP_STORE_CONNECT_API_KEY_ID
    printf '%s' "$issuer" | set_secret "$env" APP_STORE_CONNECT_API_KEY_ISSUER_ID
    set_secret "$env" APP_STORE_CONNECT_API_KEY_CONTENT <"$p8"
  done

  bold "iOS signing (signing): fastlane match"
  info "MATCH_PASSWORD encrypts the certificates in $CERTS. Store it in Bitwarden."
  local match_password
  match_password="$(ask_hidden "MATCH_PASSWORD (existing, or a new one you've saved in Bitwarden)")"
  printf '%s' "$match_password" | set_secret signing MATCH_PASSWORD

  if gh api "repos/$CERTS/keys" --jq '.[].title' 2>/dev/null | grep -qx "baobuddy-release-ci"; then
    skip "deploy key baobuddy-release-ci already on $CERTS (delete it there to rotate)"
  else
    local keydir
    keydir="$(mktemp -d)"
    chmod 700 "$keydir"
    ssh-keygen -q -t ed25519 -N "" -C "baobuddy-release-ci" -f "$keydir/id"
    gh api -X POST "repos/$CERTS/keys" -f title="baobuddy-release-ci" \
      -f key="$(cat "$keydir/id.pub")" -F read_only=false >/dev/null
    done_ "added a write deploy key to $CERTS"
    set_secret signing MATCH_SSH_PRIVATE_KEY <"$keydir/id"
    rm -rf "$keydir"
  fi

  bold "Publisher GitHub App (release-publishing, screenshot-publishing)"
  info "Reuse the App that publishes picstrip: install it on $REPO first (docs/RELEASE_SETUP.md, step 5)."
  if confirm "Is the publisher App installed on $REPO?"; then
    local app_id app_key
    app_id="$(ask_value "Publisher App ID (number)")"
    app_key="$(ask_file "Path to the App's private key (.pem)")"
    for env in release-publishing screenshot-publishing; do
      printf '%s' "$app_id" | set_secret "$env" RELEASE_APP_ID
      set_secret "$env" RELEASE_APP_PRIVATE_KEY <"$app_key"
    done
  else
    warn "skipped; rerun 'scripts/provision-repo.sh secrets' after installing the App"
  fi
}

# --- Status -----------------------------------------------------------------------------------

status() {
  bold "Status"
  for r in "$REPO" "$TAP" "$CERTS"; do
    if repo_exists "$r"; then done_ "$r"; else warn "$r missing"; fi
  done
  repo_exists "$REPO" || return 0
  local envs
  envs="$(gh api "repos/$REPO/environments" --jq '.environments[].name' 2>/dev/null || true)"
  for name in "$HELPER_ENV" "$RECEIVER_ENV" signing testflight release-publishing screenshot-publishing \
    app-store-staging production app-store-observe; do
    if grep -qx "$name" <<<"$envs"; then
      local count
      count="$(gh api "repos/$REPO/environments/$name/secrets" --jq '.total_count')"
      done_ "environment $name ($count secrets)"
    else
      warn "environment $name missing"
    fi
  done
}

main() {
  preflight
  case "${1:-setup}" in
    setup)
      create_repos
      push_main
      configure_repo
      configure_environments
      scaffold_tap
      bold "Next"
      info "1. scripts/provision-repo.sh secrets"
      info "2. Apple and GitHub App steps in docs/RELEASE_SETUP.md"
      ;;
    secrets) secrets ;;
    status) status ;;
    *) die "usage: $0 [setup|secrets|status]" ;;
  esac
}

main "$@"
