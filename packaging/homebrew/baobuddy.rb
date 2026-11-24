# Homebrew Cask template for BaoBuddy (macOS Menu Bar app + `bao-buddy` CLI).
# The macOS release workflow fills in `__VERSION__` and `__SHA256__` and attaches
# a ready-to-commit `baobuddy.rb` to each GitHub Release.
#
# Place the rendered file at `Casks/baobuddy.rb` in `northcutted/homebrew-tap`,
# then install with:
#   brew install --cask northcutted/tap/baobuddy

cask "baobuddy" do
  version "__VERSION__"
  sha256 "__SHA256__"

  url "https://github.com/northcutted/baobuddy/releases/download/helper-v#{version}/BaoBuddyHelper-#{version}-macos.zip"
  name "BaoBuddy"
  desc "Hardware-backed biometric companion & CLI for OpenBao and HashiCorp Vault"
  homepage "https://github.com/northcutted/baobuddy"

  # The repository also publishes iOS releases (v* tags), so match only helper-v* tags.
  livecheck do
    url "https://github.com/northcutted/baobuddy"
    regex(/^helper-v(\d+(?:\.\d+)+)$/i)
    strategy :github_releases
  end

  depends_on macos: ">= :sequoia"

  app "BaoBuddyHelper.app"
  binary "#{appdir}/BaoBuddyHelper.app/Contents/MacOS/BaoBuddyHelper", target: "bao-buddy"

  uninstall quit: "com.northcutt.BaoBuddy.Helper"

  zap trash: [
    "~/.config/baobuddy",
  ]

  caveats <<~EOS
    `brew uninstall --zap` removes ~/.config/baobuddy but intentionally does NOT
    delete macOS Keychain items (your server-scoped Secure Enclave key handles,
    SSH delivery key, or active `openbao-grant.*` / `openbao-grant-artifact.*`
    tokens). To remove those manually, delete the `com.northcutt.baogrant.*`,
    `openbao-grant*`, and `openbao-grant-artifact*` items in Keychain Access.
  EOS
end
