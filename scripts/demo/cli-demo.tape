# CLI demo: a coding agent's grant, approved with Touch ID, used, and revoked.
# Run through scripts/demo/record-cli-demo.sh, which starts a throwaway
# `bao server -dev`, isolates BaoBuddy's profiles, and exports the environment
# this tape expects. The Touch ID prompt needs a person at the Mac.

Output docs/media/cli-demo.gif
Output docs/media/cli-demo.mp4

Set Shell "bash"
Set FontSize 20
Set Width 1280
Set Height 760
Set Padding 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set WindowBar Colorful

Hide
Type "export PS1='\[\e[38;5;79m\]$\[\e[0m\] ' && clear"
Enter
Show

Type "# A short-lived OpenBao token, approved with Touch ID"
Sleep 600ms
Enter
Type "bao-buddy health"
Sleep 400ms
Enter
Sleep 2s

Type "export BAO_TOKEN=$(bao-buddy grant --on direct --hours 1 \"
Enter
Type "    --policies db-readonly --why 'Run the staging migration check')"
Sleep 500ms
Enter
# Touch ID prompt: approve it on the Mac.
Sleep 12s

Type "bao token lookup -format=json | jq '.data | {policies, ttl, meta}'"
Sleep 400ms
Enter
Sleep 3s

Type "bao read -format=json secret/data/staging/db/postgres | jq -r .data.data.username"
Sleep 400ms
Enter
Sleep 2s

Type "bao read secret/data/staging/app/config   # not in the grant"
Sleep 400ms
Enter
Sleep 2500ms

Type "bao token revoke -self && bao token lookup"
Sleep 400ms
Enter
Sleep 3s
