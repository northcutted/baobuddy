# AI Agent Integration (MCP Server, Skills & Prompts)

BaoBuddy ships a built-in, zero-dependency **stdio MCP server** (`bao-buddy mcp`) plus ready-to-use skills and prompts so AI coding agents (**Claude Code**, **OpenAI Codex**, **Cursor**, **Windsurf**, **Antigravity**) can safely request short-lived, Touch ID / Face ID–approved OpenBao & HashiCorp Vault access.

## Security Guarantees
- **No secrets in LLM context**: Approved tokens go straight into macOS Keychain or `baobuddy-receiver`; MCP tools only return non-secret metadata (`active`, `ttl_seconds`, `policies`, `target`).
- **Mandatory human biometric approval**: Agents can request a grant (opening the native Touch ID popover or producing a `baobuddy://grant?...` link), never approve one silently.
- **Least-privilege self-revocation**: Agents can revoke their own active grant immediately once a task finishes.

## 1. Connect the MCP Server

Generate the exact config for your machine anytime:
```bash
bao-buddy mcp --print-config
```

### Claude Code / Cursor / Windsurf / Antigravity (`.mcp.json`)
```json
{
  "mcpServers": {
    "baobuddy": {
      "command": "/Applications/BaoBuddyHelper.app/Contents/MacOS/BaoBuddyHelper",
      "args": ["mcp"]
    }
  }
}
```

### OpenAI Codex (`~/.codex/config.toml`)
```toml
[mcp_servers.baobuddy]
command = "/Applications/BaoBuddyHelper.app/Contents/MacOS/BaoBuddyHelper"
args = ["mcp"]
```

## 2. Add the Agent Rule or Skill
- **Tailored `AGENTS.md` / `CLAUDE.md` rule**: Run `bao-buddy agent-prompt --copy` (or **Settings → About → Copy AGENTS.md Rule**) to generate a snippet listing your exact server policies, audit ticket format, and targets, or copy [AGENTS.snippet.md](AGENTS.snippet.md).
- **Portable Agent Skill**: Copy [baobuddy/SKILL.md](baobuddy/SKILL.md) into your agent's skills directory (`.claude/skills/baobuddy/`, `.agents/skills/baobuddy/`, etc.).
- **Pre-built Operational Prompts**: See [workflows.md](workflows.md) for copy-paste prompts (read-only triage, audited elevated deploys, OpenTofu apply with auto-revoke).
