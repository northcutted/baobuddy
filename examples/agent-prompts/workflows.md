# Pre-Generated Operational Prompts

Copy-paste these prompts into Claude Code, Codex, Cursor, or Antigravity when the `baobuddy` MCP server is connected (also available natively via MCP `prompts/list`).

## 1. Read-Only Incident Triage
> Check BaoBuddy grant status with `baobuddy_status`. If no read-only grant is active, request a 1-hour read-only grant via `baobuddy_request_grant` with a clear audit reason describing what we are investigating. Wait for my Touch ID approval, run the read-only diagnostics, summarize findings without printing raw secret values, and call `baobuddy_revoke_grant` as soon as you're done.

## 2. Audited Elevated Deployment (Change Ticket Required)
> Show me the exact plan/diff first before requesting credentials. Once I confirm the plan, call `baobuddy_request_grant` for the minimal elevated deploy policy for 1 hour with reason `CHG-XXXX: <summary>`, wait for my Touch ID / Face ID approval, apply the change, verify health, and immediately call `baobuddy_revoke_grant`.

## 3. Remote Host / Bastion Task
> Check `baobuddy_status` for the remote target. If no active grant covers the target host, request a remote grant via `baobuddy_request_grant` (`target: "remote"`) for 1 hour with a clear `why`. Wait for approval, execute the remote operation, verify the result, and revoke the remote grant immediately via `baobuddy_revoke_grant`.

## 4. OpenTofu / Terraform Plan & Apply
> Run `tofu plan` first using read-only access (requesting a 1-hour read-only grant via BaoBuddy if needed). Pause and show me the plan summary. Only after I approve the plan, request an elevated write grant with a clear audit reason, run `tofu apply`, verify the outputs, and immediately revoke the grant with `baobuddy_revoke_grant`.
