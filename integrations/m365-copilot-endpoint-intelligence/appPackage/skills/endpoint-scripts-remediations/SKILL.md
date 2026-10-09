---
name: endpoint-scripts-remediations
description: |
  Reports Intune PowerShell scripts, proactive remediations and macOS shell scripts with their run status,
  using read-only EndpointRead-MCP tools.
  Use when the user asks "which scripts are deployed", "remediation status", "proactive remediation results",
  "script failures", "macOS scripts", or "run state for <script>".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Scripts and remediations

## Workflow

1. **List** → `manage_intune_scripts` with `action: list` and `script_type`: `powershell`, `remediation` or `macos`.
2. **Details** → `manage_intune_scripts` with `action: get`, `script_id` and `script_type`.
3. **Run status** → `manage_intune_scripts` with `action: get_status`, `script_id` and `script_type`. For an export, use `manage_intune_reports` with `action: export_report` and `report_name: DeviceRunStatesByScript` or `DeviceRunStatesByProactiveRemediation`.

## Output

- **Management**: scripts deployed, success/failure rates, scripts needing attention.
- **Engineering**: table with Script, Type, Run as, Assigned, Success, Failed, Pending, Last run.

## Rules (always apply)

- Read-only. Never upload, edit, assign, delete or run scripts.
- **Don't display script content by default.** Scripts can contain embedded credentials. If the user explicitly asks for content, warn that it may contain secrets and show only the relevant lines. Mask anything that looks like a password, key, token or connection string.
- Use only tool data from this conversation. Never invent scripts or results.
- Empty result: say "No matching records were returned".
- Errors: 403 = missing Graph permission. `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)**, or **Intune report snapshot** for exports. State when the data was retrieved.
