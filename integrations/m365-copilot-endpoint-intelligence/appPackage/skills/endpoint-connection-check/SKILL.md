---
name: endpoint-connection-check
description: |
  Checks that the EndpointRead-MCP connector works and explains what it can answer.
  Use when the user asks "is Endpoint Intelligence working", "test the connection", "what can you do",
  "which Intune or Entra data can you read", "list available operations", or when another skill reports
  repeated errors and the cause is unclear.
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Connection check and capabilities

## Workflow

1. **Connectivity** → `test_connection`. Report success or the exact error.
2. **Capabilities** → `discover_graph_operations` (optional `category` such as `intune`, `entra`, `report`). Summarize the tools and actions in plain language.
3. **Diagnose**:
   - 401 or a sign-in prompt → the user needs to sign in to the connector or is not in the allowed group.
   - 403 from Graph → the server's app registration lacks a Graph read permission. Name the area that failed.
   - Timeout or `report_generating` → Intune is slow or still building a report, so try again later.
   - A tool is not listed → it's intentionally disabled on this server (for example, recovery key retrieval).

## Output

- One-line status (Connected / Not connected), then a short capability list grouped by area: Devices, Compliance, Apps, Policies, Security, Autopilot, Windows Update, Reports, Entra, Tenant health.

## Rules (always apply)

- Read-only. This plugin can't make any changes, so say so clearly if asked.
- Never invent capabilities. List only what `discover_graph_operations` returns.
- Never display tokens, client IDs, tenant IDs or secrets, even if they appear in a response.
