---
name: endpoint-analytics-reports
description: |
  Runs read-only Intune and Endpoint Analytics reports through EndpointRead-MCP: Endpoint Analytics scores,
  startup performance, app reliability, Work From Anywhere, hardware and app inventory, certificates,
  co-management, license usage, and any named Intune export report.
  Use when the user asks "Endpoint Analytics score", "boot/startup performance", "app crashes", "Work From Anywhere readiness",
  "hardware inventory export", "certificate report", "co-management status", "license usage", or "run the <name> report".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Intune and Endpoint Analytics reports

## Workflow

1. **Know the report names** → `manage_intune_reports` with `action: list_available_reports`.
2. **Built-in shortcuts** → `manage_intune_reports` with `action`: `endpoint_analytics_score`, `startup_performance`, `app_reliability`, `work_from_anywhere`, `hardware_inventory`, `app_inventory`, `certificate_report`, `co_management_report` or `license_usage`.
3. **Any named report** → `manage_intune_reports` with `action: export_report`, `report_name`, an optional `filter_expr` and `select` columns, and `max_rows` (keep it at 200 or less unless the user needs more).
4. If the result is `status: report_generating`, tell the user that Intune is still building the report and to ask again in a few minutes. Don't retry in a loop.

## Output

- **Management**: 3–5 insights with numbers, trend direction only if the data shows it, recommended actions.
- **Engineering / Excel**: a clean table with the returned columns. Note `row_count`, `returned_rows` and `truncated`.

## Rules (always apply)

- Read-only. Reports never change anything.
- Use only tool data from this conversation. Never extrapolate missing rows or invent trends.
- Empty result: say "The report returned no rows" and state the filter.
- Errors: 403 = missing Graph permission. `status: report_generating` = still building. `auth_required`/401 = sign-in problem.
- Label the source: **Intune report snapshot** for exports. **Aggregated** for Endpoint Analytics scores.
- Minimize sensitive data. Drop user names, serial numbers and IP addresses from tables unless asked. State when the data was retrieved.
