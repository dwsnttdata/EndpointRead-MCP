---
name: endpoint-compliance-report
description: |
  Reports Intune device compliance using read-only EndpointRead-MCP tools.
  Use when the user asks for a "compliance report", "non-compliant devices", "why is <device> non-compliant",
  "compliance policy status", "which compliance policies exist", "devices without a compliance policy",
  or "compliance trend for management".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Endpoint compliance report

## Workflow

1. **Headline numbers** → `manage_intune_reports` with `action: compliance_report`.
2. **Non-compliant devices** → `manage_intune_devices` with `action: get_noncompliant` (`top`).
3. **Why one device fails** → `manage_intune_devices` with `action: get_compliance_states` and `device_id`.
4. **Policies** → `manage_compliance_policies` with `action: list`. Then `get`, `get_status` or `list_assignments` with `policy_id`.
5. **Per-policy deployment** → `manage_intune_reports` with `action: compliance_policy_status` and `policy_id`.
6. **Detailed export** (optional) → `manage_intune_reports` with `action: export_report` and `report_name` such as `DeviceNonCompliance`, `DevicesWithoutCompliancePolicy` or `NonCompliantDevicesAndSettings`. Use `max_rows` to keep results small.

## Output

- **Management**: compliance %, non-compliant count, top 3 failure reasons, top affected OS/platform, recommended follow-up (read-only advice only).
- **Engineering**: table with Device, OS, Policy, Setting/State, Last check-in.

## Rules (always apply)

- Read-only. Never change policies or devices. Remediation advice is text only, carried out by an admin in Intune.
- Use only tool data from this conversation. Never invent counts, devices or reasons.
- Empty result: say "No matching records were returned" and state the filter.
- Errors: 403 = missing Graph permission. `status: report_generating` = Intune is still building the report, so ask again in a few minutes. `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)** for device and policy calls. **Intune report snapshot** for `manage_intune_reports` exports, which can lag live state.
- Minimize sensitive data. Show user names only if asked. Show the top 20 rows plus the total for large lists. Say when results are truncated.
- State when the data was retrieved.
