---
name: endpoint-periodic-summary
description: |
  Produces a weekly or monthly endpoint management summary from read-only EndpointRead-MCP data,
  formatted for management or engineering and ready for Word, Excel, PowerPoint, email or SharePoint.
  Use when the user asks for a "weekly endpoint report", "monthly Intune summary", "endpoint status for management",
  "executive summary of devices and compliance", "slide deck on endpoint health", or "status email for the endpoint team".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Weekly or monthly endpoint summary

## Workflow

1. Confirm the audience (**management** or **engineering**) and the format (Word, Excel, PowerPoint, email or SharePoint page). If not stated, default to a management summary in a document format.
2. Collect data. Run each call once, and skip a section if its call fails (note the failure):
   - Devices: `get_intune_overview`, plus `manage_intune_devices` with `action: get_stale` and `days_inactive: 30`
   - Compliance: `manage_intune_reports` with `action: compliance_report`, plus `manage_intune_devices` with `action: get_noncompliant` and `top: 20`
   - Apps: `manage_intune_apps` with `action: list` and `top: 20`, then `get_install_status` for the apps the user names
   - Security: `manage_intune_reports` with `action: device_protection_overview`
   - Windows servicing: `manage_windows_update` with `action: list_update_rings`, plus `get_intune_overview` for the OS split
   - Autopilot: `manage_autopilot` with `action: get_deployment_status`
   - Service health: `manage_tenant_admin` with `action: get_service_health`
3. Build the report using the structure below. Use only numbers returned by the tools.
4. Hand the content to Cowork's built-in Word, Excel, PowerPoint or email capabilities for the final file.

## Report structure

1. **Title and period**, for example "Endpoint summary — week ending <date>". Add the data retrieval time.
2. **Headline KPIs**: total devices, % compliant, non-compliant, stale (30 days), Autopilot success, active service incidents.
3. **What changed**: only if the user supplies a previous report or baseline. Never invent trends.
4. **Risks and issues**: top 3–5, each with impact and owner suggestion.
5. **Recommended actions**: read-only advice for admins.
6. **Appendix (engineering)**: detail tables.
7. **Data sources and gaps**: list each section as **Live (Graph)**, **Intune report snapshot** or **Aggregated**, plus any sections skipped because of errors or missing permissions.

Format by target:
- **PowerPoint**: one slide per section, 3–5 bullets each.
- **Excel**: one table per sheet, header row only.
- **Email**: under 200 words plus the KPI table.
- **SharePoint**: headings plus tables.

## Rules (always apply)

- Read-only. Recommend actions; never perform them.
- Never fabricate data or trends. If a section has no data, write "No data returned" or "Not available (missing permission)".
- Minimize sensitive data. Use aggregate numbers in management reports, and include device or user names only in the engineering appendix when asked.
- Never include recovery keys, secrets, tokens, tenant IDs or client IDs.
