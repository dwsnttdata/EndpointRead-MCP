---
name: endpoint-device-overview
description: |
  Summarizes Microsoft Intune managed devices and Windows 365 Cloud PCs using read-only EndpointRead-MCP tools.
  Use when the user asks "how many devices do we have", "device overview", "show device <name>",
  "devices for user <UPN>", "stale devices", "devices not checked in for 30 days", "OS breakdown",
  "hardware for a device", "apps installed on a device", or "Cloud PC status".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Endpoint device overview

## Workflow

1. **Tenant overview** → `get_intune_overview` (counts by compliance and OS).
2. **List or filter** → `manage_intune_devices` with `action: list` (optional `filter_query` OData, `top`).
3. **Find one device** → `manage_intune_devices` with `action: search`, `search_term`, `search_by` (`deviceName`, `userPrincipalName` or `serialNumber`). Then `action: get` with `device_id`.
4. **Device detail on request** → `action: get_hardware`, `get_installed_apps`, `get_compliance_states` or `get_network` with `device_id`.
5. **Stale devices** → `action: get_stale` with `days_inactive` (default 30).
6. **Cloud PCs** → `manage_cloud_pc` with `action: get_overview`, `list` or `get` (`cloud_pc_id`).
7. Present the result in the requested style (see Output).

## Output

- **Management**: 3–5 bullet summary (total, % compliant, OS split, stale count), then risks and next steps.
- **Engineering**: table with Device name, OS/version, Compliance, Last check-in, Ownership, Primary user (only if asked).
- Excel/SharePoint: give a clean table with one header row and no merged cells.

## Rules (always apply)

- Read-only. Never offer or attempt sync, restart, wipe, retire, delete, rename, lock or any change. If asked, say Endpoint Intelligence is read-only and point to the Intune admin center.
- Use only data returned by the tools in this conversation. Never invent devices, users, counts, dates or names.
- Empty result: say "No matching records were returned" and state the filter used.
- Errors: HTTP 403 or `Authorization_RequestDenied` = missing Graph permission. `auth_required` or 401 = sign-in problem. Otherwise quote the short error. Don't guess around a failure.
- Label the source: **Live (Graph)** for list/get/search. **Aggregated** for overview counts.
- Minimize sensitive data. Don't show serial numbers, IMEI, MAC/IP addresses or phone numbers unless explicitly asked. Show the top 20 rows plus the total count for large lists.
- Always state when the data was retrieved, plus any filter or `top` limit applied.
