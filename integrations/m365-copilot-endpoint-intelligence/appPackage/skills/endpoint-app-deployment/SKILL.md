---
name: endpoint-app-deployment
description: |
  Reports Intune application deployment, install status, discovered apps and app protection (MAM) using read-only EndpointRead-MCP tools.
  Use when the user asks "app deployment status", "is <app> installed", "install failures for <app>",
  "which apps are assigned", "discovered apps", "app protection policies", "MAM registrations",
  or "app configuration policies".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Endpoint app deployment

## Workflow

1. **Find the app** → `manage_intune_apps` with `action: search` and `search_term`, or `action: list`.
2. **App detail and assignments** → `manage_intune_apps` with `action: get` and `app_id`.
3. **Install status** → `manage_intune_apps` with `action: get_install_status` and `app_id`. For a summary report, use `manage_intune_reports` with `action: app_install_status` and `app_id`.
4. **Discovered (detected) apps** → `manage_intune_apps` with `action: list_discovered`. For a tenant-wide export, use `manage_intune_reports` with `action: app_inventory`.
5. **App protection / configuration** → `manage_app_config_mam` with `action: list_protection_policies`, `list_config_policies` or `get_config_policy` (`policy_id`). For MAM registrations, use `manage_intune_apps` with `action: get_mam_registrations`.

## Output

- **Management**: success rate, failed/pending counts, top failure reasons, apps at risk.
- **Engineering**: table with App, Version, Assignment intent/group, Installed, Failed, Pending, Not applicable.

## Rules (always apply)

- Read-only. Never assign, unassign, create, update or delete apps.
- Use only tool data from this conversation. Never invent app names, versions or counts.
- Empty result: say "No matching records were returned" and state the search term.
- Errors: 403 = missing Graph permission. `status: report_generating` = report still being built. `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)** for app calls. **Intune report snapshot** for report exports.
- Minimize sensitive data. List user names or devices only when asked. Show the top 20 rows plus the total for large lists.
- State when the data was retrieved.
