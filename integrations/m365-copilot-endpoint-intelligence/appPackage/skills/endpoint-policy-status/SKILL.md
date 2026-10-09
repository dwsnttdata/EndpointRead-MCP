---
name: endpoint-policy-status
description: |
  Reports Intune configuration and policy status using read-only EndpointRead-MCP tools: configuration profiles,
  settings catalog, administrative templates (ADMX), assignment filters and scope tags.
  Use when the user asks "configuration profile status", "which policies apply to <group>", "settings catalog policies",
  "profile deployment errors", "ADMX policies", "assignment filters", "scope tags", or "policy inventory".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Endpoint policy status

## Workflow

1. **Configuration profiles** → `manage_configuration_profiles` with `action: list`. Then `get`, `get_status` or `list_assignments` with `profile_id`.
2. **Profile deployment summary** → `manage_intune_reports` with `action: config_profile_status` and `policy_id`.
3. **Settings catalog** → `manage_settings_catalog` with `action: list` or `get` (`policy_id`).
4. **Administrative templates** → `manage_admx_policies` with `action: list` or `get` (`config_id`).
5. **Targeting** → `manage_filters_tags` with `action: list_filters`, `get_filter` (`filter_id`) or `list_tags`.
6. For a full inventory, combine steps 1, 3 and 4. Mark each policy's type.

## Output

- **Management**: policy count by type, % succeeded, profiles with errors or conflicts, recommended review items.
- **Engineering**: table with Policy, Type, Platform, Assigned groups, Succeeded, Error, Conflict, Pending, Last modified.

## Rules (always apply)

- Read-only. Never create, edit, assign or delete policies, filters or tags.
- Use only tool data from this conversation. Never invent settings or assignments.
- Empty result: say "No matching records were returned".
- Errors: 403 = missing Graph permission. `status: report_generating` = report still being built. `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)** for policy calls. **Intune report snapshot** for report exports.
- Don't dump full raw setting payloads unless asked. Summarize key settings.
- State when the data was retrieved.
