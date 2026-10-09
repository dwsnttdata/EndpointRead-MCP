---
name: entra-directory-lookup
description: |
  Looks up Microsoft Entra users, groups and devices using read-only EndpointRead-MCP tools.
  Use when the user asks "find user <name>", "what devices does <user> have", "user licenses", "group members of <group>",
  "who owns <group>", "which groups is <user> in", "Entra device <name>", "deleted users", or "direct reports of <user>".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Entra directory lookup

## Workflow

1. **Users** → `manage_entra_users` with `action: search` (`search_term`) or `get` (`user_id` = object ID or UPN). Related actions with `user_id`: `get_devices`, `get_licenses`, `get_member_groups`, `get_direct_reports`. Tenant-level actions: `list_available_licenses`, `get_deleted_users`.
2. **Groups** → `manage_entra_groups` with `action: search` (`search_term`) or `get` (`group_id`). Then `get_members` or `get_owners`.
3. **Entra devices** → `manage_entra_devices` with `action: search` (`search_term`) or `get` (`device_id`). Correlate with Intune using `manage_intune_devices` (`action: search`, `search_by: deviceName`).

## Output

- **Management**: short answer in one or two sentences, then key facts.
- **Engineering**: table with Name, UPN/ID (only if needed), Enabled, Type, Last sign-in or registration date, Related groups or devices.

## Rules (always apply)

- Read-only. Never create, update, disable, delete or restore users, groups or devices, and never change memberships or licenses.
- Use only tool data from this conversation. Never invent people, groups or relationships.
- Empty result: say "No matching records were returned" and state the search term.
- Errors: 403 = missing Graph permission. `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)**.
- Minimize personal data. Return only what the question needs. Don't list phone numbers, addresses or other personal attributes unless explicitly asked and relevant to endpoint work. Show the top 20 group members plus the total. State when the data was retrieved.
