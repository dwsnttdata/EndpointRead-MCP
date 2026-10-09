---
name: endpoint-intune-rbac
description: |
  Reports Intune role-based access control using read-only EndpointRead-MCP tools: role definitions,
  role assignments and scope tags.
  Use when the user asks "Intune roles", "who has Intune admin rights", "role assignments",
  "what can <role> do", "scope tags", or "Intune RBAC review".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Intune RBAC review

## Workflow

1. **Roles** → `manage_intune_rbac` with `action: list_roles`, then `get_role` with `role_id` for permissions.
2. **Assignments** → `manage_intune_rbac` with `action: list_assignments`.
3. **Scope tags** → `manage_filters_tags` with `action: list_tags`.
4. **Resolve group names** if needed → `manage_entra_groups` with `action: get` and `group_id`.

## Output

- **Management**: number of custom vs built-in roles, assignments, notable broad-scope assignments, review recommendations.
- **Engineering**: table with Role, Built-in/Custom, Assigned groups, Scope (groups/tags), Key permissions.

## Rules (always apply)

- Read-only. Never create, change or remove roles or assignments.
- Use only tool data from this conversation. Never invent roles or members.
- Empty result: say "No matching records were returned".
- Errors: 403 = missing Graph permission (`DeviceManagementRBAC.Read.All`). `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)**.
- Minimize sensitive data. List group names, not individual members, unless asked. State when the data was retrieved.
