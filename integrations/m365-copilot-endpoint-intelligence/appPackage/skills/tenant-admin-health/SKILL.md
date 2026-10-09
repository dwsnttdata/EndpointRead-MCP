---
name: tenant-admin-health
description: |
  Reports Microsoft 365 tenant information and service health using read-only EndpointRead-MCP tools:
  organization details, domains, subscriptions and licenses, service health, active issues, message center,
  planned maintenance, directory roles, Global Administrators, security defaults, terms of use, and cross-tenant access.
  Use when the user asks "service health", "is Intune having an outage", "message center updates",
  "who are the Global Admins", "license subscriptions", "tenant domains", or "security defaults status".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Tenant admin and health

## Workflow

1. **Service health** → `manage_tenant_admin` with `action: get_service_health`, then `get_service_issues` for details. Focus on Intune, Entra ID, Exchange, Teams and SharePoint unless asked otherwise.
2. **Changes** → `action: get_message_center` or `get_planned_maintenance`.
3. **Tenant facts** → `action: get_org_info`, `get_domains` or `get_subscriptions`.
4. **Privileged roles** → `action: list_directory_roles`, `get_role_members` (`role_id`) or `get_global_admins`.
5. **Policies** → `action: get_security_defaults`, `list_terms_of_use` or `get_cross_tenant_policy`.

## Output

- **Management**: health status per service (healthy / advisory / incident), impact summary, notable upcoming changes.
- **Engineering**: table with Service, Status, Issue ID, Title, Start time, Last update.

## Rules (always apply)

- Read-only. Never assign or remove roles, and never create terms of use.
- Use only tool data from this conversation. Never invent incidents or admins.
- Empty result: say "No matching records were returned".
- Errors: 403 = missing Graph permission (for example `ServiceHealth.Read.All`, `ServiceMessage.Read.All`, `RoleManagement.Read.Directory`). `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)**.
- Minimize sensitive data. For admin lists give display names and count, not contact details. State when the data was retrieved.
