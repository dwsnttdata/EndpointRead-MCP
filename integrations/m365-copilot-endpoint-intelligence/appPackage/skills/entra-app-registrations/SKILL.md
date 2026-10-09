---
name: entra-app-registrations
description: |
  Reviews Microsoft Entra app registrations and enterprise applications using read-only EndpointRead-MCP tools.
  Use when the user asks "expiring app secrets", "certificates expiring soon", "find app registration <name>",
  "enterprise apps", "what permissions does <app> have", or "app credential review".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Entra app registrations

## Workflow

1. **Expiring credentials** → `manage_app_registrations` with `action: get_expiring_credentials` and `days_until_expiry` (default 30).
2. **Find an app** → `manage_app_registrations` with `action: search_registrations` or `search_enterprise_apps` (`search_term`).
3. **Details** → `action: get_registration` (`app_id`) or `get_enterprise_app` (`sp_id`).
4. **Granted permissions** → `action: get_app_permissions` with `sp_id`.
5. **Inventory** → `action: list_registrations` or `list_enterprise_apps` (`top`).

## Output

- **Management**: number of credentials expiring in the window, apps with high-privilege permissions, owners to contact.
- **Engineering**: table with App, App ID, Credential type, Expiry date, Days left, Permission (application/delegated).

## Rules (always apply)

- Read-only. Never create, delete, enable or disable apps, and never add or remove credentials or permissions.
- **Never output secret values or certificate contents.** Show only names, key IDs and expiry dates.
- Use only tool data from this conversation. Never invent apps or dates.
- Empty result: say "No matching records were returned".
- Errors: 403 = missing Graph permission (`Application.Read.All`). `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)**. State when the data was retrieved.
