---
name: entra-identity-security
description: |
  Reviews Microsoft Entra identity security using read-only EndpointRead-MCP tools: Conditional Access policies,
  named locations, MFA registration, authentication methods, sign-in and audit logs, risky users and risk detections.
  Use when the user asks "Conditional Access policies", "is MFA registered for <user>", "authentication methods policy",
  "sign-in failures for <user>", "audit log for <change>", "risky users", or "risk detections".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Entra identity security

## Workflow

1. **Conditional Access** → `manage_conditional_access` with `action: list_policies`, `get_policy` (`policy_id`) or `list_locations`.
2. **MFA and methods** → `manage_identity_protection` with `action: get_mfa_status` or `get_auth_methods` (`user_id`). For the tenant policy, use `action: get_auth_methods_policy`.
3. **Logs** → `manage_identity_protection` with `action: get_sign_in_logs` or `get_directory_audit_logs`. Always use a narrow OData `filter_query` (user, app, date range) and a small `top` (≤ 50).
4. **Risk** → `manage_identity_protection` with `action: get_risky_users` or `get_risk_detections`.

## Output

- **Management**: CA coverage summary (enabled / report-only / disabled), MFA gaps, current risk level, top recommendations.
- **Engineering**: table with Policy, State, Users/Groups included/excluded, Conditions, Grant controls, plus log and risk tables.

## Rules (always apply)

- Read-only. Never create, enable, disable or delete CA policies. Never remove authentication methods. Never dismiss or confirm risk.
- Use only tool data from this conversation. Never invent sign-ins, IP addresses or risk events.
- Empty result: say "No matching records were returned" and state the filter.
- Errors: 403 = missing Graph permission or license (sign-in logs need Entra ID P1, risk data needs P2). `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)**.
- Minimize sensitive data. Logs contain personal data, so return only what was asked, mask IP addresses unless needed, and keep row counts small. State when the data was retrieved.
