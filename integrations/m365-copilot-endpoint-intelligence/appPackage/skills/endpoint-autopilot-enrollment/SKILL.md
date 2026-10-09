---
name: endpoint-autopilot-enrollment
description: |
  Reports Windows Autopilot and Intune enrollment status using read-only EndpointRead-MCP tools.
  Use when the user asks "Autopilot status", "Autopilot devices", "deployment profiles", "ESP profiles",
  "Autopilot deployment failures", "enrollment failures", "enrollment restrictions", "Apple DEP/ADE or VPP token status",
  or "Android Enterprise status".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Autopilot and enrollment

## Workflow

1. **Autopilot devices** → `manage_autopilot` with `action: list_devices` (`top`).
2. **Profiles** → `manage_autopilot` with `action: list_profiles`, `get_profile` (`profile_id`) or `list_esp_profiles`.
3. **Deployment results** → `manage_autopilot` with `action: get_deployment_status`. For an exported report, use `manage_intune_reports` with `action: export_report` and `report_name: AutopilotV1DeploymentStatus` or `AutopilotV2DeploymentStatus`.
4. **Enrollment failures** → `manage_intune_reports` with `action: enrollment_failures`.
5. **Enrollment configuration** → `manage_intune_enrollment` with `action: list_restrictions`, `list_dep_tokens`, `list_vpp_tokens`, `get_vpp_token` (`token_id`), `list_dep_profiles` (`token_id`) or `list_android_enterprise`.
6. **Token health**: flag Apple tokens that have expired or expire within 30 days, using the expiry dates returned.

## Output

- **Management**: devices registered, deployments succeeded/failed, top failure reasons, token expiry risks.
- **Engineering**: table with Serial (only if asked), Model, Profile, Deployment state, Failure phase/reason, Date.

## Rules (always apply)

- Read-only. Never import, delete or assign Autopilot devices or profiles, and never sync tokens.
- Use only tool data from this conversation. Never invent devices or dates.
- Empty result: say "No matching records were returned".
- Errors: 403 = missing Graph permission. `status: report_generating` = report still being built. `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)** for Autopilot/enrollment calls. **Intune report snapshot** for exports.
- Minimize sensitive data. Hide serial numbers and hardware hashes unless explicitly asked. State when the data was retrieved.
