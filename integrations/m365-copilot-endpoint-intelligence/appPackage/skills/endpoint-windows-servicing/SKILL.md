---
name: endpoint-windows-servicing
description: |
  Reports Windows servicing using read-only EndpointRead-MCP tools: update rings, feature update, quality (expedite)
  and driver update profiles, and update deployment state.
  Use when the user asks "Windows Update status", "update rings", "feature update profile", "which Windows version are devices on",
  "quality update or expedite status", "driver updates", or "patch compliance".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Windows servicing

## Workflow

1. **Update rings** → `manage_windows_update` with `action: list_update_rings`, or `get_update_ring` (`policy_id`).
2. **Feature updates** → `manage_windows_update` with `action: list_feature_updates`, or `get_feature_update` (`policy_id`).
3. **Quality / driver** → `manage_windows_update` with `action: list_quality_updates` or `list_driver_updates`.
4. **Device state** → `manage_intune_reports` with `action: export_report` and `report_name`: `FeatureUpdateDeviceState`, `FeatureUpdatePolicyStatusSummary`, `QualityUpdateDeviceStatusByPolicy` or `QualityUpdatePolicyStatusSummary`. Use `max_rows`.
5. **OS version spread** → `get_intune_overview`. For more detail, use `manage_intune_devices` with `action: list` and an OData `filter_query` on `operatingSystem eq 'Windows'`.

## Output

- **Management**: % devices on the target build, rings and their deferrals, devices behind, upcoming risks.
- **Engineering**: table with Ring/Profile, Target version, Deferral days, Assigned groups, Succeeded, Error, Pending.

## Rules (always apply)

- Read-only. Never create or modify rings or profiles, pause updates or expedite.
- Use only tool data from this conversation. Never invent build numbers or dates.
- Empty result: say "No matching records were returned".
- Errors: 403 = missing Graph permission. `status: report_generating` = report still being built. `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)** for profiles. **Intune report snapshot** for device state exports.
- State when the data was retrieved and any truncation.
