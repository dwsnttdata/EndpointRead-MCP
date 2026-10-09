---
name: endpoint-security-posture
description: |
  Reports endpoint security posture using read-only EndpointRead-MCP tools: endpoint security policies
  (antivirus, firewall, EDR, disk encryption), security baselines, malware, Defender health and encryption status.
  Use when the user asks "security posture", "endpoint security policies", "security baseline status",
  "malware detections", "Defender status", "firewall status", "encryption report", or "BitLocker status".
license: MIT
metadata:
  author: Endpoint Engineering
  version: "1.0"
---

# Endpoint security posture

## Workflow

1. **Endpoint security policies** → `manage_endpoint_security` with `action: list_policies`. Then `get_policy` or `get_policy_status` with `policy_id`. Use `list_templates` for available templates.
2. **Security baselines** → `manage_security_baselines` with `action: list_profiles`, `list_templates` or `get_status` (`profile_id`).
3. **Protection overview** → `manage_intune_reports` with `action: device_protection_overview`.
4. **Malware** → `manage_intune_reports` with `action: malware_report`. For one device, use `action: malware_on_device` with `device_id`.
5. **Encryption status** → `manage_intune_reports` with `action: encryption_report`.
6. **Other exports** → `manage_intune_reports` with `action: export_report` and `report_name` such as `FirewallStatus`, `DefenderAgents`, `UnhealthyDefenderAgents` or `TpmAttestationStatus`.

## Output

- **Management**: posture score in words (good / needs attention / at risk), key gaps, devices affected, top 3 actions for the security team.
- **Engineering**: table with Control, Policy/Baseline, Succeeded, Error, Conflict, Not applicable, plus a malware/encryption detail table.

## Rules (always apply)

- Read-only. Never start scans, update signatures, rotate keys or change policies.
- **Never retrieve or display BitLocker or FileVault recovery keys.** That capability is intentionally disabled. If asked, say so and point to the Intune or Entra admin center with proper approval.
- Use only tool data from this conversation. Never invent detections or counts.
- Empty result: say "No matching records were returned".
- Errors: 403 = missing Graph permission. `status: report_generating` = report still being built. `auth_required`/401 = sign-in problem.
- Label the source: **Live (Graph)** for policy calls. **Intune report snapshot** for report exports.
- Minimize sensitive data. Show the top 20 rows plus the total. State when the data was retrieved.
