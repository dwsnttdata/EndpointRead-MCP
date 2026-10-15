#!/usr/bin/env python3
"""
EndpointRead-MCP — Read-Only Intune & Entra MCP Server

Architecture: read-only MCP surface for Intune & Entra GET/LIST/SEARCH operations.
Each tool accepts an `action` parameter so the LLM can invoke any operation
without the server needing to expose a separate MCP tool per endpoint.
No external CSV/JSON catalog files are required — everything is self-contained
in this module, which keeps the server portable for Copilot Studio hosting.
"""
from __future__ import annotations

import asyncio
import csv
import io
import os
import sys
import zipfile
from typing import Any

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from intune_mcp_server.config import get_config  # noqa: F401  (ensures .env is loaded)
from intune_mcp_server.graph_client import AuthRequiredError, get_graph_client

def _transport_security() -> TransportSecuritySettings:
    """Allow local dev hosts plus the Azure App Service hostname (Copilot Studio hosting)."""
    allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    allowed_origins = [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]

    azure_hostname = os.getenv("WEBSITE_HOSTNAME")
    if azure_hostname:
        allowed_hosts.append(azure_hostname)
        allowed_origins.extend(
            [
                f"https://{azure_hostname}",
                f"http://{azure_hostname}",
            ]
        )

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )

# Copilot Studio requires JSON responses (not SSE streaming) and a stateless
# HTTP transport since each call may be routed to a different instance.
mcp = FastMCP(
    "endpointread-mcp-server",
    host="0.0.0.0",
    json_response=True,
    stateless_http=True,
    transport_security=_transport_security(),
)

# Optional comma-separated tool allowlist; empty means every tool is exposed.
_ENABLED_TOOLS = {t.strip() for t in os.getenv("MCP_ENABLED_TOOLS", "").split(",") if t.strip()}
# Optional cap (seconds) on report export polling; 0 keeps each call's own timeout.
_EXPORT_TIMEOUT_CAP = int(os.getenv("REPORT_EXPORT_TIMEOUT_SECONDS", "0") or 0)

def _tool():
    """Register a tool as read-only, unless MCP_ENABLED_TOOLS excludes it."""
    def decorator(fn):
        if _ENABLED_TOOLS and fn.__name__ not in _ENABLED_TOOLS:
            return fn
        title = fn.__name__.removeprefix("manage_").replace("_", " ").title() + " (Read-only)"
        annotations = ToolAnnotations(
            title=title,
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
        return mcp.tool(title=title, annotations=annotations)(fn)
    return decorator

def main() -> None:
    """Console entry point for stdio MCP transport."""
    mcp.run(transport="stdio")

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

# Curated subset of the ~178 Intune report names available via the Graph
# `/deviceManagement/reports/exportJobs` endpoint. Any valid Graph reportName
# can be passed to the 'export_report' action even if not listed here.
_COMMON_INTUNE_REPORTS: dict[str, str] = {
    "Devices": "All managed devices",
    "DevicesWithInventory": "Devices with hardware inventory",
    "DeviceCompliance": "Device compliance status",
    "DeviceNonCompliance": "Device non-compliance report",
    "DevicesWithoutCompliancePolicy": "Devices without a compliance policy",
    "NonCompliantDevicesAndSettings": "Non-compliant devices and settings",
    "ActiveMalware": "Active malware detections",
    "Malware": "Detected malware reports",
    "DefenderAgents": "Microsoft Defender agent status",
    "UnhealthyDefenderAgents": "Unhealthy Defender endpoints",
    "FirewallStatus": "MDM firewall status for Windows 10+",
    "AllAppsList": "All apps list",
    "AppInvAggregate": "Discovered apps aggregate",
    "AppInvRawData": "Discovered apps raw data",
    "AppInstallStatusAggregate": "App install status aggregate",
    "DeviceInstallStatusByApp": "Device install status by app",
    "UserInstallStatusAggregateByApp": "User install status by app",
    "MAMAppProtectionStatus": "MAM app protection status (iOS/Android)",
    "MAMAppConfigurationStatus": "MAM app configuration status",
    "AllDeviceCertificates": "All device certificates",
    "TpmAttestationStatus": "TPM attestation status",
    "DeviceEncryption": "Device encryption status",
    "ConfigurationPolicyAggregate": "Configuration policy aggregate",
    "DeviceConfigurationPolicyStatuses": "Device configuration policy status",
    "Policies": "All device policies",
    "PolicyNonComplianceAgg": "Policy non-compliance aggregate",
    "SettingComplianceAggReport": "Setting compliance aggregate report",
    "FeatureUpdateDeviceState": "Feature update device state",
    "FeatureUpdatePolicyStatusSummary": "Feature update policy status summary",
    "QualityUpdateDeviceStatusByPolicy": "Quality update device status by policy",
    "QualityUpdatePolicyStatusSummary": "Quality update policy status summary",
    "WindowsDeviceHealthAttestationReport": "Windows device health attestation report",
    "EnrollmentActivity": "Device enrollment activity",
    "DeviceEnrollmentFailures": "Device enrollment failures",
    "AutopilotV1DeploymentStatus": "Autopilot v1 deployment status",
    "AutopilotV2DeploymentStatus": "Autopilot v2 deployment status",
    "EADeviceScoresV2": "Endpoint Analytics device scores",
    "EAAppPerformance": "Endpoint Analytics app performance",
    "EAStartupPerfDevicePerformanceV2": "Endpoint Analytics startup performance by device",
    "WorkFromAnywhereDeviceList": "Work From Anywhere device list",
    "DeviceRunStatesByScript": "Device run states by script",
    "DeviceRunStatesByProactiveRemediation": "Device run states by proactive remediation",
    "Users": "All users",
    "AllGroupsInMyOrg": "All groups in the organization",
}

async def _run_export_job(
    c,
    report_name: str,
    filter_expr: str = "",
    select: list[str] | None = None,
    max_rows: int = 500,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Create an Intune report export job, poll until it completes, then download and parse the CSV.

    Mirrors the export -> poll -> download pattern used by Microsoft's own
    Intune report export workflow (POST exportJobs, GET exportJobs('id') until
    status == 'completed', then download the pre-authenticated CSV/zip URL).
    """
    body: dict[str, Any] = {
        "reportName": report_name,
        "format": "csv",
        "localizationType": "LocalizedValuesAsAdditionalColumn",
    }
    if filter_expr:
        body["filter"] = filter_expr
    if select:
        body["select"] = select

    if _EXPORT_TIMEOUT_CAP > 0:
        timeout_seconds = min(timeout_seconds, _EXPORT_TIMEOUT_CAP)

    job = await c.create_report_export_job(json=body)
    job_id = job.get("id")
    if not job_id:
        return {"error": f"Export job for '{report_name}' did not return a job id.", "response": job}

    poll_interval = 4
    elapsed = 0
    status_endpoint = f"/deviceManagement/reports/exportJobs('{job_id}')"
    job_status = job
    while elapsed < timeout_seconds:
        await asyncio.sleep(poll_interval)
        elapsed += poll_interval
        job_status = await c.get(status_endpoint, use_beta=True)
        status = str(job_status.get("status", "")).lower()
        if status == "completed":
            break
        if status in {"failed", "cancelled", "error"}:
            return {"error": f"Export job for '{report_name}' {status}.", "details": job_status}
    else:
        return {
            "status": "report_generating",
            "error": f"Export job for '{report_name}' timed out after {timeout_seconds}s.",
            "message": "Intune is still generating this report. No data was returned; try again in a few minutes.",
            "job_id": job_id,
        }

    download_url = job_status.get("url")
    if not download_url:
        return {"error": f"Export job for '{report_name}' completed without a download URL.", "details": job_status}

    client = await c.get_http_client()
    download_response = await client.get(download_url)
    if download_response.status_code != 200:
        return {"error": f"Failed to download report '{report_name}': HTTP {download_response.status_code}"}

    content = download_response.content
    if content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            csv_names = [n for n in zf.namelist() if n.lower().endswith(".csv")]
            if not csv_names:
                return {"error": f"No CSV file found in report archive for '{report_name}'."}
            csv_text = zf.read(csv_names[0]).decode("utf-8-sig")
    else:
        csv_text = content.decode("utf-8-sig")

    reader = csv.DictReader(io.StringIO(csv_text))
    columns = list(reader.fieldnames or [])
    rows = list(reader)
    total_rows = len(rows)
    return {
        "report_name": report_name,
        "job_id": job_id,
        "columns": columns,
        "row_count": total_rows,
        "returned_rows": min(total_rows, max_rows),
        "truncated": total_rows > max_rows,
        "rows": rows[:max_rows],
    }

# ===========================================================================
# TOOL 1 — Connection & Health
# ===========================================================================
@_tool()
async def authenticate_mcp_session() -> dict[str, Any]:
    """Verify the current Copilot user can obtain a delegated Graph token."""
    c = get_graph_client()
    try:
        auth_info = await c.ensure_authenticated()
        return {
            "status": "authenticated",
            "message": "MCP session is authenticated.",
            **auth_info,
        }
    except AuthRequiredError as exc:
        return {
            "status": "auth_required",
            "message": str(exc),
            "details": exc.details,
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc)}

@_tool()
async def test_connection() -> dict[str, Any]:
    """Test the connection to Microsoft Graph API and return tenant information."""
    try:
        c = get_graph_client()
        await c.ensure_authenticated()
        if c.config.auth_mode == "obo":
            user = await c.get("/me")
            return {
                "status": "connected",
                "message": "Microsoft Graph is connected as the signed-in user.",
                "user": {
                    "displayName": user.get("displayName"),
                    "id": user.get("id"),
                    "userPrincipalName": user.get("userPrincipalName"),
                },
            }

        org = await c.get("/organization")
        info = org.get("value", [{}])[0]
        return {
            "status": "connected",
            "message": "Successfully connected to Microsoft Graph API",
            "tenant": {"displayName": info.get("displayName"), "id": info.get("id")},
        }
    except Exception as exc:
        if isinstance(exc, AuthRequiredError):
            return {
                "status": "auth_required",
                "message": str(exc),
                "details": exc.details,
            }
        return {"status": "error", "message": str(exc)}

@_tool()
async def get_auth_status() -> dict[str, Any]:
    """Get current authentication mode and sign-in/cache status."""
    c = get_graph_client()
    status = await c.get_auth_status()
    if status.get("auth_mode") in {"delegated", "hybrid"} and status.get("require_user_login") and not status.get("cached_accounts"):
        try:
            await c.ensure_authenticated()
        except AuthRequiredError:
            pass
    return await c.get_auth_status()

@_tool()
async def start_interactive_sign_in() -> dict[str, Any]:
    """Start user sign-in flow (device code) and return sign-in instructions."""
    c = get_graph_client()
    if c.config.auth_mode == "obo":
        return {
            "status": "not_available",
            "message": "Copilot Studio performs user sign-in for OBO. Authenticate the Copilot connection, then retry.",
        }
    return await c.start_interactive_sign_in()

@_tool()
async def complete_interactive_sign_in() -> dict[str, Any]:
    """Complete user sign-in flow after user enters device code."""
    c = get_graph_client()
    if c.config.auth_mode == "obo":
        return {
            "status": "not_available",
            "message": "Copilot Studio performs user sign-in for OBO. Authenticate the Copilot connection, then retry.",
        }
    return await c.complete_interactive_sign_in()

@_tool()
async def complete_interactive_login() -> dict[str, Any]:
    """Compatibility wrapper that completes the interactive sign-in flow for the MCP session."""
    return await complete_interactive_sign_in()

@_tool()
async def connect_intune_mcp_server() -> dict[str, Any]:
    """One-step connection flow: trigger sign-in if needed, then verify Graph connectivity."""
    c = get_graph_client()

    # First, check whether an interactive sign-in is currently pending.
    status = await c.get_auth_status()
    if status.get("pending_interactive_login"):
        try:
            sign_in = await c.complete_interactive_sign_in()
            return {
                "status": "signed_in",
                "message": "Interactive sign-in completed. Re-run connect_intune_mcp_server to validate full connection.",
                "details": sign_in,
            }
        except Exception as exc:
            return {
                "status": "auth_pending",
                "message": "Complete the browser/device-code sign-in, then run connect_intune_mcp_server again.",
                "error": str(exc),
            }

    # Then attempt Graph connectivity. If user-login gate is enabled, this will
    # automatically trigger the configured sign-in flow from the .env settings.
    try:
        await c.ensure_authenticated()
        if c.config.auth_mode == "obo":
            user = await c.get("/me")
            return {
                "status": "connected",
                "message": "Intune MCP server is connected as the signed-in user.",
                "user": {
                    "displayName": user.get("displayName"),
                    "id": user.get("id"),
                    "userPrincipalName": user.get("userPrincipalName"),
                },
            }

        org = await c.get("/organization")
        info = org.get("value", [{}])[0]
        return {
            "status": "connected",
            "message": "Intune MCP server is connected and authenticated.",
            "tenant": {
                "displayName": info.get("displayName"),
                "id": info.get("id"),
            },
        }
    except Exception as exc:
        if isinstance(exc, AuthRequiredError):
            return {
                "status": "auth_required",
                "message": "User sign-in required. Complete the device-code flow and run connect_intune_mcp_server again.",
                "details": exc.details,
            }
        return {
            "status": "error",
            "message": str(exc),
        }

# ===========================================================================
# TOOL 2 — Intune Overview
# ===========================================================================
@_tool()
async def get_intune_overview() -> dict[str, Any]:
    """Return device counts, compliance distribution and OS breakdown for the tenant."""
    c = get_graph_client()
    try:
        raw = await c.get("/deviceManagement/managedDevices?$select=complianceState,operatingSystem&$top=999")
        devices = raw.get("value", [])
        compliance: dict[str, int] = {}
        os_map: dict[str, int] = {}
        for d in devices:
            compliance[d.get("complianceState", "unknown")] = compliance.get(d.get("complianceState", "unknown"), 0) + 1
            os_map[d.get("operatingSystem", "unknown")] = os_map.get(d.get("operatingSystem", "unknown"), 0) + 1
        return {"total_devices": len(devices), "by_compliance": compliance, "by_os": os_map}
    except Exception as exc:
        return {"error": str(exc)}

# ===========================================================================
# TOOL 3 — Intune Managed Devices
# ===========================================================================
@_tool()
async def manage_intune_devices(
    action: str,
    device_id: str = "",
    filter_query: str = "",
    search_term: str = "",
    search_by: str = "deviceName",
    top: int = 50,
    days_inactive: int = 30,
) -> dict[str, Any]:
    """
    Read-only: view Intune managed devices, inventory and compliance state.

    action values:
      list            — List all managed devices (supports filter_query, top)
      get             — Get full device details (requires device_id)
      search          — Search by deviceName/userPrincipalName/serialNumber (search_term, search_by)
      get_noncompliant— List non-compliant devices
      get_stale       — Devices inactive for N days (days_inactive)
      get_hardware    — Hardware inventory for a device (device_id)
      get_network     — Network info (MAC, subnet) for a device (device_id)
      get_installed_apps — Apps detected on a device (device_id)
      get_compliance_states — Compliance policy states for a device (device_id)
      get_log_requests — Diagnostic log collection requests for a device (device_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get', 'search', 'get_noncompliant', 'get_stale', 'get_hardware', 'get_network', 'get_installed_apps', 'get_compliance_states', 'get_log_requests'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list":
        ep = f"/deviceManagement/managedDevices?$top={min(top, 1000)}"
        if filter_query:
            ep += f"&$filter={filter_query}"
        r = await c.get(ep)
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get":
        dev = await c.get(f"/deviceManagement/managedDevices/{device_id}")
        try:
            cs = await c.get(f"/deviceManagement/managedDevices/{device_id}/deviceCompliancePolicyStates")
            dev["_compliancePolicyStates"] = cs.get("value", [])
        except Exception:
            pass
        return dev

    if a == "search":
        ep = f"/deviceManagement/managedDevices?$filter=contains({search_by},'{search_term}')&$top={top}"
        r = await c.get(ep)
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get_noncompliant":
        r = await c.get(f"/deviceManagement/managedDevices?$filter=complianceState eq 'noncompliant'&$top={top}")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get_stale":
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days_inactive)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r = await c.get(f"/deviceManagement/managedDevices?$filter=lastSyncDateTime le {cutoff}&$top={top}")
        return {"count": len(r.get("value", [])), "days_inactive": days_inactive, "devices": r.get("value", [])}

    if a == "get_hardware":
        return await c.get(f"/deviceManagement/managedDevices/{device_id}?$select=hardwareInformation,serialNumber,model,manufacturer", use_beta=True)

    if a == "get_network":
        return await c.get(f"/deviceManagement/managedDevices/{device_id}?$select=wifiMacAddress,ethernetMacAddress,deviceName")

    if a == "get_installed_apps":
        r = await c.get(f"/deviceManagement/managedDevices/{device_id}/detectedApps", use_beta=True)
        return {"count": len(r.get("value", [])), "apps": r.get("value", [])}

    if a == "get_compliance_states":
        r = await c.get(f"/deviceManagement/managedDevices/{device_id}/deviceCompliancePolicyStates")
        return {"count": len(r.get("value", [])), "states": r.get("value", [])}

    if a == "get_log_requests":
        r = await c.get(f"/deviceManagement/managedDevices/{device_id}/logCollectionRequests", use_beta=True)
        return {"count": len(r.get("value", [])), "requests": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 4 — Device Encryption & BitLocker
# ===========================================================================
@_tool()
async def manage_device_encryption(
    action: str,
    device_id: str = "",
    key_id: str = "",
) -> dict[str, Any]:
    """
    Read-only: view device encryption keys and reports.

    action values:
      list_bitlocker_keys — List all BitLocker recovery keys for the tenant
      get_bitlocker_key   — Get a specific BitLocker recovery key with value (key_id)
      get_filevault_key   — Get macOS FileVault recovery key (device_id)
      get_encryption_report — Export device encryption status report
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_bitlocker_keys', 'get_bitlocker_key', 'get_filevault_key', 'get_encryption_report'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_bitlocker_keys":
        r = await c.get("/informationProtection/bitlocker/recoveryKeys")
        return {"count": len(r.get("value", [])), "keys": r.get("value", [])}

    if a == "get_bitlocker_key":
        return await c.get(f"/informationProtection/bitlocker/recoveryKeys/{key_id}?$select=key")

    if a == "get_filevault_key":
        return await c.get(f"/deviceManagement/managedDevices/{device_id}/getFileVaultKey", use_beta=True)

    if a == "get_encryption_report":
        r = await c.create_report_export_job(
            json={"reportName": "DeviceEncryption", "filter": "", "select": []}
        )
        return r

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 5 — Intune App Management
# ===========================================================================
@_tool()
async def manage_intune_apps(
    action: str,
    app_id: str = "",
    search_term: str = "",
    top: int = 50,
    assignment_id: str = "",
) -> dict[str, Any]:
    """
    Read-only: view Intune mobile apps, assignments and install status.

    action values:
      list            — List all mobile apps (top)
      get             — Get app details + assignments (app_id)
      search          — Search apps by display name (search_term)
      get_install_status — Get app install summary (app_id)
      list_discovered — List all apps discovered across managed devices
      get_mam_registrations — List managed app registrations (MAM enrollment)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get', 'search', 'get_install_status', 'list_discovered', 'get_mam_registrations'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list":
        r = await c.get(f"/deviceAppManagement/mobileApps?$top={top}")
        return {"count": len(r.get("value", [])), "apps": r.get("value", [])}

    if a == "get":
        app = await c.get(f"/deviceAppManagement/mobileApps/{app_id}")
        try:
            asgn = await c.get(f"/deviceAppManagement/mobileApps/{app_id}/assignments")
            app["_assignments"] = asgn.get("value", [])
        except Exception:
            pass
        return app

    if a == "search":
        r = await c.get(
            f"/deviceAppManagement/mobileApps?$filter=contains(displayName,'{search_term}')&$top={top}&$count=true",
            headers={"ConsistencyLevel": "eventual"},
        )
        return {"count": len(r.get("value", [])), "apps": r.get("value", [])}

    if a == "get_install_status":
        return await c.get(f"/deviceAppManagement/mobileApps/{app_id}/installSummary")

    if a == "list_discovered":
        r = await c.get(f"/deviceManagement/detectedApps?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "apps": r.get("value", [])}

    if a == "get_mam_registrations":
        r = await c.get(f"/deviceAppManagement/managedAppRegistrations?$top={top}")
        return {"count": len(r.get("value", [])), "registrations": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 6 — App Config & MAM Policies
# ===========================================================================
@_tool()
async def manage_app_config_mam(
    action: str,
    policy_id: str = "",
    top: int = 50,
    platform: str = "ios",
) -> dict[str, Any]:
    """
    Read-only: view app configuration policies and MAM (app protection) policies.

    action values:
      list_config_policies   — List all managed app config policies (targeted)
      get_config_policy      — Get a specific app config policy (policy_id)
      list_protection_policies — List MAM/app protection policies
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_config_policies', 'get_config_policy', 'list_protection_policies'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }
    plat_ep = "/deviceAppManagement/iosManagedAppProtections" if platform.lower() == "ios" else "/deviceAppManagement/androidManagedAppProtections"

    if a == "list_config_policies":
        r = await c.get(f"/deviceAppManagement/targetedManagedAppConfigurations?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get_config_policy":
        return await c.get(f"/deviceAppManagement/targetedManagedAppConfigurations/{policy_id}")

    if a == "list_protection_policies":
        r = await c.get(f"/deviceAppManagement/managedAppPolicies?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 7 — Compliance Policies
# ===========================================================================
@_tool()
async def manage_compliance_policies(
    action: str,
    policy_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Intune device compliance policies, assignments and status.

    action values:
      list        — List all compliance policies
      get         — Get compliance policy details (policy_id)
      get_status  — Get device deployment status for a policy (policy_id)
      list_assignments — List assignments for a policy (policy_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get', 'get_status', 'list_assignments'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }
    base = "/deviceManagement/deviceCompliancePolicies"

    if a == "list":
        r = await c.get(f"{base}?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{policy_id}")

    if a == "get_status":
        r = await c.get(f"{base}/{policy_id}/deviceStatuses")
        return {"count": len(r.get("value", [])), "statuses": r.get("value", [])}

    if a == "list_assignments":
        r = await c.get(f"{base}/{policy_id}/assignments")
        return {"count": len(r.get("value", [])), "assignments": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 8 — Configuration Profiles
# ===========================================================================
@_tool()
async def manage_configuration_profiles(
    action: str,
    profile_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Intune device configuration profiles, assignments and status.

    action values:
      list        — List all configuration profiles
      get         — Get profile details (profile_id)
      get_status  — Get device deployment status (profile_id)
      list_assignments — List assignments (profile_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get', 'get_status', 'list_assignments'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }
    base = "/deviceManagement/deviceConfigurations"

    if a == "list":
        r = await c.get(f"{base}?$top={top}")
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{profile_id}")

    if a == "get_status":
        r = await c.get(f"{base}/{profile_id}/deviceStatuses")
        return {"count": len(r.get("value", [])), "statuses": r.get("value", [])}

    if a == "list_assignments":
        r = await c.get(f"{base}/{profile_id}/assignments")
        return {"count": len(r.get("value", [])), "assignments": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 9 — Settings Catalog
# ===========================================================================
@_tool()
async def manage_settings_catalog(
    action: str,
    policy_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Intune settings catalog configuration policies.

    action values:
      list    — List all settings catalog policies
      get     — Get policy details (policy_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }
    base = "/deviceManagement/configurationPolicies"

    if a == "list":
        r = await c.get(f"{base}?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{policy_id}", use_beta=True)

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 10 — ADMX / Group Policy Configurations
# ===========================================================================
@_tool()
async def manage_admx_policies(
    action: str,
    config_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Intune ADMX (Administrative Templates / Group Policy) configurations.

    action values:
      list    — List all ADMX configurations
      get     — Get ADMX config details (config_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }
    base = "/deviceManagement/groupPolicyConfigurations"

    if a == "list":
        r = await c.get(f"{base}?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "configurations": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{config_id}", use_beta=True)

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 11 — Endpoint Security
# ===========================================================================
@_tool()
async def manage_endpoint_security(
    action: str,
    policy_id: str = "",
    template_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Intune endpoint security policies (Antivirus, Firewall, EDR, etc.).

    action values:
      list_policies     — List all endpoint security policies
      get_policy        — Get policy details (policy_id)
      get_policy_status — Device state summary for a policy (policy_id)
      list_templates    — List all security templates
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_policies', 'get_policy', 'get_policy_status', 'list_templates'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_policies":
        r = await c.get(f"/deviceManagement/intents?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get_policy":
        return await c.get(f"/deviceManagement/intents/{policy_id}", use_beta=True)

    if a == "get_policy_status":
        return await c.get(f"/deviceManagement/intents/{policy_id}/deviceStateSummary", use_beta=True)

    if a == "list_templates":
        r = await c.get(f"/deviceManagement/templates?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "templates": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 12 — Security Baselines
# ===========================================================================
@_tool()
async def manage_security_baselines(
    action: str,
    profile_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    View Intune security baseline templates and deployed profiles.

    action values:
      list_templates — List all security baseline templates
      list_profiles  — List deployed security baseline profiles
      get_status     — Get device deployment status for a profile (profile_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_templates', 'list_profiles', 'get_status'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_templates":
        r = await c.get(f"/deviceManagement/templates?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "templates": r.get("value", [])}

    if a == "list_profiles":
        r = await c.get(f"/deviceManagement/intents?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "get_status":
        r = await c.get(f"/deviceManagement/intents/{profile_id}/deviceStates", use_beta=True)
        return {"count": len(r.get("value", [])), "states": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 13 — Windows Update Policies
# ===========================================================================
@_tool()
async def manage_windows_update(
    action: str,
    policy_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Windows Update rings and feature/quality/driver update profiles.

    action values:
      list_update_rings       — List all Windows update rings
      get_update_ring         — Get update ring details (policy_id)
      list_feature_updates    — List Windows feature update profiles
      get_feature_update      — Get a feature update profile (policy_id)
      list_quality_updates    — List quality/expedite update policies
      list_driver_updates     — List driver update profiles
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_update_rings', 'get_update_ring', 'list_feature_updates', 'get_feature_update', 'list_quality_updates', 'list_driver_updates'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_update_rings":
        r = await c.get(f"/deviceManagement/deviceConfigurations?$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&$top={top}")
        return {"count": len(r.get("value", [])), "rings": r.get("value", [])}

    if a == "get_update_ring":
        return await c.get(f"/deviceManagement/deviceConfigurations/{policy_id}")

    if a == "list_feature_updates":
        r = await c.get(f"/deviceManagement/windowsFeatureUpdateProfiles?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "get_feature_update":
        return await c.get(f"/deviceManagement/windowsFeatureUpdateProfiles/{policy_id}", use_beta=True)

    if a == "list_quality_updates":
        r = await c.get(f"/deviceManagement/windowsQualityUpdateProfiles?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "list_driver_updates":
        r = await c.get(f"/deviceManagement/windowsDriverUpdateProfiles?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 14 — Intune Scripts & Remediations
# ===========================================================================
@_tool()
async def manage_intune_scripts(
    action: str,
    script_id: str = "",
    top: int = 50,
    script_type: str = "powershell",
) -> dict[str, Any]:
    """
    Read-only: view Intune PowerShell scripts, proactive remediations and macOS shell scripts.

    script_type: powershell | remediation | macos

    action values:
      list     — List scripts (script_type)
      get      — Get script details (script_id, script_type)
      get_status — Device run states for a script (script_id, script_type)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get', 'get_status'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    ep_map = {
        "powershell": "/deviceManagement/deviceManagementScripts",
        "remediation": "/deviceManagement/deviceHealthScripts",
        "macos":       "/deviceManagement/deviceShellScripts",
    }
    base = ep_map.get(script_type.lower(), ep_map["powershell"])

    if a == "list":
        r = await c.get(f"{base}?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "scripts": r.get("value", [])}

    if a == "get":
        return await c.get(f"{base}/{script_id}", use_beta=True)

    if a == "get_status":
        r = await c.get(f"{base}/{script_id}/deviceRunStates", use_beta=True)
        return {"count": len(r.get("value", [])), "states": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 15 — Enrollment
# ===========================================================================
@_tool()
async def manage_intune_enrollment(
    action: str,
    config_id: str = "",
    token_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Intune enrollment restrictions, Apple VPP/DEP tokens, and Android Enterprise.

    action values:
      list_restrictions      — List device enrollment configurations/restrictions
      list_vpp_tokens        — List Apple VPP tokens
      get_vpp_token          — Get a VPP token (token_id)
      list_dep_tokens        — List Apple DEP/ADE onboarding settings
      list_android_enterprise — List Android Enterprise account settings
      get_failures_report    — Export enrollment failures report
      list_dep_profiles      — List enrollment profiles for a DEP token (token_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_restrictions', 'list_vpp_tokens', 'get_vpp_token', 'list_dep_tokens', 'list_android_enterprise', 'get_failures_report', 'list_dep_profiles'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_restrictions":
        r = await c.get(f"/deviceManagement/deviceEnrollmentConfigurations?$top={top}")
        return {"count": len(r.get("value", [])), "configurations": r.get("value", [])}

    if a == "list_vpp_tokens":
        r = await c.get(f"/deviceAppManagement/vppTokens?$top={top}")
        return {"count": len(r.get("value", [])), "tokens": r.get("value", [])}

    if a == "get_vpp_token":
        return await c.get(f"/deviceAppManagement/vppTokens/{token_id}")

    if a == "list_dep_tokens":
        r = await c.get(f"/deviceManagement/depOnboardingSettings?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "tokens": r.get("value", [])}

    if a == "list_android_enterprise":
        r = await c.get("/deviceManagement/androidManagedStoreAccountEnterpriseSettings", use_beta=True)
        return r

    if a == "get_failures_report":
        return await c.create_report_export_job(
            json={"reportName": "DeviceEnrollmentFailures", "filter": "", "select": []}
        )

    if a == "list_dep_profiles":
        r = await c.get(f"/deviceManagement/depOnboardingSettings/{token_id}/enrollmentProfiles", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 16 — Autopilot
# ===========================================================================
@_tool()
async def manage_autopilot(
    action: str,
    device_id: str = "",
    profile_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Windows Autopilot devices, deployment profiles and deployment status.

    action values:
      list_devices         — List all Autopilot device identities
      list_profiles        — List all Autopilot deployment profiles
      get_profile          — Get profile details (profile_id)
      get_deployment_status — Autopilot deployment events
      list_esp_profiles    — List Enrollment Status Page profiles
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_devices', 'list_profiles', 'get_profile', 'get_deployment_status', 'list_esp_profiles'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_devices":
        r = await c.get(f"/deviceManagement/windowsAutopilotDeviceIdentities?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "list_profiles":
        r = await c.get(f"/deviceManagement/windowsAutopilotDeploymentProfiles?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "profiles": r.get("value", [])}

    if a == "get_profile":
        return await c.get(f"/deviceManagement/windowsAutopilotDeploymentProfiles/{profile_id}", use_beta=True)

    if a == "get_deployment_status":
        r = await c.get(f"/deviceManagement/autopilotEvents?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "events": r.get("value", [])}

    if a == "list_esp_profiles":
        r = await c.get(f"/deviceManagement/deviceEnrollmentConfigurations?$top={top}")
        profiles = [
            cfg for cfg in r.get("value", [])
            if cfg.get("@odata.type", "").endswith("windows10EnrollmentCompletionPageConfiguration")
        ]
        return {"count": len(profiles), "profiles": profiles}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 17 — Filters & Scope Tags
# ===========================================================================
@_tool()
async def manage_filters_tags(
    action: str,
    filter_id: str = "",
    tag_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Intune assignment filters and scope tags.

    action values:
      list_filters   — List all assignment filters
      get_filter     — Get filter details (filter_id)
      list_tags      — List all scope tags
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_filters', 'get_filter', 'list_tags'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_filters":
        r = await c.get(f"/deviceManagement/assignmentFilters?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "filters": r.get("value", [])}

    if a == "get_filter":
        return await c.get(f"/deviceManagement/assignmentFilters/{filter_id}", use_beta=True)

    if a == "list_tags":
        r = await c.get(f"/deviceManagement/roleScopeTags?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "tags": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 18 — Intune RBAC
# ===========================================================================
@_tool()
async def manage_intune_rbac(
    action: str,
    role_id: str = "",
    assignment_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Intune RBAC role definitions and role assignments.

    action values:
      list_roles         — List all role definitions (built-in + custom)
      get_role           — Get role definition details (role_id)
      list_assignments   — List all role assignments
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_roles', 'get_role', 'list_assignments'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_resource_operations":
        r = await c.get("/deviceManagement/resourceOperations?$top=999")
        return {"count": len(r.get("value", [])), "operations": r.get("value", [])}

    if a == "list_roles":
        r = await c.get(f"/deviceManagement/roleDefinitions?$top={top}")
        return {"count": len(r.get("value", [])), "roles": r.get("value", [])}

    if a == "get_role":
        return await c.get(f"/deviceManagement/roleDefinitions/{role_id}")

    if a == "list_assignments":
        r = await c.get(f"/deviceManagement/roleAssignments?$top={top}")
        return {"count": len(r.get("value", [])), "assignments": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 19 — Windows 365 Cloud PC
# ===========================================================================
@_tool()
async def manage_cloud_pc(
    action: str,
    cloud_pc_id: str = "",
    policy_id: str = "",
    connection_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Windows 365 Cloud PCs, provisioning policies and network connections.

    action values:
      list            — List all Cloud PCs
      get             — Get Cloud PC details (cloud_pc_id)
      get_overview    — Cloud PC overview/summary
      list_snapshots  — List available snapshots (cloud_pc_id)
      get_audit_events — Audit event logs
      list_provisioning_policies — List provisioning policies
      list_gallery_images   — List gallery images for provisioning
      list_connections      — List Azure network connections
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get', 'get_overview', 'list_snapshots', 'get_audit_events', 'list_provisioning_policies', 'list_gallery_images', 'list_connections'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }
    ve = "/deviceManagement/virtualEndpoint"

    if a == "list":
        r = await c.get(f"{ve}/cloudPCs?$top={top}")
        return {"count": len(r.get("value", [])), "cloudPCs": r.get("value", [])}

    if a == "get":
        return await c.get(f"{ve}/cloudPCs/{cloud_pc_id}")

    if a == "get_overview":
        r = await c.get(f"{ve}/cloudPCs?$top=999")
        items = r.get("value", [])
        status_map: dict[str, int] = {}
        for i in items:
            s = i.get("status", "unknown")
            status_map[s] = status_map.get(s, 0) + 1
        return {"total": len(items), "by_status": status_map}

    if a == "list_snapshots":
        r = await c.get(f"{ve}/cloudPCs/{cloud_pc_id}/snapshots", use_beta=True)
        return {"count": len(r.get("value", [])), "snapshots": r.get("value", [])}

    if a == "get_audit_events":
        r = await c.get(f"{ve}/auditEvents?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "events": r.get("value", [])}

    if a == "list_provisioning_policies":
        r = await c.get(f"{ve}/provisioningPolicies?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "list_gallery_images":
        r = await c.get(f"{ve}/galleryImages?$top={top}")
        return {"count": len(r.get("value", [])), "images": r.get("value", [])}

    if a == "list_connections":
        r = await c.get(f"{ve}/onPremisesConnections?$top={top}")
        return {"count": len(r.get("value", [])), "connections": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 20 — Entra ID Users
# ===========================================================================
@_tool()
async def manage_entra_users(
    action: str,
    user_id: str = "",
    search_term: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Entra ID users, their devices, licenses, reports and group memberships.

    action values:
      list               — List all users (top)
      get                — Get user details (user_id or UPN)
      search             — Search users by displayName (search_term)
      get_devices        — List managed devices for a user (user_id)
      get_licenses       — Get license assignments (user_id)
      list_available_licenses — List available license SKUs in tenant
      get_deleted_users  — List recently deleted users
      get_direct_reports — List user's direct reports (user_id)
      get_member_groups  — List groups the user belongs to (user_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get', 'search', 'get_devices', 'get_licenses', 'list_available_licenses', 'get_deleted_users', 'get_direct_reports', 'get_member_groups'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list":
        r = await c.get(f"/users?$top={top}")
        return {"count": len(r.get("value", [])), "users": r.get("value", [])}

    if a == "get":
        return await c.get(f"/users/{user_id}")

    if a == "search":
        r = await c.get(f"/users?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "users": r.get("value", [])}

    if a == "get_devices":
        r = await c.get(f"/users/{user_id}/managedDevices")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get_licenses":
        r = await c.get(f"/users/{user_id}/licenseDetails")
        return {"count": len(r.get("value", [])), "licenses": r.get("value", [])}

    if a == "list_available_licenses":
        r = await c.get("/subscribedSkus")
        return {"count": len(r.get("value", [])), "skus": r.get("value", [])}

    if a == "get_deleted_users":
        r = await c.get(f"/directory/deletedItems/microsoft.graph.user?$top={top}")
        return {"count": len(r.get("value", [])), "users": r.get("value", [])}

    if a == "get_direct_reports":
        r = await c.get(f"/users/{user_id}/directReports")
        return {"count": len(r.get("value", [])), "reports": r.get("value", [])}

    if a == "get_member_groups":
        r = await c.get(f"/users/{user_id}/memberOf")
        return {"count": len(r.get("value", [])), "groups": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 21 — Entra ID Groups
# ===========================================================================
@_tool()
async def manage_entra_groups(
    action: str,
    group_id: str = "",
    member_id: str = "",
    search_term: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Entra ID groups, members and owners.

    action values:
      list            — List all groups
      get             — Get group details (group_id)
      search          — Search groups by displayName (search_term)
      get_members     — List group members (group_id)
      get_owners      — List group owners (group_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get', 'search', 'get_members', 'get_owners'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list":
        r = await c.get(f"/groups?$top={top}")
        return {"count": len(r.get("value", [])), "groups": r.get("value", [])}

    if a == "get":
        return await c.get(f"/groups/{group_id}")

    if a == "search":
        r = await c.get(f"/groups?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "groups": r.get("value", [])}

    if a == "get_members":
        r = await c.get(f"/groups/{group_id}/members?$top={top}")
        return {"count": len(r.get("value", [])), "members": r.get("value", [])}

    if a == "get_owners":
        r = await c.get(f"/groups/{group_id}/owners?$top={top}")
        return {"count": len(r.get("value", [])), "owners": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 22 — Entra ID Devices
# ===========================================================================
@_tool()
async def manage_entra_devices(
    action: str,
    device_id: str = "",
    intune_device_id: str = "",
    search_term: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Entra ID device objects (separate from Intune managed devices).

    action values:
      list          — List all Entra ID devices
      get           — Get device details (device_id)
      search        — Search by displayName (search_term)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list', 'get', 'search'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list":
        r = await c.get(f"/devices?$top={top}")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    if a == "get":
        return await c.get(f"/devices/{device_id}")

    if a == "search":
        r = await c.get(f"/devices?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 23 — Conditional Access
# ===========================================================================
@_tool()
async def manage_conditional_access(
    action: str,
    policy_id: str = "",
    location_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only: view Entra ID Conditional Access policies and named locations.

    action values:
      list_policies    — List all CA policies
      get_policy       — Get CA policy details (policy_id)
      list_locations   — List named locations
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_policies', 'get_policy', 'list_locations'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }
    ca = "/identity/conditionalAccess/policies"
    nl = "/identity/conditionalAccess/namedLocations"

    if a == "list_policies":
        r = await c.get(f"{ca}?$top={top}")
        return {"count": len(r.get("value", [])), "policies": r.get("value", [])}

    if a == "get_policy":
        return await c.get(f"{ca}/{policy_id}")

    if a == "list_locations":
        r = await c.get(f"{nl}?$top={top}")
        return {"count": len(r.get("value", [])), "locations": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 24 — Identity Protection & Authentication
# ===========================================================================
@_tool()
async def manage_identity_protection(
    action: str,
    user_id: str = "",
    method_id: str = "",
    top: int = 50,
    filter_query: str = "",
) -> dict[str, Any]:
    """
    Read-only: view identity protection, authentication methods, sign-in logs and risky users.

    action values:
      get_auth_methods         — List authentication methods for a user (user_id)
      get_mfa_status           — Check MFA registration status for a user (user_id)
      get_auth_methods_policy  — Get tenant-wide authentication methods policy
      get_sign_in_logs         — Sign-in logs (filter_query for OData filter, top)
      get_directory_audit_logs — Directory audit logs (filter_query, top)
      get_risky_users          — List risky users
      get_risk_detections      — Get risk detection events
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'get_auth_methods', 'get_mfa_status', 'get_auth_methods_policy', 'get_sign_in_logs', 'get_directory_audit_logs', 'get_risky_users', 'get_risk_detections'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "get_auth_methods":
        r = await c.get(f"/users/{user_id}/authentication/methods")
        return {"count": len(r.get("value", [])), "methods": r.get("value", [])}

    if a == "get_mfa_status":
        return await c.get(f"/reports/authenticationMethods/userRegistrationDetails/{user_id}", use_beta=True)

    if a == "get_auth_methods_policy":
        return await c.get("/policies/authenticationMethodsPolicy")

    if a == "get_sign_in_logs":
        ep = f"/auditLogs/signIns?$top={top}"
        if filter_query:
            ep += f"&$filter={filter_query}"
        r = await c.get(ep)
        return {"count": len(r.get("value", [])), "logs": r.get("value", [])}

    if a == "get_directory_audit_logs":
        ep = f"/auditLogs/directoryAudits?$top={top}"
        if filter_query:
            ep += f"&$filter={filter_query}"
        r = await c.get(ep)
        return {"count": len(r.get("value", [])), "logs": r.get("value", [])}

    if a == "get_risky_users":
        r = await c.get(f"/identityProtection/riskyUsers?$top={top}")
        return {"count": len(r.get("value", [])), "users": r.get("value", [])}

    if a == "get_risk_detections":
        r = await c.get(f"/identityProtection/riskDetections?$top={top}")
        return {"count": len(r.get("value", [])), "detections": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 25 — App Registrations & Enterprise Apps
# ===========================================================================
@_tool()
async def manage_app_registrations(
    action: str,
    app_id: str = "",
    sp_id: str = "",
    search_term: str = "",
    top: int = 50,
    days_until_expiry: int = 30,
) -> dict[str, Any]:
    """
    Read-only: view Entra ID app registrations and enterprise apps (service principals).

    action values:
      list_registrations   — List all app registrations
      get_registration     — Get app registration details (app_id)
      search_registrations — Search registrations by name (search_term)
      get_expiring_credentials — App regs with credentials expiring soon (days_until_expiry)
      list_enterprise_apps — List all enterprise apps (service principals)
      get_enterprise_app   — Get enterprise app details (sp_id)
      search_enterprise_apps — Search enterprise apps by name (search_term)
      get_app_permissions  — Permissions granted to an enterprise app (sp_id)
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'list_registrations', 'get_registration', 'search_registrations', 'get_expiring_credentials', 'list_enterprise_apps', 'get_enterprise_app', 'search_enterprise_apps', 'get_app_permissions'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_registrations":
        r = await c.get(f"/applications?$top={top}")
        return {"count": len(r.get("value", [])), "registrations": r.get("value", [])}

    if a == "get_registration":
        return await c.get(f"/applications/{app_id}")

    if a == "search_registrations":
        r = await c.get(f"/applications?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "registrations": r.get("value", [])}

    if a == "get_expiring_credentials":
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) + timedelta(days=days_until_expiry)
        r = await c.get(f"/applications?$select=displayName,passwordCredentials,keyCredentials&$top=999")
        expiring = []
        for app in r.get("value", []):
            for cred in app.get("passwordCredentials", []) + app.get("keyCredentials", []):
                end = cred.get("endDateTime")
                if end and datetime.fromisoformat(end.replace("Z", "+00:00")) <= cutoff:
                    expiring.append({"app": app.get("displayName"), "credentialId": cred.get("keyId"), "expiresAt": end})
        return {"count": len(expiring), "expiring_credentials": expiring}

    if a == "list_enterprise_apps":
        r = await c.get(f"/servicePrincipals?$top={top}")
        return {"count": len(r.get("value", [])), "apps": r.get("value", [])}

    if a == "get_enterprise_app":
        return await c.get(f"/servicePrincipals/{sp_id}")

    if a == "search_enterprise_apps":
        r = await c.get(f"/servicePrincipals?$filter=startswith(displayName,'{search_term}')&$top={top}")
        return {"count": len(r.get("value", [])), "apps": r.get("value", [])}

    if a == "get_app_permissions":
        role_asgn = await c.get(f"/servicePrincipals/{sp_id}/appRoleAssignments")
        oauth2 = await c.get(f"/servicePrincipals/{sp_id}/oauth2PermissionGrants")
        return {"appRoleAssignments": role_asgn.get("value", []), "oauth2PermissionGrants": oauth2.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 26 — Tenant Administration
# ===========================================================================
@_tool()
async def manage_tenant_admin(
    action: str,
    role_id: str = "",
    member_id: str = "",
    agreement_id: str = "",
    top: int = 50,
) -> dict[str, Any]:
    """
    Read-only tenant information — org info, service health, directory roles, subscriptions, terms of use.

    action values:
      get_org_info          — Get organization/tenant information
      get_domains           — List tenant domains
      get_service_health    — M365 service health status overview
      get_service_issues    — Current/recent service issues
      get_message_center    — Message center posts/advisories
      get_planned_maintenance — Planned maintenance events
      list_directory_roles  — List active directory roles
      get_role_members      — List members of a directory role (role_id)
      get_global_admins     — List Global Administrator members
      get_subscriptions     — List subscribed license SKUs
      get_security_defaults — Check security defaults status
      list_terms_of_use     — List Terms of Use agreements
      get_cross_tenant_policy — Get cross-tenant access (B2B) policy
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {'get_org_info', 'get_domains', 'get_service_health', 'get_service_issues', 'get_message_center', 'get_planned_maintenance', 'list_directory_roles', 'get_role_members', 'get_global_admins', 'get_subscriptions', 'get_security_defaults', 'list_terms_of_use', 'get_cross_tenant_policy'}
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "get_org_info":
        r = await c.get("/organization")
        return r.get("value", [{}])[0]

    if a == "get_domains":
        r = await c.get("/domains")
        return {"count": len(r.get("value", [])), "domains": r.get("value", [])}

    if a == "get_service_health":
        r = await c.get("/admin/serviceAnnouncement/healthOverviews")
        return {"count": len(r.get("value", [])), "health": r.get("value", [])}

    if a == "get_service_issues":
        r = await c.get(f"/admin/serviceAnnouncement/issues?$top={top}")
        return {"count": len(r.get("value", [])), "issues": r.get("value", [])}

    if a == "get_message_center":
        r = await c.get(f"/admin/serviceAnnouncement/messages?$top={top}")
        return {"count": len(r.get("value", [])), "messages": r.get("value", [])}

    if a == "get_planned_maintenance":
        r = await c.get(f"/admin/serviceAnnouncement/messages?$filter=tags/any(t:t eq 'Action required')&$top={top}")
        return {"count": len(r.get("value", [])), "messages": r.get("value", [])}

    if a == "list_directory_roles":
        r = await c.get("/directoryRoles")
        return {"count": len(r.get("value", [])), "roles": r.get("value", [])}

    if a == "get_role_members":
        r = await c.get(f"/directoryRoles/{role_id}/members")
        return {"count": len(r.get("value", [])), "members": r.get("value", [])}

    if a == "get_global_admins":
        r = await c.get("/directoryRoles?$filter=roleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'")
        roles = r.get("value", [])
        if not roles:
            return {"members": []}
        members = await c.get(f"/directoryRoles/{roles[0]['id']}/members")
        return {"count": len(members.get("value", [])), "members": members.get("value", [])}

    if a == "get_subscriptions":
        r = await c.get("/subscribedSkus")
        return {"count": len(r.get("value", [])), "skus": r.get("value", [])}

    if a == "get_security_defaults":
        return await c.get("/policies/identitySecurityDefaultsEnforcementPolicy")

    if a == "list_terms_of_use":
        r = await c.get(f"/agreements?$top={top}")
        return {"count": len(r.get("value", [])), "agreements": r.get("value", [])}

    if a == "get_cross_tenant_policy":
        return await c.get("/policies/crossTenantAccessPolicy")

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 27 — Intune Reports & Analytics (read-only)
# ===========================================================================
@_tool()
async def manage_intune_reports(
    action: str,
    report_name: str = "",
    filter_expr: str = "",
    select: list[str] | None = None,
    policy_id: str = "",
    app_id: str = "",
    device_id: str = "",
    top: int = 50,
    max_rows: int = 500,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """
    Read-only Intune reports, endpoint analytics and report export jobs.

    action values:
      list_available_reports    — List common Intune report names usable with 'export_report'
      export_report             — Run any Intune report export job (report_name, filter_expr, select, max_rows)
      compliance_report         — Device compliance summary
      config_profile_status     — Deployment status for a config profile (policy_id)
      compliance_policy_status  — Deployment status for a compliance policy (policy_id)
      app_install_status        — App install summary (app_id)
      license_usage             — License usage summary
      hardware_inventory        — Hardware inventory export (DevicesWithInventory)
      malware_report            — Windows protection / malware state export
      malware_on_device         — Detected malware on a device (device_id)
      device_protection_overview— Device protection status overview
      endpoint_analytics_score  — Endpoint Analytics baseline scores
      startup_performance       — Device startup performance data
      app_reliability           — Application reliability/crash scores
      work_from_anywhere        — Work From Anywhere readiness export
      app_inventory             — App inventory export across all devices
      certificate_report        — Device certificate status export
      co_management_report      — Co-management eligibility/status
      encryption_report         — Device encryption status export
      enrollment_failures       — Enrollment failures export

    Export-job actions (export_report, hardware_inventory, malware_report, work_from_anywhere,
    app_inventory, certificate_report, encryption_report, enrollment_failures) create an async
    Graph export job, poll it until completion, download the resulting CSV/zip and return the
    parsed columns and rows (capped at max_rows).
    """
    c = get_graph_client()
    a = action.lower().strip()

    allowed_actions = {
        "list_available_reports", "export_report", "compliance_report", "config_profile_status",
        "compliance_policy_status", "app_install_status", "license_usage", "hardware_inventory",
        "malware_report", "malware_on_device", "device_protection_overview", "endpoint_analytics_score",
        "startup_performance", "app_reliability", "work_from_anywhere", "app_inventory",
        "certificate_report", "co_management_report", "encryption_report", "enrollment_failures",
    }
    if a not in allowed_actions:
        return {
            "error": f"Action '{action}' is not available in EndpointRead-MCP (read-only).",
            "allowed_actions": sorted(allowed_actions),
        }

    if a == "list_available_reports":
        return {"available_reports": _COMMON_INTUNE_REPORTS}

    export_job_reports = {
        "export_report": report_name,
        "hardware_inventory": "DevicesWithInventory",
        "malware_report": "Malware",
        "work_from_anywhere": "WorkFromAnywhereDeviceList",
        "app_inventory": "AppInvAggregate",
        "certificate_report": "AllDeviceCertificates",
        "encryption_report": "DeviceEncryption",
        "enrollment_failures": "DeviceEnrollmentFailures",
    }
    if a in export_job_reports:
        name = export_job_reports[a]
        if not name:
            return {"error": "report_name is required for action 'export_report'."}
        return await _run_export_job(
            c, name, filter_expr=filter_expr, select=select,
            max_rows=max_rows, timeout_seconds=timeout_seconds,
        )

    if a == "compliance_report":
        return await c.get("/deviceManagement/deviceCompliancePolicyDeviceStateSummary")

    if a == "config_profile_status":
        r = await c.get(f"/deviceManagement/deviceConfigurations/{policy_id}/deviceStatuses?$top={top}")
        return {"count": len(r.get("value", [])), "statuses": r.get("value", [])}

    if a == "compliance_policy_status":
        r = await c.get(f"/deviceManagement/deviceCompliancePolicies/{policy_id}/deviceStatuses?$top={top}")
        return {"count": len(r.get("value", [])), "statuses": r.get("value", [])}

    if a == "app_install_status":
        return await c.get(f"/deviceAppManagement/mobileApps/{app_id}/installSummary")

    if a == "license_usage":
        r = await c.get("/subscribedSkus")
        return {"count": len(r.get("value", [])), "skus": r.get("value", [])}

    if a == "malware_on_device":
        r = await c.get(f"/deviceManagement/managedDevices/{device_id}/windowsProtectionState/detectedMalwareState", use_beta=True)
        return {"count": len(r.get("value", [])), "malware": r.get("value", [])}

    if a == "device_protection_overview":
        return await c.get("/deviceManagement/managedDeviceOverview")

    if a == "endpoint_analytics_score":
        r = await c.get(f"/deviceManagement/userExperienceAnalyticsBaselines?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "baselines": r.get("value", [])}

    if a == "startup_performance":
        r = await c.get(f"/deviceManagement/userExperienceAnalyticsDeviceStartupHistory?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "data": r.get("value", [])}

    if a == "app_reliability":
        r = await c.get(f"/deviceManagement/userExperienceAnalyticsAppHealthApplicationPerformance?$top={top}", use_beta=True)
        return {"count": len(r.get("value", [])), "data": r.get("value", [])}

    if a == "co_management_report":
        r = await c.get(f"/deviceManagement/managedDevices?$select=id,deviceName,managementAgent,deviceEnrollmentType&$top={top}")
        return {"count": len(r.get("value", [])), "devices": r.get("value", [])}

    return {"error": f"Unknown action: {action}"}

# ===========================================================================
# TOOL 28 — Discover Available Operations (Read-Only Catalog)
# ===========================================================================
def _read_only_catalog() -> dict[str, dict[str, Any]]:
    return {
        "manage_admx_policies": {"description": "Read ADMX policy configurations", "actions": ["list", "get"]},
        "manage_app_config_mam": {"description": "Read app config and MAM protection policies", "actions": ["list_config_policies", "get_config_policy", "list_protection_policies"]},
        "manage_app_registrations": {"description": "Read app registrations and enterprise apps", "actions": ["list_registrations", "get_registration", "search_registrations", "get_expiring_credentials", "list_enterprise_apps", "get_enterprise_app", "search_enterprise_apps", "get_app_permissions"]},
        "manage_autopilot": {"description": "Read Autopilot devices and profiles", "actions": ["list_devices", "list_profiles", "get_profile", "get_deployment_status", "list_esp_profiles"]},
        "manage_cloud_pc": {"description": "Read Cloud PC inventory and status", "actions": ["list", "get", "get_overview", "list_snapshots", "get_audit_events", "list_provisioning_policies", "list_gallery_images", "list_connections"]},
        "manage_compliance_policies": {"description": "Read compliance policies and status", "actions": ["list", "get", "get_status", "list_assignments"]},
        "manage_conditional_access": {"description": "Read Conditional Access policies and locations", "actions": ["list_policies", "get_policy", "list_locations"]},
        "manage_configuration_profiles": {"description": "Read configuration profiles and status", "actions": ["list", "get", "get_status", "list_assignments"]},
        "manage_device_encryption": {"description": "Read BitLocker/FileVault and encryption report", "actions": ["list_bitlocker_keys", "get_bitlocker_key", "get_filevault_key", "get_encryption_report"]},
        "manage_endpoint_security": {"description": "Read endpoint security policies", "actions": ["list_policies", "get_policy", "get_policy_status", "list_templates"]},
        "manage_entra_devices": {"description": "Read Entra devices", "actions": ["list", "get", "search"]},
        "manage_entra_groups": {"description": "Read Entra groups, members, and owners", "actions": ["list", "get", "search", "get_members", "get_owners"]},
        "manage_entra_users": {"description": "Read Entra users and related metadata", "actions": ["list", "get", "search", "get_devices", "get_licenses", "list_available_licenses", "get_deleted_users", "get_direct_reports", "get_member_groups"]},
        "manage_filters_tags": {"description": "Read assignment filters and scope tags", "actions": ["list_filters", "get_filter", "list_tags"]},
        "manage_identity_protection": {"description": "Read identity protection posture and logs", "actions": ["get_auth_methods", "get_mfa_status", "get_auth_methods_policy", "get_sign_in_logs", "get_directory_audit_logs", "get_risky_users", "get_risk_detections"]},
        "manage_intune_apps": {"description": "Read Intune apps and install state", "actions": ["list", "get", "search", "get_install_status", "list_discovered", "get_mam_registrations"]},
        "manage_intune_devices": {"description": "Read managed devices and diagnostics metadata", "actions": ["list", "get", "search", "get_noncompliant", "get_stale", "get_hardware", "get_network", "get_installed_apps", "get_compliance_states", "get_log_requests"]},
        "manage_intune_enrollment": {"description": "Read enrollment restrictions and token state", "actions": ["list_restrictions", "list_vpp_tokens", "get_vpp_token", "list_dep_tokens", "list_android_enterprise", "get_failures_report", "list_dep_profiles"]},
        "manage_intune_rbac": {"description": "Read Intune RBAC roles and assignments", "actions": ["list_roles", "get_role", "list_assignments"]},
        "manage_intune_reports": {"description": "Run read-only Intune reports and report export jobs", "actions": ["list_available_reports", "export_report", "compliance_report", "config_profile_status", "compliance_policy_status", "app_install_status", "license_usage", "hardware_inventory", "malware_report", "malware_on_device", "device_protection_overview", "endpoint_analytics_score", "startup_performance", "app_reliability", "work_from_anywhere", "app_inventory", "certificate_report", "co_management_report", "encryption_report", "enrollment_failures"]},
        "manage_intune_scripts": {"description": "Read script inventory and execution status", "actions": ["list", "get", "get_status"]},
        "manage_security_baselines": {"description": "Read security baseline templates and profiles", "actions": ["list_templates", "list_profiles", "get_status"]},
        "manage_settings_catalog": {"description": "Read settings catalog policies", "actions": ["list", "get"]},
        "manage_tenant_admin": {"description": "Read tenant metadata and service health", "actions": ["get_org_info", "get_domains", "get_service_health", "get_service_issues", "get_message_center", "get_planned_maintenance", "list_directory_roles", "get_role_members", "get_global_admins", "get_subscriptions", "get_security_defaults", "list_terms_of_use", "get_cross_tenant_policy"]},
        "manage_windows_update": {"description": "Read Windows Update rings and profiles", "actions": ["list_update_rings", "get_update_ring", "list_feature_updates", "get_feature_update", "list_quality_updates", "list_driver_updates"]},
    }

@_tool()
async def discover_graph_operations(category: str = "") -> dict[str, Any]:
    """List all supported read-only Graph operations grouped by tool/domain."""
    catalog = _read_only_catalog()
    if _ENABLED_TOOLS:
        catalog = {k: v for k, v in catalog.items() if k in _ENABLED_TOOLS}
    if category:
        cat_lower = category.lower()
        catalog = {
            k: v for k, v in catalog.items()
            if cat_lower in k.lower() or cat_lower in v["description"].lower()
        }

    total_actions = sum(len(v["actions"]) for v in catalog.values())
    return {
        "tool_count": len(catalog),
        "matching_tools": len(catalog),
        "total_actions_covered": total_actions,
        "tools": {
            name: {
                "description": info["description"],
                "action_count": len(info["actions"]),
                "actions": info["actions"],
            }
            for name, info in catalog.items()
        },
    }

if __name__ == "__main__":
    mcp.run()
