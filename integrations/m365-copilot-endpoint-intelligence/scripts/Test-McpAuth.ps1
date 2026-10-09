<#
.SYNOPSIS
    Verifies that an EndpointRead-MCP endpoint rejects anonymous requests.

.DESCRIPTION
    Sends unauthenticated MCP requests (no data tools are called) and expects HTTP 401.
    Works in Windows PowerShell 5.1 and PowerShell 7+.
    Never pass tokens or secrets to this script.

.EXAMPLE
    .\Test-McpAuth.ps1 -McpUrl "https://<DATAHUB_HOST>/mcp"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$McpUrl
)

$ErrorActionPreference = 'Stop'

# Quotes typed at the interactive parameter prompt become part of the value.
$McpUrl = $McpUrl.Trim().Trim("'", '"')
if ($McpUrl -notmatch '^https://') {
    throw "McpUrl must start with https:// (received: $McpUrl)"
}

# Windows PowerShell 5.1 may not enable TLS 1.2 by default.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Get-AnonymousStatusCode {
    param([string]$Body)
    try {
        $response = Invoke-WebRequest -Uri $McpUrl -Method Post -Body $Body -ContentType 'application/json' `
            -Headers @{ Accept = 'application/json, text/event-stream' } `
            -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 30
        [int]$response.StatusCode
    }
    catch {
        if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { throw }
    }
}

$initialize = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"auth-check","version":"1.0"}}}'
$toolsList  = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

$checks = @(
    @{ Name = 'Anonymous POST initialize'; Body = $initialize }
    @{ Name = 'Anonymous POST tools/list'; Body = $toolsList }
)

$failed = 0
$redirected = 0
foreach ($check in $checks) {
    $status = Get-AnonymousStatusCode -Body $check.Body
    if ($status -eq 302) { $redirected++ }
    $result = if ($status -eq 401) { 'PASS' } else { $failed++; 'FAIL' }
    '{0,-4}  {1,-28} HTTP {2} (expected 401)' -f $result, $check.Name, $status
}

if ($redirected -gt 0) {
    Write-Warning "Easy Auth is on but redirects to sign-in. Set 'Unauthenticated requests' to 'HTTP 401 Unauthorized'."
    exit 1
}

if ($failed -gt 0) {
    Write-Warning "$failed check(s) failed. Easy Auth is not enforcing authentication on this endpoint."
    exit 1
}
'All checks passed: anonymous access is blocked.'
exit 0
