<#
.SYNOPSIS
    Validates and packages the Endpoint Intelligence Copilot Cowork plugin.

.DESCRIPTION
    Fills ${{KEY}} placeholders in appPackage/manifest.json from an env file, checks the
    Cowork packaging rules (manifest fields, skill folders and frontmatter, icons), then writes
    a .zip with all content at the root and forward-slash entry names.
    Works in Windows PowerShell 5.1 and PowerShell 7+.

.EXAMPLE
    .\Build-CoworkPackage.ps1
    .\Build-CoworkPackage.ps1 -EnvFile ..\env\.env.local -OutputPath ..\build\endpoint-intelligence.zip
#>
[CmdletBinding()]
param(
    [string]$EnvFile,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

# $PSScriptRoot isn't available in param defaults on Windows PowerShell 5.1.
if (-not $EnvFile) { $EnvFile = Join-Path $PSScriptRoot '..\env\.env.local' }
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot '..\build\endpoint-intelligence.zip' }

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$appPackage = Join-Path $root 'appPackage'
$errors = New-Object System.Collections.Generic.List[string]

function Add-Error([string]$Message) { $errors.Add($Message) }

# --- Load env values ---------------------------------------------------------
if (-not (Test-Path $EnvFile)) { throw "Env file not found: $EnvFile (copy env/.env.local.sample to env/.env.local)" }
$values = @{}
foreach ($line in Get-Content $EnvFile) {
    if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
    $key, $value = $line -split '=', 2
    $values[$key.Trim()] = $value.Trim()
}

# --- Resolve manifest placeholders --------------------------------------------
$template = Get-Content (Join-Path $appPackage 'manifest.json') -Raw
$resolved = [regex]::Replace($template, '\$\{\{([A-Z0-9_]+)\}\}', {
        param($m)
        $name = $m.Groups[1].Value
        if ($values.ContainsKey($name) -and $values[$name] -and $values[$name] -notmatch '<|>') { return $values[$name] }
        Add-Error "Missing or placeholder value for $name in $EnvFile"
        return $m.Value
    })

try { $manifest = $resolved | ConvertFrom-Json } catch { throw "manifest.json is not valid JSON: $($_.Exception.Message)" }

# --- Manifest checks ----------------------------------------------------------
if ($manifest.manifestVersion -ne '1.29') { Add-Error "manifestVersion must be 1.29" }
if ($manifest.id -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { Add-Error "id must be a GUID" }
if ($manifest.name.short.Length -gt 30) { Add-Error "name.short exceeds 30 characters" }
if ($manifest.description.short.Length -gt 80) { Add-Error "description.short exceeds 80 characters" }
if ($manifest.description.full.Length -gt 4000) { Add-Error "description.full exceeds 4000 characters" }
foreach ($p in 'websiteUrl', 'privacyUrl', 'termsOfUseUrl') {
    if ($manifest.developer.$p -notmatch '^https://') { Add-Error "developer.$p must be an https URL" }
}

$connectorIds = @{}
foreach ($c in @($manifest.agentConnectors)) {
    if (-not $c.id -or -not $c.displayName) { Add-Error "Each connector requires id and displayName" }
    if ($connectorIds.ContainsKey($c.id)) { Add-Error "Duplicate connector id: $($c.id)" } else { $connectorIds[$c.id] = $true }
    $mcp = $c.toolSource.remoteMcpServer
    if ($mcp.mcpServerUrl -notmatch '^https://') { Add-Error "Connector $($c.id): mcpServerUrl must be HTTPS" }
    $auth = $mcp.authorization
    if ($auth.type -ne 'None' -and -not $auth.referenceId) { Add-Error "Connector $($c.id): referenceId required for $($auth.type)" }
    if ($auth.type -eq 'None' -and $auth.referenceId) { Add-Error "Connector $($c.id): referenceId must not be set when type is None" }
    if ($auth.referenceId -and $auth.referenceId.Length -gt 128) { Add-Error "Connector $($c.id): referenceId exceeds 128 characters" }
}

# --- Skill checks (ASKILL rules) ----------------------------------------------
$skills = @($manifest.agentSkills)
if ($skills.Count -gt 20) { Add-Error "ASKILL-M002: more than 20 skills" }
$seen = @{}
foreach ($s in $skills) {
    $folder = $s.folder
    if (-not $folder) { Add-Error "ASKILL-M001: skill entry without folder"; continue }
    if ($folder.Length -gt 256) { Add-Error "ASKILL-M003: folder path too long: $folder" }
    if ($seen.ContainsKey($folder)) { Add-Error "ASKILL-P008: duplicate folder $folder" } else { $seen[$folder] = $true }

    $dir = Join-Path $appPackage ($folder -replace '^\./', '')
    $skillFile = Join-Path $dir 'SKILL.md'
    if (-not (Test-Path $dir)) { Add-Error "ASKILL-P001: folder missing: $folder"; continue }
    if (-not (Test-Path $skillFile)) { Add-Error "ASKILL-P002: SKILL.md missing in $folder"; continue }

    $text = Get-Content $skillFile -Raw
    $fm = [regex]::Match($text, '^---\r?\n(.*?)\r?\n---', 'Singleline')
    if (-not $fm.Success) { Add-Error "ASKILL-P003: invalid frontmatter in $folder"; continue }
    $yaml = $fm.Groups[1].Value
    $nameMatch = [regex]::Match($yaml, '(?m)^name:\s*(\S+)\s*$')
    if (-not $nameMatch.Success) { Add-Error "ASKILL-P004: name missing in $folder"; continue }
    $name = $nameMatch.Groups[1].Value
    $leaf = Split-Path $dir -Leaf
    if ($name -ne $leaf) { Add-Error "ASKILL-P006: name '$name' does not match folder '$leaf'" }
    if ($name -notmatch '^[a-z0-9]+(-[a-z0-9]+)*$' -or $name.Length -gt 64) { Add-Error "ASKILL-P007: name '$name' is not valid kebab-case (1-64)" }

    $descMatch = [regex]::Match($yaml, '(?ms)^description:\s*\|?\s*\r?\n(.*?)(?=^\S|\z)')
    if (-not $descMatch.Success) { $descMatch = [regex]::Match($yaml, '(?m)^description:\s*(.+)$') }
    if (-not $descMatch.Success) { Add-Error "ASKILL-P005: description missing in $folder"; continue }
    $desc = ($descMatch.Groups[1].Value -split '\r?\n' | ForEach-Object { $_.Trim() }) -join ' '
    if ($desc.Trim().Length -lt 1 -or $desc.Length -gt 1024) { Add-Error "Description length must be 1-1024 in $folder (is $($desc.Length))" }

    $companions = Get-ChildItem $dir -Recurse -File | Where-Object Name -ne 'SKILL.md'
    if ($companions.Count -gt 20) { Add-Error "More than 20 companion files in $folder" }
    foreach ($f in $companions) {
        if ($f.Name.StartsWith('.')) { Add-Error "Hidden companion file not allowed: $($f.FullName)" }
        if ($f.Length -gt 5MB) { Add-Error "Companion file over 5 MB: $($f.FullName)" }
    }
}

# --- Icons --------------------------------------------------------------------
function Get-PngSize([string]$Path) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $w = ($bytes[16] -shl 24) -bor ($bytes[17] -shl 16) -bor ($bytes[18] -shl 8) -bor $bytes[19]
    $h = ($bytes[20] -shl 24) -bor ($bytes[21] -shl 16) -bor ($bytes[22] -shl 8) -bor $bytes[23]
    return "$w`x$h"
}
foreach ($icon in @(@{ File = $manifest.icons.color; Size = '192x192' }, @{ File = $manifest.icons.outline; Size = '32x32' })) {
    $path = Join-Path $appPackage $icon.File
    if (-not (Test-Path $path)) { Add-Error "Icon missing: $($icon.File)"; continue }
    $size = Get-PngSize $path
    if ($size -ne $icon.Size) { Add-Error "Icon $($icon.File) is $size, expected $($icon.Size)" }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Host "ERROR  $_" -ForegroundColor Red }
    throw "Validation failed with $($errors.Count) error(s). No package was written."
}

# --- Package (forward-slash entry names, content at zip root) ---------------
$outDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

$zip = [System.IO.Compression.ZipFile]::Open($OutputPath, 'Create')
try {
    $entry = $zip.CreateEntry('manifest.json')
    $writer = New-Object System.IO.StreamWriter($entry.Open(), (New-Object System.Text.UTF8Encoding($false)))
    $writer.Write($resolved); $writer.Dispose()

    $files = @($manifest.icons.color, $manifest.icons.outline | ForEach-Object { Join-Path $appPackage $_ })
    $files += Get-ChildItem (Join-Path $appPackage 'skills') -Recurse -File | ForEach-Object FullName
    foreach ($file in $files) {
        $relative = $file.Substring($appPackage.Length + 1) -replace '\\', '/'
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file, $relative) | Out-Null
    }
}
finally { $zip.Dispose() }

Write-Host "PASS   Manifest v$($manifest.manifestVersion), $($skills.Count) skills, $(@($manifest.agentConnectors).Count) connector(s), icons OK"
Write-Host "Package: $((Resolve-Path $OutputPath).Path)"
