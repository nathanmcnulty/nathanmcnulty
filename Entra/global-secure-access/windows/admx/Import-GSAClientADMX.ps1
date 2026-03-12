<#
.SYNOPSIS
    Imports the Global Secure Access Client ADMX template into Microsoft Intune.

.DESCRIPTION
    Uploads GlobalSecureAccessClient.admx and en-US\GlobalSecureAccessClient.adml to
    Intune using the Graph API groupPolicyUploadedDefinitionFiles endpoint. After upload,
    the settings appear in Intune under Devices > Configuration > Administrative Templates
    (or Settings Catalog) under the "Global Secure Access > Client Settings" category.

.PARAMETER AdmxPath
    Path to the GlobalSecureAccessClient.admx file. Defaults to the same directory as
    this script.

.PARAMETER AdmlPath
    Path to the GlobalSecureAccessClient.adml file. Defaults to en-US\ under the same
    directory as this script.

.PARAMETER Force
    If specified, deletes any existing uploaded definition file with the same filename
    before uploading. Without this switch, the script exits if a duplicate is found.

.EXAMPLE
    .\Import-GSAClientADMX.ps1

.EXAMPLE
    .\Import-GSAClientADMX.ps1 -Force

.NOTES
    Required Graph permission: DeviceManagementConfiguration.ReadWrite.All
    Requires: Microsoft.Graph.Authentication module (Connect-MgGraph)
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$AdmxPath = (Join-Path $PSScriptRoot "GlobalSecureAccessClient.admx"),
    [string]$AdmlPath = (Join-Path $PSScriptRoot "en-US\GlobalSecureAccessClient.adml"),
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Verify required files exist
# ---------------------------------------------------------------------------
foreach ($path in @($AdmxPath, $AdmlPath)) {
    if (-not (Test-Path $path)) {
        Write-Error "Required file not found: $path"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Connect to Microsoft Graph if not already connected
# ---------------------------------------------------------------------------
$context = Get-MgContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All" -NoWelcome
    $context = Get-MgContext
}

Write-Host "Connected as: $($context.Account)" -ForegroundColor Cyan
Write-Host "Tenant:       $($context.TenantId)" -ForegroundColor Cyan
Write-Host ""

# Verify the required scope is present
$hasScope = $context.Scopes -contains "DeviceManagementConfiguration.ReadWrite.All"
if (-not $hasScope) {
    Write-Warning "The current session may not have DeviceManagementConfiguration.ReadWrite.All scope."
    Write-Warning "If the upload fails with 403, reconnect with: Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All'"
}

# ---------------------------------------------------------------------------
# Check for existing upload with the same filename
# ---------------------------------------------------------------------------
$admxFileName = [System.IO.Path]::GetFileName($AdmxPath)
Write-Host "Checking for existing '$admxFileName' in Intune..." -ForegroundColor Cyan

$existingFiles = Invoke-MgGraphRequest -Method GET `
    -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles" |
    Select-Object -ExpandProperty value

$existing = $existingFiles | Where-Object { $_.fileName -eq $admxFileName }

if ($existing) {
    if ($Force) {
        Write-Host "Found existing definition file (ID: $($existing.id)). Removing it..." -ForegroundColor Yellow
        Invoke-MgGraphRequest -Method DELETE `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($existing.id)"
        Write-Host "Removed existing definition file." -ForegroundColor Green
        Start-Sleep -Seconds 2
    } else {
        Write-Host ""
        Write-Host "An existing ADMX upload named '$admxFileName' already exists (ID: $($existing.id))." -ForegroundColor Yellow
        Write-Host "Status: $($existing.status)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To replace it, re-run with the -Force switch:" -ForegroundColor Cyan
        Write-Host "  .\Import-GSAClientADMX.ps1 -Force" -ForegroundColor White
        exit 0
    }
}

# ---------------------------------------------------------------------------
# Read and base64-encode the ADMX and ADML files
# ---------------------------------------------------------------------------
Write-Host "Reading and encoding ADMX/ADML files..." -ForegroundColor Cyan

$admxBytes   = [System.IO.File]::ReadAllBytes($AdmxPath)
$admlBytes   = [System.IO.File]::ReadAllBytes($AdmlPath)
$admxContent = [Convert]::ToBase64String($admxBytes)
$admlContent = [Convert]::ToBase64String($admlBytes)

Write-Host "  ADMX: $AdmxPath ($($admxBytes.Length) bytes)" -ForegroundColor Gray
Write-Host "  ADML: $AdmlPath ($($admlBytes.Length) bytes)" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Build the request body
# ---------------------------------------------------------------------------
$body = @{
    "@odata.type" = "#microsoft.graph.groupPolicyUploadedDefinitionFile"
    "fileName"    = $admxFileName
    "content"     = $admxContent
    "languageFiles" = @(
        @{
            "@odata.type"  = "#microsoft.graph.groupPolicyUploadedLanguageFile"
            "fileName"     = [System.IO.Path]::GetFileName($AdmlPath)
            "languageCode" = "en-US"
            "content"      = $admlContent
        }
    )
}

# ---------------------------------------------------------------------------
# Upload to Intune
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Uploading '$admxFileName' to Intune..." -ForegroundColor Cyan

try {
    $result = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles" `
        -Body ($body | ConvertTo-Json -Depth 10) `
        -ContentType "application/json"
} catch {
    Write-Host ""
    Write-Error "Upload failed: $_"
    if ($_.ErrorDetails.Message) {
        $errDetail = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($errDetail) {
            Write-Host "Graph error code:    $($errDetail.error.code)" -ForegroundColor Red
            Write-Host "Graph error message: $($errDetail.error.message)" -ForegroundColor Red
        }
    }
    exit 1
}

$definitionFileId = $result.id
Write-Host "Upload submitted. Definition File ID: $definitionFileId" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Poll for final status (upload is processed asynchronously)
# ---------------------------------------------------------------------------
Write-Host "Waiting for Intune to process the ADMX..." -ForegroundColor Cyan

$maxAttempts  = 20
$pollInterval = 5
$attempt      = 0
$finalStatus  = $null

do {
    Start-Sleep -Seconds $pollInterval
    $attempt++

    try {
        $statusResult = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$definitionFileId"
        $finalStatus = $statusResult.status
    } catch {
        Write-Warning "Failed to retrieve status on attempt $attempt : $_"
        continue
    }

    Write-Host "  Attempt $attempt / $maxAttempts : status = $finalStatus" -ForegroundColor Gray

} while ($finalStatus -notin @('available', 'uploadFailed') -and $attempt -lt $maxAttempts)

# ---------------------------------------------------------------------------
# Report result
# ---------------------------------------------------------------------------
Write-Host ""
if ($finalStatus -eq 'available') {
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  ADMX template imported successfully!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Definition File ID : $definitionFileId" -ForegroundColor Cyan
    Write-Host "Status             : $finalStatus" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Settings included in this template:" -ForegroundColor White
    Write-Host "  Computer Configuration > Global Secure Access > Client Settings > Access Controls" -ForegroundColor Gray
    Write-Host "    - Restrict Non-Privileged Users from Disabling or Enabling the Client" -ForegroundColor Gray
    Write-Host "    - Enable External User (B2B Guest) Access (Preview)" -ForegroundColor Gray
    Write-Host "  User Configuration > Global Secure Access > Client Settings > Access Controls" -ForegroundColor Gray
    Write-Host "    - Disable Private Access" -ForegroundColor Gray
    Write-Host "  Computer Configuration > Global Secure Access > Client Settings > System Tray UI Controls" -ForegroundColor Gray
    Write-Host "    - Hide Sign Out Button" -ForegroundColor Gray
    Write-Host "    - Hide Disable Private Access Button" -ForegroundColor Gray
    Write-Host "    - Hide Disable Button" -ForegroundColor Gray
    Write-Host "  Computer Configuration > Global Secure Access > Client Settings > Network Settings" -ForegroundColor Gray
    Write-Host "    - Prefer IPv4 over IPv6 (Recommended for Global Secure Access)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. In Intune, go to Devices > Manage devices > Configuration" -ForegroundColor White
    Write-Host "  2. Select + Create > + New Policy" -ForegroundColor White
    Write-Host "  3. Platform: Windows 10 and later, Profile type: Administrative Templates" -ForegroundColor White
    Write-Host "  4. Search for 'Global Secure Access' to find the imported settings" -ForegroundColor White
    Write-Host "  5. Configure each setting and assign the profile to device/user groups" -ForegroundColor White
} elseif ($finalStatus -eq 'uploadFailed') {
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host "  Upload failed! Intune rejected the ADMX template." -ForegroundColor Red
    Write-Host "================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Definition File ID : $definitionFileId" -ForegroundColor Yellow
    Write-Host "Status             : $finalStatus" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  - Verify the ADMX XML is valid (no syntax errors)" -ForegroundColor White
    Write-Host "  - Ensure all string IDs referenced in the ADMX are defined in the ADML" -ForegroundColor White
    Write-Host "  - Check that the policy namespace is unique (not already used by another ADMX)" -ForegroundColor White
    Write-Host "  - Review the definition file in Graph Explorer for additional error details:" -ForegroundColor White
    Write-Host "    GET https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$definitionFileId" -ForegroundColor Gray
    exit 1
} else {
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "  Upload timed out waiting for 'available' status." -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Last known status  : $finalStatus" -ForegroundColor Yellow
    Write-Host "Definition File ID : $definitionFileId" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "The upload may still be processing. Check status with:" -ForegroundColor Cyan
    Write-Host "  Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$definitionFileId'" -ForegroundColor Gray
}
