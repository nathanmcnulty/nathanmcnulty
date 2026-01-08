<#
.SYNOPSIS
    Removes Intune policies containing "- OIB -" in their name.

.DESCRIPTION
    This script finds and deletes Intune policies that were imported from the
    Open Intune Baseline repository. It searches for policies with "- OIB -" or "- Baseline - BYOD -"
    in their display name across:
    - Settings Catalog policies
    - Compliance policies
    - Device Configuration policies
    - Driver Update Profiles
    - Android App Protection policies
    - iOS App Protection policies

.PARAMETER PolicyName
    Filter policies by name. Supports wildcards (e.g., "*BitLocker*").
    Only OIB/BYOD policies matching this filter will be deleted.

.PARAMETER WhatIf
    Shows what would be deleted without actually deleting.

.PARAMETER Force
    Skips confirmation prompt before deletion.

.EXAMPLE
    .\Remove-OIBPolicies.ps1 -WhatIf
    Shows which policies would be deleted without deleting them.

.EXAMPLE
    .\Remove-OIBPolicies.ps1
    Deletes all OIB policies after confirmation.

.EXAMPLE
    .\Remove-OIBPolicies.ps1 -Force
    Deletes all OIB policies without confirmation prompt.

.EXAMPLE
    .\Remove-OIBPolicies.ps1 -PolicyName "*BitLocker*"
    Deletes only OIB policies with BitLocker in the name.

.EXAMPLE
    .\Remove-OIBPolicies.ps1 -PolicyName "*WUfB*" -Force
    Deletes all OIB Windows Update policies without confirmation.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$PolicyName,
    
    [switch]$Force
)

# Import required modules
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Helper Functions

function Write-ColorOutput {
    param(
        [string]$Message,
        [ValidateSet('Success', 'Error', 'Warning', 'Info')]
        [string]$Type = 'Info'
    )
    
    $color = switch ($Type) {
        'Success' { 'Green' }
        'Error' { 'Red' }
        'Warning' { 'Yellow' }
        'Info' { 'Cyan' }
    }
    
    Write-Host $Message -ForegroundColor $color
}

function Get-AllGraphPages {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )
    
    $headers = @{ "OData-Version" = "4.0" }
    $allResults = @()
    $nextLink = $Uri
    
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -Headers $headers
        $allResults += $response.value
        $nextLink = $response.'@odata.nextLink'
    } while ($nextLink)
    
    return $allResults
}

# Main Script

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "OIB Policy Removal Tool" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Verify authentication
try {
    $context = Get-MgContext
    if (-not $context) {
        Write-ColorOutput "Not authenticated. Connecting to Microsoft Graph..." -Type Info
        Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All' -NoWelcome -ErrorAction Stop
        $context = Get-MgContext
    }
    
    Write-ColorOutput "✓ Authenticated as: $($context.Account)" -Type Success
    Write-ColorOutput "✓ Tenant: $($context.TenantId)`n" -Type Success
}
catch {
    Write-ColorOutput "Error connecting to Microsoft Graph: $($_.Exception.Message)" -Type Error
    exit 1
}

# Collect all OIB policies
Write-ColorOutput "Searching for OIB policies..." -Type Info

$allPolicies = @()

# Get Settings Catalog policies
try {
    Write-Host "  Checking Settings Catalog policies..." -ForegroundColor Gray
    $settingsCatalog = Get-AllGraphPages -Uri '/beta/deviceManagement/configurationPolicies?$select=id,name'
    $oibSettingsCatalog = $settingsCatalog | Where-Object { $_.name -like '*- OIB -*' -or $_.name -like '*- Baseline - BYOD -*' }
    foreach ($policy in $oibSettingsCatalog) {
        $allPolicies += [PSCustomObject]@{
            Id = $policy.id
            Name = $policy.name
            Type = 'Settings Catalog'
            Endpoint = "/beta/deviceManagement/configurationPolicies/$($policy.id)"
        }
    }
    Write-Host "    Found $($oibSettingsCatalog.Count) Settings Catalog policies" -ForegroundColor Gray
}
catch {
    Write-ColorOutput "  Warning: Could not retrieve Settings Catalog policies: $($_.Exception.Message)" -Type Warning
}

# Get Compliance policies
try {
    Write-Host "  Checking Compliance policies..." -ForegroundColor Gray
    $compliance = Get-AllGraphPages -Uri '/beta/deviceManagement/deviceCompliancePolicies?$select=id,displayName'
    $oibCompliance = $compliance | Where-Object { $_.displayName -like '*- OIB -*' -or $_.displayName -like '*- Baseline - BYOD -*' }
    foreach ($policy in $oibCompliance) {
        $allPolicies += [PSCustomObject]@{
            Id = $policy.id
            Name = $policy.displayName
            Type = 'Compliance Policy'
            Endpoint = "/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)"
        }
    }
    Write-Host "    Found $($oibCompliance.Count) Compliance policies" -ForegroundColor Gray
}
catch {
    Write-ColorOutput "  Warning: Could not retrieve Compliance policies: $($_.Exception.Message)" -Type Warning
}

# Get Device Configuration policies
try {
    Write-Host "  Checking Device Configuration policies..." -ForegroundColor Gray
    $deviceConfig = Get-AllGraphPages -Uri '/beta/deviceManagement/deviceConfigurations?$select=id,displayName'
    $oibDeviceConfig = $deviceConfig | Where-Object { $_.displayName -like '*- OIB -*' -or $_.displayName -like '*- Baseline - BYOD -*' }
    foreach ($policy in $oibDeviceConfig) {
        $allPolicies += [PSCustomObject]@{
            Id = $policy.id
            Name = $policy.displayName
            Type = 'Device Configuration'
            Endpoint = "/beta/deviceManagement/deviceConfigurations/$($policy.id)"
        }
    }
    Write-Host "    Found $($oibDeviceConfig.Count) Device Configuration policies" -ForegroundColor Gray
}
catch {
    Write-ColorOutput "  Warning: Could not retrieve Device Configuration policies: $($_.Exception.Message)" -Type Warning
}

# Get Driver Update Profiles
try {
    Write-Host "  Checking Driver Update Profiles..." -ForegroundColor Gray
    $driverProfiles = Get-AllGraphPages -Uri '/beta/deviceManagement/windowsDriverUpdateProfiles?$select=id,displayName'
    $oibDriverProfiles = $driverProfiles | Where-Object { $_.displayName -like '*- OIB -*' -or $_.displayName -like '*- Baseline - BYOD -*' }
    foreach ($policy in $oibDriverProfiles) {
        $allPolicies += [PSCustomObject]@{
            Id = $policy.id
            Name = $policy.displayName
            Type = 'Driver Update Profile'
            Endpoint = "/beta/deviceManagement/windowsDriverUpdateProfiles/$($policy.id)"
        }
    }
    Write-Host "    Found $($oibDriverProfiles.Count) Driver Update Profiles" -ForegroundColor Gray
}
catch {
    Write-ColorOutput "  Warning: Could not retrieve Driver Update Profiles: $($_.Exception.Message)" -Type Warning
}

# Get Android App Protection policies
try {
    Write-Host "  Checking Android App Protection policies..." -ForegroundColor Gray
    $androidAppProtection = Get-AllGraphPages -Uri '/beta/deviceAppManagement/androidManagedAppProtections?$select=id,displayName'
    $oibAndroidApp = $androidAppProtection | Where-Object { $_.displayName -like '*- OIB -*' -or $_.displayName -like '*- Baseline - BYOD -*' }
    foreach ($policy in $oibAndroidApp) {
        $allPolicies += [PSCustomObject]@{
            Id = $policy.id
            Name = $policy.displayName
            Type = 'Android App Protection'
            Endpoint = "/beta/deviceAppManagement/androidManagedAppProtections/$($policy.id)"
        }
    }
    Write-Host "    Found $($oibAndroidApp.Count) Android App Protection policies" -ForegroundColor Gray
}
catch {
    Write-ColorOutput "  Warning: Could not retrieve Android App Protection policies: $($_.Exception.Message)" -Type Warning
}

# Get iOS App Protection policies
try {
    Write-Host "  Checking iOS App Protection policies..." -ForegroundColor Gray
    $iosAppProtection = Get-AllGraphPages -Uri '/beta/deviceAppManagement/iosManagedAppProtections?$select=id,displayName'
    $oibIosApp = $iosAppProtection | Where-Object { $_.displayName -like '*- OIB -*' -or $_.displayName -like '*- Baseline - BYOD -*' }
    foreach ($policy in $oibIosApp) {
        $allPolicies += [PSCustomObject]@{
            Id = $policy.id
            Name = $policy.displayName
            Type = 'iOS App Protection'
            Endpoint = "/beta/deviceAppManagement/iosManagedAppProtections/$($policy.id)"
        }
    }
    Write-Host "    Found $($oibIosApp.Count) iOS App Protection policies" -ForegroundColor Gray
}
catch {
    Write-ColorOutput "  Warning: Could not retrieve iOS App Protection policies: $($_.Exception.Message)" -Type Warning
}

Write-Host ""

# Apply PolicyName filter if specified
if ($PolicyName) {
    $beforeFilterCount = $allPolicies.Count
    $allPolicies = $allPolicies | Where-Object { $_.Name -like $PolicyName }
    $filteredCount = $beforeFilterCount - $allPolicies.Count
    if ($filteredCount -gt 0) {
        Write-ColorOutput "Filtered out $filteredCount policies not matching '$PolicyName'`n" -Type Info
    }
}

# Check if any policies found
if ($allPolicies.Count -eq 0) {
    Write-ColorOutput "No OIB policies found in Intune." -Type Info
    exit 0
}

# Display found policies
Write-ColorOutput "Found $($allPolicies.Count) OIB policies:`n" -Type Warning
$allPolicies | Sort-Object Type, Name | Format-Table -Property Name, Type -AutoSize

# Confirm deletion
if (-not $Force -and -not $WhatIfPreference) {
    Write-Host ""
    $confirmation = Read-Host "Are you sure you want to delete these $($allPolicies.Count) policies? (yes/no)"
    if ($confirmation -ne 'yes') {
        Write-ColorOutput "`nOperation cancelled." -Type Warning
        exit 0
    }
}

# Delete policies
Write-Host "`n"
$deleted = 0
$failed = 0
$headers = @{ 'OData-Version' = '4.0' }

foreach ($policy in $allPolicies) {
    if ($PSCmdlet.ShouldProcess($policy.Name, "Delete $($policy.Type)")) {
        try {
            Invoke-MgGraphRequest -Method DELETE -Uri $policy.Endpoint -Headers $headers -ErrorAction Stop
            Write-ColorOutput "✓ Deleted: $($policy.Name)" -Type Success
            $deleted++
        }
        catch {
            Write-ColorOutput "✗ Failed to delete: $($policy.Name) - $($_.Exception.Message)" -Type Error
            $failed++
        }
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Deletion Summary" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-ColorOutput "✓ Deleted: $deleted" -Type Success
if ($failed -gt 0) {
    Write-ColorOutput "✗ Failed: $failed" -Type Error
}
