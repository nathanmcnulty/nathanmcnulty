<#
.SYNOPSIS
    Imports Intune policies from JSON files in the Open Intune Baselines repository.

.DESCRIPTION
    This script imports various Intune policy types from JSON files (scripts not supported at this time):
    - Settings Catalog policies (deviceManagementConfigurationPolicy)
    - Compliance Policies (deviceCompliancePolicy)
    - Device Configuration policies
    - Update Policies
    - macOS configuration policies
    
    The script uses the Microsoft Graph API via Invoke-MgGraphRequest and includes:
    - Automatic retry logic (configurable, once per policy by default)
    - Policy verification after creation
    - Detailed logging of successes and failures
    - Progress tracking

.PARAMETER Path
    The root path containing the OpenIntuneBaseline folder structure.
    Defaults to the script's directory.
    If the OpenIntuneBaseline folder is not found, the script will attempt to download and extract it from GitHub.

.PARAMETER Platform
    Filter by platform: Windows, macOS, Windows365, BYOD, or All
    Default: All

.PARAMETER PolicyType
    Filter by policy type: SettingsCatalog, Compliance, DeviceConfiguration, UpdatePolicies, or All
    Default: All

.PARAMETER FileName
    Import a specific policy file by name. The script will search all subfolders
    for the file, so you don't need to specify the full path.
    Supports wildcards (e.g., "*BitLocker*").

.PARAMETER MaxRetries
    Maximum number of retry attempts per policy if creation fails.
    Default: 1

.PARAMETER WhatIf
    Shows what would be imported without actually importing.

.EXAMPLE
    .\Import-IntuneBaselines.ps1
    Imports all policies from all platforms

.EXAMPLE
    .\Import-IntuneBaselines.ps1 -Platform Windows -PolicyType SettingsCatalog
    Imports only Windows Settings Catalog policies

.EXAMPLE
    .\Import-IntuneBaselines.ps1 -WhatIf
    Shows what would be imported without making changes

.EXAMPLE
    .\Import-IntuneBaselines.ps1 -FileName "*BitLocker*"
    Imports all policies with BitLocker in the filename

.EXAMPLE
    .\Import-IntuneBaselines.ps1 -FileName "Win - OIB - ES - Encryption - D - BitLocker (OS Disk) - v3.7.json"
    Imports a specific policy by exact filename

.NOTES
    Requires:
    - Microsoft.Graph PowerShell SDK
    - Authentication with appropriate permissions (DeviceManagementConfiguration.ReadWrite.All)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$Path = $PSScriptRoot,
    
    [Parameter()]
    [ValidateSet('Windows', 'macOS', 'Windows365', 'BYOD', 'All')]
    [string]$Platform = 'All',
    
    [Parameter()]
    [ValidateSet('SettingsCatalog', 'Compliance', 'DeviceConfiguration', 'UpdatePolicies', 'NativeImport', 'All')]
    [string]$PolicyType = 'All',
    
    [Parameter()]
    [string]$FileName,
    
    [Parameter()]
    [int]$MaxRetries = 1
)

# Import required modules
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Initialize tracking variables
$script:SuccessfulImports = @()
$script:FailedImports = @()
$script:SkippedPolicies = @()
$script:DownloadedBaseline = $false

# Helper Functions

function Get-OpenIntuneBaseline {
    <#
    .SYNOPSIS
        Downloads and extracts the Open Intune Baseline from GitHub if not available locally.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BasePath
    )
    
    $zipUrl = "https://github.com/SkipToTheEndpoint/OpenIntuneBaseline/archive/refs/heads/main.zip"
    $zipPath = Join-Path $BasePath "OpenIntuneBaseline.zip"
    $expectedPath = Join-Path $BasePath "OpenIntuneBaseline"
    
    Write-ColorOutput "OpenIntuneBaseline folder not found locally." -Type Warning
    Write-ColorOutput "Downloading latest version from GitHub..." -Type Info
    
    try {
        # Download the ZIP file
        Write-Host "  Downloading from: $zipUrl" -ForegroundColor Gray
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        
        $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
        Write-ColorOutput "  ✓ Downloaded successfully ($zipSize MB)" -Type Success
        
        # Extract the ZIP
        Write-Host "  Extracting archive..." -ForegroundColor Gray
        Expand-Archive -Path $zipPath -DestinationPath $BasePath -Force
        
        # GitHub extracts to OpenIntuneBaseline-main, rename to OpenIntuneBaseline
        $extractedFolder = Join-Path $BasePath "OpenIntuneBaseline-main"
        if (Test-Path $extractedFolder) {
            # Remove existing OpenIntuneBaseline folder if it exists (shouldn't, but just in case)
            if (Test-Path $expectedPath) {
                Remove-Item $expectedPath -Recurse -Force -WhatIf:$false
            }
            Rename-Item -Path $extractedFolder -NewName "OpenIntuneBaseline" -WhatIf:$false
            Write-ColorOutput "  ✓ Extracted and ready" -Type Success
        }
        
        # Clean up ZIP file
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue -WhatIf:$false
        
        # Verify the folder exists
        if (Test-Path $expectedPath) {
            $jsonCount = (Get-ChildItem -Path $expectedPath -Filter "*.json" -Recurse).Count
            Write-ColorOutput "  ✓ Found $jsonCount policy files`n" -Type Success
            $script:DownloadedBaseline = $true
            return $true
        }
        else {
            Write-ColorOutput "  ✗ Extraction failed - folder not found" -Type Error
            return $false
        }
    }
    catch {
        Write-ColorOutput "  ✗ Download failed: $($_.Exception.Message)" -Type Error
        # Clean up partial download
        if (Test-Path $zipPath) {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue -WhatIf:$false
        }
        return $false
    }
}

function Get-ExistingOIBPolicies {
    <#
    .SYNOPSIS
        Retrieves all existing OIB policies from Intune for comparison.
    #>
    
    Write-ColorOutput "Checking for existing OIB policies in Intune..." -Type Info
    
    $existingPolicies = @{}
    $headers = @{
        'Content-Type' = 'application/json'
        'OData-Version' = '4.0'
    }
    
    function Get-AllGraphPages {
        param(
            [string]$Uri,
            [hashtable]$Headers
        )
        
        $allResults = @()
        $currentUri = $Uri
        
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $currentUri -Headers $Headers
            if ($response.value) {
                $allResults += $response.value
            }
            $currentUri = $response.'@odata.nextLink'
        } while ($currentUri)
        
        return $allResults
    }
    
    try {
        # Get Settings Catalog policies
        Write-Host "  Checking Settings Catalog policies..." -ForegroundColor Gray
        $scPolicies = Get-AllGraphPages -Uri '/beta/deviceManagement/configurationPolicies' -Headers $headers
        $scFiltered = $scPolicies | Where-Object { $_.name -like '*- OIB -*' -or $_.name -like '*- Baseline - BYOD -*' }
        foreach ($policy in $scFiltered) {
            $existingPolicies[$policy.name] = @{
                Id = $policy.id
                Type = 'Settings Catalog'
            }
        }
        Write-Host "    Found $($scFiltered.Count) Settings Catalog policies" -ForegroundColor Gray
        
        # Get Compliance policies
        Write-Host "  Checking Compliance policies..." -ForegroundColor Gray
        $compPolicies = Get-AllGraphPages -Uri '/beta/deviceManagement/deviceCompliancePolicies' -Headers $headers
        $compFiltered = $compPolicies | Where-Object { $_.displayName -like '*- OIB -*' -or $_.displayName -like '*- Baseline - BYOD -*' }
        foreach ($policy in $compFiltered) {
            $existingPolicies[$policy.displayName] = @{
                Id = $policy.id
                Type = 'Compliance'
            }
        }
        Write-Host "    Found $($compFiltered.Count) Compliance policies" -ForegroundColor Gray
        
        # Get Device Configuration policies
        Write-Host "  Checking Device Configuration policies..." -ForegroundColor Gray
        $dcPolicies = Get-AllGraphPages -Uri '/beta/deviceManagement/deviceConfigurations' -Headers $headers
        $dcFiltered = $dcPolicies | Where-Object { $_.displayName -like '*- OIB -*' -or $_.displayName -like '*- Baseline - BYOD -*' }
        foreach ($policy in $dcFiltered) {
            $existingPolicies[$policy.displayName] = @{
                Id = $policy.id
                Type = 'Device Configuration'
            }
        }
        Write-Host "    Found $($dcFiltered.Count) Device Configuration policies" -ForegroundColor Gray
        
        # Get Android App Protection policies
        Write-Host "  Checking Android App Protection policies..." -ForegroundColor Gray
        $androidAppPolicies = Get-AllGraphPages -Uri '/beta/deviceAppManagement/androidManagedAppProtections' -Headers $headers
        $androidFiltered = $androidAppPolicies | Where-Object { $_.displayName -like '*- OIB -*' -or $_.displayName -like '*- Baseline - BYOD -*' }
        foreach ($policy in $androidFiltered) {
            $existingPolicies[$policy.displayName] = @{
                Id = $policy.id
                Type = 'Android App Protection'
            }
        }
        Write-Host "    Found $($androidFiltered.Count) Android App Protection policies" -ForegroundColor Gray
        
        # Get iOS App Protection policies
        Write-Host "  Checking iOS App Protection policies..." -ForegroundColor Gray
        $iosAppPolicies = Get-AllGraphPages -Uri '/beta/deviceAppManagement/iosManagedAppProtections' -Headers $headers
        $iosFiltered = $iosAppPolicies | Where-Object { $_.displayName -like '*- OIB -*' -or $_.displayName -like '*- Baseline - BYOD -*' }
        foreach ($policy in $iosFiltered) {
            $existingPolicies[$policy.displayName] = @{
                Id = $policy.id
                Type = 'iOS App Protection'
            }
        }
        Write-Host "    Found $($iosFiltered.Count) iOS App Protection policies" -ForegroundColor Gray
        
        $totalCount = $existingPolicies.Count
        Write-ColorOutput "  ✓ Found $totalCount existing OIB policies`n" -Type Success
        
        return $existingPolicies
    }
    catch {
        Write-ColorOutput "  ⚠ Warning: Could not retrieve existing policies: $($_.Exception.Message)" -Type Warning
        Write-ColorOutput "  Continuing without duplicate check...`n" -Type Warning
        return @{}
    }
}

function Write-ColorOutput {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
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

function Get-PolicyTypeInfo {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$PolicyJson
    )
    
    # Determine policy type based on JSON structure
    $odataType = $PolicyJson.'@odata.type'
    
    if ($odataType) {
        switch -Wildcard ($odataType) {
            '*windows10CompliancePolicy' {
                return @{
                    Type = 'Windows10Compliance'
                    Endpoint = '/beta/deviceManagement/deviceCompliancePolicies'
                    DisplayName = 'Windows 10+ Compliance Policy'
                }
            }
            '*macOSCompliancePolicy' {
                return @{
                    Type = 'macOSCompliance'
                    Endpoint = '/beta/deviceManagement/deviceCompliancePolicies'
                    DisplayName = 'macOS Compliance Policy'
                }
            }
            '*deviceManagementConfigurationPolicy' {
                return @{
                    Type = 'SettingsCatalog'
                    Endpoint = '/beta/deviceManagement/configurationPolicies'
                    DisplayName = 'Settings Catalog Policy'
                }
            }
            '*windowsUpdateForBusinessConfiguration' {
                return @{
                    Type = 'WindowsUpdate'
                    Endpoint = '/beta/deviceManagement/deviceConfigurations'
                    DisplayName = 'Windows Update Policy'
                }
            }
            '*windowsHealthMonitoringConfiguration' {
                return @{
                    Type = 'HealthMonitoring'
                    Endpoint = '/beta/deviceManagement/deviceConfigurations'
                    DisplayName = 'Health Monitoring Policy'
                }
            }
            '*windowsDriverUpdateProfile' {
                return @{
                    Type = 'DriverUpdate'
                    Endpoint = '/beta/deviceManagement/windowsDriverUpdateProfiles'
                    DisplayName = 'Driver Update Profile'
                }
            }
            '*androidManagedAppProtection' {
                return @{
                    Type = 'AndroidAppProtection'
                    Endpoint = '/beta/deviceAppManagement/androidManagedAppProtections'
                    DisplayName = 'Android App Protection Policy'
                }
            }
            '*iosManagedAppProtection' {
                return @{
                    Type = 'iOSAppProtection'
                    Endpoint = '/beta/deviceAppManagement/iosManagedAppProtections'
                    DisplayName = 'iOS App Protection Policy'
                }
            }
            default {
                return @{
                    Type = 'Unknown'
                    Endpoint = $null
                    DisplayName = "Unknown ($odataType)"
                }
            }
        }
    }
    
    # Fallback: Check for settings array (Settings Catalog / Configuration Policy)
    if ($PolicyJson.settings -or $PolicyJson.PSObject.Properties.Name -contains 'technologies') {
        return @{
            Type = 'SettingsCatalog'
            Endpoint = '/beta/deviceManagement/configurationPolicies'
            DisplayName = 'Settings Catalog Policy'
        }
    }
    
    # If we can't determine, return unknown
    return @{
        Type = 'Unknown'
        Endpoint = $null
        DisplayName = 'Unknown Policy Type'
    }
}

function Remove-ReadOnlyProperties {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$PolicyJson
    )
    
    # For compliance policies, extract scheduledActionsForRule values FIRST (before any processing)
    # This preserves the template's grace period hours and other action settings
    $scheduledActionsData = $null
    if ($PolicyJson.'@odata.type' -like '*CompliancePolicy' -and $PolicyJson.scheduledActionsForRule) {
        $scheduledActionsData = @()
        foreach ($action in $PolicyJson.scheduledActionsForRule) {
            $actionData = @{
                ruleName = if ($action.ruleName) { $action.ruleName } else { 'PasswordRequired' }
                scheduledActionConfigurations = @()
            }
            if ($action.scheduledActionConfigurations) {
                foreach ($config in $action.scheduledActionConfigurations) {
                    $cleanConfig = @{
                        actionType = $config.actionType
                        gracePeriodHours = $config.gracePeriodHours
                        notificationTemplateId = if ($config.notificationTemplateId -and 
                                                     $config.notificationTemplateId -ne '00000000-0000-0000-0000-000000000000') { 
                            $config.notificationTemplateId 
                        } else { 
                            '' 
                        }
                    }
                    # Only add notificationMessageCCList if it exists and has items
                    if ($config.notificationMessageCCList -and $config.notificationMessageCCList.Count -gt 0) {
                        $cleanConfig['notificationMessageCCList'] = @($config.notificationMessageCCList)
                    }
                    $actionData.scheduledActionConfigurations += $cleanConfig
                }
            }
            $scheduledActionsData += $actionData
        }
    }
    
    # Create a copy
    $cleanedPolicy = $PolicyJson | ConvertTo-Json -Depth 50 | ConvertFrom-Json
    
    # Clean object recursively - preserve @odata.type everywhere but remove other @odata annotations
    function Remove-ObjectPropertiesRecursively {
        param($Object)
        
        if ($null -eq $Object) { return $null }
        
        if ($Object -is [System.Management.Automation.PSCustomObject]) {
            # Get all properties that contain @odata in their name (EXCEPT @odata.type) or start with #microsoft.graph
            $propsToRemove = @()
            $Object.PSObject.Properties | Where-Object { 
                ($_.Name -like '*@odata*' -and $_.Name -ne '@odata.type') -or 
                $_.Name -like '#microsoft.graph*' 
            } | ForEach-Object {
                $propsToRemove += $_.Name
            }
            foreach ($prop in $propsToRemove) {
                $Object.PSObject.Properties.Remove($prop)
            }
            
            # Recursively process remaining properties
            foreach ($prop in @($Object.PSObject.Properties)) {
                if ($prop.Name -eq 'children' -and $null -eq $prop.Value) {
                    # If property is named "children" and is null, make it empty array
                    $Object.PSObject.Properties.Remove('children')
                    $Object | Add-Member -NotePropertyName 'children' -NotePropertyValue @() -Force
                } elseif ($prop.Value -is [System.Management.Automation.PSCustomObject]) {
                    $prop.Value = Remove-ObjectPropertiesRecursively -Object $prop.Value
                } elseif ($prop.Value -is [Array]) {
                    $newArray = @()
                    foreach ($item in $prop.Value) {
                        $newArray += Remove-ObjectPropertiesRecursively -Object $item
                    }
                    $prop.Value = $newArray
                }
            }
        }
        elseif ($Object -is [Array]) {
            $newArray = @()
            foreach ($item in $Object) {
                $newArray += Remove-ObjectPropertiesRecursively -Object $item
            }
            return $newArray
        }
        
        return $Object
    }
    
    # Remove read-only and metadata properties at root level
    $propertiesToRemove = @(
        'id',
        'createdDateTime',
        'lastModifiedDateTime',
        'version',
        'isAssigned',
        'settingCount',
        'priorityMetaData',
        'creationSource',
        'assignments',
        'scheduledActionsForRule',
        'deviceSettingStateSummaries',
        'deviceStatuses',
        'deviceStatusOverview',
        'userStatuses',
        'userStatusOverview',
        'groupAssignments',
        'qualityUpdatesPauseStartDate',
        'featureUpdatesPauseStartDate',
        'supportsScopeTags',
        'deviceManagementApplicabilityRuleOsEdition',
        'deviceManagementApplicabilityRuleOsVersion',
        'deviceManagementApplicabilityRuleDeviceMode',
        'deviceReporting',
        'newUpdates',
        'inventorySyncStatus',
        'driverInventories',
        'deployedAppCount',
        'apps'
    )
    
    foreach ($prop in $propertiesToRemove) {
        if ($cleanedPolicy.PSObject.Properties.Name -contains $prop) {
            $cleanedPolicy.PSObject.Properties.Remove($prop)
        }
    }
    
    # Remove id from each setting in the settings array (for Settings Catalog policies)
    if ($cleanedPolicy.settings) {
        foreach ($setting in $cleanedPolicy.settings) {
            if ($setting.PSObject.Properties.Name -contains 'id') {
                $setting.PSObject.Properties.Remove('id')
            }
        }
    }
    
    # Clean all @odata annotations (except @odata.type) and #microsoft.graph actions recursively
    $cleanedPolicy = Remove-ObjectPropertiesRecursively -Object $cleanedPolicy
    
    # Ensure roleScopeTagIds is an array
    if ($cleanedPolicy.PSObject.Properties.Name -contains 'roleScopeTagIds' -and $cleanedPolicy.roleScopeTagIds -isnot [Array]) {
        $cleanedPolicy.roleScopeTagIds = @($cleanedPolicy.roleScopeTagIds)
    }
    
    # Convert null collection properties to empty arrays
    $collectionProps = @('validOperatingSystemBuildRanges')
    foreach ($prop in $collectionProps) {
        if ($cleanedPolicy.PSObject.Properties.Name -contains $prop -and $null -eq $cleanedPolicy.$prop) {
            $cleanedPolicy.$prop = @()
        }
    }
    
    # Re-add scheduledActionsForRule for compliance policies with values extracted from template
    # The template files contain this property, but it includes read-only metadata (@odata.context, @odata.id, etc.)
    # that cannot be used during policy creation. We preserve the template's action settings (including grace periods)
    # while removing the metadata. If extraction failed, fall back to safe defaults.
    if ($cleanedPolicy.'@odata.type' -like '*CompliancePolicy') {
        if ($scheduledActionsData) {
            $cleanedPolicy | Add-Member -NotePropertyName 'scheduledActionsForRule' -NotePropertyValue $scheduledActionsData -Force
        }
        else {
            # Fallback to safe defaults if extraction failed
            $cleanedPolicy | Add-Member -NotePropertyName 'scheduledActionsForRule' -NotePropertyValue @(
                @{
                    ruleName = 'PasswordRequired'
                    scheduledActionConfigurations = @(
                        @{
                            actionType = 'block'
                            gracePeriodHours = 0
                            notificationTemplateId = ''
                        }
                    )
                }
            ) -Force
        }
    }
    
    return $cleanedPolicy
}

function Invoke-PolicyImport {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [Parameter(Mandatory)]
        [int]$MaxRetries
    )
    
    $fileName = Split-Path $FilePath -Leaf
    Write-ColorOutput "Processing: $fileName" -Type Info
    
    try {
        # Read and parse JSON
        $policyJson = Get-Content $FilePath -Raw | ConvertFrom-Json
        
        # Get policy type info
        $policyInfo = Get-PolicyTypeInfo -PolicyJson $policyJson
        
        if ($null -eq $policyInfo.Endpoint) {
            Write-ColorOutput "  ⚠ Skipped: Unsupported policy type - $($policyInfo.DisplayName)" -Type Warning
            $script:SkippedPolicies += [PSCustomObject]@{
                File = $fileName
                Reason = "Unsupported policy type: $($policyInfo.DisplayName)"
            }
            return
        }
        
        # Clean up the policy JSON
        $cleanedPolicy = Remove-ReadOnlyProperties -PolicyJson $policyJson
        
        # Get policy name
        $policyName = if ($cleanedPolicy.displayName) { 
            $cleanedPolicy.displayName 
        } elseif ($cleanedPolicy.name) { 
            $cleanedPolicy.name 
        } else { 
            $fileName 
        }
        
        Write-ColorOutput "  Policy: $policyName" -Type Info
        Write-ColorOutput "  Type: $($policyInfo.DisplayName)" -Type Info
        
        # Attempt import with retries
        $attempt = 0
        $success = $false
        $lastError = $null
        
        while (-not $success -and $attempt -lt $MaxRetries) {
            $attempt++
            
            try {
                if ($attempt -gt 1) {
                    Write-ColorOutput "  Retry attempt $attempt of $MaxRetries..." -Type Warning
                    Start-Sleep -Seconds 2
                }
                
                if ($PSCmdlet.ShouldProcess($policyName, "Import policy")) {
                    # Convert to JSON for API call
                    $body = $cleanedPolicy | ConvertTo-Json -Depth 50
                    
                    # Create the policy
                    $result = Invoke-MgGraphRequest -Method POST -Uri $policyInfo.Endpoint -Body $body -ContentType 'application/json'
                    
                    if ($result.id) {
                        Write-ColorOutput "  ✓ Created successfully (ID: $($result.id))" -Type Success
                        
                        # Verify the policy was created
                        Start-Sleep -Seconds 1
                        $verifyUri = "$($policyInfo.Endpoint)/$($result.id)"
                        $verification = Invoke-MgGraphRequest -Method GET -Uri $verifyUri
                        
                        if ($verification.id -eq $result.id) {
                            Write-ColorOutput "  ✓ Verified policy exists in Intune" -Type Success
                            
                            $script:SuccessfulImports += [PSCustomObject]@{
                                File = $fileName
                                PolicyName = $policyName
                                PolicyId = $result.id
                                PolicyType = $policyInfo.DisplayName
                                Attempts = $attempt
                            }
                            
                            $success = $true
                        } else {
                            throw "Policy verification failed"
                        }
                    }
                }
            }
            catch {
                $lastError = $_
                Write-ColorOutput "  ✗ Attempt $attempt failed: $($_.Exception.Message)" -Type Error
                
                # Check if it's a permanent error
                if ($_.Exception.Message -like '*already exists*' -or 
                    $_.Exception.Message -like '*duplicate*') {
                    Write-ColorOutput "  Policy may already exist - skipping" -Type Warning
                    $script:SkippedPolicies += [PSCustomObject]@{
                        File = $fileName
                        Reason = "Policy already exists"
                    }
                    return
                }
            }
        }
        
        if (-not $success) {
            Write-ColorOutput "  ✗ FAILED after $MaxRetries attempts" -Type Error
            $script:FailedImports += [PSCustomObject]@{
                File = $fileName
                PolicyName = $policyName
                PolicyType = $policyInfo.DisplayName
                LastError = $lastError.Exception.Message
                Attempts = $attempt
            }
        }
    }
    catch {
        Write-ColorOutput "  ✗ Error reading file: $($_.Exception.Message)" -Type Error
        $script:FailedImports += [PSCustomObject]@{
            File = $fileName
            PolicyName = 'Unknown'
            PolicyType = 'Unknown'
            LastError = $_.Exception.Message
            Attempts = 0
        }
    }
    
    Write-Host ""
}

function Get-PolicyFiles {
    param(
        [Parameter(Mandatory)]
        [string]$BasePath,
        
        [Parameter(Mandatory)]
        [string]$Platform,
        
        [Parameter(Mandatory)]
        [string]$PolicyType,
        
        [Parameter()]
        [string]$FileName
    )
    
    $policyFiles = @()
    
    # If FileName is specified, search all subfolders for matching files
    if ($FileName) {
        $baselinePath = Join-Path $BasePath "OpenIntuneBaseline"
        if (-not (Test-Path $baselinePath)) {
            Write-ColorOutput "Error: OpenIntuneBaseline folder not found at: $baselinePath" -Type Error
            return @()
        }
        
        # Search recursively for files matching the pattern
        $matchingFiles = Get-ChildItem -Path $baselinePath -Filter "*.json" -Recurse | 
            Where-Object { $_.Name -like $FileName }
        
        if ($matchingFiles.Count -eq 0) {
            Write-ColorOutput "No files found matching: $FileName" -Type Warning
            return @()
        }
        
        # Deduplicate: prefer NativeImport folder when same filename exists in multiple locations
        $deduplicatedFiles = @()
        $grouped = $matchingFiles | Group-Object Name
        foreach ($group in $grouped) {
            if ($group.Count -eq 1) {
                $deduplicatedFiles += $group.Group[0]
            } else {
                # Prefer NativeImport folder
                $nativeImportFile = $group.Group | Where-Object { $_.FullName -like '*\NativeImport\*' } | Select-Object -First 1
                if ($nativeImportFile) {
                    $deduplicatedFiles += $nativeImportFile
                } else {
                    # No NativeImport version, use first match
                    $deduplicatedFiles += $group.Group[0]
                }
            }
        }
        
        return $deduplicatedFiles
    }
    
    # Build search paths based on filters
    $platforms = if ($Platform -eq 'All') {
        @('WINDOWS', 'MACOS', 'WINDOWS365', 'BYOD')
    } else {
        @($Platform.ToUpper())
    }
    
    foreach ($plat in $platforms) {
        $platformPath = Join-Path $BasePath "OpenIntuneBaseline\$plat"
        
        if (-not (Test-Path $platformPath)) {
            Write-ColorOutput "Warning: Platform path not found: $platformPath" -Type Warning
            continue
        }
        
        # Determine which policy folders to search
        $folders = switch ($PolicyType) {
            'All' { 
                @('SettingsCatalog', 'CompliancePolicies', 'DeviceConfiguration', 
                  'UpdatePolicies', 'DriverUpdateProfiles', 'NativeImport') 
            }
            'SettingsCatalog' { @('SettingsCatalog') }
            'Compliance' { @('CompliancePolicies') }
            'DeviceConfiguration' { @('DeviceConfiguration') }
            'UpdatePolicies' { @('UpdatePolicies', 'DriverUpdateProfiles') }
            'NativeImport' { @('NativeImport') }
        }
        
        foreach ($folder in $folders) {
            # Check in IntuneManagement subfolder first
            $searchPath = Join-Path $platformPath "IntuneManagement\$folder"
            if (Test-Path $searchPath) {
                $files = Get-ChildItem -Path $searchPath -Filter '*.json' -File
                $policyFiles += $files
            }
            
            # Also check direct subfolder (for NativeImport on macOS)
            $searchPath = Join-Path $platformPath $folder
            if (Test-Path $searchPath) {
                $files = Get-ChildItem -Path $searchPath -Filter '*.json' -File
                $policyFiles += $files
            }
        }
    }
    
    return $policyFiles
}

#endregion

#region Main Script

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Open Intune Baseline Policy Importer" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Verify authentication or connect
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
        Write-ColorOutput "Error verifying authentication: $($_.Exception.Message)" -Type Error
        exit 1
    }
    
    # Check if OpenIntuneBaseline folder exists, download if not
    $baselinePath = Join-Path $Path "OpenIntuneBaseline"
    if (-not (Test-Path $baselinePath)) {
        $downloadSuccess = Get-OpenIntuneBaseline -BasePath $Path
        if (-not $downloadSuccess) {
            Write-ColorOutput "Unable to find or download the Open Intune Baseline files." -Type Error
            Write-ColorOutput "Please ensure you have internet connectivity or download manually from:" -Type Info
            Write-ColorOutput "  https://github.com/SkipToTheEndpoint/OpenIntuneBaseline" -Type Info
            exit 1
        }
    }
    
    # Get all policy files
    Write-ColorOutput "Scanning for policy files..." -Type Info
    $policyFiles = Get-PolicyFiles -BasePath $Path -Platform $Platform -PolicyType $PolicyType -FileName $FileName
    
    if ($policyFiles.Count -eq 0) {
        Write-ColorOutput "No policy files found matching the criteria." -Type Warning
        exit 0
    }
    
    Write-ColorOutput "Found $($policyFiles.Count) policy file(s) to import`n" -Type Success
    
    # Get existing OIB policies from Intune to avoid duplicates
    $existingPolicies = Get-ExistingOIBPolicies
    
    # Filter out policies that already exist
    $policiesToImport = @()
    foreach ($file in $policyFiles) {
        try {
            $policyJson = Get-Content $file.FullName -Raw | ConvertFrom-Json
            $policyName = if ($policyJson.displayName) { 
                $policyJson.displayName 
            } elseif ($policyJson.name) { 
                $policyJson.name 
            } else { 
                $null
            }
            
            if ($policyName -and $existingPolicies.ContainsKey($policyName)) {
                $existingInfo = $existingPolicies[$policyName]
                Write-ColorOutput "  ⊗ Skipping existing policy: $policyName ($($existingInfo.Type))" -Type Warning
                $script:SkippedPolicies += [PSCustomObject]@{
                    File = $file.Name
                    Reason = "Policy already exists in Intune (ID: $($existingInfo.Id))"
                }
            } else {
                $policiesToImport += $file
            }
        }
        catch {
            # If we can't parse the file, include it for processing (error will be caught later)
            $policiesToImport += $file
        }
    }
    
    if ($policiesToImport.Count -eq 0) {
        Write-ColorOutput "All policies already exist in Intune. Nothing to import." -Type Warning
        exit 0
    }
    
    $skippedCount = $policyFiles.Count - $policiesToImport.Count
    if ($skippedCount -gt 0) {
        Write-ColorOutput "Skipped $skippedCount existing policies" -Type Warning
    }
    Write-ColorOutput "Importing $($policiesToImport.Count) new policies...`n" -Type Success
    
    # Process each policy
    $currentFile = 0
    foreach ($file in $policiesToImport) {
        $currentFile++
        Write-Host "[$currentFile/$($policiesToImport.Count)] " -NoNewline -ForegroundColor Gray
        Invoke-PolicyImport -FilePath $file.FullName -MaxRetries $MaxRetries
    }
    
    # Summary Report
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Import Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    Write-ColorOutput "✓ Successful: $($script:SuccessfulImports.Count)" -Type Success
    Write-ColorOutput "✗ Failed: $($script:FailedImports.Count)" -Type Error
    Write-ColorOutput "⚠ Skipped: $($script:SkippedPolicies.Count)" -Type Warning
    Write-Host ""
    
    # Detailed success list
    if ($script:SuccessfulImports.Count -gt 0) {
        Write-ColorOutput "Successfully Imported Policies:" -Type Success
        $script:SuccessfulImports | Format-Table -Property PolicyName, PolicyType, PolicyId, Attempts -AutoSize
    }
    
    # Detailed failure list
    if ($script:FailedImports.Count -gt 0) {
        Write-ColorOutput "`nFailed Imports:" -Type Error
        $script:FailedImports | Format-Table -Property PolicyName, PolicyType, LastError -AutoSize
    }
    
    # Detailed skipped list
    if ($script:SkippedPolicies.Count -gt 0) {
        Write-ColorOutput "`nSkipped Policies:" -Type Warning
        $script:SkippedPolicies | Format-Table -Property File, Reason -AutoSize
    }
    
    # Export results to CSV
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $exportPath = Join-Path $Path "ImportResults-$timestamp.csv"
    
    $allResults = @()
    $allResults += $script:SuccessfulImports | Select-Object *, @{N='Status';E={'Success'}}
    $allResults += $script:FailedImports | Select-Object *, @{N='Status';E={'Failed'}}
    $allResults += $script:SkippedPolicies | Select-Object *, @{N='Status';E={'Skipped'}}
    
    if ($allResults.Count -gt 0) {
        $allResults | Export-Csv -Path $exportPath -NoTypeInformation
        Write-ColorOutput "`n✓ Results exported to: $exportPath" -Type Success
    }
}
catch {
    Write-ColorOutput "Fatal error: $($_.Exception.Message)" -Type Error
    Write-ColorOutput $_.ScriptStackTrace -Type Error
    exit 1
}
