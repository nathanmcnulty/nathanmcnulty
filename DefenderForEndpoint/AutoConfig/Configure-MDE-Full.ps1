function Get-DefenderAuth {  
  # Copy sccauth from the browser
  $sccauth = Read-Host -Prompt "Enter sccauth cookie value" -AsSecureString
  #if ($sccauth.Length -ne 2368) { Write-Output "sccauth was $($sccauth.Length) characters and may be incorrect" }

  # Copy xsrf token from the browser
  $xsrf = Read-Host -Prompt "Enter xsrf cookie value" -AsSecureString
  if ($xsrf.Length -ne 347) { Write-Output "xsrf was $($xsrf.Length) characters and may be incorrect" }

  # Create session and cookies
  $global:session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  $global:session.Cookies.Add((New-Object System.Net.Cookie("sccauth", "$($sccauth | ConvertFrom-SecureString -AsPlainText)", "/", "security.microsoft.com")))
  $global:session.Cookies.Add((New-Object System.Net.Cookie("XSRF-TOKEN", "$($xsrf | ConvertFrom-SecureString -AsPlainText)", "/", "security.microsoft.com")))

  # Set the headers to include the xsrf token
  [Hashtable]$global:headers=@{}
  $global:headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($global:session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value)
}

function Invoke-DefenderApi {
  [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Method = "GET",
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        [Parameter(Mandatory=$false)]
        [string]$AdditionalHeaders,
        [Parameter(Mandatory=$false)]
        [string]$Body = ""
    )
    # Add additional headers such as api-version where needed
    if ($additionalHeaders) { $global:headers.Add($additionalHeaders) }

    # Invoke the request
    try {
      Invoke-RestMethod -Method $method -Uri "https://security.microsoft.com/apiproxy/$uri" -Headers $global:headers -Body $Body  -ContentType "application/json" -WebSession $global:session -UseBasicParsing
      if ($Method -in "PATCH","POST","PUT") { Start-Sleep -Seconds 15 }
    }
    catch {
      Write-Error $_.Exception.Message -ErrorAction Continue
      Get-DefenderAuth
      Invoke-RestMethod -Method $method -Uri "https://security.microsoft.com/apiproxy/$uri" -Headers $global:headers -Body $Body  -ContentType "application/json" -WebSession $global:session -UseBasicParsing
    }   
  
    # Remove additional header that was added to ensure no conflicts
    if ($additionalHeaders) { $global:headers.Remove($additionalHeaders) }
}

function Write-Log {
  [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [array]$Settings,
        [Parameter(Mandatory=$false)]
        [string]$Uri,
        [Parameter(Mandatory=$true)]
        [string]$Subject,
        [Parameter(Mandatory=$true)]
        [string]$Type
    )
if ($Type -eq "Existing") {
$content = @"
$Subject - $Type values:

$(($Settings).Trim('{}').Split(',').Trim('') | ForEach-Object { Write-Output "$_`n" })

To revert settings, run:

`$body = '$Settings'
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy$Uri" -Body `$body -ContentType "application/json" -WebSession `$session -Headers `$headers

"@
} elseif ($Type -eq "New") {
$content = @"
$Subject - $Type values:

$(($Settings).Trim('{}').Split(',').Trim('') | ForEach-Object { Write-Output "$_`n" })
"@
} else {
  $content = @"
$Subject - $Type values:

$($Settings | ForEach-Object { Write-Output "$_`n" })
"@
}
  Add-Content -Path $path -Value "$(Get-Date -UFormat %r)`t$Content"
}

# Create log if it doesn't exist
$path = "$($PWD.path)\$(Get-Date -UFormat %F)-Defender.log"
if (!(Test-Path -Path $path)) {
  New-Item -Path $path
}

# Get authentication details
Get-DefenderAuth

##################################################

### Advanced Settings ###

# Enable Advanced Features
$subject = "Advanced Features"
# Get existing settings
$settings = Invoke-DefenderApi -Uri "/mtp/settings/GetAdvancedFeaturesSetting"
Write-Log -Settings ($settings | ConvertTo-Json) -Uri "/mtp/settings/SaveAdvancedFeaturesSetting" -Subject $subject -Type "Existing"

# Check settings that should be true
$changes = New-Object System.Collections.ArrayList
"EnableWdavPassiveModeRemediation","HidePotentialDuplications","BlockListEnabled","SkypeIntegrationEnabled","ShowUserAadProfile","AutoResolveInvestigatedAlerts","EnableMcasIntegration","EnableWdavAntiTampering","AllowWdavNetworkBlock","M365SecureScoreIntegrationEnabled","WebCategoriesEnabled","EnableAuditTrail","EnableQuarantinedFileDownload","UseSimplifiedConnectivity","UseSimplifiedConnectivityViaApi" | ForEach-Object { 
  if ($settings.$_ -ne $true) {
    $settings.$_ = $true
    $changes.Add("$_,`$true")
  }
}
# Check settings that should be false
"MagellanOptOut","IsolateIncidentsWithDifferentDeviceGroups" | ForEach-Object { 
  if ($settings.$_ -ne $false) {
    $settings.$_ = $false
    $changes.Add("$_,`$false")
  }
}

# If changes are required, log changes, attempt to make them, and verify they were set
if ($changes) {
  # Write changes to log
  Write-Log -Settings $changes -Subject $subject -Type "Change"
  Write-Output "Changing values:`n`n$($changes | ForEach-Object { Write-Output "$_" })"

  # Set desired settings with one retry
  Invoke-DefenderApi -Method "POST" -Uri "/mtp/settings/SaveAdvancedFeaturesSetting" -Body ($settings | ConvertTo-Json)
  $new = Invoke-DefenderApi -Uri "/mtp/settings/GetAdvancedFeaturesSetting"
  $compare = Compare-Object -ReferenceObject ($settings | ConvertTo-Json -Compress) -DifferenceObject ($new | ConvertTo-Json -Compress)
  if ($compare) { 
    Write-Output "Retrying..."
    Invoke-DefenderApi -Method "POST" -Uri "/mtp/settings/SaveAdvancedFeaturesSetting" -Body ($settings | ConvertTo-Json)
    $new = Invoke-DefenderApi -Uri "/mtp/settings/GetAdvancedFeaturesSetting"
  }
  Write-Log -Settings ($new | ConvertTo-Json) -Subject $subject -Type "New"

  # Look for settings that did not change  
  $failed = New-Object System.Collections.ArrayList
  $changes | ForEach-Object {
    $setting = $_.Split(",")[0]
    $value = $_.Split(",")[1]
    if ($new.$setting -ne $value) { $failed.Add($_) }
  }
  if ($failed) { Write-Log -Settings $failed -Subject $subject -Type "Failed to update" }
}

# Enable Live Response
$subject = "Advanced Features - Enable Live Response"
# Get existing settings
$settings = Invoke-DefenderApi -Uri "/mtp/liveResponseApi/get_properties?useV2Api=true&useV3Api=true"
Write-Log -Settings ($settings | ConvertTo-Json) -Uri "/mtp/liveResponseApi/update_properties?useV2Api=true&useV3Api=true" -Subject $subject -Type "Existing"

# Check settings that should be true
$changes = New-Object System.Collections.ArrayList
"AutomatedIrLiveResponse","LiveResponseForServers" | ForEach-Object { 
  if ($settings.$_ -ne $true) {
    $settings.$_ = $true
    $changes.Add("$_,`$true")
  }
}
# Check settings that should be false
"AutomatedIrUnsignedScripts" | ForEach-Object { 
  if ($settings.$_ -ne $false) {
    $settings.$_ = $false
    $changes.Add("$_,`$false")
  }
}

# If changes are required, log changes, attempt to make them, and verify they were set
if ($changes) {
  # Write changes to log
  Write-Log -Settings $changes -Subject $subject -Type "Change"
  Write-Output "Changing values:`n`n$($changes | ForEach-Object { Write-Output "$_" })"

  # Set desired settings with one retry
  Invoke-DefenderApi -Method "POST" -Uri "/mtp/liveResponseApi/update_properties?useV2Api=true&useV3Api=true" -Body ($settings | ConvertTo-Json)
  $new = Invoke-DefenderApi -Uri "/mtp/liveResponseApi/get_properties?useV2Api=true&useV3Api=true"
  $compare = Compare-Object -ReferenceObject ($settings | ConvertTo-Json -Compress) -DifferenceObject ($new | ConvertTo-Json -Compress)
  if ($compare) { 
    Write-Output "Retrying..."
    Invoke-DefenderApi -Method "POST" -Uri "/mtp/liveResponseApi/update_properties?useV2Api=true&useV3Api=true" -Body ($settings | ConvertTo-Json)
    $new = Invoke-DefenderApi -Uri "/mtp/liveResponseApi/get_properties?useV2Api=true&useV3Api=true"
  }
  Write-Log -Settings ($new | ConvertTo-Json) -Subject $subject -Type "New"

  # Look for settings that did not change
  $failed = New-Object System.Collections.ArrayList
  $changes | ForEach-Object {
    $setting = $_.Split(",")[0]
    $value = $_.Split(",")[1]
    if ($new.$setting -ne $value) { $failed.Add($_) }
  }
  if ($failed) { Write-Log -Settings $failed -Subject $subject -Type "Failed to update" }
}

# Enable Deception
$subject = "Advanced Features - Enable Deception"
# Get existing settings
$settings = Invoke-DefenderApi -Uri "/mtp/k8s/deception/portal/deceptionsettings"
if ($settings.areDeceptionRulesMisconfigured -ne $false) { Write-Warning "Deception rules are misconfigured" }
Write-Log -Settings ($settings | ConvertTo-Json) -Uri "/mtp/k8s/deception/portal/deceptionsettings/update" -Subject $subject -Type "Existing"

# Check settings that should be true
$changes = New-Object System.Collections.ArrayList
"isDeceptionEnabled" | ForEach-Object { 
  if ($settings.$_ -ne $true) {
    $settings.$_ = $true
    $changes.Add("$_,`$true")
  }
}

# If changes are required, log changes, attempt to make them, and verify they were set
if ($changes) {
  # Write changes to log
  Write-Log -Settings $changes -Subject $subject -Type "Change"
  Write-Output "Changing values:`n`n$($changes | ForEach-Object { Write-Output "$_" })"

  # Set desired settings with one retry
  Invoke-DefenderApi -Method "POST" -Uri "/mtp/k8s/deception/portal/deceptionsettings/update" -Body ($settings | ConvertTo-Json)
  $new = Invoke-DefenderApi -Uri "/mtp/k8s/deception/portal/deceptionsettings"
  $compare = Compare-Object -ReferenceObject ($settings | ConvertTo-Json -Compress) -DifferenceObject ($new | ConvertTo-Json -Compress)
  if ($compare) { 
    Write-Output "Retrying..."
    Invoke-DefenderApi -Method "POST" -Uri "/mtp/k8s/deception/portal/deceptionsettings/update" -Body ($settings | ConvertTo-Json)
    $new = Invoke-DefenderApi -Uri "/mtp/k8s/deception/portal/deceptionsettings"
  }
  Write-Log -Settings ($new | ConvertTo-Json) -Subject $subject -Type "New"

  # Look for settings that did not change
  $failed = New-Object System.Collections.ArrayList
  $changes | ForEach-Object {
    $setting = $_.Split(",")[0]
    $value = $_.Split(",")[1]
    if ($new.$setting -ne $value) { $failed.Add($_) }
  }
  if ($failed) { Write-Log -Settings $failed -Subject $subject -Type "Failed to update" }
}

# Enable Share endpoint alerts with Microsoft Compliance Center
$subject = "Advanced Features - Share endpoint alerts with Microsoft Compliance Center"
# Get existing settings
$settings = Invoke-DefenderApi -Uri "/mtp/wdatpInternalApi/compliance/alertSharing/status/"
Write-Log -Settings ($settings | ConvertTo-Json) -Uri "/mtp/wdatpInternalApi/compliance/alertSharing/status/" -Subject $subject -Type "Existing"

# Check settings that should be true
$changes = New-Object System.Collections.ArrayList
if ($settings -ne $true) {
  $settings = "true"
  $changes.Add("true")
}

# If changes are required, log changes, attempt to make them, and verify they were set
if ($changes) {
  # Write changes to log
  Write-Log -Settings $changes -Subject $subject -Type "Change"
  Write-Output "Changing values:`n`n$($changes | ForEach-Object { Write-Output "$_" })"

  # Set desired settings with one retry
  Invoke-DefenderApi -Method "POST" -Uri "/mtp/wdatpInternalApi/compliance/alertSharing/status/" -Body $settings
  $new = Invoke-DefenderApi -Uri "/mtp/wdatpInternalApi/compliance/alertSharing/status/"
  $compare = Compare-Object -ReferenceObject ($settings | ConvertTo-Json -Compress) -DifferenceObject ($new | ConvertTo-Json -Compress)
  if ($compare) { 
    Write-Output "Retrying..."
    Invoke-DefenderApi -Method "POST" -Uri "/mtp/wdatpInternalApi/compliance/alertSharing/status/" -Body $settings
    $new = Invoke-DefenderApi -Uri "/mtp/wdatpInternalApi/compliance/alertSharing/status/"
  }
  Write-Log -Settings ($new | ConvertTo-Json) -Subject $subject -Type "New"

  # Look for settings that did not change
  if ($new -ne $true) { Write-Log -Settings "true" -Subject $subject -Type "Failed to update" }
}

#Enable Microsoft Intune connection
$subject = "Advanced Features - Enable Microsoft Intune connection"
# Get existing settings
$settings = Invoke-DefenderApi -Uri "/mtp/responseApiPortal/onboarding/intune/status"
Write-Log -Settings "{`"timeout`":60000}" -Uri "/mtp/responseApiPortal/onboarding/intune/deprovision" -Subject $subject -Type "Existing"

# Check settings that should be changed
$changes = New-Object System.Collections.ArrayList
if ($settings -ne 1) {
  $settings = "{`"timeout`":60000}"
  $changes.Add("IntuneStatus,1")
}

# If changes are required, log changes, attempt to make them, and verify they were set
if ($changes) {
  # Write changes to log
  Write-Log -Settings $changes -Subject $subject -Type "Change"
  Write-Output "Changing values:`n`n$($changes | ForEach-Object { Write-Output "$_" })"

  # Set desired settings with one retry
  Invoke-DefenderApi -Method "POST" -Uri "/mtp/responseApiPortal/onboarding/intune/provision" -Body $settings
  $new = Invoke-DefenderApi -Uri "/mtp/responseApiPortal/onboarding/intune/status"
  $compare = Compare-Object -ReferenceObject ($settings | ConvertTo-Json -Compress) -DifferenceObject ($new | ConvertTo-Json -Compress)
  if ($compare) { 
    Write-Output "Retrying..."
    Invoke-DefenderApi -Method "POST" -Uri "/mtp/responseApiPortal/onboarding/intune/provision" -Body $settings
    $new = Invoke-DefenderApi -Uri "/mtp/responseApiPortal/onboarding/intune/status"
  }
  Write-Log -Settings ($new | ConvertTo-Json) -Subject $subject -Type "New"

  # Look for settings that did not change
  if ($new -ne 1) { Write-Log -Settings "IntuneStatus,1" -Subject $subject -Type "Failed to update" }
}

# Enable Authenticated telemetry
$subject = "Advanced Features - Enable Authenticated telemetry"
# Get existing settings
$settings = Invoke-DefenderApi -Uri "/mtp/responseApiPortal/senseauth/allownonauthsense"
Write-Log -Settings "{`"allowNonAuthenticatedSense`":false}" -Uri "/mtp/responseApiPortal/senseauth/allownonauthsense" -Subject $subject -Type "Existing"

# Check settings that should be changed
$changes = New-Object System.Collections.ArrayList
if ($settings -ne "True") {
  $settings = "{`"allowNonAuthenticatedSense`":true}"
  $changes.Add("allowNonAuthenticatedSense,true")
}

# If changes are required, log changes, attempt to make them, and verify they were set
if ($changes) {
  # Write changes to log
  Write-Log -Settings $changes -Subject $subject -Type "Change"
  Write-Output "Changing values:`n`n$($changes | ForEach-Object { Write-Output "$_" })"

  # Set desired settings with one retry
  Invoke-DefenderApi -Method "POST" -Uri "/mtp/responseApiPortal/senseauth/allownonauthsense" -Body $settings
  $new = Invoke-DefenderApi -Uri "/mtp/responseApiPortal/senseauth/allownonauthsense"
  $compare = Compare-Object -ReferenceObject ($settings | ConvertTo-Json -Compress) -DifferenceObject ($new | ConvertTo-Json -Compress)
  if ($compare) { 
    Write-Output "Retrying..."
    Invoke-DefenderApi -Method "POST" -Uri "/mtp/responseApiPortal/senseauth/allownonauthsense" -Body $settings
    $new = Invoke-DefenderApi -Uri "/mtp/responseApiPortal/senseauth/allownonauthsense"
  }
  Write-Log -Settings ($new | ConvertTo-Json) -Subject $subject -Type "New"

  # Look for settings that did not change
  if ($new -ne "True") { Write-Log -Settings "allowNonAuthenticatedSense,true" -Subject $subject -Type "Failed to update" }
}

# Enable Preview features
$subject = "Advanced Features - Enable Preview features"
# Get existing settings
$settings = Invoke-DefenderApi -Uri "/mtp/settings/GetPreviewExperienceSetting?context=MdatpContext"
Write-Log -Settings "{`"IsOptIn`":false}" -Uri "/mtp/settings/SavePreviewExperienceSetting?context=MdatpContext" -Subject $subject -Type "Existing"

# Check settings that should be changed
$changes = New-Object System.Collections.ArrayList
if ($settings.IsOptIn -ne "True") {
  $settings = "{`"IsOptIn`":true}"
  $changes.Add("IsOptIn,true")
}

# If changes are required, log changes, attempt to make them, and verify they were set
if ($changes) {
  # Write changes to log
  Write-Log -Settings $changes -Subject $subject -Type "Change"
  Write-Output "Changing values:`n`n$($changes | ForEach-Object { Write-Output "$_" })"

  # Set desired settings with one retry
  Invoke-DefenderApi -Method "POST" -Uri "/mtp/settings/SavePreviewExperienceSetting?context=MdatpContext" -Body $settings
  $new = Invoke-DefenderApi -Uri "/mtp/settings/GetPreviewExperienceSetting?context=MdatpContext"
  $compare = Compare-Object -ReferenceObject ($settings | ConvertTo-Json -Compress) -DifferenceObject ($new | ConvertTo-Json -Compress)
  if ($compare) { 
    Write-Output "Retrying..."
    Invoke-DefenderApi -Method "POST" -Uri "/mtp/settings/SavePreviewExperienceSetting?context=MdatpContext" -Body $settings
    $new = Invoke-DefenderApi -Uri "/mtp/settings/GetPreviewExperienceSetting?context=MdatpContext"
  }
  Write-Log -Settings ($new | ConvertTo-Json) -Subject $subject -Type "New"

  # Look for settings that did not change
  if ($new -ne "True") { Write-Log -Settings "IsOptIn,true" -Subject $subject -Type "Failed to update" }
}

##################################################

### Device Groups ###
$subject = "Device Groups"

# Privileged Servers
$PrivServers = @{
  MachineGroupId = -1
  Name = "Privileged Servers"
  Description = "Privileged Servers"
  AutoRemediationLevel = 3
  Priority = 123456789
  IsUnassignedMachineGroup = $false
  MachineCount = 0
  LastUpdated = "2024-11-01T00:00:00.000Z"
  GroupRules = @(
    @{ OperatorType = 0; Property = 0; PropertyValue = "" }
    @{ OperatorType = 0; Property = 1; PropertyValue = "" }
    @{ OperatorType = 2; Property = 2; PropertyValue = "Privileged" }
    @{ OperatorType = 4; Property = 3; PropertyValue = "[`"WindowsServer2022`",`"WindowsServer2019`",`"WindowsServer2016`",`"WindowsServer2012R2`",`"Windows2016`",`"Linux`"]" }
    @{ OperatorType = 0; Property = 4; PropertyValue = "" }
  )
  MachineGroupAssignments = @()
  OldMachineGroupId = $null
} | ConvertTo-Json -Depth 4

# Servers
$Servers = @{
  MachineGroupId = -1
  Name = "Servers"
  Description = "Servers"
  AutoRemediationLevel = 3
  Priority = 123456789
  IsUnassignedMachineGroup = $false
  MachineCount = 0
  LastUpdated = "2024-11-01T00:00:00.000Z"
  GroupRules = @(
    @{ OperatorType = 0; Property = 0; PropertyValue = "" }
    @{ OperatorType = 0; Property = 1; PropertyValue = "" }
    @{ OperatorType = 0; Property = 2; PropertyValue = "" }
    @{ OperatorType = 4; Property = 3; PropertyValue = "[`"WindowsServer2022`",`"WindowsServer2019`",`"WindowsServer2016`",`"WindowsServer2012R2`",`"Windows2016`",`"Linux`"]" }
    @{ OperatorType = 0; Property = 4; PropertyValue = "" }
  )
  MachineGroupAssignments = @()
  OldMachineGroupId = $null
} | ConvertTo-Json -Depth 4

# Privileged Endpoints
$PrivEndpoints = @{
  MachineGroupId = -1
  Name = "Privileged Endpoints"
  Description = "Privileged Endpoints"
  AutoRemediationLevel = 3
  Priority = 123456789
  IsUnassignedMachineGroup = $false
  MachineCount = 0
  LastUpdated = "2024-11-01T00:00:00.000Z"
  GroupRules = @(
    @{ OperatorType = 0; Property = 0; PropertyValue = "" }
    @{ OperatorType = 0; Property = 1; PropertyValue = "" }
    @{ OperatorType = 2; Property = 2; PropertyValue = "Privileged" }
    @{ OperatorType = 4; Property = 3; PropertyValue = "[`"Windows11`",`"Windows10`",`"macOS`",`"iOS`",`"Android`",`"Windows10WVD`"]" }
    @{ OperatorType = 0; Property = 4; PropertyValue = "" }
  )
  MachineGroupAssignments = @()
  OldMachineGroupId = $null
} | ConvertTo-Json -Depth 4

# Endpoints
$Endpoints = @{
  MachineGroupId = -1
  Name = "Endpoints"
  Description = "Endpoints"
  AutoRemediationLevel = 3
  Priority = 123456789
  IsUnassignedMachineGroup = $false
  MachineCount = 0
  LastUpdated = "2024-11-01T00:00:00.000Z"
  GroupRules = @(
    @{ OperatorType = 0; Property = 0; PropertyValue = "" }
    @{ OperatorType = 0; Property = 1; PropertyValue = "" }
    @{ OperatorType = 0; Property = 2; PropertyValue = "" }
    @{ OperatorType = 4; Property = 3; PropertyValue = "[`"Windows11`",`"Windows10`",`"macOS`",`"iOS`",`"Android`",`"Windows10WVD`"]" }
    @{ OperatorType = 0; Property = 4; PropertyValue = "" }
  )
  MachineGroupAssignments = @()
  OldMachineGroupId = $null
} | ConvertTo-Json -Depth 4

# This iterates through the list of variables storign the device group details - add/remove as needed
[array]$body = @()
$PrivServers,$Servers,$PrivEndpoints,$Endpoints | ForEach-Object {
    # Get existing devices groups
    $existingGroups = (Invoke-DefenderApi -Uri "/mtp/rbacManagementApi/rbac/machine_groups?addAadGroupNames=true&addMachineGroupCount=false").items

    # Add group to body, setting priority to one less than the previous lowest device group priority
    0..($existingGroups.count -1) | ForEach-Object { $body += "$($existingGroups[$_] | ConvertTo-Json -Depth 4)," }
    $body += $_.Replace('123456789',$existingGroups.Priority[-2] + 1)

    # Create new device group
    Invoke-DefenderApi -Method "PUT" -Uri "/mtp/rbacManagementApi/rbac/machine_groups" -Body "[$body]"
    Write-Log -Settings ($body | ConvertTo-Json -Depth 4) -Subject $subject -Type "New"

    # Cleanup and wait
    Remove-Variable existingGroups,body
}


##################################################

### Deception rules ###
$subject = "Deception rules"

# Get existing settings
$settings = Invoke-DefenderApi -Uri "/mtp/k8s/deception/portal/deceptionrules/ffffffff-ffff-ffff-ffff-ffffffffffff"
Write-Log -Settings "" -Uri "/mtp/k8s/deception/portal/deceptionrules/ffffffff-ffff-ffff-ffff-ffffffffffff/updatestate?isEnabled=false" -Subject $subject -Type "Existing"

# If changes are required, log changes, attempt to make them, and verify they were set
if ($settings.isEnabled -ne $true) {
  # Write changes to log
  Write-Log -Settings "isEnabled,true" -Subject $subject -Type "Change"
  Write-Output "Changing values:`n`nisEnabled,true"

  # Set desired settings with one retry
  Invoke-DefenderApi -Method "PUT" -Uri "/mtp/k8s/deception/portal/deceptionrules/ffffffff-ffff-ffff-ffff-ffffffffffff/updatestate?isEnabled=true"
  $new = Invoke-DefenderApi -Uri "/mtp/k8s/deception/portal/deceptionrules/ffffffff-ffff-ffff-ffff-ffffffffffff"
  if ($new.isEnabled -ne $true) { 
    Write-Output "Retrying..."
    Invoke-DefenderApi -Method "PUT" -Uri "/mtp/k8s/deception/portal/deceptionrules/ffffffff-ffff-ffff-ffff-ffffffffffff/updatestate?isEnabled=true"
    $new = Invoke-DefenderApi -Uri "/mtp/k8s/deception/portal/deceptionrules/ffffffff-ffff-ffff-ffff-ffffffffffff"
  }
  Write-Log -Settings ($new | ConvertTo-Json -Depth 4) -Subject $subject -Type "New"

  # Look for settings that did not change
  if ($new.isEnabled -ne $true) { Write-Log -Settings "isEnabled,true" -Subject $subject -Type "Failed to update" }
}

##################################################

### Download installers and onboarding files ###

# Create output directory in Downloads folder
New-Item -Path $PWD -ItemType Directory -Name "Defender" -Force

# Get onboarding files for Windows
0,2,4,5 | ForEach-Object {
  $url = Invoke-DefenderApi -Uri "/mtp/packages/DownloadOnboardingPackage?mgmtTool=$_&channelRouting=2"
  Invoke-WebRequest -Uri $url -OutFile "$PWD\Defender\GatewayWindowsDefenderATPOnboardingPackage.zip"
  Expand-Archive -Path "$PWD\Defender\GatewayWindowsDefenderATPOnboardingPackage.zip" -DestinationPath "$PWD\Defender\Windows"
}

# Get onboarding files for macOS
6,7 | ForEach-Object {
  $url = Invoke-DefenderApi -Uri "/mtp/packages/DownloadOnboardingPackage?mgmtTool=$_&channelRouting=2"
  Invoke-WebRequest -Uri $url -OutFile "$PWD\Defender\GatewayWindowsDefenderATPOnboardingPackage.zip"
  Expand-Archive -Path "$PWD\Defender\GatewayWindowsDefenderATPOnboardingPackage.zip" -DestinationPath "$PWD\Defender\macOS"
}

# Get onboarding fiels for Linux
8,9 | ForEach-Object {
  $url = Invoke-DefenderApi -Uri "/mtp/packages/DownloadOnboardingPackage?mgmtTool=$_&channelRouting=2"
  Invoke-WebRequest -Uri $url -OutFile "$PWD\Defender\GatewayWindowsDefenderATPOnboardingPackage.zip"
  Expand-Archive -Path "$PWD\Defender\GatewayWindowsDefenderATPOnboardingPackage.zip" -DestinationPath "$PWD\Defender\Linux"
}

# Get Server 2012/2016 installer
$version = (Invoke-RestMethod -Uri 'https://www.microsoft.com/security/encyclopedia/adlpackages.aspx?action=info').versions.platform
Invoke-WebRequest -Uri "https://definitionupdates.microsoft.com/download/DefinitionUpdates/platform/$version/x64/md4ws.msi" -OutFile "$PWD\Defender\Windows\md4ws.msi"

# Get WSL2 plug-in
Invoke-WebRequest -Uri "https://aka.ms/defenderPlugin" -OutFile "$PWD\Defender\Windows\defenderplugin-x64.msi"

# Get macOS installer
Invoke-WebRequest -Uri "https://officecdn-microsoft-com.akamaized.net/pr/C1297A47-86C4-4C1F-97FA-950631F94777/MacAutoupdate/wdav.pkg" -OutFile "$PWD\Defender\macOS\wdav.pkg"

# Cleanup
Remove-Item -Path "$PWD\Defender\GatewayWindowsDefenderATPOnboardingPackage.zip" -Force