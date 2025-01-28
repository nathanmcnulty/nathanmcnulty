# Automated Configuration

This is a collection of commands that will help automate the configuration of the Defender for Endpoint settings. To use this, you must obtain the sccauth value and xsrf-token value from the browser and use it to create cookies and headers for our API calls. This is because we are using an internal API to configure settings, and there isn't a public way to get the right tokens.

## Table of Contents

[Setting up our session and cookies](README.md#setting-up-our-session-and-cookies)

[General - Advanced features](README.md#advanced-features)

[General - Licenses](README.md#licenses)

[General - Email notifications](README.md#email-notifications)

[Permissions - Roles](README.md#roles)

[Permissions - Device groups](README.md#device-groups)

[Rules - Deception rules](README.md#deception-rules)

[Rules - Indicators](README.md#indicators)

[Rules - Web content filtering](README.md#web-content-filtering)

[Rules - Automation uploads](README.md#automation-uploads)

[Rules - Automation folder exclusions](README.md#automation-folder-exclusions)

[Configuration management- Enforcement scope](README.md#enforcement-scope)

[Configuration management - Intune permissions](README.md#intune-permissions)

[Device management - Onboarding](README.md#onboarding)

[Device management - Offboarding](README.md#offboarding)

## Setting up our session and cookies

First, we need to create a WebRequestSession object contaning the sccauth and xsrf cookies copied from the browser and headers with the xsrf token. To get this, open Developer Tools in your browser and make sure the Network tab is set to preserve logs, then log into security.microsoft.com. Search for **apiproxy** and select a request.

![img](./img/sccauth-1.png)

Under headers, scroll down under the cookies section, copy the value after sccauth (it is very long) all the way to the next semicolon and save it into the $sccauth variable. Now do the same for xsrf-token and save it into the $xsrf variable.

![img](./img/sccauth-2.png)

Now we can create a session with those cookies:

```powershell
# Copy sccauth from the browser
$sccauth = Read-Host -Prompt "Enter sccauth cookie value" -AsSecureString
if ($sccauth.Length -ne 2368) { Write-Warning "sccauth was $(sccauth.Length) characters and may be incorrect" }

# Copy xsrf token from the browser
$xsrf = Read-Host -Prompt "Enter xsrf cookie value" -AsSecureString
if ($xsrf.Length -ne 347) { Write-Warning "xsrf was $($xsrf.Length) characters and may be incorrect" }

# Create session and cookies
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.Cookies.Add((New-Object System.Net.Cookie("sccauth", "$($sccauth | ConvertFrom-SecureString -AsPlainText)", "/", "security.microsoft.com")))
$session.Cookies.Add((New-Object System.Net.Cookie("XSRF-TOKEN", "$($xsrf | ConvertFrom-SecureString -AsPlainText)", "/", "security.microsoft.com")))

# Set the headers to include the xsrf token
[Hashtable]$Headers=@{}
$headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value)

```

With this complete, we can now make requests to the internal API :)

## General

### Advanced features

The body below will enable most options in Advanced features except "Restrict correlation to within scoped device groups​" which is not applicable to most organizations. Some settings, such as Live Response and Deception require additional API calls.

```powershell
# Get values
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/GetAdvancedFeaturesSetting" -ContentType "application/json" -WebSession $session -Headers $headers

# Update values
$body = @{
    AatpIntegrationEnabled = $false
    AatpWorkspaceExists = $false
    AllowWdavNetworkBlock = $true
    AutoResolveInvestigatedAlerts = $true
    BilbaoApproved = $false
    BilbaoEnabled = $false
    BlockListEnabled = $true
    DartDataCollection = $false
    EnableAggregatedReporting = $false
    EnableAipIntegration = $false
    EnableAuditTrail = $true
    EnableCustomAsrAdvancedProcessTermination = $false
    EnableEndpointDlp = $true
    EnableExcludedDevices = $false
    EnableMcasIntegration = $true
    EnableQuarantinedFileDownload = $true
    EnableWdavAntiTampering = $true
    EnableWdavAuditMode = $false
    EnableWdavPassiveModeRemediation = $true
    HidePotentialDuplications = $true
    IsolateIncidentsWithDifferentDeviceGroups = $false
    LicenseEnabled = $true
    M365SecureScoreIntegrationEnabled = $true
    MagellanOptOut = $false
    MobileDeactivationPeriodInDays = $null
    O365ToAtpIntegrationEnabled = $false
    OfficeIntegrationEnabled = $false
    OfficeLicenseEnabled = $false
    ShowUserAadProfile = $true
    SkypeIntegrationEnabled = $true
    UseSimplifiedConnectivity = $true
    UseSimplifiedConnectivityViaApi = $true
    WebCategoriesEnabled = $true
} | ConvertTo-Json

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/settings/SaveAdvancedFeaturesSetting" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers

```

| Feature Name | Recommended Value | Description |
| ------ | ------ | ------ |
| AatpIntegrationEnabled | N/A | ??? Not in portal - Likely removed as these are always integrated in XDR now ??? |
| AatpWorkspaceExists | N/A | ??? Not in portal - Likely removed as these are always integrated in XDR now ??? |
| AllowWdavNetworkBlock | True | [Custom network indicators](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#custom-network-indicators) |
| AutoResolveInvestigatedAlerts | True | [Automatically resolve alerts](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#automatically-resolve-alerts) |
| BilbaoApproved | N/A | [Endpoint Attack Notifications](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#endpoint-attack-notifications) |
| BilbaoEnabled | N/A | [Endpoint Attack Notifications](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#endpoint-attack-notifications) |
| BlockListEnabled | True | [Allow or block file](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#allow-or-block-file) | 
| DartDataCollection | N/A | Microsoft Defender Experts integration |
| EnableAggregatedReporting | True | [New Feature (01.21.2025)](https://learn.microsoft.com/en-us/defender-endpoint/aggregated-reporting) |
| EnableAipIntegration | N/A | Not in portal - Likely replaced by newer Compliance Center sharing |
| EnableAuditTrail | True | [Unified audit log](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#unified-audit-log) |
| EnableCustomAsrAdvancedProcessTermination | N/A | ??? Not in portal - Custom ASR rules with the ability to terminate processes ??? |
| EnableEndpointDlp | N/A | Not in portal - True when we have provisioned Endpoint DLP in Purview |
| EnableExcludedDevices | N/A | ??? Not in portal - Maybe from before we could exclude devices from TVM repoting ??? |
| EnableMcasIntegration | True | [Microsoft Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#microsoft-defender-for-cloud-apps) |
| EnableQuarantinedFileDownload | True | [Download quarantined files](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#download-quarantined-files) |
| EnableWdavAntiTampering | True | [Tamper protection](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#tamper-protection) |
| EnableWdavAuditMode | N/A | ??? Not in portal - Might be to force passive mode across all devices ??? |
| EnableWdavPassiveModeRemediation | True | [Enable EDR in block mode](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#enable-edr-in-block-mode) |
| HidePotentialDuplications | True | [Hide potential duplicate device records](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#hide-potential-duplicate-device-records) |
| IsolateIncidentsWithDifferentDeviceGroups | False  | [Restrict correlation to within scoped device groups​](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#restrict-correlation-to-within-scoped-device-groups) |
| LicenseEnabled | N/A | ??? Not in portal - Need to check M365 Business Premium and E3 tenant, likely true if licensed but maybe means license level ??? |
| M365SecureScoreIntegrationEnabled | True  | ??? Not in portal - Likely removed as these are always integrated in XDR now ??? |
| MagellanOptOut | False | [Device discovery](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#device-discovery) |
| MobileDeactivationPeriodInDays | N/A | ??? Not in portal - Might be adjustable timeout for mobile devices before marking them as not active ???|
| OfficeIntegrationEnabled | N/A | ??? Discovered 2024/12/12 ??? |
| OfficeLicenseEnabled | N/A | ??? Discovered 2024/12/12 ??? |
| O365ToAtpIntegrationEnabled | N/A | ??? Discovered 2024/12/12 ??? |
| ShowUserAadProfile | True | [Show user details](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#show-user-details) |
| SkypeIntegrationEnabled | True | [Skype for Business integration](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#skype-for-business-integration) |
| UseSimplifiedConnectivity | True | [Default to streamlined connectivity when onboarding devices in Defender portal​](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#default-to-streamlined-connectivity-when-onboarding-devices-in-the-defender-portal)​ |
| UseSimplifiedConnectivityViaApi | True | Apply streamlined connectivity settings to devices managed by Intune and Defender for Cloud |
| WebCategoriesEnabled | True | [Web content filtering](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features#web-content-filtering) |

These are a good starting point, and you can adjust as needed for your environment. If you have a dev tenant, you can definitely play with some of these settings and see what breaks ;)

The following will enable Live Response for clients and servers, and it will also allow unsigned scripts to be run. It is recommended to move to signed scripts, but remember that uploading scripts to the library still requires administrative rights to begin with.

```powershell
# Get values
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/get_properties?useV2Api=true&useV3Api=true" -ContentType "application/json" -WebSession $session -Headers $headers

# Update values
$body = @{
    properties = @{
        AutomatedIrLiveResponse = $true
        AutomatedIrUnsignedScripts = $true
        LiveResponseForServers = $true
    }
} | ConvertTo-Json

Invoke-RestMethod -Method "PATCH" -Uri "https://security.microsoft.com/apiproxy/mtp/liveResponseApi/update_properties?useV2Api=true&useV3Api=true" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers

```

To enable Deception:

```powershell
# Get values
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/k8s/deception/portal/deceptionsettings" -ContentType "application/json" -WebSession $session -Headers $headers

# Update values
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/k8s/deception/portal/deceptionsettings/update" -Body "{`"isDeceptionEnabled` =true}" -ContentType "application/json" -WebSession $session -Headers $headers

```

To enable Share endpoint alerts with Microsoft Compliance Center:

```powershell
# Get values
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/wdatpInternalApi/compliance/alertSharing/status/" -ContentType "application/json" -WebSession $session -Headers $headers

# Update values
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/wdatpInternalApi/compliance/alertSharing/status/" -Body "true" -ContentType "application/json" -WebSession $session -Headers $headers

```

To enable Microsoft Intune connection:

```powershell
# Get values (0 is disabled, 1 is enabled)
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/onboarding/intune/status" -ContentType "application/json" -WebSession $session -Headers $headers

# Update values
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/onboarding/intune/provision" -Body "{`"timeout` =60000}" -ContentType "application/json" -WebSession $session -Headers $headers

```

To enable Authenticated telemetry:

```powershell
# Get values
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/senseauth/allownonauthsense" -ContentType "application/json" -WebSession $session -Headers $headers

# Update values
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/senseauth/allownonauthsense" -Body "{`"allowNonAuthenticatedSense` =true}" -ContentType "application/json" -WebSession $session -Headers $headers

```

To enable Preview features:

```powershell
# Get values
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/settings/GetPreviewExperienceSetting?context=MdatpContext" -ContentType "application/json" -WebSession $session -Headers $headers

# Update values
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/settings/SavePreviewExperienceSetting?context=MdatpContext" -Body "{`"IsOptIn` =true}" -ContentType "application/json" -WebSession $session -Headers $headers

```

### Licenses

This section is mostly for usage check, but for environments with M365 Business Premium / Defender for Business, we can define the licensing level as Defender for Business or Defender for Endpoint P2. Next time I get access to a Defender for Business environment, I will try to map out those settings.

This will kick back the license usage details:

```powershell
# Get license count
(Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/licenses/mgmt/aadlicenses/sums" -ContentType "application/json" -WebSession $session -Headers $headers).sums

# Get usage
(Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/k8sMachineApi/ine/machineapiservice/machines/skuReport" -ContentType "application/json" -WebSession $session -Headers $headers).Sums

```

### Email notifications

I recommend moving to Defender XDR email notifications. Once I complete mapping out that API, I will publish that under the Defender XDR section and link to it from here :) 

Here's how we can get existing email notification settings, and later I'll figure out how to migrate them to Defender XDR:

```powershell
# Get Alerts notifications
(Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/alertsEmailNotifications/email_notifications" -ContentType "application/json" -WebSession $session -Headers $headers).items


# Get vulnerability notifications
$headers["api-version"] = "1.0"
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/tvm/orgsettings/vulnerability-notification-rules" -ContentType "application/json" -WebSession $session -Headers $headers

```

## Permissions

### Roles

To simplify and future-proof, we are going to enable and set up roles in the newer Unified RBAC. If you have existing roles in MDE, you might want to import existing roles before changing to the Unified RBAC. The following will automate importing existing roles that haven't alreay been imported.

> [!NOTE]
> Permission changes made in MDE RBAC do not automatically update roles that have been imported to Unified RBAC. To reflect any changes made in MDE RBAC, you will need to re-import the roles to Unified RBAC. This script will miss these changes.

```powershell
# Get Unified RBAC roles applicable to MDE
$urbac = (Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/urbacConfiguration/gw/unifiedrbac/configuration/roleDefinitions" -ContentType "application/json" -WebSession $session -Headers $headers).value | Where-Object { $_.dataSources -in "All","Mde" }

# Get list of IDs for roles already imported from MDE
$imported = $urbac.originalRoleInfo.originalId

# Get list of roles in MDE RBAC
$mderbac = (Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/urbacConfiguration/gw/unifiedrbac/configuration/migration/importedRoleDefinitions/?workloadsToImportFrom[0]=Mde" -ContentType "application/json" -WebSession $session -Headers $headers).value

# Import missing roles from MDE RBAC to Unified RBAC
$mderbac.originalId | ForEach-Object { 
    if ($_ -notin $imported) {
        $body = @{
            originalRoleIdsPerWorkload = @{ Mde = @("$_") }
        } | ConvertTo-Json
        (Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/urbacConfiguration/gw/unifiedrbac/configuration/migration/importedRoleDefinitions/" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers -Verbose).value
    }
}

```

Now that the roles have been imported, we can enable Unified RBAC. This requires an additional header indicating the API version:

```powershell
# Enable Unified RBAC for Defender for Endpoint
$headers["api-version"] = "2.0"
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/urbacConfiguration/gw/unifiedrbac/configuration/enablement/?workload=Mde" -ContentType "application/json" -WebSession $session -Headers $headers

```

To create a read-only role:

```powershell
# Name of group that will be assigned to role
$name = "Defender - Read All"

# Get group details for body
$group = Get-MgGroup -Filter "DisplayName eq '$name'" | Out-GridView -PassThru

# Build body for request
$body = @{
    displayName = "Read-only Security Operations"
    description = "Read-only Security Operations"
    rolePermissions = @( @{ 
        allowedResourceActions = @( "microsoft.xdr/secops/*/read" ) 
    } )
    roleAssignments = @( @{ 
        id = ""
        roleDefinitionId = ""
        displayName = "$($group.DisplayName)"
        appScopeIds = @( "All" )
        principalIds = @( "$($group.Id)" )
        principals = @( @{
            displayName = "$($group.DisplayName)"
            description = "$($group.DisplayName)"
            principalId = "$($group.Id)"
            type = "User"
        } )
        scopes = @()
    } )
    isEnabled = $true
} | ConvertTo-Json -Depth 4

(Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/urbacConfiguration/gw/unifiedrbac/configuration/roleDefinitions/" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers -Verbose).value

```

### Device groups

Device groups provide a way for us to scope RBAC permissions and certain features, such as Indicators and Web Content Filtering. Typically creating one or two device groups is sufficient for small orgs, but larger orgs may require many device groups.

A simple starting point for this example will be privileged endpoints, non-privileged endpoints, privileged servers, and non-privileged servers.

> [!NOTE]
> I had issues saving more than one new device group at a time, I believe due to MachineGroupId assignment. I worked around this by creating one at a time and getting a new list of existing groups each time.

```powershell
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
$PrivServers,$Servers,$PrivEndpoints,$Endpoints | ForEach-Object {
    # Get existing devices groups
    $existingGroups = (Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/rbacManagementApi/rbac/machine_groups?addAadGroupNames=true&addMachineGroupCount=false" -ContentType "application/json" -WebSession $session -Headers $headers).items

    # Create new body, setting priority to one less than the previous lowest device group priority
    0..($existingGroups.count -1) | ForEach-Object { [array]$body += "$($existingGroups[$_] | ConvertTo-Json -Depth 4)," }
    $body += $_.Replace('123456789',$existingGroups.Priority[-2] + 1)

    # Create new device group
    Invoke-RestMethod -Method "PUT" -Uri "https://security.microsoft.com/apiproxy/mtp/rbacManagementApi/rbac/machine_groups" -Body "[$body]" -ContentType "application/json" -WebSession $session -Headers $headers

    # Cleanup and wait
    Remove-Variable existingGroups,body
    Start-Sleep -Seconds 15
}

```

## Rules

### Deception rules

After enabling the deception feature, we can enable the default deception rule as well as create our own rules / lures. I always recommend enabling at least the default rule, and so I'll show how to detect if it is enabled and how to enable it if it isn't.

```powershell
# Get values
$response = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/k8s/deception/portal/deceptionrules" -ContentType "application/json" -WebSession $session -Headers $headers

# Update values
if ($response.isEnabled -eq $false) {
  Invoke-RestMethod -Method "PUT" -Uri "https://security.microsoft.com/apiproxy/mtp/k8s/deception/portal/deceptionrules/ffffffff-ffff-ffff-ffff-ffffffffffff/updatestate?isEnabled=true" -ContentType "application/json" -WebSession $session -Headers $headers
}

```

This is an example of how we could generate our own rule set instead. This will likely throw conflicts if we have the default rule enabled due to sharing the same default IPs for the hosts. Using custom IPs could result in false positives, but I will try to document that later.

```powershell
# Autogenerated set of lures
$decoys = (Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/k8s/deception/portal/decoys/generate" -ContentType "application/json" -WebSession $session -Headers $headers) | ConvertTo-Json -Depth 4

$body = @{
    id = "00000000-0000-0000-0000-000000000000"
    name = "Additional Lures"
    description = "Additional Lures"
    decoys = $decoys
    action = 1
    lureFamily = 3
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/k8s/deception/portal/deceptionrules" -ContentType "application/json" -Body $body -WebSession $session -Headers $headers

```

### Indicators

Indicators have an official API endpoint and should be managed through those endpoints. There are technically two endpoints, one that handles with individual incidacators and a second that handles bulk (import) indicators. For most of our automation, we are interested in the import API.

[Defender API docs](https://learn.microsoft.com/en-us/defender-endpoint/api/import-ti-indicators)

[Example script for import](https://github.com/nathanmcnulty/nathanmcnulty/blob/master/DefenderForEndpoint/MDE-API-ImportIndicator.ps1)

### Web content filtering

I will have to map out each category to their ID later, but this is a basic example of blocking categories that are higher risk while trying to still be mostly open.

```powershell
# Get policies
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/userRequests/webcategory/policies" -ContentType "application/json" -WebSession $session -Headers $headers

# Get list of device group IDs
(Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/rbacManagementApi/rbac/machine_groups?addAadGroupNames=true&addMachineGroupCount=false" -ContentType "application/json" -WebSession $session -Headers $headers).items | Select-Object MachineGroupId,Name

# Create policy (leave RbacGroupIds empty for all device groups)
$body = @{
  AuditCategoryIds = @(65,75,47,62,18,29,76,14,68,73,26,7,19,70,92,48,39)
  BlockedCategoryIds = @(33,77,46,78,12,21,23,67,84,51,52)
  PolicyName = "Baseline policy"
  RbacGroupIds = @()
} | ConvertTo-Json

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/userRequests/webcategory/policy" -ContentType "application/json" -Body $body -WebSession $session -Headers $headers

```

### Automation uploads

This controls how automated investigation handles sample submission, which file types are allowed to be uploaded, and whether memory contents should be analyzed. This specific API call requires the "tenant-id" header with your tenantId in it.

```powershell
$tenantId = (Get-MgContext).TenantId
$headers["tenant-id"] = "$tenantId"

$response = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/autoIr/admin/advanced" -ContentType "application/json" -WebSession $session -Headers $headers

$body = @{
  cloud_upload = $true
  computer_file_extension = "rb,wsf,msi,vbs,reg,ko.gz,ps1,url,elf,job,ko,ws,gadget,vbe,com,bat,js,scr,cmd,rgs,air,sys,cpl,inf,sh,pl,tcl,'',dll,py,exe,vb,lnk"
  upload_memory_content = $true
} | ConvertTo-Json

Invoke-RestMethod -Method "PATCH" -Uri "https://security.microsoft.com/apiproxy/mtp/autoIr/admin/advanced" -ContentType "application/json" -Body $body -WebSession $session -Headers $headers

```

### Automation folder exclusions

I'm capturing these details to check if we have anything configured. For Maester tests, may attempt to add some logic to check for poorly defined exclusions or something :)

```powershell
# Get list of automation folder exclusions
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/autoIr/folder_exclusion/all" -ContentType "application/json" -WebSession $session -Headers $headers

# Create automation folder exclusion
$body = @{
  description = "Test"
  folder = "C:\Test"
  extensions = @("")
  fileNames = @("Test.exe")
} | ConvertTo-Json

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/autoIr/folder_exclusion/all" -ContentType "application/json" -Body $body -WebSession $session -Headers $headers

```

## Configuration Management

### Enforcement scope

For now, just mapping the API endpoints for getting values.

```powershell
# Check that Intune is configured to enable this feature
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/memonboardstatus" -ContentType "application/json" -WebSession $session -Headers $headers

# Get current config
$response = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/mdestatus" -ContentType "application/json" -WebSession $session -Headers $headers

# ascEnabled : True enables managing devices onboarded through Defender for Cloud
# mdeEnabledWithSccm : True means MDE will override the ConfigMgr agent policies
$response

# mdeEnabled : 0 means disabled, 1 means on all devices, 2 means on tagged devices
$response.osFamilies

```

There's a preview feature for managing security settings on Domain Controllers, and these are the two API endpoints for that:

```powershell
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/domaincontrollers/totals" -ContentType "application/json" -WebSession $session -Headers $headers

Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/domaincontrollers/list" -ContentType "application/json" -WebSession $session -Headers $headers

```

### Intune permissions

Any groups assigned here are granted the Endpoint security managers role in Intune. This will show how to get an existing list as well as how to add a group.

```powershell
# Get existing groups
$existingGroups = (Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/MemPermissions/MemRoleAssignment" -ContentType "application/json" -WebSession $session -Headers $headers).members

# Get a list of all groups via the API proxy
(Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/rbacManagementApi/rbac/aad_groups" -ContentType "application/json" -WebSession $session -Headers $headers).items

# Add a group
[array]$memberIds = $existingGroups.memberId
$memberIds += "f500e338-db07-4fbd-a77a-f2e9bf11810d"
$body = @{ membersIds = @( $memberIds ) } | ConvertTo-Json

Invoke-RestMethod -Method "PUT" -Uri "https://security.microsoft.com/apiproxy/mtp/siamApi/MemPermissions/MemRoleAssignment" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers

```

## Device Management

### Onboarding

The URL to download the onboarding package is the same but changes some values based on the management type and connectivity mode. It is highly recommended to use Streamlined Connectivity to simplify network / ZTNA management.

This table contains the management tool (mgmtTool) value you'll use depending on what you need:

| OS | Method | Value | Docs |
| ------ | ------ | ------ | ------ |
| Windows | Group Policy | 0 | [Onboard Windows devices using Group Policy](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-gp) |
| Windows | Intune/MDM | 2 | [Onboard Windows devices to Defender for Endpoint using Intune](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-mdm) |
| Windows | Configuration Manager | 2 | [Onboard Windows devices using Configuration Manager](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-sccm) |
| Windows | Script | 4 | [Onboard Windows devices using a local script](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-script) |
| Windows | VDI | 5 | [Onboard non-persistent virtual desktop infrastructure (VDI) devices](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-vdi) |
| macOS | MDM / Intune | 6 | [Microsoft Defender for Endpoint on Mac](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-mac) |
| macOS | Script | 7 | [Microsoft Defender for Endpoint on Mac](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-mac) |
| Linux | Configuration Management Tools | 8 | [Microsoft Defender for Endpoint on Linux](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-linux) |
| Linux | Script | 9 | [Microsoft Defender for Endpoint on Linux](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-linux) |

This table contains the connectivity mode (channelRouting) value you'll use depending on what you need (recommend streamlined connectivity):

| Mode | Value | Docs |
| ------ | ------ | ------ |
| Standard Connectivity | 1 | [Standard Connectivity](https://learn.microsoft.com/en-us/defender-endpoint/configure-environment) |
| Streamlined Connectivity | 2 | [Streamlined Connectivity](https://learn.microsoft.com/en-us/defender-endpoint/configure-device-connectivity) |

To download the onboarding script, we set our mgmtTool and channelRouting values and run the following:

```powershell
# Example downloading onboarding script for Group Policy using Streamlined Connectivity, note mgmtTool and channelRouting values at the end of the URL
$mgmtTool = 0
$channelRouting = 2
$url = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/packages/DownloadOnboardingPackage?mgmtTool=$mgmtTool&channelRouting=$channelRouting" -ContentType "application/json" -WebSession $session -Headers $headers
Invoke-WebRequest -Uri $url -OutFile "$env:USERPROFILE\Downloads\GatewayWindowsDefenderATPOnboardingPackage.zip"
Expand-Archive -Path "$env:USERPROFILE\Downloads\GatewayWindowsDefenderATPOnboardingPackage.zip"

```

Server 2012/2016 require an downloading the Unified MDE agent, and you can always get the latest version like this:

```powershell
$version = (Invoke-RestMethod -Uri 'https://www.microsoft.com/security/encyclopedia/adlpackages.aspx?action=info').versions.platform
Invoke-WebRequest -Uri "https://definitionupdates.microsoft.com/download/DefinitionUpdates/platform/$version/x64/md4ws.msi" -OutFile "$env:USERPROFILE\Downloads\md4ws.msi"

```

I haven't captured how to get the latest macOS link, but this is the most current as of 2024/12/17:

```powershell
# Get MDE for macOS installation package
Invoke-WebRequest -Uri "https://officecdn-microsoft-com.akamaized.net/pr/C1297A47-86C4-4C1F-97FA-950631F94777/MacAutoupdate/wdav.pkg" -OutFile "$env:USERPROFILE\Downloads\wdav.pkg"

```

This should always redirect to the latest version of the plugin:

```powershell
# Get WSL2 plug-in installation package
Invoke-WebRequest -Uri "https://aka.ms/defenderPlugin" -OutFile "$env:USERPROFILE\Downloads\defenderplugin-x64.msi"

```

### Offboarding

The URL to download the offboarding package is the same but changes some values based on the management type.

This table contains the management tool (mgmtTool) value you'll use depending on what you need:

| OS | Method | Value | Docs |
| ------ | ------ | ------ | ------ |
| Windows | Group Policy | 0 | [Onboard Windows devices using Group Policy](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-gp) |
| Windows | Intune/MDM | 2 | [Onboard Windows devices to Defender for Endpoint using Intune](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-mdm) |
| Windows | Configuration Manager | 2 | [Onboard Windows devices using Configuration Manager](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-sccm) |
| Windows | Script | 4 | [Onboard Windows devices using a local script](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-script) |
| Windows | VDI | 5 | [Onboard non-persistent virtual desktop infrastructure](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-vdi) |
| macOS | MDM / Intune | 6 | [Microsoft Defender for Endpoint on Mac](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-mac) |
| macOS | Script | 7 | [Microsoft Defender for Endpoint on Mac](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-mac) |
| Linux | Configuration Management Tools | 8 | [Microsoft Defender for Endpoint on Linux](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-linux) |
| Linux | Script | 9 | [Microsoft Defender for Endpoint on Linux](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint-linux) |

```powershell
# Example downloading offboarding script for Group Policy using Streamlined Connectivity, note mgmtTool and channelRouting values at the end of the URL
$mgmtTool = 0
$url = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/packages/DownloadOffboardingPackage?mgmtTool=$mgmtTool" -ContentType "application/json" -WebSession $session -Headers $headers
$filename = $url.Split('/')[-1].Split('?')[0]
Invoke-WebRequest -Uri $url -OutFile "$env:USERPROFILE\Downloads\$filename"
Expand-Archive -Path "$env:USERPROFILE\Downloads\$filename"

```
