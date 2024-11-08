# Automated Configuration

This is a collection of commands that will help automate the configuration of the Defender for Endpoint settings. To use this, you must obtain the sccauth value and xsrf-token value from the browser and use it to create cookies and headers for our API calls. This is because we are using an internal API to configure settings, and there isn't a public way to get the right tokens.

## Table of Contents

[Setting up our session and cookies](README.md#setting-up-our-session-and-cookies)

[Advanced Features](README.md#advanced-features)

[Roles](README.md#roles)

[Device Groups](README.md#device-groups)

## Setting up our session and cookies

First, we need to create a WebRequestSession object contaning the sccauth and xsrf cookies copied from the browser and headers with the xsrf token. To get this, open Developer Tools in your browser and make sure the Network tab is set to preserve logs, then log into security.microsoft.com. Search for **apiproxy** and select a request.

![img](./img/sccauth-1.png)

Under headers, scroll down under the cookies section, copy the value after sccauth (it is very long) all the way to the next semicolon and save it into the $sccauth variable. Now do the same for xsrf-token and save it into the $xsrf variable.

![img](./img/sccauth-2.png)

Now we can create a session with those cookies:

```powershell
# Create session to store cookies in
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

# Copy sccauth from the browser
$sccauth = Get-Clipboard
$session.Cookies.Add((New-Object System.Net.Cookie("sccauth", "$sccauth", "/", "security.microsoft.com")))

# Copy xsrf token from the browser
$xsrf = Get-Clipboard
$session.Cookies.Add((New-Object System.Net.Cookie("XSRF-TOKEN", "$xsrf", "/", "security.microsoft.com")))

# Set the headers to include the xsrf token
[Hashtable]$Headers=@{}
$headers["X-XSRF-TOKEN"] = [System.Net.WebUtility]::UrlDecode($session.cookies.GetCookies("https://security.microsoft.com")['xsrf-token'].Value)
```

With this complete, we can now make requests to the internal API :)

## Advanced Features

The body below will enable most options in Advanced features except "Restrict correlation to within scoped device groups​" which is not applicable to most organizations. Some settings, such as Live Response and Deception require additional API calls.

```powershell
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
    M365SecureScoreIntegrationEnabled = $false
    MagellanOptOut = $false
    MobileDeactivationPeriodInDays = $null
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
| AatpIntegrationEnabled | False  | ??? Not in portal - Likely removed as these are always integrated in XDR now ??? |
| AatpWorkspaceExists | False  | ??? Not in portal - Likely removed as these are always integrated in XDR now ??? |
| AllowWdavNetworkBlock | True  | Custom network indicators |
| AutoResolveInvestigatedAlerts | True  | Automatically resolve alerts |
| BilbaoApproved | False  | Endpoint Attack Notifications |
| BilbaoEnabled | False  | Endpoint Attack Notifications |
| BlockListEnabled | True | Allow or block file | 
| DartDataCollection | False  | Microsoft Defender Experts integration |
| EnableAggregatedReporting | False  | ??? Not in portal - Not sure... ??? |
| EnableAipIntegration | False  | Not in portal - Likely replaced by newer Compliance Center sharing |
| EnableAuditTrail | True  | Unified audit log |
| EnableCustomAsrAdvancedProcessTermination | False  | ??? Not in portal - Custom ASR rules with the ability to terminate processes ??? |
| EnableEndpointDlp | True  | Not in portal - True when we have provisioned Endpoint DLP in Purview |
| EnableExcludedDevices | False  | ??? Not in portal - Maybe from before we could exclude devices from TVM repoting ??? |
| EnableMcasIntegration | True  | Microsoft Defender for Cloud Apps |
| EnableQuarantinedFileDownload | True  | Download quarantined files |
| EnableWdavAntiTampering | True  | Tamper protection |
| EnableWdavAuditMode | False | ??? Not in portal - Might be to force passive mode across all devices ??? |
| EnableWdavPassiveModeRemediation | True | Enable EDR in block mode |
| HidePotentialDuplications | True | Hide potential duplicate device records |
| IsolateIncidentsWithDifferentDeviceGroups | False  | Restrict correlation to within scoped device groups​ |
| LicenseEnabled | True | ??? Not in portal - Need to check M365 Business Premium and E3 tenant, likely true if licensed but maybe means license level ??? |
| M365SecureScoreIntegrationEnabled | False  | ??? Not in portal - Likely removed as these are always integrated in XDR now ??? |
| MagellanOptOut | False  | Device discovery |
| MobileDeactivationPeriodInDays | Null  | ??? Not in portal - Might be adjustable timeout for mobile devices before marking them as not active ???|
| ShowUserAadProfile | True  | Show user details |
| SkypeIntegrationEnabled | True  | Skype for business integration |
| UseSimplifiedConnectivity | True  | Default to streamlined connectivity when onboarding devices in Defender portal​​ |
| UseSimplifiedConnectivityViaApi | True  | Apply streamlined connectivity settings to devices managed by Intune and Defender for Cloud |
| WebCategoriesEnabled | True  | Web content filtering |

These are a good starting point, and you can adjust as needed for your environment. If you have a dev tenant, you can definitely play with some of these settings and see what breaks ;)

The following will enable Live Response for clients and servers, and it will also allow unsigned scripts to be run. It is recommended to move to signed scripts, but remember that uploading scripts to the library still requires administrative rights to begin with.

```powershell
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
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/k8s/deception/portal/deceptionsettings/update" -Body "{`"isDeceptionEnabled` =true}" -ContentType "application/json" -WebSession $session -Headers $headers
```

To enable Share endpoint alerts with Microsoft Compliance Center:

```powershell
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/wdatpInternalApi/compliance/alertSharing/status/" -Body "true" -ContentType "application/json" -WebSession $session -Headers $headers
```

To enable Microsoft Intune connection:

```powershell
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/onboarding/intune/provision" -Body "{`"timeout` =60000}" -ContentType "application/json" -WebSession $session -Headers $headers
```

To enable Authenticated telemetry:

```powershell
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/responseApiPortal/senseauth/allownonauthsense" -Body "{`"allowNonAuthenticatedSense` =true}" -ContentType "application/json" -WebSession $session -Headers $headers
```

To enable Preview features:

```powershell
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/mtp/settings/SavePreviewExperienceSetting?context=MdatpContext" -Body "{`"IsOptIn` =true}" -ContentType "application/json" -WebSession $session -Headers $headers
```

## Roles

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

## Device Groups

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
    @{ OperatorType = 4; Property = 3; PropertyValue = "[`"WindowsServer2022`",`"WindowsServer2019`",`"WindowsServer2016`",`"WindowsServer2012R2`",`"WindowsServer2008R2`",`"Windows8blueserver`",`"Windows8server`",`"Windows2008`",`"Windows2016`",`"Windows2003`"]" }
    @{ OperatorType = 0; Property = 4; PropertyValue = "" }
  )
  MachineGroupAssignments = @()
  OldMachineGroupId = $null
} | ConvertTo-Json -Depth 4

# Non-Privileged Servers
$NonPrivServers = @{
  MachineGroupId = -1
  Name = "Non-Privileged Servers"
  Description = "Non-Privileged Servers"
  AutoRemediationLevel = 3
  Priority = 123456789
  IsUnassignedMachineGroup = $false
  MachineCount = 0
  LastUpdated = "2024-11-01T00:00:00.000Z"
  GroupRules = @(
    @{ OperatorType = 0; Property = 0; PropertyValue = "" }
    @{ OperatorType = 0; Property = 1; PropertyValue = "" }
    @{ OperatorType = 0; Property = 2; PropertyValue = "" }
    @{ OperatorType = 4; Property = 3; PropertyValue = "[`"WindowsServer2022`",`"WindowsServer2019`",`"WindowsServer2016`",`"WindowsServer2012R2`",`"WindowsServer2008R2`",`"Windows8blueserver`",`"Windows8server`",`"Windows2008`",`"Windows2016`",`"Windows2003`"]" }
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

# Non-Privileged Endpoints
$NonPrivEndpoints = @{
  MachineGroupId = -1
  Name = "Non-Privileged Endpoints"
  Description = "Non-Privileged Endpoints"
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
$PrivServers,$NonPrivServers,$PrivEndpoints,$NonPrivEndpoints | ForEach-Object {
    # Get existing devices groups
    $existingGroups = (Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/mtp/rbacManagementApi/rbac/machine_groups?addAadGroupNames=true&addMachineGroupCount=false" -ContentType "application/json" -WebSession $session -Headers $headers).items

    # Create new body, setting priority to one less than the previous lowest device group priority
    0..($existingGroups.count -1) | ForEach-Object { [array]$body += "$($existingGroups[$_] | ConvertTo-Json -Depth 4)," }
    $body += $_.Replace('123456789',$existingGroups.Priority[-2] + 1)

    # Create new device group
    Invoke-RestMethod -Method PUT -Uri "https://security.microsoft.com/apiproxy/mtp/rbacManagementApi/rbac/machine_groups" -Body "[$body]" -ContentType "application/json" -WebSession $session -Headers $headers

    # Cleanup and wait
    Remove-Variable existingGroups,body
    Start-Sleep -Seconds 15
}
```