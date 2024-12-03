# Automated Configuration

This is a collection of commands that will help automate the configuration of the Defender for Identity settings. To use this, you must obtain the sccauth value and xsrf-token value from the browser and use it to create cookies and headers for our API calls. This is because we are using an internal API to configure settings, and there isn't a public way to get the right tokens.

## Table of Contents

[Setting up our session and cookies](README.md#setting-up-our-session-and-cookies)

[Creating the workspace](README.md#creating-the-workspace)

[General - Sensors](README.md#sensors)

[General - Directory services accounts](README.md#directory-services-accounts)

[General - Manage action accounts](README.md#roles)

[General - VPN](README.md#vpn)

[General - Adjust alert threshholds](README.md#adjust-alert-threshholds)

[General - About](README.md#about)

[Entity tags - Sensitive](README.md#sensitive)

[Entity tags - Honeytoken](README.md#honeytoken)

[Entity tags - Exchange server](README.md#exchange-server)

[Actions and exclusions - Global excluded entities](README.md#global-excluded-entities)

[Actions and exclusions - Exclusions by detection rule](README.md#exclusions-by-detection-rule)

[Notifications - Health issues notifications](README.md#health-issues-notifications)

[Notifications - Alert notifications](README.md#alert-notifications)

[Notifications - Syslog notifications](README.md#syslog-notifications)

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

## Creating the workspace

We can check and see if the Defender for Identity workspace has been created yet, and if not, create it. For new deployments, this will be important to kick off provisioining and check before we attempt to configure the service ;)

```powershell
# Check if workspace exists
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/workspaces/isWorkspaceExists/" -ContentType "application/json" -WebSession $session -Headers $headers

# If 

```
## General

### Sensors

This is where we can check health of existing sensors and download new sensors for installation

```powershell
# Check how many DCs exist and are being covered
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/sensors/domainControllerCoverage" -ContentType "application/json" -WebSession $session -Headers $headers

# Get list of sensors
(Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/odata/sensors" -ContentType "application/json" -WebSession $session -Headers $headers).value

# Get access key
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/workspace/sensorDeploymentAccessKey" -ContentType "application/json" -WebSession $session -Headers $headers

# Get sensor download
$url = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/sensors/deploymentPackageUri" -ContentType "application/json" -WebSession $session -Headers $headers

```

To edit sensor settings, we can do the following:

```powershell
# Get sensor
$name = "sml-dc01"
$sensor = (Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/odata/sensors" -ContentType "application/json" -WebSession $session -Headers $headers).value | Where-Object { $_.Name -eq $name }

# Here you can modify Description and whether the network adapter is enabled or not
$body = @{
  Description = "Description"
  NetworkAdapters = @(@{
    Id = $sensor.Settings.NetworkAdapters.Id
    IsEnabled = $true
    Name = $sensor.Settings.NetworkAdapters.Name
  })
  DomainControllerDnsNames = @($sensor.Settings.DomainControllerDnsNames)
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Method "PUT" -Uri "https://security.microsoft.com/apiproxy/aatp/odata/sensors/$($sensor.Id)/settings" -ContentType "application/json" -Body $body -WebSession $session -Headers $headers

```

To enable/disable delayed updates, we can do the following:

```powershell
# Get sensor
$name = "sml-dc01"
$sensor = (Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/odata/sensors" -ContentType "application/json" -WebSession $session -Headers $headers).value | Where-Object { $_.Name -eq $name }

# $true enables delayed deployment, $false disables delayed deployment
$body = @{ IsDelayedDeploymentEnabled = $false } | ConvertTo-Json

Invoke-RestMethod -Method "PUT" -Uri "https://security.microsoft.com/apiproxy/aatp/odata/sensors/$($sensor.Id)/settings" -ContentType "application/json" -Body $body -WebSession $session -Headers $headers

```

I did not document deleting a sensor here for a few reasons, but it is possible to mass delete sensors... :)

### Directory services accounts

Directory services accounts

```powershell
# Get a list of directory services accounts
(Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/odata/directoryServices" -ContentType "application/json" -WebSession $session -Headers $headers).value

```

To add a directory services account:

```powershell
# Add a directory services accounts
$body = @{
  Id = ""
  AccountName = "gmsa-mdi-ds"
  DomainDnsName = "sharemylabs.com"
  AccountPassword = $null
  IsGroupManagedServiceAccount = $true
  IsSingleLabelAccountDomainName = $false
} | ConvertTo-Json

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/aatp/odata/directoryServices" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers -AllowInsecureRedirect

```

To delete a directory services account:

```powershell
# Delete a directory services accounts
$body = @{ id = "gmsa-mdi-ds@sharemylabs.com" } | ConvertTo-Json

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/aatp/odata/directoryServices/delete" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers

```

### Manage action accounts

Manage action accounts


```powershell
# Get configuration for action accounts
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/remediationActions/configuration" -ContentType "application/json" -WebSession $session -Headers $headers

```

Enable using local SYSTEM account for remediation action:

```powershell
# Turn off using local system for action account
$body = @{ IsRemediationWithLocalSystemEnabled = $true }

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/aatp/api/remediationActions/configuration" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers
```

Turn off system account for remediation and manually configure a gMSA (not recommended):

```powershell
# Add action accout
$body = @{ 
  Id = ""
  AccountName = "gmsa-mdi-action"
  DomainDnsName = "sharemylabs.com"
  AccountPassword = $null
  IsGroupManagedServiceAccount = $true
  IsSingleLabelAccountDomainName = $false 
}

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/aatp/odata/EntityRemediatorCredentials" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers

# Turn off using local system for action account
$body = @{ IsRemediationWithLocalSystemEnabled = $false }

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/aatp/api/remediationActions/configuration" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers

```

### VPN

VPN

```powershell
# Get current configuration
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/mtp/vpnConfiguration/" -ContentType "application/json" -WebSession $session -Headers $headers

```

Enable RADIUS accounting and save shared secret:

```powershell
# Enable and configure RADIUS accounting shared secret
$body = @{
  IsRadiusEventListenerEnabled = $true
  RadiusEventListenerSharedSecret = "secretValue"
} | ConvertTo-Json
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/aatp/api/mtp/vpnConfiguration/" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers

```

Turn off RADIUS accounting:

```powershell
# Disable RADIUS accounting
$body = @{
  IsRadiusEventListenerEnabled = $false
  RadiusEventListenerSharedSecret = ""
} | ConvertTo-Json
Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/aatp/api/mtp/vpnConfiguration/" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers

```

### Adjust alert threshholds

Adjust alert threshholds

```powershell
$response = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/alertthresholds" -ContentType "application/json" -WebSession $session -Headers $headers

# Check if Recommended test mode is enabled
$response.IsRecommendedTestModeEnabled

# Check alert thresholds
$response.AlertThresholds

```

To change a threshold:

```powershell
# Get current configuration
$response = Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/alertthresholds" -ContentType "application/json" -WebSession $session -Headers $headers

# Review thresholds
$response.AlertThresholds

# Change thresholds
$response.AlertThresholds[1].Threshold = "Low"
$response.AlertThresholds[6].Threshold = "Medium"

# Save body
$body = $response | ConvertTo-Json -Depth 4

Invoke-RestMethod -Method "POST" -Uri "https://security.microsoft.com/apiproxy/aatp/api/alertthresholds" -Body $body -ContentType "application/json" -WebSession $session -Headers $headers

```

### About

This is some basic data about the workspace and licenses

```powershell
Invoke-RestMethod -Uri "https://security.microsoft.com/apiproxy/aatp/api/mtp/applicationData" -ContentType "application/json" -WebSession $session -Headers $headers

```

## Entity tags

### Sensitive

Sensitive

```powershell

```

### Honeytoken

Honeytoken

```powershell

```

### Exchange servers

Exchange servers

```powershell

```

## Actions and exclusions

### Global excluded entities

Global excluded entities

```powershell

```

### Exclusions by detection rule

Exclusions by detection rule

```powershell

```

## Notifications

### Health issue notifications

```powershell

```

### Alert notifications

```powershell

```

### Syslog notifications

```powershell

```