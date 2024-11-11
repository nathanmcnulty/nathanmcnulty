# Automated Configuration

This is a collection of commands that will help automate the configuration of the Defender XDR portal settings. To use this, you must obtain the sccauth value and xsrf-token value from the browser and use it to create cookies and headers for our API calls. This is because we are using an internal API to configure settings, and there isn't a public way to get the right tokens.

## Setting up our session and cookies

First, we need to create a WebRequestSession object contaning the sccauth and xsrf cookies copied from the browser and headers with the xsrf token. To get this, open Developer Tools in your browser and make sure the Network tab is set to preserve logs, then log into security.microsoft.com. Search for **apiproxy** and select a request.

![img](./img/sccauth-1.png)

Under headers, scroll down under the cookies section, copy the value after sccauth (it is very long) all the way to the next semicolon and save it into the $sccauth variable. Now do the same for xsrf-token and save it into the $xsrf variable.

![img](./img/sccauth-2.png)

Now we can create a session with that cookie:

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

## Defender XDR - Alert service settings

By default, Entra Identity Protection only shares High risk alerts to the Defender XDR service, and none of the Defender for Cloud alerts are shared. 

Most organizations will find more value in using Defender XDR as a unified security platform for all investigation and response, so I recommend enabling all alerts and handling everything in the unified Defender platform.

### Microsoft Entra ID Protection

This body configures to "All alerts" (Recommended):

```powershell
$body = @{
    Feedback = $null
    DisablementType = "None"
} | ConvertTo-Json
```

This body configures to "High-impact alerts only":

```powershell
$body = @{
    Feedback = $null
    DisablementType = "None"
} | ConvertTo-Json
```

This command makes the change:

```powershell
Invoke-RestMethod -Method PUT -Uri "https://security.microsoft.com/apiproxy/mtp/alertsApiService/workloads/disabled?workload=Aad" -Body $body -ContentType "application/json" -WebSession $session
```

### Defender for Cloud

This body configures to "All alerts" (Recommended):

```powershell
$body = @{
    Feedback = $null
    DisablementType = "None"
} | ConvertTo-Json
```

This body configures to "No alerts":

```powershell
$body = @{
    Feedback = $null
    DisablementType = "Full"
} | ConvertTo-Json
```

This command makes the change:

```powershell
Invoke-RestMethod -Method PUT -Uri "https://security.microsoft.com/apiproxy/mtp/alertsApiService/workloads/disabled?workload=Mdc"  -Body $body -ContentType "application/json" -WebSession $session
```
