# Automated Configuration

This is a collection of commands that will help autoamte the configuration of the Defender XDR portal settings. To use this, you must obtain the sccauth token value from the browser and use it in the script. This is because we are using an internal API to configure settings, and there isn't a public way to get the right tokens.

## Setting up our session and cookies

First, we need to create a session object contaning the sccauth cookie copied from the browser. To get this, open Developer Tools in your browser and make sure the Network tab is set to preserve logs, then log into security.microsoft.com. Search for **apiproxy** and select a request.

![img](./img/sccauth-1.png)

Under headers, scroll down under the cookies section and copy the value after sccauth (it is very long) all the way to the next semicolon.

![img](./img/sccauth-2.png)

Now we can create a session with that cookie:

```powershell
# Create session to store cookies in
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

# Copy sccauth cookie from browser
$sccauth = Get-Clipboard
$session.Cookies.Add((New-Object System.Net.Cookie("sccauth", "$sccauth", "/", "security.microsoft.com")))
```

With this complete, we can now make requests to the internal API :)

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
