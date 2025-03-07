# Get Azure access token
$token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-AzAccessToken -ResourceUrl "https://management.azure.com" -AsSecureString).Token))

# Iterate through subscriptions and output Defender for Servers Plan
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
Get-AzSubscription | ForEach-Object {
    # Request Defender plans
    $wr = @{
        UseBasicParsing = $true
        Uri = "https://management.azure.com/subscriptions/$($_.Id)/providers/Microsoft.Security/pricings?api-version=2023-01-01"
        Method = "GET"
        WebSession = $session
        Headers = @{
            "Authorization"="Bearer $token"
        }
        ContentType = "application/json"
    }
    $plan = (((Invoke-WebRequest @wr).Content | ConvertFrom-Json).value | where-object { $_.name -eq 'VirtualMachines' }).properties.subPlan
    if ($plan -notmatch 'P') { $plan = 'Not Enabled' }
    [array]$report += "$($_.Name),$($_.Id),$plan"
}
$report