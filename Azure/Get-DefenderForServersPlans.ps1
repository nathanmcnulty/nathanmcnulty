# Tenant Id
$tenantId = ''

# Get Azure access token
$token = Get-AzAccessToken -TenantId $tenantId -ResourceUrl "https://management.azure.com"

# Iterate through subscriptions and output Defender for Servers Plan
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
(Get-AzSubscription -TenantId $tenantId) | ForEach-Object {
    # Request Defender plans
    $wr = @{
        UseBasicParsing = $true
        Uri = "https://management.azure.com/subscriptions/$($_.Id)/providers/Microsoft.Security/pricings?api-version=2023-01-01"
        Method = "GET"
        WebSession = $session
        Headers = @{
            "Authorization"="Bearer $($token.token)"
        }
        ContentType = "application/json"
    }
    $plan = (((Invoke-WebRequest @wr).Content | ConvertFrom-Json).value | where-object { $_.name -eq 'VirtualMachines' }).properties.subPlan
    if ($plan -notmatch 'P') { $plan = 'Not Enabled' }
    [array]$report += "$($_.Name),$($_.Id),$plan"
}
$report