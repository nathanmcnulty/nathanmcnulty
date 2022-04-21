## Requires User.ReadWrite.All
# Get connection information from the automation account
$Connection = Get-AutomationConnection -Name AzureRunAsConnection

# Connect to the Graph API as the automation account
Connect-MgGraph -ClientID $Connection.ApplicationId -TenantId $Connection.TenantId -CertificateThumbprint $Connection.CertificateThumbprint

# Get Zulu formatted time from 7 days ago for filter
$date = (Get-Date (Get-Date).AddDays(-7) -Format u).Replace(' ','T')

# Get guest users older than 7 days and remove them
Get-MgUser -Filter "userType eq 'guest' AND createdDateTime le $date" | ForEach-Object {
    Write-Output "Removing $($_.userPrincipalName)"
    Remove-MgUser -UserId $_.Id -WhatIf
}
