## Requires Device.ReadWrite.All and MI or SP in Cloud Device Administrator
# Get connection information from the automation account
$Connection = Get-AutomationConnection -Name AzureRunAsConnection

# Connect to the Graph API as the automation account
Connect-MgGraph -ClientID $Connection.ApplicationId -TenantId $Connection.TenantId -CertificateThumbprint $Connection.CertificateThumbprint

# Get Zulu formatted time from 90 days ago for filter
$date = (Get-Date (Get-Date).AddDays(-90) -Format u).Replace(' ','T')

# Get devices that haven't signed in for more than 90 days and disable them
Get-MgDevice -All -Filter "ApproximateLastSignInDateTime le $date" | ForEach-Object { 
	Update-MgDevice -DeviceId $_.Id -AccountEnabled:$false
}