# Connect to the Graph API as the automation account
Connect-MgGraph -Identity

# Get Zulu formatted time from 90 days ago for filter
$date = (Get-Date (Get-Date).AddDays(-90) -Format u).Replace(' ','T')

# Get devices that haven't signed in for more than 90 days and disable them
Get-MgDevice -All -Filter "ApproximateLastSignInDateTime le $date"  | ForEach-Object { 
	Write-Output "Deleting $($_.DisplayName),$($_.DeviceId)"
    Remove-MgDevice -DeviceId $_.Id
}
