# Connect to the Graph API as the automation account managed identity
Connect-MgGraph -Identity

# Get Zulu formatted time from 90 days ago for filter
$date = (Get-Date (Get-Date).AddDays(-90) -Format u).Replace(' ','T')

# Get devices that haven't signed in for more than 90 days
$devices = Get-MgDevice -All -Filter "ApproximateLastSignInDateTime le $date"

# If less than 10 devices, delete them
if ($devices.count -lt 10) {
   $devices | ForEach-Object { 
      Write-Output "Deleting $($_.DisplayName),$($_.DeviceId)"
      Remove-MgDevice -DeviceId $_.Id
   }
} else { Write-Output "Safety threshold reached - $($devices.count) devices found" }