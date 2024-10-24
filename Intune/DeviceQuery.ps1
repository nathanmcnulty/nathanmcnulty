# You will need to obtain a bearer token with permissions to use device query and use it with this script
$token = Get-Clipboard

# Convert query to base64
$query = [Convert]::ToBase64String([char[]]'WindowsEvent("Microsoft-Windows-CodeIntegrity/Operational") | where EventId == 3076')

# Get devices from a group and translate to their Intune object ID
$devices = ((Get-MgGroupMember -GroupId 84e4d080-9f80-45b2-8c19-d2c2ab973745).Id | ForEach-Object {
    Get-MgDeviceManagementManagedDevice -Filter "AzureAdDeviceId eq '$((Get-MgDevice -DeviceId $_).DeviceId)'"
}).Id

# Make the request to create the device query for each device and store the Intune ID and query ID in a variable
$headers = @{
    "authorization"="Bearer $token"
}
$body = @{
    query = $query
} | ConvertTo-Json
$devices | ForEach-Object { 
    [array]$responses += "$_,$((Invoke-RestMethod -UseBasicParsing -Uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices/04faf88e-6fe3-46df-8d9c-6da64b912f5b/createQuery' -Method 'POST' -Headers $headers -ContentType 'application/json' -Body $body).Id)"
}

# The query may take a while and you'll need to play with the delay
Start-Sleep -Seconds 60

# Iterate through each response and get the results
$responses | ForEach-Object {
    [array]$results += (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($_.split(',')[0])/queryResults/$($_.split(',')[1])" -Headers $headers -ContentType 'application/json').results
}

# Decode the base64 responses back to something we can read :)
$bytes = [Convert]::FromBase64String($results)
[System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
