## Service Principal Info
$tenantId = '847b3907-ca15-b0f4-b171-eb18319dbfab'
$appId = '6b3b624f-99bb-4ad7-bd38-16a6b3a476a2'
$appSecret = 'wjA8Q~vTRm3XChp_IzD2odWYKWZcaoA9a4Ozldrl'

## Get Token
$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$token = (Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop).access_token

## Set the WebRequest headers
$headers = @{
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token"
}

# Get list of devices with a VDI or ServerCore tag
[array]$VDI = (Invoke-WebRequest -Method GET -Uri "https://api.securitycenter.microsoft.com/api/machines/findbytag?tag=VDI" -Headers $headers | ConvertFrom-Json).value.Id
[array]$ServerCore = (Invoke-WebRequest -Method GET -Uri "https://api.securitycenter.microsoft.com/api/machines/findbytag?tag=ServerCore" -Headers $headers | ConvertFrom-Json).value.Id

# Get list of Servers that do not have the VDI or ServerCore tag
[array]$EligibleServers = (Invoke-WebRequest -Method GET -Uri "https://api.securitycenter.microsoft.com/api/machines" -Headers $headers | ConvertFrom-Json).value.Id | Where-Object { $_.osPlatform -like "WindowsServer*" -and $_ -notin $VDI -and $_ -notin $ServerCore }

# Add MDE-Management tag
$body = @{
    "Value" = "MDE-Management"
    "Action" = "Add"
    "MachineIds" = @($EligibleServers)
} | ConvertTo-Json
Invoke-WebRequest -Method POST -Uri "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines" -Headers $headers -Body $body

# Remove MDE-Management tag if applied by accident
$body = @{
    "Value" = "MDE-Management"
    "Action" = "Remove"
    "MachineIds" = @($VDI)
} | ConvertTo-Json
Invoke-WebRequest -Method POST -Uri "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines" -Headers $headers -Body $body
$body = @{
    "Value" = "MDE-Management"
    "Action" = "Remove"
    "MachineIds" = @($ServerCore)
} | ConvertTo-Json
Invoke-WebRequest -Method POST -Uri "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines" -Headers $headers -Body $body
