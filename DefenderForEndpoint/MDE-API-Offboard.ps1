## Service Principal Info
$tenantId = '847b5907-ca15-40f4-b171-eb18619dbfab'
$appId = '6b5b624f-994b-4ad7-bd38-16a6baa476a2'
$appSecret = 'Mug8Q~WQdVqrn83BRM8NUSaoRlfj9YjaR1YyIDahp'
 
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

# List of deviceIds to be offboarded (MDE deviceId, not Entra deviceId or Intune deviceId)
$deviceIds = "1283558cd4e01916cb61d605968640c8b290a9bf","9383128cd4e01916cb61d605968640c8b290a2da"

# Create body with comment
$body = @{
    "Comment" = "Offboard machine by script"
} | ConvertTo-Json

# Offboard each device in the list of $deviceIds
$deviceIds | ForEach-Objects {
    Invoke-WebRequest -Method POST -Uri "https://api.security.microsoft.com/api/machines/$_/offboard" -Body $body -Headers $headers
}
