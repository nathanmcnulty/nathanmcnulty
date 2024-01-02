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

# Import Indicators
$body = '{
    "Indicators":
    [
        {
            "indicatorValue": "123.123.123.123",
            "indicatorType": "IpAddress",
            "title": "CS Team Server",
            "application": null,
            "expirationTime": "2022-04-01T00:00:00Z",
            "action": "Block",
            "severity": "Informational",
            "description": "Block communication to CS Team Servers",
            "recommendedActions": "nothing",
            "rbacGroupNames": []
        },
        {
            "indicatorValue": "maliciousdomain.com",
            "indicatorType": "DomainName",
            "title": "Malicious Domain",
            "application": null,
            "expirationTime": "2022-12-31T00:00:00Z",
            "action": "Block",
            "severity": "Medium",
            "description": "Block malicious domain",
            "recommendedActions": "nothing",
            "rbacGroupNames": []
        },
    {
            "indicatorValue": "https://www.reddit.com/r/riskysubforum",
            "indicatorType": "Url",
            "title": "Risky URL",
            "application": null,
            "expirationTime": "2022-12-31T00:00:00Z",
            "action": "Alert",
            "severity": "Medium",
            "description": "Alert on visit to risky URLs",
            "recommendedActions": "nothing",
            "rbacGroupNames": []
        }
    ]
}'
Invoke-WebRequest -Method POST -Uri "https://api.securitycenter.microsoft.com/api/indicators/import" -Headers $headers -Body $body