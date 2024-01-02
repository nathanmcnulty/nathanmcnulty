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
            "action": "Block",
            "severity": "High",
            "category": 1,
            "application": null,
            "educateUrl": null,
            "bypassDurationHours": null,
            "title": "CS Team Server",
            "description": "Block communication to CS Team Servers",
            "recommendedActions": "nothing",
            "expirationTime": "2024-04-01T00:00:00Z",
            "lastUpdatedBy": null,
            "rbacGroupNames": [],
            "rbacGroupIds": [],
            "notificationId": null,
            "notificationBody": null,
            "version": null,
            "mitreTechniques": [],
            "historicalDetection": false,
            "lookBackPeriod": null,
            "generateAlert": true,
            "additionalInfo": null,
            "externalId": null,
            "certificateInfo": null
        },
        {
            "indicatorValue": "maliciousdomain.com",
            "indicatorType": "DomainName",
            "action": "Block",
            "severity": "Medium",
            "category": 1,
            "application": null,
            "educateUrl": null,
            "bypassDurationHours": null,
            "title": "Malicious Domain",
            "description": "Block malicious domain",
            "recommendedActions": "nothing",
            "expirationTime": "2024-12-31T00:00:00Z",
            "lastUpdatedBy": null,
            "rbacGroupNames": [],
            "rbacGroupIds": [],
            "notificationId": null,
            "notificationBody": null,
            "version": null,
            "mitreTechniques": [],
            "historicalDetection": false,
            "lookBackPeriod": null,
            "generateAlert": false,
            "additionalInfo": null,
            "externalId": null,
            "certificateInfo": null
        },
        {
            "indicatorValue": "https://www.reddit.com/r/riskysubforum",
            "indicatorType": "Url",
            "action": "Audit",
            "severity": "Low",
            "category": 1,
            "application": null,
            "educateUrl": null,
            "bypassDurationHours": null,
            "title": "Risky URL",
            "description": "Alert on visit to risky URLs",
            "recommendedActions": "nothing",
            "expirationTime": "2024-12-31T00:00:00Z",
            "lastUpdatedBy": null,
            "rbacGroupNames": [],
            "rbacGroupIds": [],
            "notificationId": null,
            "notificationBody": null,
            "version": null,
            "mitreTechniques": [],
            "historicalDetection": false,
            "lookBackPeriod": null,
            "generateAlert": true,
            "additionalInfo": null,
            "externalId": null,
            "certificateInfo": null
        },
        {
            "indicatorValue": "3395856ce81f2b7382dee72602f798b642f14140",
            "indicatorType": "FileSha1",
            "action": "Audit",
            "severity": "Informational",
            "category": 1,
            "application": null,
            "educateUrl": null,
            "bypassDurationHours": null,
            "title": "EICAR SHA1",
            "description": "Testing",
            "recommendedActions": "nothing",
            "expirationTime": "2024-12-31T00:00:00Z",
            "lastUpdatedBy": null,
            "rbacGroupNames": [],
            "rbacGroupIds": [],
            "notificationId": null,
            "notificationBody": null,
            "version": null,
            "mitreTechniques": [],
            "historicalDetection": false,
            "lookBackPeriod": null,
            "generateAlert": true,
            "additionalInfo": null,
            "externalId": null,
            "certificateInfo": null
        },
        {
            "indicatorValue": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "indicatorType": "FileSha256",
            "action": "Allowed",
            "severity": "Informational",
            "category": 1,
            "application": null,
            "educateUrl": null,
            "bypassDurationHours": null,
            "title": "EICAR SHA256",
            "description": "Testing",
            "recommendedActions": "nothing",
            "expirationTime": "2024-12-31T00:00:00Z",
            "lastUpdatedBy": null,
            "rbacGroupNames": [],
            "rbacGroupIds": [],
            "notificationId": null,
            "notificationBody": null,
            "version": null,
            "mitreTechniques": [],
            "historicalDetection": false,
            "lookBackPeriod": null,
            "generateAlert": false,
            "additionalInfo": null,
            "externalId": null,
            "certificateInfo": null
        },
        {
            "indicatorValue": "6e2cac2f88c3309ec6559b7ccdb94b8c4195d0e5",
            "indicatorType": "CertificateThumbprint",
            "action": "Allowed",
            "severity": "Informational",
            "category": 1,
            "application": null,
            "educateUrl": null,
            "bypassDurationHours": null,
            "title": "Tailscale",
            "description": "Tailscale",
            "recommendedActions": "nothing",
            "expirationTime": "2024-12-31T00:00:00Z",
            "lastUpdatedBy": null,
            "rbacGroupNames": [],
            "rbacGroupIds": [],
            "notificationId": null,
            "notificationBody": null,
            "version": null,
            "mitreTechniques": [],
            "historicalDetection": false,
            "lookBackPeriod": null,
            "generateAlert": false,
            "additionalInfo": null,
            "externalId": null,
            "certificateInfo": {
                "issuer": "CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, O=\"DigiCert, Inc.\", C=US",
                "serial": "0192B944718F5465875E5BD94E52EBDA",
                "subject": "CN=Tailscale Inc., O=Tailscale Inc., L=Toronto, S=Ontario, C=CA, SERIALNUMBER=1131559-5, businessCategory=Private Organization, jurisdictionCountryName=CA",
                "sha256": "8f7183d53245db675d52cf00d75990d924011f9dd81c61114ce6e063cb726043"
            }
        }
    ]
}'
$response = Invoke-WebRequest -Method POST -Uri "https://api.securitycenter.microsoft.com/api/indicators/import" -Headers $headers -Body $body
