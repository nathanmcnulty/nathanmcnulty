# Defender for Endpoint API

## Authenticating

```powershell
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
```

## Granting permissions to Managed Identities

```powershell
$MI = "34634404-8c0b-4141-a9dd-195fa6e6a51f"

# Connect to Graph with scope to grant API permissions to Managed Identity
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"

# Get SP for WindowsDefenderATP API
$MdeSp = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq 'fc780465-2017-40d4-a0c5-307022471b92'").value

# Get each permission App Role ID and assign the App Role to the Managed Identity
"Machine.ReadWrite.All" | ForEach-Object {
   $permission = $_
   $AppRole = $MdeSp.AppRoles | Where-Object {$_.Value -eq $permission -and $_.AllowedMemberTypes -contains "Application"}
   $body = @{
    "principalId" = $MI
    "resourceId" = $MdeSp.Id
    "appRoleId" = $AppRole.Id
   }
   Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MI/appRoleAssignments" -Body ($body | ConvertTo-Json) -ContentType "application/json"
}
```
