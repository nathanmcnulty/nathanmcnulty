# Connect to Graph API with proper scopes
$tenantId = (Get-MgContext).TenantId
Connect-MgGraph -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All" -TenantId $tenantId

# Create SP
$app = New-MgApplication -DisplayName "O365MgmtActivityAPI" -SignInAudience "AzureADMyOrg"
$sp = New-MgServicePrincipal -AppId $app.AppId

# Create client secret
$secret = Add-MgServicePrincipalPassword -ServicePrincipalId $sp.Id

# Add ActivityFeed.Read permissions
$params = @{
    "PrincipalId" = $sp.Id
    "ResourceId" = "81868f89-2147-4232-9f11-f30f6a408210"
    "AppRoleId" = "594c1fb6-4f81-4475-ae41-0c394909246c"
}
New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -BodyParameter $params

# Get token for Office 365 Management Activity API and set headers
$tenantId = (Get-MgContext).TenantId

$body = @{
    grant_type = "client_credentials"
    resource = "https://manage.office.com"
    client_id = $sp.AppId
    client_secret = $secret.SecretText
}
$wr = @{
    Method = "POST"
    Uri = "https://login.microsoftonline.com/$tenantId/oauth2/token?api-version=1.0"
    Body = $body
}
$oauth = Invoke-RestMethod @wr
$headers = @{ "Authorization"="$($oauth.token_type) $($oauth.access_token)" }

# Start subscription using token against O365 Management Activity API
$tenantId = (Get-MgContext).TenantId
$contentType = "Audit.AzureActiveDirectory"
$webhookUrl = "https://sub.domain.com/webhook"

$body = @"
{
    "webhook" : {
        "address" : "$webhookUrl"
    }
}
"@
$wr = @{
    UseBasicParsing = $true
    Uri = "https://manage.office.com/api/v1.0/$tenantId/activity/feed/subscriptions/start?contentType=$contentType"
    Method = "POST"
    Body = $body
    ContentType = "application/json"
}
$response = Invoke-RestMethod @wr -Headers $headers

# Get subscriptions using token against O365 Management Activity API
$tenantId = (Get-MgContext).TenantId

$wr = @{
    UseBasicParsing = $true
    Uri = "https://manage.office.com/api/v1.0/$tenantId/activity/feed/subscriptions/list?"
    ContentType = "application/json"
}
$response = Invoke-RestMethod @wr -Headers $headers

# Get content from subscription using token against O365 Management Activity API
$tenantId = (Get-MgContext).TenantId
$contentType = "Audit.AzureActiveDirectory"

$wr = @{
    UseBasicParsing = $true
    Uri = "https://manage.office.com/api/v1.0/$tenantId/activity/feed/subscriptions/content?contentType=$contentType"
    ContentType = "application/json"
}
(Invoke-RestMethod @wr -Headers $headers).contentUri | ForEach-Object { [array]$content += Invoke-RestMethod -Uri $_ -Headers $headers }

# Get Content
$headers = @{ "Authorization"="$($oauth.token_type) $($oauth.access_token)" }
$response.contentUri | ForEach-Object { Invoke-RestMethod -Uri $_ -Headers $headers }

# Stop subscription using token against O365 Management Activity API
$tenantId = (Get-MgContext).TenantId
$contentType = "Audit.AzureActiveDirectory"

$wr = @{
    UseBasicParsing = $true
    Uri = "https://manage.office.com/api/v1.0/$tenantId/activity/feed/subscriptions/stop?contentType=$contentType"
    Method = "POST"
    ContentType = "application/json"
}
$response = Invoke-RestMethod @wr -Headers $headers
