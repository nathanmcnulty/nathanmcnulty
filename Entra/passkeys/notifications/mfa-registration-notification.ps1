param(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData,

    [Parameter(Mandatory = $false)]
    [object] $Request,

    [Parameter(Mandatory = $false)]
    [object] $TriggerMetadata,

    [Parameter(Mandatory = $false)]
    [string] $SenderMailbox = $env:SENDER_MAILBOX,

    [Parameter(Mandatory = $false)]
    [string] $AllowedRecipientDomains = $env:ALLOWED_RECIPIENT_DOMAINS,

    [Parameter(Mandatory = $false)]
    [string] $HelpdeskContact = $(if ($env:HELPDESK_CONTACT) { $env:HELPDESK_CONTACT } else { 'the helpdesk' }),

    [Parameter(Mandatory = $false)]
    [string] $EmailSubjectPrefix = $(if ($env:EMAIL_SUBJECT_PREFIX) { $env:EMAIL_SUBJECT_PREFIX } else { '[Security notification] MFA method registered:' })
)

$ErrorActionPreference = 'Stop'
$null = $TriggerMetadata

function ConvertFrom-JsonIfNeeded {
    param([object] $Value)

    if ($Value -is [string]) {
        return $Value | ConvertFrom-Json
    }

    return $Value
}

function Get-FirstDetailValue {
    param(
        [object] $Details,
        [string] $Name,
        [string] $DefaultValue = ''
    )

    $value = if ($Details -is [System.Collections.IDictionary]) {
        $Details[$Name]
    }
    else {
        $property = $Details.PSObject.Properties[$Name]
        if ($null -ne $property) { $property.Value }
    }

    if ($null -eq $value) {
        return $DefaultValue
    }

    $values = @($value)
    if ($values.Count -eq 0 -or [string]::IsNullOrWhiteSpace([string]$values[0])) {
        return $DefaultValue
    }

    return [string]$values[0]
}

if ([string]::IsNullOrWhiteSpace($SenderMailbox)) {
    throw 'SenderMailbox is required. Set the runbook parameter or SENDER_MAILBOX application setting.'
}

if ([string]::IsNullOrWhiteSpace($AllowedRecipientDomains)) {
    throw 'AllowedRecipientDomains is required. Supply a comma- or semicolon-separated list of accepted recipient domains.'
}

$payload = if ($null -ne $WebhookData) {
    $automationInput = ConvertFrom-JsonIfNeeded -Value $WebhookData
    if (-not $automationInput.RequestBody) {
        throw 'WebhookData.RequestBody is empty.'
    }
    ConvertFrom-JsonIfNeeded -Value $automationInput.RequestBody
}
elseif ($null -ne $Request) {
    ConvertFrom-JsonIfNeeded -Value $Request.Body
}
else {
    throw 'Supply WebhookData from Azure Automation or Request from an HTTP-triggered Azure Function.'
}

$details = if ($payload.ExtendedProperties.'Custom Details') {
    ConvertFrom-JsonIfNeeded -Value $payload.ExtendedProperties.'Custom Details'
}
elseif ($payload.CustomDetails) {
    ConvertFrom-JsonIfNeeded -Value $payload.CustomDetails
}
else {
    $payload
}

$recipientEmail = Get-FirstDetailValue -Details $details -Name 'RecipientEmail'
$authenticationMethod = Get-FirstDetailValue -Details $details -Name 'AuthenticationMethod'
$registrationTime = Get-FirstDetailValue -Details $details -Name 'RegistrationTime'
$sourceIpAddress = Get-FirstDetailValue -Details $details -Name 'SourceIPAddress' -DefaultValue 'Not recorded'
$operationName = Get-FirstDetailValue -Details $details -Name 'OperationName'
$correlationId = Get-FirstDetailValue -Details $details -Name 'CorrelationId'

foreach ($requiredValue in @{
    RecipientEmail = $recipientEmail
    AuthenticationMethod = $authenticationMethod
    RegistrationTime = $registrationTime
    OperationName = $operationName
    CorrelationId = $correlationId
}.GetEnumerator()) {
    if ([string]::IsNullOrWhiteSpace($requiredValue.Value)) {
        throw "Webhook payload is missing required field '$($requiredValue.Key)'."
    }
}

try {
    $recipientAddress = [System.Net.Mail.MailAddress]::new($recipientEmail)
}
catch {
    throw "RecipientEmail '$recipientEmail' is not a valid email address."
}

$allowedDomains = @(
    $AllowedRecipientDomains -split '[,;]' |
        ForEach-Object { $_.Trim().ToLowerInvariant() } |
        Where-Object { $_ }
)
$recipientDomain = $recipientAddress.Host.ToLowerInvariant()
if ($recipientDomain -notin $allowedDomains) {
    throw "Recipient domain '$recipientDomain' is not in AllowedRecipientDomains."
}

Connect-MgGraph -Identity -NoWelcome

$message = @{
    message = @{
        subject = "$EmailSubjectPrefix $authenticationMethod"
        body = @{
            contentType = 'Text'
            content = @"
The following MFA method was registered for your account.

MFA method: $authenticationMethod
Time: $registrationTime
Source IP address: $sourceIpAddress
Operation: $operationName
Correlation ID: $correlationId

If you registered this MFA method, no action is required. If you did not, contact $HelpdeskContact immediately.
"@
        }
        toRecipients = @(
            @{
                emailAddress = @{
                    address = $recipientAddress.Address
                }
            }
        )
    }
    saveToSentItems = $true
}

$escapedSender = [uri]::EscapeDataString($SenderMailbox)
Invoke-MgGraphRequest `
    -Method POST `
    -Uri "https://graph.microsoft.com/v1.0/users/$escapedSender/sendMail" `
    -Body ($message | ConvertTo-Json -Depth 10) `
    -ContentType 'application/json'

$result = [ordered]@{
    status = 'Accepted'
    recipient = $recipientAddress.Address
    authenticationMethod = $authenticationMethod
    correlationId = $correlationId
}

if (Get-Command Push-OutputBinding -ErrorAction SilentlyContinue) {
    Push-OutputBinding -Name Response -Value @{
        StatusCode = 202
        Body = ($result | ConvertTo-Json)
        Headers = @{ 'Content-Type' = 'application/json' }
    }
}
else {
    [pscustomobject]$result
}
