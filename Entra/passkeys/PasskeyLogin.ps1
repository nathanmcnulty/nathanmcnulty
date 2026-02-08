#Requires -Version 7.0

<#
.SYNOPSIS
    Standalone script for Entra ID Passkey authentication.

.DESCRIPTION
    This script performs FIDO2 passkey authentication to Entra ID without requiring the TokenTactics module.
    It supports both loading passkey details from a JSON file or providing them manually.

.PARAMETER KeyFilePath
    Path to JSON file containing passkey details.
    
    The JSON file should contain the following properties:
    - credentialId: FIDO2 credential ID (base64url encoded or UUID format)
    - privateKey: Private key in PEM format (with BEGIN/END PRIVATE KEY headers)
    - relyingParty: Relying party identifier (e.g., "login.microsoft.com")
    - url: Authentication URL (e.g., "https://login.microsoft.com")
    - userHandle: FIDO2 user handle (base64url encoded)
    - username: User principal name (e.g., "user@domain.com")
    
    Example format:
    {
        "credentialId": "AbCd1234EfGh5678IjKl",
        "privateKey": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...\n-----END PRIVATE KEY-----",
        "relyingParty": "login.microsoft.com",
        "url": "https://login.microsoft.com",
        "userHandle": "ExAmPlE_UsErHaNdLe_BaSe64UrLeNcOdEd",
        "username": "user@example.com"
    }

.PARAMETER UserPrincipalName
    User principal name for authentication.

.PARAMETER UserHandle
    FIDO2 user handle (base64url encoded).

.PARAMETER CredentialId
    FIDO2 credential ID (base64url encoded or UUID format).

.PARAMETER PrivateKey
    Private key in PEM format or base64 encoded.

.PARAMETER RelyingParty
    Relying party identifier. Defaults to "login.microsoft.com".

.PARAMETER AuthUrl
    OAuth authorization URL. Defaults to Microsoft Azure CLI endpoint.

.PARAMETER UserAgent
    User agent string for HTTP requests.

.PARAMETER Proxy
    Proxy server URL if needed.

.EXAMPLE
    .\PasskeyLogin.ps1 -KeyFilePath .\passkey.json

.EXAMPLE
    .\PasskeyLogin.ps1 -UserPrincipalName user@domain.com -UserHandle "base64handle" -CredentialId "base64id" -PrivateKey "-----BEGIN PRIVATE KEY-----..."

.NOTES
    Requires PowerShell 7.0 or later for ECDsa PEM support.
    
    Based on TokenTacticsV2 by Fabian Bader
    https://github.com/f-bader/TokenTacticsV2
    
    Created with assistance from GitHub Copilot
    
    This standalone script extracts the core passkey authentication logic
    from the TokenTactics module for easy portability and integration.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory, ParameterSetName = 'Path')]
    [string]$KeyFilePath,

    [Alias('UserName')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
    [Parameter(Mandatory, ParameterSetName = 'Manual')]
    [string]$UserPrincipalName,

    [Parameter(Mandatory, ParameterSetName = 'Manual')]
    [string]$UserHandle,

    [Parameter(Mandatory, ParameterSetName = 'Manual')]
    [string]$CredentialId,

    [Parameter(Mandatory, ParameterSetName = 'Manual')]
    [string]$PrivateKey,

    [Parameter(Mandatory = $false)]
    $RelyingParty = "login.microsoft.com",

    [Parameter(Mandatory = $false)]
    $AuthUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=msauth.com.msauth.unsignedapp://auth&scope=https://graph.microsoft.com/.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46",

    [Parameter(Mandatory = $false)]
    $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

    [Parameter(Mandatory = $false)]
    [string]$Proxy
)

#region Helper Functions

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function Confirm-Base64Url {
    param([string]$Value)
    return $Value.TrimEnd('=') -replace '\+','-' -replace '/','_'
}

function ConvertTo-PEMPrivateKey {
    param (
        [Parameter(Mandatory)]
        [string]$PrivateKey
    )

    # Check if it's already in PEM format
    if ($PrivateKey.Trim() -match "^-----BEGIN PRIVATE KEY-----") {
        return $PrivateKey
    }

    # Remove any whitespace
    $cleanKey = $PrivateKey.Trim() -replace "`r|`n|\s", ""

    # Replace invalid characters (if any)
    $cleanKey = $cleanKey -replace "-", "+" -replace "_", "/"

    # Wrap at 64 characters
    $wrappedKey = ""
    for ($i = 0; $i -lt $cleanKey.Length; $i += 64) {
        if ($i + 64 -lt $cleanKey.Length) {
            $wrappedKey += $cleanKey.Substring($i, 64) + "`n"
        } else {
            $wrappedKey += $cleanKey.Substring($i)
        }
    }

    $pemKey = "-----BEGIN PRIVATE KEY-----`n$wrappedKey`n-----END PRIVATE KEY-----"
    return $pemKey
}

function New-FidoAuthenticatorData {
    param(
        [Parameter(Mandatory)]
        [string]$RpId,
        [int]$SignCount = 0,
        [byte]$Flags = 0x05
    )

    # 1. RP ID Hash (32 bytes)
    $rpIdBytes = [System.Text.Encoding]::UTF8.GetBytes($RpId)
    $rpIdHash = [System.Security.Cryptography.SHA256]::HashData($rpIdBytes)

    # 2. Flags (1 byte)
    # 3. Counter (Big Endian)
    $cntBytes = [BitConverter]::GetBytes([int]$SignCount)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($cntBytes) }

    # Combine
    $authData = [byte[]]::new(37)
    [Array]::Copy($rpIdHash, 0, $authData, 0, 32)
    $authData[32] = $Flags
    [Array]::Copy($cntBytes, 0, $authData, 33, 4)

    return $authData
}

function New-FidoSignature {
    param(
        [Parameter(Mandatory)]
        [string]$Challenge,
        [Parameter(Mandatory)]
        [string]$Origin,
        [Parameter(Mandatory)]
        [byte[]]$AuthDataBytes,
        [Parameter(Mandatory)]
        [string]$PrivateKeyPem
    )

    # 1. ClientDataJSON
    $clientData = [ordered]@{
        challenge   = $Challenge
        crossOrigin = $false
        origin      = $Origin
        type        = "webauthn.get"
    }
    $clientJson = $clientData | ConvertTo-Json -Compress -Depth 10
    $clientBytes = [System.Text.Encoding]::UTF8.GetBytes($clientJson)
    $clientHash = [System.Security.Cryptography.SHA256]::HashData($clientBytes)

    # 2. Sign (AuthData + ClientDataHash)
    $dataToSign = $AuthDataBytes + $clientHash

    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    $ecdsa.ImportFromPem($PrivateKeyPem)

    # 3. Generate Signature
    $sigBytes = $ecdsa.SignData(
        $dataToSign, 
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, 
        [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )

    return @{
        Signature  = $sigBytes
        ClientData = $clientBytes
    }
}

#endregion

#region Main Script

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 (Core) for ECDsa PEM support."
    exit 1
}

# Load key data if file provided
if ($PSCmdlet.ParameterSetName -eq 'Path') {
    if (-not (Test-Path $KeyFilePath)) {
        Write-Error "Key file '$KeyFilePath' not found."
        exit 1
    }

    Write-Host "$([char]0x2718) Loading key data from file: $KeyFilePath" -ForegroundColor Cyan
    try {
        $keyData = Get-Content $KeyFilePath -Raw | ConvertFrom-Json
    } catch {
        Write-Error "Invalid JSON in key file."
        exit 1
    }
}

# Configure proxy if specified
$PSDefaultParameterValues = @{}
$PSDefaultParameterValues.Add('Invoke-WebRequest:Verbose', $false)

if ($Proxy) {
    Write-Verbose "Setting proxy to $Proxy"
    $PSDefaultParameterValues.Add('Invoke-WebRequest:Proxy', $Proxy)
}

# Determine parameters
$targetUser = $keyData.username ?? $keyData.userName ?? $UserPrincipalName
if (-not $targetUser) {
    Write-Error "Username not found in JSON or arguments."
    exit 1
}

$rpId = $keyData.relyingParty ?? $keyData.rpId ?? $RelyingParty
$origin = $keyData.url ?? "https://$($rpId)"
$origin = [uri]"$origin" | Select-Object -ExpandProperty Host
$origin = "https://$($origin)"

$userHandle = $keyData.userHandle ?? $UserHandle
if (-not $userHandle) {
    Write-Error "UserHandle not found in JSON or arguments."
    exit 1
}
$userHandle = Confirm-Base64Url $userHandle

$credentialId = $keyData.credentialId ?? $CredentialId
if (-not $credentialId) {
    Write-Error "CredentialId not found in JSON or arguments."
    exit 1
}

# Convert UUID format to base64url if necessary
if ($credentialId -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
    Write-Verbose "Converting UUID format credential ID to base64url"
    $hexString = $credentialId.Replace('-', '')
    $rawBytes = [byte[]]::new($hexString.Length / 2)
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $rawBytes[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    $base64 = [Convert]::ToBase64String($rawBytes)
    $credentialId = $base64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
} else {
    $credentialId = Confirm-Base64Url $credentialId
}

Write-Host "$([char]0x2714) User:       $targetUser" -ForegroundColor Gray
Write-Host "$([char]0x2714) RP ID:      $rpId" -ForegroundColor Gray
Write-Host "$([char]0x2714) Origin:     $origin" -ForegroundColor Gray
Write-Host "$([char]0x2714) CredID:     $credentialId" -ForegroundColor Gray
Write-Host "$([char]0x2714) UserHandle: $userHandle" -ForegroundColor Gray

# Private Key
[int]$SignCount = $keyData.signCount ?? $keyData.counter ?? 0
$PrivateKeyPem = $keyData.privateKey ?? $keyData.keyValue ?? $PrivateKey
$PrivateKeyPem = ConvertTo-PEMPrivateKey -PrivateKey $PrivateKeyPem
if (-not $PrivateKeyPem) {
    Write-Error "Private key conversion failed."
    exit 1
}

# Configure Session
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = $UserAgent

# Validate auth URL
try {
    $uriBuilder = [System.UriBuilder]$AuthUrl
    $query = [System.Web.HttpUtility]::ParseQueryString($uriBuilder.Query)
} catch {
    Write-Error "Invalid auth URL format. $($_.Exception.Message)"
    exit 1
}

if ($AuthUrl -notmatch "^https://login.microsoftonline.com/") {
    Write-Error "Auth URL must start with 'https://login.microsoftonline.com/'"
    exit 1
}

# Check required parameters
$RequiredParams = @("client_id", "response_type", "redirect_uri")
foreach ($param in $RequiredParams) {
    if (-not $query.Get($param)) {
        Write-Error "Missing required parameter '$param' in auth URL."
        exit 1
    }
}

# Add additional parameters
if (-not $query.Get("sso_reload")) {
    $AuthUrl = "$AuthUrl&sso_reload=true"
}
if (-not $query.Get("login_hint")) {
    $AuthUrl = "$AuthUrl&login_hint=$targetUser"
}

Write-Verbose "Auth URL: $AuthUrl"

# Initial request
Write-Host "$([char]0x2718) Warming up session on login.microsoftonline.com..." -ForegroundColor Cyan
$InitialResponse = Invoke-WebRequest -UseBasicParsing -Uri $AuthUrl -Method Get -WebSession $session -SkipHttpErrorCheck
if ($InitialResponse.Content -match '{(.*)}') {
    $SessionInformation = $Matches[0] | ConvertFrom-Json
}

# Validate FIDO2 support
Write-Host "$([char]0x2718) Validating FIDO2 support..." -ForegroundColor Cyan
if (-not $SessionInformation.oGetCredTypeResult.Credentials.HasFido -or -not $SessionInformation.sFidoChallenge) {
    Write-Error "User does not have FIDO credentials registered or no challenge received."
    exit 1
}

$serverChallenge = [System.Text.Encoding]::ASCII.GetBytes($SessionInformation.sFidoChallenge)
Write-Host "$([char]0x2714) Challenge Received." -ForegroundColor Green

# Generate FIDO Assertion
Write-Host "$([char]0x2718) Generating FIDO Assertion locally..." -ForegroundColor Cyan

try {
    $authData = New-FidoAuthenticatorData -RpId $rpId -SignCount $SignCount
    $crypto = New-FidoSignature -Challenge (ConvertTo-Base64Url $serverChallenge) -Origin $origin -AuthDataBytes $authData -PrivateKeyPem $PrivateKeyPem

    $fidoPayload = [ordered]@{
        id                = $credentialId
        clientDataJSON    = (ConvertTo-Base64Url $crypto.ClientData)
        authenticatorData = (ConvertTo-Base64Url $authData)
        signature         = (ConvertTo-Base64Url $crypto.Signature)
        userHandle        = $userHandle
    }

    $credentialsJson = $SessionInformation.oGetCredTypeResult.Credentials.FidoParams.AllowList -join ','
} catch {
    Write-Error "FIDO Assertion generation failed: $($_.Exception.Message)"
    exit 1
}

# Submit verification request
Write-Host "$([char]0x2718) Get required pre-information from microsoft.com..." -ForegroundColor Cyan
$verifyUrl = "https://login.microsoft.com/common/fido/get?uiflavor=Web"

$bodyVerify = @{
    allowedIdentities = 2
    canary            = $SessionInformation.sFT
    ServerChallenge   = $SessionInformation.sFT
    postBackUrl       = $SessionInformation.urlPost
    postBackUrlAad    = $SessionInformation.urlPostAad
    postBackUrlMsa    = $SessionInformation.urlPostMsa
    cancelUrl         = $SessionInformation.urlRefresh
    resumeUrl         = $SessionInformation.urlResume
    correlationId     = $SessionInformation.correlationId
    credentialsJson   = $credentialsJson
    ctx               = $SessionInformation.sCtx
    username          = $targetUser
    loginCanary       = $SessionInformation.canary
}

try {
    $respVerify = Invoke-WebRequest -UseBasicParsing -Uri $verifyUrl -Method Post -Body $bodyVerify -WebSession $session
    $respVerify.Content -match '{(.*)}' | Out-Null
    $ResponseInformation = $Matches[0] | ConvertFrom-Json
} catch {
    Write-Error "Verification request failed: $($_.Exception.Message)"
    exit 1
}

# Submit FIDO2 assertion
$LoginUri = "https://login.microsoftonline.com/common/login"
$Payload = @{
    type         = 23
    ps           = 23
    assertion    = ($fidoPayload | ConvertTo-Json -Compress -Depth 10)
    lmcCanary    = $ResponseInformation.sCrossDomainCanary
    hpgrequestid = $ResponseInformation.sessionId
    ctx          = $ResponseInformation.sCtx
    canary       = $ResponseInformation.canary
    flowToken    = $ResponseInformation.sFT
}

Write-Host "$([char]0x2718) Submitting FIDO2 assertion to microsoftonline.com..." -ForegroundColor Cyan
$respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $LoginUri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck

# Allow server processing time
Start-Sleep -Milliseconds 500

# Submit with sso_reload
$LoginUri = "https://login.microsoftonline.com/common/login?sso_reload=true"
$Payload.flowToken = $SessionInformation.oGetCredTypeResult.FlowToken

Write-Host "$([char]0x2718) Submitting FIDO2 assertion with sso_reload..." -ForegroundColor Cyan
$respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $LoginUri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck

# Allow server processing time before parsing response
Start-Sleep -Milliseconds 500

# Parse response with validation
if (-not ($respFinalize.Content -match '{(.*)}')) {
    Write-Warning "No JSON response received from server. Login may have completed."
    $Debug = @{ pgid = $null }
} else {
    try {
        $Debug = $Matches[0] | ConvertFrom-Json
        if ($Debug.pgid) {
            Write-Host "$([char]0x2718) PageID: $($Debug.pgid)" -ForegroundColor Gray
            $CurrentPageId = $Debug.pgid
        }
    } catch {
        Write-Verbose "Failed to parse response JSON: $($_.Exception.Message)"
        $Debug = @{ pgid = $null }
    }
}

# Handle interrupts (CMSI, KMSI, etc.)
$LoopCount = 0
$InterruptHandlers = @{
    "CmsiInterrupt" = @{
        Message = "Handling consent prompt"
        Uri = "https://login.microsoftonline.com/appverify"
        Method = "Post"
        Body = @{
            ContinueAuth = "true"
            i19 = { Get-Random -Minimum 1000 -Maximum 9999 }.Invoke()
            canary = { $Debug.canary }
            iscsrfspeedbump = "false"
            flowToken = { $Debug.sFT }
            hpgrequestid = { $Debug.correlationId }
            ctx = { $Debug.sCtx }
        }
    }
    "KmsiInterrupt" = @{
        Message = "Handling KMSI prompt"
        Uri = "https://login.microsoftonline.com/kmsi"
        Method = "Post"
        Body = @{
            LoginOptions = 1
            type = 28
            ctx = { $Debug.sCtx }
            hpgrequestid = { $Debug.correlationId }
            flowToken = { $Debug.sFT }
            canary = { $Debug.canary }
            i19 = 4130
        }
    }
    "ConvergedSignIn" = @{
        Message = "Handling ConvergedSignIn"
        Uri = { $Debug.urlLogin + "&sessionid=$(($Debug.arrSessions[0].id ?? $Debug.sessionId))" }
        Method = "Get"
    }
}

while ($Debug.pgid -in $InterruptHandlers.Keys) {
    if ($CurrentPageId -eq $LastPageId -or ++$LoopCount -gt 10) {
        Write-Warning "$(if ($CurrentPageId -eq $LastPageId) { 'Stuck in' } else { 'Exceeded maximum' }) interrupt loop. Exiting."
        Write-Verbose "LastPageId: $LastPageId, CurrentPageId: $CurrentPageId, LoopCount: $LoopCount"
        break
    }
    $LastPageId = $CurrentPageId

    $handler = $InterruptHandlers[$Debug.pgid]
    Write-Host "$([char]0x2718) $($handler.Message)..." -ForegroundColor Cyan
    
    $params = @{
        Uri = if ($handler.Uri -is [scriptblock]) { & $handler.Uri } else { $handler.Uri }
        Method = $handler.Method
        WebSession = $session
        UseBasicParsing = $true
        SkipHttpErrorCheck = $true
        MaximumRedirection = 10
    }
    
    if ($handler.Body) {
        $resolvedBody = @{}
        foreach ($key in $handler.Body.Keys) {
            $resolvedBody[$key] = if ($handler.Body[$key] -is [scriptblock]) { & $handler.Body[$key] } else { $handler.Body[$key] }
        }
        $params.Body = $resolvedBody
    }
    
    $respFinalize = Invoke-WebRequest @params
    
    # Allow server processing time after handling interrupt
    Start-Sleep -Milliseconds 300

    if (-not ($respFinalize.Content -match '{(.*)}')) {
        Write-Verbose "No JSON response from interrupt handler. Assuming completion."
        break
    }
    
    try {
        $Debug = $Matches[0] | ConvertFrom-Json
        if ($Debug.pgid) {
            Write-Host "$([char]0x2718) PageID: $($Debug.pgid)" -ForegroundColor Gray
            $CurrentPageId = $Debug.pgid
        } else {
            # No page ID means we're likely done with interrupts
            Write-Verbose "No page ID in response. Exiting interrupt loop."
            break
        }
    } catch {
        Write-Warning "Failed to parse JSON response. Exiting loop."
        Write-Verbose "Parse error: $($_.Exception.Message)"
        break
    }
}

# Allow final cookie propagation
Start-Sleep -Milliseconds 500

# Check success
$allCookies = $session.Cookies.GetCookies("https://login.microsoftonline.com")
Write-Verbose "Checking cookies: $($allCookies.Name -join ', ')"

if ($allCookies | Where-Object Name -Like "ESTS*") {
    Write-Host "\n$([char]0x2714) Login Successful!" -ForegroundColor Green
    
    $ESTSAUTH = $allCookies | Where-Object Name -EQ "ESTSAUTH"
    $ESTSAUTHPERSISTENT = $allCookies | Where-Object Name -EQ "ESTSAUTHPERSISTENT"
    $ESTSAUTHLIGHT = $allCookies | Where-Object Name -EQ "ESTSAUTHLIGHT"
    
    $ests = @($ESTSAUTH, $ESTSAUTHPERSISTENT, $ESTSAUTHLIGHT) | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1
    
    if ($ests) {
        Write-Host "$([char]0x26BF) ESTSAUTH Cookie: $($ests.Value.Substring(0, 20))..." -ForegroundColor Gray
        $global:ESTSAUTH = $ests.Value
        $global:webSession = $session
        Write-Host "$([char]0x26BF) Session saved to `$global:webSession" -ForegroundColor Gray
        Write-Host "$([char]0x26BF) Token saved to `$global:ESTSAUTH" -ForegroundColor Gray
    }
} else {
    Write-Warning "Login flow completed but success state is unclear."
    $global:webSession = $session
}

#endregion
