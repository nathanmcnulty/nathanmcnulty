#Requires -Version 7.0
<#
.SYNOPSIS
    Registers a FIDO2 passkey using an ESTSAUTH cookie, with the credential
    private key stored in Azure Key Vault.

.DESCRIPTION
    Replicates the browser's mysignins.microsoft.com passkey registration flow using
    an ESTSAUTH/ESTSAUTHPERSISTENT cookie for silent SSO authentication. The credential
    private key is generated in Azure Key Vault (never exported) instead of saved to a
    local file.

    Only the cookie is required — the tenant is resolved automatically via the
    'organizations' authorize endpoint and confirmed from the JWT tid claim.
    UserPrincipalName is also extracted from the JWT after token exchange.

    Flow:
    1. Key Vault Setup: Acquire KV token, create EC P-256 key in Key Vault
    2. Silent Auth: Injects ESTSAUTH cookie → authorize (no prompt) → 302 with auth code
    3. Token Exchange: Auth code + PKCE → access_token + refresh_token
    4. Session Setup: session/authorize → NGC MFA claims refresh → SessionCtxV2
    5. Passkey Init: authenticationmethods/new {Type:18} → canary + serverChallenge
    6. Attestation: Builds WebAuthn attestation using KV public key + ephemeral batch key
    7. Registration: POSTs to fido/create then newfido with canary + attestation

    The credential JSON output (with a keyVault reference) is compatible with
    PasskeyLogin.ps1 for subsequent authentication.

    Key Vault token acquisition order:
    1. -KeyVaultAccessToken parameter (if provided)
    2. Get-AzAccessToken (Az.Accounts module, if connected)
    3. az account get-access-token (Azure CLI, if logged in)
    4. Error with instructions if none available

.PARAMETER ESTSAuthCookie
    Value of an ESTSAUTH or ESTSAUTHPERSISTENT cookie from login.microsoftonline.com.
    Obtain from browser DevTools → Application → Cookies → login.microsoftonline.com.

.PARAMETER KeyVaultName
    The name of the Azure Key Vault where the credential key will be stored.
    The user must have Key Vault Crypto Officer or Crypto User role on this vault.

.PARAMETER TenantId
    Optional. Azure AD tenant ID (GUID). If not specified, the 'organizations' endpoint
    is used for initial auth and the tenant is resolved from the JWT tid claim.

.PARAMETER KeyVaultKeyName
    Name for the key in Key Vault. Auto-generated as passkey-<upnprefix>-<timestamp>
    if not specified.

.PARAMETER PasskeyDisplayName
    Display name for the passkey (default: "Software Passkey").

.PARAMETER OutputPath
    Path to save the credential JSON file. Defaults to <username>_passkey_<timestamp>.json.

.PARAMETER KeyVaultAccessToken
    Pre-obtained access token for https://vault.azure.net. Bypasses Az module and
    Azure CLI checks. Obtain via:
      az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv

.EXAMPLE
    # Minimal — only the cookie and Key Vault name are required
    .\Register-KeyVaultPasskeyViaESTSAuth.ps1 -ESTSAuthCookie "1.AVIA..." -KeyVaultName "my-keyvault"

.EXAMPLE
    # With explicit tenant ID
    .\Register-KeyVaultPasskeyViaESTSAuth.ps1 -ESTSAuthCookie $cookie -KeyVaultName "my-keyvault" `
        -TenantId "847b5907-ca15-40f4-b171-eb18619dbfab"

.EXAMPLE
    # With pre-obtained Key Vault token (skips Az/CLI checks)
    .\Register-KeyVaultPasskeyViaESTSAuth.ps1 -ESTSAuthCookie $cookie -KeyVaultName "my-keyvault" `
        -KeyVaultAccessToken (az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)

.NOTES
    Author: Nathan McNulty
    Date: March 1, 2026

    Flow follows mysignins.microsoft.com passkey registration.
    The browser uses ESTS native endpoints (fido/create → newfido), NOT the Graph API.
    The credential private key is protected by Key Vault and never leaves it.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [object]$ESTSAuthCookie,

    [Parameter(Mandatory)]
    [string]$KeyVaultName,

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$KeyVaultKeyName,

    [Parameter()]
    [string]$PasskeyDisplayName = "Software Passkey",

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$KeyVaultAccessToken
)

$ErrorActionPreference = "Stop"

# Convert SecureString to plain text if needed
if ($ESTSAuthCookie -is [securestring]) {
    $ESTSAuthCookie = [System.Net.NetworkCredential]::new('', $ESTSAuthCookie).Password
} elseif ($ESTSAuthCookie -isnot [string]) {
    $ESTSAuthCookie = [string]$ESTSAuthCookie
}
$ClientId = "19db86c3-b2b9-44cc-b339-36da233a3be2"  # My Signins SPA
$RedirectUri = "https://mysignins.microsoft.com"

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  FIDO2 Passkey Registration via ESTSAUTH Cookie → Azure Key Vault" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

#region Helper Functions

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url {
    param([string]$Base64Url)
    $base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
    $padding = (4 - ($base64.Length % 4)) % 4
    $base64 += '=' * $padding
    return [Convert]::FromBase64String($base64)
}

function New-CBOREncoded {
    param($Value)
    $bytes = [System.Collections.Generic.List[byte]]::new()

    if ($Value -is [int]) {
        if ($Value -ge 0) {
            if ($Value -le 23) { $bytes.Add([byte]$Value) }
            elseif ($Value -le 255) { $bytes.Add(0x18); $bytes.Add([byte]$Value) }
            elseif ($Value -le 65535) {
                $bytes.Add(0x19)
                $lenBytes = [BitConverter]::GetBytes([uint16]$Value); [Array]::Reverse($lenBytes)
                $bytes.AddRange([byte[]]$lenBytes)
            } else {
                $bytes.Add(0x1A)
                $lenBytes = [BitConverter]::GetBytes([uint32]$Value); [Array]::Reverse($lenBytes)
                $bytes.AddRange([byte[]]$lenBytes)
            }
        } else {
            $n = -1 - $Value
            if ($n -le 23) { $bytes.Add([byte](0x20 + $n)) }
            elseif ($n -le 255) { $bytes.Add(0x38); $bytes.Add([byte]$n) }
            elseif ($n -le 65535) {
                $bytes.Add(0x39)
                $lenBytes = [BitConverter]::GetBytes([uint16]$n); [Array]::Reverse($lenBytes)
                $bytes.AddRange([byte[]]$lenBytes)
            } else {
                $bytes.Add(0x3A)
                $lenBytes = [BitConverter]::GetBytes([uint32]$n); [Array]::Reverse($lenBytes)
                $bytes.AddRange([byte[]]$lenBytes)
            }
        }
    } elseif ($Value -is [string]) {
        $textBytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        if ($textBytes.Length -le 23) { $bytes.Add([byte](0x60 + $textBytes.Length)) }
        elseif ($textBytes.Length -le 255) { $bytes.Add(0x78); $bytes.Add([byte]$textBytes.Length) }
        elseif ($textBytes.Length -le 65535) {
            $bytes.Add(0x79)
            $lenBytes = [BitConverter]::GetBytes([uint16]$textBytes.Length); [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        } else {
            $bytes.Add(0x7A)
            $lenBytes = [BitConverter]::GetBytes([uint32]$textBytes.Length); [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        }
        $bytes.AddRange([byte[]]$textBytes)
    } elseif ($Value -is [byte[]]) {
        if ($Value.Length -le 23) { $bytes.Add([byte](0x40 + $Value.Length)) }
        elseif ($Value.Length -le 255) { $bytes.Add(0x58); $bytes.Add([byte]$Value.Length) }
        elseif ($Value.Length -le 65535) {
            $bytes.Add(0x59)
            $lenBytes = [BitConverter]::GetBytes([uint16]$Value.Length); [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        } else {
            $bytes.Add(0x5A)
            $lenBytes = [BitConverter]::GetBytes([uint32]$Value.Length); [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        }
        $bytes.AddRange([byte[]]$Value)
    } elseif ($Value -is [System.Array]) {
        $count = $Value.Length
        if ($count -le 23) { $bytes.Add([byte](0x80 + $count)) }
        elseif ($count -le 255) { $bytes.Add(0x98); $bytes.Add([byte]$count) }
        else {
            $bytes.Add(0x99)
            $lenBytes = [BitConverter]::GetBytes([uint16]$count); [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        }
        foreach ($item in $Value) {
            $itemBytes = New-CBOREncoded -Value $item
            if ($itemBytes -is [byte]) { $bytes.Add($itemBytes) } else { $bytes.AddRange([byte[]]$itemBytes) }
        }
    } elseif ($Value -is [System.Collections.IDictionary]) {
        $count = $Value.Count
        if ($count -le 23) { $bytes.Add([byte](0xA0 + $count)) }
        elseif ($count -le 255) { $bytes.Add(0xB8); $bytes.Add([byte]$count) }
        else {
            $bytes.Add(0xB9)
            $lenBytes = [BitConverter]::GetBytes([uint16]$count); [Array]::Reverse($lenBytes)
            $bytes.AddRange([byte[]]$lenBytes)
        }
        foreach ($entry in $Value.GetEnumerator()) {
            $keyBytes = New-CBOREncoded -Value $entry.Key
            $valBytes = New-CBOREncoded -Value $entry.Value
            if ($keyBytes -is [byte]) { $bytes.Add($keyBytes) } else { $bytes.AddRange([byte[]]$keyBytes) }
            if ($valBytes -is [byte]) { $bytes.Add($valBytes) } else { $bytes.AddRange([byte[]]$valBytes) }
        }
    }
    return ,[byte[]]$bytes.ToArray()
}

#endregion

$spaHeaders = @{
    'Origin'         = $RedirectUri
    'Referer'        = "$RedirectUri/"
    'Sec-Fetch-Mode' = 'cors'
    'Sec-Fetch-Site' = 'cross-site'
    'Sec-Fetch-Dest' = 'empty'
}

$webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$tokenScope = "$ClientId/.default openid profile offline_access"

# Generate PKCE
$verifierBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
$codeVerifier = [Convert]::ToBase64String($verifierBytes) -replace '\+','-' -replace '/','_' -replace '=',''
$challengeBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
$codeChallenge = [Convert]::ToBase64String($challengeBytes) -replace '\+','-' -replace '/','_' -replace '=',''

# ══════════════════════════════════════════════════════════════════════
# STAGE 0: Key Vault Setup
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 0: Key Vault Setup ===" -ForegroundColor Cyan
Write-Host ""

# Acquire Key Vault access token
$kvToken = $null

if ($KeyVaultAccessToken) {
    $kvToken = $KeyVaultAccessToken
    Write-Host "  ✓ Using provided -KeyVaultAccessToken" -ForegroundColor Green
} else {
    # Try Az.Accounts module
    if (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue) {
        try {
            Write-Host "  Trying Az.Accounts module..." -ForegroundColor Yellow
            $azToken = Get-AzAccessToken -ResourceUrl "https://vault.azure.net" -ErrorAction Stop
            $kvToken = $azToken.Token
            Write-Host "  ✓ Key Vault token acquired via Az.Accounts" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠ Az.Accounts available but failed: $_" -ForegroundColor DarkYellow
            Write-Host "    (Run Connect-AzAccount if not logged in)" -ForegroundColor DarkYellow
        }
    }

    # Try Azure CLI if Az module didn't work
    if (-not $kvToken) {
        if (Get-Command az -ErrorAction SilentlyContinue) {
            try {
                Write-Host "  Trying Azure CLI..." -ForegroundColor Yellow
                $cliResult = az account get-access-token --resource https://vault.azure.net --output json 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $kvToken = ($cliResult | ConvertFrom-Json).accessToken
                    Write-Host "  ✓ Key Vault token acquired via Azure CLI" -ForegroundColor Green
                } else {
                    Write-Host "  ⚠ Azure CLI failed: $cliResult" -ForegroundColor DarkYellow
                    Write-Host "    (Run 'az login' if not logged in)" -ForegroundColor DarkYellow
                }
            } catch {
                Write-Host "  ⚠ Azure CLI error: $_" -ForegroundColor DarkYellow
            }
        }
    }

    if (-not $kvToken) {
        throw @"
Could not acquire a Key Vault access token. To fix this, use one of the following options:

  Option 1 – Provide a pre-obtained token:
    -KeyVaultAccessToken (az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv)

  Option 2 – Azure PowerShell module:
    Install-Module Az.Accounts
    Connect-AzAccount
    Then re-run this script.

  Option 3 – Azure CLI:
    winget install Microsoft.AzureCLI
    az login
    Then re-run this script.
"@
    }
}

# Placeholder key name — will be updated with UPN prefix once we have it from the JWT
$kvKeyNameIsAutoGenerated = [string]::IsNullOrEmpty($KeyVaultKeyName)
if (-not $kvKeyNameIsAutoGenerated) {
    $kvKeyNameResolved = $KeyVaultKeyName
}

# ══════════════════════════════════════════════════════════════════════
# STAGE 1: Silent Auth via ESTSAUTH Cookie
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 1: Silent Auth (ESTSAUTH Cookie) ===" -ForegroundColor Cyan
Write-Host ""

if ($TenantId) {
    $authority = $TenantId
    Write-Host "  ✓ Using provided TenantId: $TenantId" -ForegroundColor Green
} else {
    $authority = 'organizations'
    Write-Host "  Using 'organizations' authority (tenant will be resolved from SSO cookie)" -ForegroundColor Yellow
}

$cookieDomain = ".login.microsoftonline.com"
$webSession.Cookies.Add([System.Net.Cookie]::new("ESTSAUTHPERSISTENT", $ESTSAuthCookie, "/", $cookieDomain))
$webSession.Cookies.Add([System.Net.Cookie]::new("ESTSAUTH", $ESTSAuthCookie, "/", $cookieDomain))
Write-Host "  ✓ ESTSAUTH cookie injected" -ForegroundColor Green

$state = [guid]::NewGuid().ToString()
$authUrl = "https://login.microsoftonline.com/$authority/oauth2/v2.0/authorize?" + `
    "client_id=$ClientId" + `
    "&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($RedirectUri))" + `
    "&scope=$([System.Web.HttpUtility]::UrlEncode($tokenScope))" + `
    "&response_type=code" + `
    "&response_mode=fragment" + `
    "&code_challenge=$codeChallenge" + `
    "&code_challenge_method=S256" + `
    "&state=$state"

Write-Host "  Requesting silent auth..." -ForegroundColor Yellow
$authCode = $null
$silentUrl = $authUrl
for ($silentRedirect = 0; $silentRedirect -lt 10; $silentRedirect++) {
    try {
        $silentResp = Invoke-WebRequest -Uri $silentUrl -UseBasicParsing -MaximumRedirection 0 -WebSession $webSession
        if ($silentResp.Content -match 'action="([^"]+)"') {
            $formAction = $matches[1]
            $hiddenFields = [regex]::Matches($silentResp.Content, '<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"')
            $formData = ($hiddenFields | ForEach-Object {
                "$([System.Web.HttpUtility]::UrlEncode($_.Groups[1].Value))=$([System.Web.HttpUtility]::UrlEncode($_.Groups[2].Value))"
            }) -join '&'
            if ($formAction -and $formData) {
                if ($formAction.StartsWith('/')) { $u = [uri]$silentUrl; $formAction = "$($u.Scheme)://$($u.Host)$formAction" }
                $silentUrl = $formAction
                $silentResp = Invoke-WebRequest -Uri $silentUrl -Method POST -Body $formData -ContentType "application/x-www-form-urlencoded" -WebSession $webSession -MaximumRedirection 0 -UseBasicParsing
                continue
            }
        }
        if ($silentResp.Content -match '\$Config=(\{.+\});') {
            $pageCfg = $matches[1] | ConvertFrom-Json
            $pgid = $pageCfg.pgid
            $errMsg = $pageCfg.strServiceExceptionMessage
            if ($pgid -eq 'ConvergedTFA') {
                throw "MFA required but not satisfied — the ESTSAUTH cookie does not contain a completed MFA session. Ensure the cookie is captured AFTER MFA is completed (e.g., after Authenticator push approval)."
            } elseif ($pgid -eq 'ConvergedSignIn') {
                throw "Cookie session expired or invalid — Azure AD returned the sign-in page. The cookie may have expired or been revoked."
            } elseif ($errMsg) {
                throw "Azure AD returned page '$pgid' with error: $errMsg"
            } else {
                throw "Azure AD returned page '$pgid' instead of silent auth redirect. Cookie may be invalid or expired."
            }
        }
        throw "Unexpected 200 response during silent auth."
    } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        $statusCode = [int]$_.Exception.Response.StatusCode
        if ($statusCode -ge 300 -and $statusCode -lt 400) {
            $location = $_.Exception.Response.Headers.Location.ToString()
            if ($location.StartsWith('/')) { $u = [uri]$silentUrl; $location = "$($u.Scheme)://$($u.Host)$location" }
            if ($location -match '[#?&]code=([^&#]+)') {
                $authCode = [System.Web.HttpUtility]::UrlDecode($matches[1])
                Write-Host "  ✓ Silent auth successful! Got auth code (len=$($authCode.Length))" -ForegroundColor Green
                break
            }
            if ($location -match 'error=([^&#]+)') {
                $errCode = [System.Web.HttpUtility]::UrlDecode($matches[1])
                $errDesc = if ($location -match 'error_description=([^&#]+)') { [System.Web.HttpUtility]::UrlDecode($matches[1]) } else { '' }
                throw "Silent auth failed: $errCode — $errDesc"
            }
            $silentUrl = $location
            continue
        }
        throw
    }
}
if (-not $authCode) { throw "Failed to get auth code via silent auth after $silentRedirect redirects." }
Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# STAGE 2: Token Exchange (SPA + PKCE)
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 2: Token Exchange ===" -ForegroundColor Cyan
Write-Host ""

$tokenBody = "client_id=$ClientId" + `
    "&scope=$([System.Web.HttpUtility]::UrlEncode($tokenScope))" + `
    "&grant_type=authorization_code" + `
    "&code=$([System.Web.HttpUtility]::UrlEncode($authCode))" + `
    "&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($RedirectUri))" + `
    "&code_verifier=$codeVerifier"

$tokenResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$authority/oauth2/v2.0/token" `
    -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -Headers $spaHeaders

$selfToken = $tokenResp.access_token
$currentRefreshToken = $tokenResp.refresh_token

Write-Host "  ✓ Token exchange successful!" -ForegroundColor Green
Write-Host "    access_token: $($selfToken.Length) chars" -ForegroundColor Gray
Write-Host "    refresh_token: $(if($currentRefreshToken){'present'}else{'MISSING'})" -ForegroundColor $(if($currentRefreshToken){'Gray'}else{'Red'})

if (-not $currentRefreshToken) {
    throw "No refresh_token returned. Cannot proceed without it."
}

# Extract UPN and TenantId from JWT
$jwtPayload = $selfToken.Split('.')[1]
switch ($jwtPayload.Length % 4) { 2 { $jwtPayload += '==' } 3 { $jwtPayload += '=' } }
$jwtJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($jwtPayload.Replace('-','+').Replace('_','/'))) | ConvertFrom-Json

if ($jwtJson.tid) {
    $TenantId = $jwtJson.tid
    $authority = $TenantId
    Write-Host "  ✓ Tenant resolved from JWT: $TenantId" -ForegroundColor Green
}

$UserPrincipalName = $jwtJson.upn
if (-not $UserPrincipalName) { $UserPrincipalName = $jwtJson.preferred_username }
if (-not $UserPrincipalName) { $UserPrincipalName = $jwtJson.unique_name }
if (-not $UserPrincipalName) { throw "Could not extract UPN from JWT. The token may not contain a UPN claim." }
Write-Host "  ✓ UPN extracted from JWT: $UserPrincipalName" -ForegroundColor Green
Write-Host ""

# Now that we have the UPN, resolve the Key Vault key name if auto-generating
if ($kvKeyNameIsAutoGenerated) {
    $upnPrefix = $UserPrincipalName.Split('@')[0]
    $kvKeyNameResolved = "passkey-$upnPrefix-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

# Create the Key Vault key now that we have the UPN for auto-naming
Write-Host "  Creating key '$kvKeyNameResolved' in vault '$KeyVaultName'..." -ForegroundColor Yellow
$kvCreateUri = "https://$KeyVaultName.vault.azure.net/keys/$kvKeyNameResolved/create?api-version=7.4"
$kvHeaders = @{
    "Authorization" = "Bearer $kvToken"
    "Content-Type"  = "application/json"
}
$kvCreateBody = @{
    kty     = "EC"
    crv     = "P-256"
    key_ops = @("sign", "verify")
} | ConvertTo-Json

try {
    $kvKey = Invoke-RestMethod -Uri $kvCreateUri -Method POST -Headers $kvHeaders -Body $kvCreateBody
} catch {
    $errDetail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
    throw "Failed to create key in Key Vault '$KeyVaultName': $errDetail`n  Ensure you have Key Vault Crypto Officer or Crypto User role on this vault."
}

$publicKeyX = [byte[]](ConvertFrom-Base64Url $kvKey.key.x)
$publicKeyY = [byte[]](ConvertFrom-Base64Url $kvKey.key.y)
$kvKeyId    = $kvKey.key.kid

Write-Host "  ✓ Key created in Key Vault" -ForegroundColor Green
Write-Host "    Key ID: $kvKeyId" -ForegroundColor Gray
Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# STAGE 3: Session Setup (session/authorize → SessionCtxV2)
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 3: Session Setup ===" -ForegroundColor Cyan
Write-Host ""

$clientSessionId = [guid]::NewGuid().ToString()
$sessHeaders = @{
    'Authorization'          = "Bearer $selfToken"
    'Origin'                 = $RedirectUri
    'Referer'                = "$RedirectUri/security-info"
    'AjaxRequest'            = 'true'
    'x-ms-mysignins-region'  = 'westus2'
    'x-ms-client-session-id' = $clientSessionId
}

$sessResp = Invoke-RestMethod -Uri "$RedirectUri/api/session/authorize" `
    -Method POST -Headers $sessHeaders -ContentType "application/json" -Body "" -WebSession $webSession

if (-not $sessResp.isAuthorized) {
    throw "Session not authorized. Response: $($sessResp | ConvertTo-Json -Compress)"
}

$sessionCtxV2 = $sessResp.sessionCtxV2
Write-Host "  ✓ Session authorized!" -ForegroundColor Green
Write-Host "    isAuthorized: $($sessResp.isAuthorized)" -ForegroundColor Gray
Write-Host "    hasMfaClaim: $($sessResp.hasMfaClaim)" -ForegroundColor Gray
Write-Host "    requireNgcMfaForSecurityInfo: $($sessResp.requireNgcMfaForSecurityInfo)" -ForegroundColor Gray
Write-Host "    SessionCtxV2: $($sessionCtxV2.Substring(0, [Math]::Min(50, $sessionCtxV2.Length)))..." -ForegroundColor Gray

if ($sessResp.requireNgcMfaForSecurityInfo) {
    Write-Host "  NGC MFA required – refreshing token with ngcmfa claims..." -ForegroundColor Yellow

    $ngcClaims = '{"id_token":{"amr":{"essential":true,"values":["ngcmfa"]}},"access_token":{"amr":{"essential":true,"values":["ngcmfa"]}}}'
    $ngcBody = "client_id=$ClientId" + `
        "&scope=$([System.Web.HttpUtility]::UrlEncode("$ClientId/.default openid"))" + `
        "&grant_type=refresh_token" + `
        "&refresh_token=$([System.Web.HttpUtility]::UrlEncode($currentRefreshToken))" + `
        "&claims=$([System.Web.HttpUtility]::UrlEncode($ngcClaims))"

    $ngcResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Method POST -Body $ngcBody -ContentType "application/x-www-form-urlencoded" -Headers $spaHeaders

    $selfToken = $ngcResp.access_token
    Write-Host "  ✓ NGC self-token acquired ($($selfToken.Length) chars)" -ForegroundColor Green

    if ($ngcResp.refresh_token) { $currentRefreshToken = $ngcResp.refresh_token }

    Write-Host "  Re-authorizing session with NGC token..." -ForegroundColor Yellow
    $sessHeaders['Authorization'] = "Bearer $selfToken"
    $sessResp2 = Invoke-RestMethod -Uri "$RedirectUri/api/session/authorize" `
        -Method POST -Headers $sessHeaders -ContentType "application/json" -Body "" -WebSession $webSession

    if (-not $sessResp2.isAuthorized) {
        throw "NGC session not authorized. Response: $($sessResp2 | ConvertTo-Json -Compress)"
    }
    $sessionCtxV2 = $sessResp2.sessionCtxV2
    Write-Host "  ✓ NGC session authorized! SessionCtxV2: $($sessionCtxV2.Substring(0,50))..." -ForegroundColor Green
}

Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# STAGE 4: Passkey Creation Init (get canary + server challenge)
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 4: Request Passkey Creation ===" -ForegroundColor Cyan
Write-Host ""

$newHeaders = @{
    'Authorization'          = "Bearer $selfToken"
    'SessionCtxV2'           = $sessionCtxV2
    'Origin'                 = $RedirectUri
    'Referer'                = "$RedirectUri/security-info"
    'AjaxRequest'            = 'true'
    'x-ms-mysignins-region'  = 'westus2'
    'x-ms-client-session-id' = $clientSessionId
}

$newResp = Invoke-WebRequest -Uri "$RedirectUri/api/authenticationmethods/new" `
    -Method POST -Headers $newHeaders -ContentType "application/json" -Body '{"Type":18}' -WebSession $webSession

$newJson = $newResp.Content | ConvertFrom-Json

if ($newJson.ErrorCode -and $newJson.ErrorCode -ne 0) {
    Write-Host "  Response:" -ForegroundColor Yellow
    Write-Host ($newJson | ConvertTo-Json -Depth 3) -ForegroundColor Gray
    throw "authenticationmethods/new returned ErrorCode $($newJson.ErrorCode)"
}

Write-Host "  ✓ Passkey creation initiated!" -ForegroundColor Green

$innerJson = $newJson.Data | ConvertFrom-Json
$requestData = $innerJson.requestData
$provisionUrl = $innerJson.provisionUrl
$fidoCanary = $requestData.canary
$serverChallenge = $requestData.serverChallenge
$postBackUrl = $requestData.postBackUrl
$fidoUserId = $requestData.userId
$correlationId = [guid]::NewGuid().ToString()
$excludeCredentials = $requestData.ExcludeNextGenCredentialsJSON

if ([string]::IsNullOrEmpty($fidoCanary)) { throw "Failed to get canary from authenticationmethods/new response" }
if ([string]::IsNullOrEmpty($serverChallenge)) { throw "No serverChallenge returned from authenticationmethods/new" }
if ([string]::IsNullOrEmpty($fidoUserId)) { throw "No userId returned from authenticationmethods/new" }

Write-Host "    provisionUrl: $provisionUrl" -ForegroundColor Gray
Write-Host "    canary: $($fidoCanary.Substring(0, [Math]::Min(60, $fidoCanary.Length)))..." -ForegroundColor Gray
Write-Host "    serverChallenge: $($serverChallenge.Substring(0,[Math]::Min(60,$serverChallenge.Length)))..." -ForegroundColor Gray
Write-Host "    correlationId: $correlationId" -ForegroundColor Gray
Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# STAGE 5: Build WebAuthn Attestation (using Key Vault public key)
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 5: Build Attestation ===" -ForegroundColor Cyan
Write-Host ""

# Generate credential ID (32 bytes)
$credentialIdBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($credentialIdBytes)
$credentialIdB64Url = ConvertTo-Base64Url $credentialIdBytes

# Build COSE key using Key Vault public key coordinates
$coseKey = [ordered]@{
    1  = 2                   # kty: EC2
    3  = -7                  # alg: ES256
    -1 = 1                   # crv: P-256
    -2 = [byte[]]$publicKeyX # x coordinate (from Key Vault)
    -3 = [byte[]]$publicKeyY # y coordinate (from Key Vault)
}
$coseKeyBytes = [byte[]](New-CBOREncoded -Value $coseKey)

# Build authenticator data
$rpId = "login.microsoft.com"
$rpIdHash = [byte[]][System.Security.Cryptography.SHA256]::HashData(
    [System.Text.Encoding]::UTF8.GetBytes($rpId)
)
$authDataFlags = [byte[]]@(0x45)  # UP=1, AT=1
$signCount = [byte[]]@(0, 0, 0, 0)
$aaguid = [byte[]]::new(16)
$credIdLen = [BitConverter]::GetBytes([uint16]$credentialIdBytes.Length)
[Array]::Reverse($credIdLen)

[byte[]]$authData = $rpIdHash + $authDataFlags + $signCount + $aaguid + $credIdLen + $credentialIdBytes + $coseKeyBytes

# Build client data JSON
$challengeB64Url = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($serverChallenge))
$clientData = [ordered]@{
    type        = "webauthn.create"
    challenge   = $challengeB64Url
    origin      = "https://$rpId"
    crossOrigin = $false
} | ConvertTo-Json -Compress

$clientDataBytes = [System.Text.Encoding]::UTF8.GetBytes($clientData)
$clientDataB64Url = ConvertTo-Base64Url $clientDataBytes

# Sign with ephemeral batch attestation key (packed attestation)
# Microsoft requires full attestation (x5c certificate), not self-attestation.
# The batch key is ephemeral — it is only used here for registration and then discarded.
# The credential private key (used for authentication) lives in Key Vault.
[byte[]]$clientDataHash = [System.Security.Cryptography.SHA256]::HashData($clientDataBytes)
[byte[]]$signatureBase = $authData + $clientDataHash

$batchEcDsa = [System.Security.Cryptography.ECDsa]::Create(
    [System.Security.Cryptography.ECCurve]::CreateFromValue("1.2.840.10045.3.1.7")
)
try {
    $certReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=Batch Certificate, OU=Authenticator Attestation, O=Chromium, C=US",
        $batchEcDsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $batchCert = $certReq.CreateSelfSigned(
        [DateTimeOffset]::new(2017, 7, 14, 2, 40, 0, [TimeSpan]::Zero),
        [DateTimeOffset]::new(2046, 2, 6, 6, 33, 7, [TimeSpan]::Zero)
    )
    $batchCertDer = $batchCert.RawData

    $signatureBytes = $batchEcDsa.SignData(
        $signatureBase,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )
} finally {
    $batchEcDsa.Dispose()
}

# Build CBOR attestation object with x5c for full packed attestation
$attStmt = [ordered]@{ "alg" = -7; "sig" = [byte[]]$signatureBytes; "x5c" = @(,[byte[]]$batchCertDer) }
$attestationObj = [ordered]@{
    "fmt"      = "packed"
    "attStmt"  = $attStmt
    "authData" = [byte[]]$authData
}
$attestationObjBytes = [byte[]](New-CBOREncoded -Value $attestationObj)
$attestationObjB64Url = ConvertTo-Base64Url $attestationObjBytes

$extensionResults = '{"hmacCreateSecret":false}'
$extensionResultsB64Url = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($extensionResults))

Write-Host "  ✓ Attestation built (credential key in Key Vault, batch key ephemeral)" -ForegroundColor Green
Write-Host "    credentialId: $credentialIdB64Url" -ForegroundColor Gray
Write-Host "    rpId: $rpId" -ForegroundColor Gray
Write-Host "    authData: $($authData.Length) bytes" -ForegroundColor Gray
Write-Host "    attestationObject: $($attestationObjBytes.Length) bytes" -ForegroundColor Gray
Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# STAGE 5b: Call fido/create (registers challenge server-side)
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 5b: Register Challenge (fido/create) ===" -ForegroundColor Cyan
Write-Host ""

$fidoCreateBody = [ordered]@{
    correlationId                  = $correlationId
    canary                         = $fidoCanary
    ExcludeNextGenCredentialsJSON  = if ($excludeCredentials) { $excludeCredentials } else { '[]' }
    memberName                     = $UserPrincipalName
    postBackUrl                    = "$(if ($postBackUrl) { $postBackUrl } else { "$RedirectUri/api/post/newfido" })?mysignins-region=westus2&cid=$correlationId"
    serverChallenge                = $serverChallenge
    userDisplayName                = $PasskeyDisplayName
    userIconUrl                    = ''
    userId                         = $fidoUserId
}

$fidoCreateFormBody = ($fidoCreateBody.GetEnumerator() | ForEach-Object {
    "$([System.Web.HttpUtility]::UrlEncode($_.Key))=$([System.Web.HttpUtility]::UrlEncode($_.Value))"
}) -join '&'

$fidoCreateUrl = if ($provisionUrl) { "$provisionUrl`?cid=$correlationId" } else { "https://login.microsoft.com/$TenantId/fido/create?cid=$correlationId" }
Write-Host "  POST fido/create..." -ForegroundColor Yellow
Write-Host "  URL: $fidoCreateUrl" -ForegroundColor Gray

try {
    $fidoCreateResp = Invoke-WebRequest -Uri $fidoCreateUrl -Method POST -Body $fidoCreateFormBody `
        -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -WebSession $webSession
    Write-Host "  ✓ fido/create OK (status=$($fidoCreateResp.StatusCode), size=$($fidoCreateResp.Content.Length))" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ fido/create failed: $_" -ForegroundColor DarkYellow
    Write-Host "    Continuing anyway - the challenge may still be valid..." -ForegroundColor DarkYellow
}
Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# STAGE 6: Finalize Registration (newfido → verify)
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 6: Finalize Registration ===" -ForegroundColor Cyan
Write-Host ""

$newFidoUrl = if ($postBackUrl) {
    if ($postBackUrl -notmatch '\?') { "$postBackUrl`?mysignins-region=westus2&cid=$correlationId" }
    else { $postBackUrl }
} else {
    "$RedirectUri/api/post/newfido?mysignins-region=westus2&cid=$correlationId"
}

$newFidoBody = [ordered]@{
    canary                  = $fidoCanary
    authenticator           = 'cross-platform'
    transports              = 'usb'
    aaguid                  = '00000000-0000-0000-0000-000000000000'
    credentialDeviceType    = 'singleDevice'
    credentialBackedUp      = 'false'
    attestationParseError   = ''
    error_code              = ''
    suberror_code           = ''
    clientDataJson          = $clientDataB64Url
    attestationObject       = $attestationObjB64Url
    credentialId            = $credentialIdB64Url
    clientExtensionResults  = $extensionResultsB64Url
    i19                     = ''
}

$newFidoFormBody = ($newFidoBody.GetEnumerator() | ForEach-Object {
    "$([System.Web.HttpUtility]::UrlEncode($_.Key))=$([System.Web.HttpUtility]::UrlEncode($_.Value))"
}) -join '&'

$fidoHeaders = @{
    'Origin'  = 'https://login.microsoft.com'
    'Referer' = 'https://login.microsoft.com/'
}

Write-Host "  Step 1: Submitting attestation to newfido..." -ForegroundColor Yellow
Write-Host "  URL: $newFidoUrl" -ForegroundColor Gray

$fidoResp = Invoke-WebRequest -Uri $newFidoUrl -Method POST -Body $newFidoFormBody `
    -ContentType "application/x-www-form-urlencoded" -Headers $fidoHeaders -UseBasicParsing -WebSession $webSession

Write-Host "  ✓ newfido response: $($fidoResp.StatusCode) ($($fidoResp.Content.Length) bytes)" -ForegroundColor Green

if ($fidoResp.Content -match '\$Config=(\{.+\});') {
    try {
        $respCfg = $matches[1] | ConvertFrom-Json
        if ($respCfg.iErrorCode -and $respCfg.iErrorCode -ne 0) {
            Write-Host "  ✗ newfido error: code=$($respCfg.iErrorCode)" -ForegroundColor Red
            if ($respCfg.strServiceExceptionMessage) {
                Write-Host "    $($respCfg.strServiceExceptionMessage)" -ForegroundColor Red
            }
            throw "newfido returned error code $($respCfg.iErrorCode)"
        }
    } catch [System.ArgumentException] { <# JSON parse failed, not a config block #> }
}

Write-Host ""
Write-Host "  Step 1b: Parsing newfido response..." -ForegroundColor Yellow

$newfidoContext = $null
$newfidoRedirectUrl = $null

if ($fidoResp.Content -match '<div\s+id="context"\s+data-content="([^"]*)"') {
    $newfidoContext = [System.Web.HttpUtility]::HtmlDecode($matches[1])
    Write-Host "    ✓ Extracted context from newfido ($($newfidoContext.Length) chars)" -ForegroundColor Green

    try {
        $contextObj = $newfidoContext | ConvertFrom-Json
        if ($contextObj.Canary) {
            $fidoCanary = $contextObj.Canary
            Write-Host "    ✓ Canary confirmed from newfido context" -ForegroundColor Green
        }
        if ($contextObj.AttestationObject) { Write-Host "    ✓ AttestationObject present" -ForegroundColor Green }
        if ($contextObj.ClientDataJson) { Write-Host "    ✓ ClientDataJson present" -ForegroundColor Green }
    } catch {
        Write-Host "    ⚠ Could not parse context JSON: $_" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "    ⚠ Could not extract context div from newfido HTML" -ForegroundColor DarkYellow
}

if ($fidoResp.Content -match '<div\s+id="redirectUrl"\s+data-content="([^"]*)"') {
    $newfidoRedirectUrl = [System.Web.HttpUtility]::HtmlDecode($matches[1])
    $truncUrl = if ($newfidoRedirectUrl.Length -gt 80) { "$($newfidoRedirectUrl.Substring(0,80))..." } else { $newfidoRedirectUrl }
    Write-Host "    ✓ Redirect URL: $truncUrl" -ForegroundColor Green
} else {
    Write-Host "    ⚠ Could not extract redirectUrl div from newfido HTML" -ForegroundColor DarkYellow
}

if ($newfidoRedirectUrl) {
    $navUrl = $newfidoRedirectUrl -replace '#.*$', ''
    Write-Host "    Loading security-info page (simulating browser redirect)..." -ForegroundColor Gray
    try {
        $navResp = Invoke-WebRequest -Uri $navUrl -Method GET -UseBasicParsing -WebSession $webSession
        Write-Host "    ✓ Security-info page loaded: $($navResp.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "    ⚠ Navigation to redirect URL failed (continuing): $_" -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "  Step 2: Finalizing registration (authenticationmethods/verify)..." -ForegroundColor Yellow

Write-Host "    Re-authorizing session..." -ForegroundColor Gray
$reAuthHeaders = @{
    'Authorization'          = "Bearer $selfToken"
    'SessionCtxV2'           = $sessionCtxV2
    'Origin'                 = $RedirectUri
    'Referer'                = "$RedirectUri/security-info"
    'AjaxRequest'            = 'true'
    'x-ms-mysignins-region'  = 'westus2'
    'x-ms-client-session-id' = $clientSessionId
}
try {
    $reAuthResp = Invoke-WebRequest -Uri "$RedirectUri/api/session/authorize" -Method POST `
        -Headers $reAuthHeaders -ContentType "application/json" -Body '{}' -UseBasicParsing -WebSession $webSession
    $reAuthJson = $reAuthResp.Content | ConvertFrom-Json
    if ($reAuthJson.sessionCtxV2) {
        $sessionCtxV2 = $reAuthJson.sessionCtxV2
        Write-Host "    ✓ Session re-authorized, fresh SessionCtxV2" -ForegroundColor Green
    }
} catch {
    Write-Host "    ⚠ Session re-auth failed (continuing with existing session): $_" -ForegroundColor DarkYellow
}

$verificationData = @{
    Name                   = $PasskeyDisplayName
    Canary                 = $fidoCanary
    AttestationObject      = $attestationObjB64Url
    ClientDataJson         = $clientDataB64Url
    CredentialId           = $credentialIdB64Url
    ClientExtensionResults = $extensionResultsB64Url
    PostInfo               = ""
    AAGuid                 = "00000000-0000-0000-0000-000000000000"
    CredentialDeviceType   = "singleDevice"
} | ConvertTo-Json -Compress

$verifyBody = @{
    Type             = 18
    VerificationData = $verificationData
} | ConvertTo-Json -Compress

$verifyHeaders = @{
    'SessionCtxV2'           = $sessionCtxV2
    'Origin'                 = $RedirectUri
    'Referer'                = "$RedirectUri/security-info"
    'AjaxRequest'            = 'true'
    'x-ms-mysignins-region'  = 'westus2'
    'x-ms-client-session-id' = $clientSessionId
    'x-rff'                  = 'tff,cpfaudit,enslfmg,fwdIam,pKoe,drmm,myAccSi,saap,mregph,mysigninsfido,mysigninsauthappnotification,mysigninsauthappotp,migaam,mrp,hoaref,mregextauth,mreghwoath,mregsq,premr,cepcr,ebtta,otebvpf,mysigninssetdefault,gcu,msieme,msiemedel,mdelsq,mdelhwoath,msidelauthapp,mdelph,msidelfido,msrappp,msdappp,aamp,fwdPhIam,fido2fs,psi2fs,sve,gprp,ctumaru,dhwo,legacyHwOATH,epowe,asnmfc,ppre,sspuispid,mahfc,pkrce,miseclientid,fnmosia,essvc,etmosvc,enmosia,enmosiv,enmosid,enmosisd,enmosidht,enmosiima,enmopr,asnmtabr,onmfrc,eaieci,enlnb,esiastnb,ersiemfa,duc,stffrf,svfae,gcufa,gprpfa,umarufnc,mfarae,gefmassv'
}

$verifyUrl = "$RedirectUri/api/authenticationmethods/verify"
Write-Host "  URL: $verifyUrl" -ForegroundColor Gray
Write-Host "  Body length: $($verifyBody.Length) chars" -ForegroundColor Gray

$registrationSuccess = $false
$verifyJson = $null
try {
    $verifyResp = Invoke-WebRequest -Uri $verifyUrl -Method POST -Body $verifyBody `
        -ContentType "application/json" -Headers $verifyHeaders -UseBasicParsing -WebSession $webSession

    $verifyJson = $verifyResp.Content | ConvertFrom-Json
    Write-Host "  Response: $($verifyResp.StatusCode) ($($verifyResp.Content.Length) bytes)" -ForegroundColor Gray
} catch {
    $errResp = $_.Exception.Response
    $errBody = $null
    if ($_.ErrorDetails.Message) {
        $errBody = $_.ErrorDetails.Message
    } elseif ($errResp) {
        try {
            $errStream = $errResp.GetResponseStream()
            $reader = [System.IO.StreamReader]::new($errStream)
            $errBody = $reader.ReadToEnd()
            $reader.Close()
        } catch {}
    }
    Write-Host "  HTTP Error: $($errResp.StatusCode) $($errResp.StatusCode.value__)" -ForegroundColor Red
    if ($errBody) {
        Write-Host "  Error body: $errBody" -ForegroundColor Red
        try { $verifyJson = $errBody | ConvertFrom-Json } catch {}
    } else {
        Write-Host "  Exception: $_" -ForegroundColor Red
    }
}

if ($verifyJson) {
    if ($verifyJson.ErrorCode -and $verifyJson.ErrorCode -ne 0) {
        Write-Host "  ✗ verify error: ErrorCode=$($verifyJson.ErrorCode), VerificationState=$($verifyJson.VerificationState), ErrorType=$($verifyJson.ErrorType)" -ForegroundColor Red
    }

    if ($verifyJson.VerificationState -eq 2) {
        $registrationSuccess = $true
        $regCredId = $verifyJson.DataUpdates.FidoDevices.CredentialId
        $regDisplayName = $verifyJson.DataUpdates.FidoDevices.DisplayName
        $regCreated = $verifyJson.DataUpdates.FidoDevices.CreationTime
        Write-Host "  ✓ Passkey registered successfully!" -ForegroundColor Green
        Write-Host "    CredentialId: $regCredId" -ForegroundColor Gray
        Write-Host "    DisplayName:  $regDisplayName" -ForegroundColor Gray
        Write-Host "    Created:      $regCreated" -ForegroundColor Gray
    } elseif (-not $registrationSuccess) {
        Write-Host "  ⚠ VerificationState: $($verifyJson.VerificationState) (expected 2)" -ForegroundColor DarkYellow
        Write-Host "  Full response:" -ForegroundColor Gray
        Write-Host ($verifyJson | ConvertTo-Json -Depth 5) -ForegroundColor Gray
    }
}

if (-not $registrationSuccess) {
    Write-Host "  ⚠ Could not confirm registration success - check mysignins.microsoft.com" -ForegroundColor DarkYellow
    Write-Host ""
    throw "Passkey registration failed."
}
Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# Save Credential (Key Vault reference, no private key)
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== Saving Credential ===" -ForegroundColor Cyan

if (-not $OutputPath) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputPath = Join-Path (Get-Location) "$($UserPrincipalName.Split('@')[0])_passkey_$timestamp.json"
}

$credential = @{
    credentialId    = $credentialIdB64Url
    relyingParty    = $rpId
    url             = "https://$rpId"
    userName        = $UserPrincipalName
    userHandle      = $fidoUserId
    displayName     = $PasskeyDisplayName
    keyVault        = @{
        vaultName = $KeyVaultName
        keyName   = $kvKeyNameResolved
        keyId     = $kvKeyId
    }
    createdDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

$credential | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "  ✓ Credential saved to: $OutputPath" -ForegroundColor Green
Write-Host "  🔒 Private key remains in Key Vault: $KeyVaultName/$kvKeyNameResolved" -ForegroundColor Green
Write-Host ""

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  Passkey registration complete!" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
Write-Host "  Use PasskeyLogin.ps1 with the credential file to authenticate:" -ForegroundColor Gray
Write-Host "    .\PasskeyLogin.ps1 -KeyFilePath ""$OutputPath"" ``" -ForegroundColor Gray
Write-Host "        -KeyVaultClientId '<app-id>' -KeyVaultClientSecret '<secret>' ``" -ForegroundColor Gray
Write-Host "        -KeyVaultTenantId $TenantId" -ForegroundColor Gray
Write-Host ""
