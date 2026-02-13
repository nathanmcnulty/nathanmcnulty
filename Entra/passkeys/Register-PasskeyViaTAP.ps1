#Requires -Version 7.0
<#
.SYNOPSIS
    Registers a FIDO2 passkey using a Temporary Access Pass via the ESTS native flow.

.DESCRIPTION
    Replicates the browser's mysignins.microsoft.com passkey registration flow using
    a Temporary Access Pass (TAP) for authentication.

    Flow:
    1. TAP Login: Full login flow using AccessPass field (ps=56)
    2. Token Exchange: Auth code + PKCE → access_token + refresh_token
    3. Session Setup: session/authorize → NGC MFA claims refresh → SessionCtxV2
    4. Passkey Init: authenticationmethods/new {Type:18} → canary + serverChallenge
    5. Attestation: Generates ECDSA P-256 key, builds WebAuthn attestation
    6. Registration: POSTs to fido/create then newfido with canary + attestation

    Key technical details:
    - Origin header (https://mysignins.microsoft.com) required on ALL token endpoint calls
    - NGC MFA claims refresh works with any MFA method, not just passwordless
    - authenticationmethods/new response Data field is double-JSON
    - Signatures must use DER format (Rfc3279DerSequence)

.PARAMETER TAP
    Temporary Access Pass value.

.PARAMETER UserPrincipalName
    The user's UPN (e.g., user@contoso.com).

.PARAMETER TenantId
    The Azure AD tenant ID (GUID).

.PARAMETER DisplayName
    Display name for the passkey (default: "Software Passkey").

.PARAMETER OutputPath
    Path to save the credential JSON file. Defaults to <username>_passkey_<timestamp>.json.

.EXAMPLE
    .\Register-PasskeyViaTAP.ps1 -TAP "abc123" -UserPrincipalName "user@contoso.com" -TenantId "847b5907-..."

.EXAMPLE
    .\Register-PasskeyViaTAP.ps1 -TAP $tap -UserPrincipalName "admin@contoso.com" -TenantId $tid -DisplayName "YubiKey 5"

.NOTES
    Author: Nathan McNulty
    Date: February 12, 2026
    
    Flow discovered via HAR analysis of mysignins.microsoft.com passkey registration.
    The browser uses ESTS native endpoints (fido/create → newfido), NOT the Graph API.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [object]$TAP,

    [Parameter(Mandatory)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter()]
    [string]$DisplayName = "Software Passkey",

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

# Convert SecureString to plain text if needed
if ($TAP -is [securestring]) {
    $TAP = [System.Net.NetworkCredential]::new('', $TAP).Password
} elseif ($TAP -isnot [string]) {
    $TAP = [string]$TAP
}
$ClientId = "19db86c3-b2b9-44cc-b339-36da233a3be2"  # My Signins SPA
$RedirectUri = "https://mysignins.microsoft.com"

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  FIDO2 Passkey Registration via TAP (ESTS Native Flow)" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

#region Helper Functions

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-CBOREncoded {
    param($Value)
    $bytes = [System.Collections.Generic.List[byte]]::new()

    if ($Value -is [int]) {
        if ($Value -ge 0) {
            # Major type 0: unsigned integer
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
            # Major type 1: negative integer (CBOR encodes as -1 - n)
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
        # Major type 3: text string
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
        # Major type 2: byte string
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
        # Major type 4: array
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
        # Major type 5: map
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

# Shared WebSession for cookie handling across all stages
$webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()

# Scope used throughout — $ClientId/.default gives the correct audience/permissions
$tokenScope = "$ClientId/.default openid profile offline_access"

# Generate PKCE
$verifierBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($verifierBytes)
$codeVerifier = [Convert]::ToBase64String($verifierBytes) -replace '\+','-' -replace '/','_' -replace '=',''
$challengeBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
$codeChallenge = [Convert]::ToBase64String($challengeBytes) -replace '\+','-' -replace '/','_' -replace '=',''

# ══════════════════════════════════════════════════════════════════════
# STAGE 1: TAP Login
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 1: TAP Login ===" -ForegroundColor Cyan
Write-Host ""

Write-Host "  ✓ PKCE generated" -ForegroundColor Green

# Step 1a: Load the login page
$state = [guid]::NewGuid().ToString()
$authUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?" + `
    "client_id=$ClientId" + `
    "&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($RedirectUri))" + `
    "&scope=$([System.Web.HttpUtility]::UrlEncode($tokenScope))" + `
    "&response_type=code" + `
    "&response_mode=fragment" + `
    "&prompt=login" + `
    "&login_hint=$([System.Web.HttpUtility]::UrlEncode($UserPrincipalName))" + `
    "&code_challenge=$codeChallenge" + `
    "&code_challenge_method=S256" + `
    "&state=$state"

Write-Host "  Loading login page..." -ForegroundColor Yellow
$loginPage = Invoke-WebRequest -Uri $authUrl -UseBasicParsing -MaximumRedirection 10 -WebSession $webSession

if ($loginPage.StatusCode -ne 200) {
    throw "Expected login page (200), got $($loginPage.StatusCode)"
}

# Parse $Config from HTML
if ($loginPage.Content -notmatch '\$Config=(\{.+\});') {
    throw "Could not extract `$Config from login page"
}
$config = $matches[1] | ConvertFrom-Json

if ($config.pgid -ne 'ConvergedSignIn') {
    throw "Unexpected page: $($config.pgid). Error: $($config.strServiceExceptionMessage)"
}

$flowToken = $config.sFT
$sCtx = $config.sCtx
$canary = $config.canary
$apiCanary = $config.apiCanary
$sessionId = $config.sessionId
$urlPost = $config.urlPost

Write-Host "  ✓ Login page loaded (session=$sessionId)" -ForegroundColor Green

# Step 1b: GetCredentialType (tells server we're using TAP)
Write-Host "  Calling GetCredentialType..." -ForegroundColor Yellow
$gctBody = @{
    username                = $UserPrincipalName
    isOtherIdpSupported     = $false
    checkPhones             = $false
    isRemoteNGCSupported    = $true
    isCookieBannerShown     = $false
    isFidoSupported         = $true
    originalRequest         = $sCtx
    flowToken               = $flowToken
} | ConvertTo-Json -Compress

$gctHeaders = @{
    'canary'       = $apiCanary
    'hpgrequestid' = $sessionId
    'hpgact'       = '1800'
    'hpgid'        = '1104'
}

try {
    $gctResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US" `
        -Method POST -Body $gctBody -ContentType "application/json" -Headers $gctHeaders
    
    # Update flowToken if returned
    if ($gctResp.FlowToken) {
        $flowToken = $gctResp.FlowToken
        Write-Host "  ✓ GetCredentialType OK (flowToken updated)" -ForegroundColor Green
    } else {
        Write-Host "  ✓ GetCredentialType OK" -ForegroundColor Green
    }
    
    # Check credential type
    if ($gctResp.Credentials) {
        $credTypes = ($gctResp.Credentials.PrefCredential, $gctResp.Credentials.HasPassword) -join ', '
        Write-Host "    Credential info: $credTypes" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ⚠ GetCredentialType failed (continuing without): $_" -ForegroundColor DarkYellow
}

# Step 1c: POST login with TAP
Write-Host "  Submitting TAP to login endpoint..." -ForegroundColor Yellow

$loginBody = @{
    login              = $UserPrincipalName
    loginfmt           = $UserPrincipalName
    accesspass         = $TAP
    ps                 = '56'
    psRNGCDefaultType  = '1'
    psRNGCEntropy      = ''
    psRNGCSLK          = $flowToken
    canary             = $canary
    ctx                = $sCtx
    hpgrequestid       = $sessionId
    flowToken          = $flowToken
    PPSX               = ''
    NewUser            = '1'
    FoundMSAs          = ''
    fspost             = '0'
    i21                = '0'
    CookieDisclosure   = '0'
    IsFidoSupported    = '1'
    isSignupPost       = '0'
    DfpArtifact        = ''
    i19                = '10000'
}

$formBody = ($loginBody.GetEnumerator() | ForEach-Object { "$([System.Web.HttpUtility]::UrlEncode($_.Key))=$([System.Web.HttpUtility]::UrlEncode($_.Value))" }) -join '&'

$loginUrl = "https://login.microsoftonline.com$urlPost"
if ([string]::IsNullOrEmpty($urlPost)) {
    $loginUrl = "https://login.microsoftonline.com/common/login"
}

# Follow redirect chain manually until we find the auth code
$authCode = $null
$currentUrl = $loginUrl
$currentMethod = 'POST'
$currentBody = $formBody
$currentContentType = "application/x-www-form-urlencoded"
$maxRedirects = 15

for ($redirectCount = 0; $redirectCount -lt $maxRedirects; $redirectCount++) {
    try {
        $reqParams = @{
            Uri                = $currentUrl
            Method             = $currentMethod
            WebSession         = $webSession
            MaximumRedirection = 0
            UseBasicParsing    = $true
        }
        if ($currentMethod -eq 'POST' -and $currentBody) {
            $reqParams['Body'] = $currentBody
            $reqParams['ContentType'] = $currentContentType
        }
        
        $resp = Invoke-WebRequest @reqParams -ErrorAction Stop
        
        # 200 response - might be KMSI page or login page with error
        if ($resp.StatusCode -eq 200) {
            # Check for an auto-submit form (common in redirect flows)
            if ($resp.Content -match 'action="([^"]+)"') {
                $formAction = $matches[1]
                # Extract hidden form fields
                $hiddenFields = [regex]::Matches($resp.Content, '<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"')
                $formData = ($hiddenFields | ForEach-Object { 
                    "$([System.Web.HttpUtility]::UrlEncode($_.Groups[1].Value))=$([System.Web.HttpUtility]::UrlEncode($_.Groups[2].Value))" 
                }) -join '&'
                
                if ($formAction -and $formData) {
                    # Resolve relative URL
                    if ($formAction.StartsWith('/')) {
                        $uri = [System.Uri]$currentUrl
                        $formAction = "$($uri.Scheme)://$($uri.Host)$formAction"
                    }
                    $currentUrl = $formAction
                    $currentMethod = 'POST'
                    $currentBody = $formData
                    $currentContentType = "application/x-www-form-urlencoded"
                    Write-Host "    → Following form POST to: $($formAction.Substring(0, [Math]::Min(80, $formAction.Length)))..." -ForegroundColor DarkGray
                    continue
                }
            }
            
            # Check for $Config errors
            if ($resp.Content -match '\$Config=(\{.+\});') {
                $respConfig = $matches[1] | ConvertFrom-Json
                if ($respConfig.strServiceExceptionMessage) {
                    throw "Login page error: $($respConfig.strServiceExceptionMessage)"
                }
                if ($respConfig.pgid -eq 'ConvergedSignIn') {
                    throw "Returned to login page. TAP may be invalid or expired."
                }
                if ($respConfig.pgid -eq 'KmsiBroker') {
                    # KMSI pages have a standard auto-submit form — handled by the
                    # generic form handler above. If we reach here, the form had
                    # no extractable hidden inputs; throw to avoid an infinite loop.
                    throw "KMSI page detected but could not extract form data."
                }
            }
            
            # Didn't find a redirect mechanism - dump what we got
            throw "Unexpected 200 response at redirect step $redirectCount. Content length: $($resp.Content.Length)"
        }
    } catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        # Handle redirect status codes (301, 302, 307, 308)
        $statusCode = [int]$_.Exception.Response.StatusCode
        if ($statusCode -ge 300 -and $statusCode -lt 400) {
            $location = $_.Exception.Response.Headers.Location.ToString()
            
            # Resolve relative redirect
            if ($location.StartsWith('/')) {
                $uri = [System.Uri]$currentUrl
                $location = "$($uri.Scheme)://$($uri.Host)$location"
            }
            
            # Check for auth code in fragment (#code=...) or query (?code=...)
            if ($location -match '[#?&]code=([^&#]+)') {
                $authCode = [System.Web.HttpUtility]::UrlDecode($matches[1])
                Write-Host "  ✓ TAP login successful! Got auth code (len=$($authCode.Length))" -ForegroundColor Green
                
                # Capture cookies from this response
                try {
                    foreach ($header in $_.Exception.Response.Headers.GetValues('Set-Cookie')) {
                        if ($header -match '(ESTSAUTH[^=]*)=([^;]+)') {
                            $webSession.Cookies.Add([System.Net.Cookie]::new($matches[1], $matches[2], "/", ".login.microsoftonline.com"))
                        }
                    }
                } catch {}
                break
            }
            
            # Check for error
            if ($location -match 'error=([^&#]+)') {
                $errorCode = [System.Web.HttpUtility]::UrlDecode($matches[1])
                $errorDesc = ""
                if ($location -match 'error_description=([^&#]+)') {
                    $errorDesc = [System.Web.HttpUtility]::UrlDecode($matches[1])
                }
                throw "Login failed: $errorCode - $errorDesc"
            }
            
            # Capture cookies from redirects
            try {
                foreach ($header in $_.Exception.Response.Headers.GetValues('Set-Cookie')) {
                    if ($header -match '(ESTSAUTH[^=]*)=([^;]+)') {
                        $webSession.Cookies.Add([System.Net.Cookie]::new($matches[1], $matches[2], "/", ".login.microsoftonline.com"))
                    }
                }
            } catch {}
            
            Write-Host "    → 302 to: $($location.Substring(0, [Math]::Min(80, $location.Length)))..." -ForegroundColor DarkGray
            $currentUrl = $location
            $currentMethod = 'GET'
            $currentBody = $null
            continue
        }
        throw
    }
}

if (-not $authCode) {
    throw "Failed to get auth code after $maxRedirects redirect steps"
}

Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# STAGE 2: Token Exchange (SPA + PKCE)
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 2: Token Exchange ===" -ForegroundColor Cyan
Write-Host ""

# Exchange auth code for tokens using $ClientId/.default scope (self-referencing)
# CRITICAL: Origin header is required — SPA client rejects token exchange without it
$tokenBody = "client_id=$ClientId" + `
    "&scope=$([System.Web.HttpUtility]::UrlEncode($tokenScope))" + `
    "&grant_type=authorization_code" + `
    "&code=$([System.Web.HttpUtility]::UrlEncode($authCode))" + `
    "&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($RedirectUri))" + `
    "&code_verifier=$codeVerifier"

$tokenResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -Headers $spaHeaders

$selfToken = $tokenResp.access_token
$currentRefreshToken = $tokenResp.refresh_token

Write-Host "  ✓ Token exchange successful!" -ForegroundColor Green
Write-Host "    access_token: $($selfToken.Length) chars" -ForegroundColor Gray
Write-Host "    refresh_token: $(if($currentRefreshToken){'present'}else{'MISSING'})" -ForegroundColor $(if($currentRefreshToken){'Gray'}else{'Red'})

if (-not $currentRefreshToken) {
    throw "No refresh_token returned. Cannot proceed without it."
}
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

# ── NGC MFA token refresh ──────────────────────────────────────────
# When requireNgcMfaForSecurityInfo=True, the SPA requests a token with
# amr=ngcmfa via the claims parameter. TAP satisfies NGC MFA as a
# passwordless bootstrapping credential. This is the key step that makes
# authenticationmethods/new accept the token.
if ($sessResp.requireNgcMfaForSecurityInfo) {
    Write-Host "  NGC MFA required – refreshing token with ngcmfa claims..." -ForegroundColor Yellow

    $ngcClaims = '{"id_token":{"amr":{"essential":true,"values":["ngcmfa"]}},"access_token":{"amr":{"essential":true,"values":["ngcmfa"]}}}'
    $ngcBody = "client_id=$ClientId" + `
        "&scope=$([System.Web.HttpUtility]::UrlEncode("$ClientId/.default openid"))" + `
        "&grant_type=refresh_token" + `
        "&refresh_token=$([System.Web.HttpUtility]::UrlEncode($currentRefreshToken))" + `
        "&claims=$([System.Web.HttpUtility]::UrlEncode($ngcClaims))"

    # CRITICAL: Origin header is required on ALL token endpoint calls for SPA clients.
    # Without it, the NGC MFA claims refresh fails with AADSTS130507.
    $ngcResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Method POST -Body $ngcBody -ContentType "application/x-www-form-urlencoded" -Headers $spaHeaders

    $selfToken = $ngcResp.access_token
    Write-Host "  ✓ NGC self-token acquired ($($selfToken.Length) chars)" -ForegroundColor Green

    # Update refresh_token if a new one was returned
    if ($ngcResp.refresh_token) {
        $currentRefreshToken = $ngcResp.refresh_token
    }

    # Second session/authorize with the NGC token (creates proper SessionCtxV2)
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

# Response structure: { Type: 18, VerificationState: 1, Data: "<JSON string>", ErrorCode: 0 }
if ($newJson.ErrorCode -and $newJson.ErrorCode -ne 0) {
    Write-Host "  Response:" -ForegroundColor Yellow
    Write-Host ($newJson | ConvertTo-Json -Depth 3) -ForegroundColor Gray
    throw "authenticationmethods/new returned ErrorCode $($newJson.ErrorCode)"
}

Write-Host "  ✓ Passkey creation initiated!" -ForegroundColor Green

# The Data field is a JSON string that must be parsed again
$innerJson = $newJson.Data | ConvertFrom-Json
$requestData = $innerJson.requestData
$provisionUrl = $innerJson.provisionUrl
$fidoCanary = $requestData.canary
$serverChallenge = $requestData.serverChallenge
$postBackUrl = $requestData.postBackUrl
$fidoUserId = $requestData.userId
$correlationId = [guid]::NewGuid().ToString()
$excludeCredentials = $requestData.ExcludeNextGenCredentialsJSON

if ([string]::IsNullOrEmpty($fidoCanary)) {
    Write-Host "  Response structure:" -ForegroundColor Yellow
    Write-Host ($newJson | ConvertTo-Json -Depth 3) -ForegroundColor Gray
    throw "Failed to get canary from authenticationmethods/new response"
}
if ([string]::IsNullOrEmpty($serverChallenge)) {
    throw "No serverChallenge returned from authenticationmethods/new"
}
if ([string]::IsNullOrEmpty($fidoUserId)) {
    throw "No userId returned from authenticationmethods/new (required for fido/create)"
}

Write-Host "    provisionUrl: $provisionUrl" -ForegroundColor Gray
Write-Host "    canary: $($fidoCanary.Substring(0, [Math]::Min(60, $fidoCanary.Length)))..." -ForegroundColor Gray
Write-Host "    serverChallenge: $(if($serverChallenge){$serverChallenge.Substring(0,[Math]::Min(60,$serverChallenge.Length))+'...'}else{'null'})" -ForegroundColor Gray
Write-Host "    correlationId: $correlationId" -ForegroundColor Gray
Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# STAGE 5: Build WebAuthn Attestation
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== STAGE 5: Build Attestation ===" -ForegroundColor Cyan
Write-Host ""

# Generate ES256 key pair (P-256 / secp256r1)
$ecDsa = [System.Security.Cryptography.ECDsa]::Create(
    [System.Security.Cryptography.ECCurve]::CreateFromValue("1.2.840.10045.3.1.7")
)
try {
$publicKeyParams = $ecDsa.ExportParameters($false)
Write-Host "  ✓ ES256 key pair generated" -ForegroundColor Green

# Generate credential ID (32 bytes like in HAR)
$credentialIdBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($credentialIdBytes)
$credentialIdB64Url = ConvertTo-Base64Url $credentialIdBytes

# Build COSE key (CBOR-encoded public key) — CTAP2 canonical order: sort by encoded key bytes
$coseKey = [ordered]@{
    1  = 2                          # kty: EC2
    3  = -7                         # alg: ES256
    -1 = 1                          # crv: P-256
    -2 = [byte[]]$publicKeyParams.Q.X  # x coordinate
    -3 = [byte[]]$publicKeyParams.Q.Y  # y coordinate
}
$coseKeyBytes = [byte[]](New-CBOREncoded -Value $coseKey)

# Build authenticator data
$rpId = "login.microsoft.com"
$rpIdHash = [byte[]][System.Security.Cryptography.SHA256]::HashData(
    [System.Text.Encoding]::UTF8.GetBytes($rpId)
)
$authDataFlags = [byte[]]@(0x45)  # UP=1, AT=1 (attested credential data present)
$signCount = [byte[]]@(0, 0, 0, 0)
$aaguid = [byte[]]::new(16)  # All zeros — standard for software authenticators
$credIdLen = [BitConverter]::GetBytes([uint16]$credentialIdBytes.Length)
[Array]::Reverse($credIdLen)

[byte[]]$authData = $rpIdHash + $authDataFlags + $signCount + $aaguid + $credIdLen + $credentialIdBytes + $coseKeyBytes

# Build client data JSON
# The challenge in clientDataJSON is base64url(UTF8(serverChallenge JWE string))
# This matches the browser's WebAuthn behavior - the challenge bytes ARE the JWE string
$challengeB64Url = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($serverChallenge))

$clientData = [ordered]@{
    type        = "webauthn.create"
    challenge   = $challengeB64Url
    origin      = "https://$rpId"
    crossOrigin = $false
} | ConvertTo-Json -Compress

$clientDataBytes = [System.Text.Encoding]::UTF8.GetBytes($clientData)
$clientDataB64Url = ConvertTo-Base64Url $clientDataBytes

# Sign: authData + SHA256(clientDataJSON) using a BATCH attestation key
# Microsoft requires full attestation (x5c certificate), not self-attestation
[byte[]]$clientDataHash = [System.Security.Cryptography.SHA256]::HashData($clientDataBytes)
[byte[]]$signatureBase = $authData + $clientDataHash

# Generate batch attestation key pair and self-signed certificate
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

    # Sign with BATCH key (full attestation), not credential key (self-attestation)
    $signatureBytes = $batchEcDsa.SignData(
        $signatureBase,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
    )
} finally {
    $batchEcDsa.Dispose()
}

# Build CBOR attestation object with x5c for full packed attestation
$attStmt = [ordered]@{
    "alg" = -7
    "sig" = [byte[]]$signatureBytes
    "x5c" = @(,[byte[]]$batchCertDer)
}
$attestationObj = [ordered]@{
    "fmt"     = "packed"
    "attStmt" = $attStmt
    "authData"= [byte[]]$authData
}
$attestationObjBytes = [byte[]](New-CBOREncoded -Value $attestationObj)
$attestationObjB64Url = ConvertTo-Base64Url $attestationObjBytes

# Client extension results (matching browser behavior)
$extensionResults = '{"hmacCreateSecret":false}'
$extensionResultsB64Url = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($extensionResults))

Write-Host "  ✓ Attestation built" -ForegroundColor Green
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
    userDisplayName                = $DisplayName
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

# Ensure newfido URL always has query parameters (postBackUrl from server may lack them)
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

Write-Host "  Submitting passkey to newfido..." -ForegroundColor Yellow
Write-Host "  URL: $newFidoUrl" -ForegroundColor Gray

$fidoResp = Invoke-WebRequest -Uri $newFidoUrl -Method POST -Body $newFidoFormBody `
    -ContentType "application/x-www-form-urlencoded" -Headers $fidoHeaders -UseBasicParsing -WebSession $webSession

Write-Host "  ✓ newfido response: $($fidoResp.StatusCode) ($($fidoResp.Content.Length) bytes)" -ForegroundColor Green

# Check for errors in newfido response
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

# ── Step 1b: Parse newfido response (context in div data-content, not form inputs) ──
Write-Host ""
Write-Host "  Step 1b: Parsing newfido response..." -ForegroundColor Yellow

# The newfido HTML uses <div> elements with data-content attributes:
#   <div id="context" data-content="{...JSON...}"></div>
#   <div id="redirectUrl" data-content="https://...#fidoProvisionSuccess=<canary>"></div>
# Browser JS stores context in sessionStorage, then redirects to redirectUrl.

$newfidoContext = $null
$newfidoRedirectUrl = $null

# Parse context div
if ($fidoResp.Content -match '<div\s+id="context"\s+data-content="([^"]*)"') {
    $newfidoContext = [System.Web.HttpUtility]::HtmlDecode($matches[1])
    Write-Host "    ✓ Extracted context from newfido ($($newfidoContext.Length) chars)" -ForegroundColor Green

    # Parse the context JSON to confirm data and extract server-side canary
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

# Parse redirectUrl div
if ($fidoResp.Content -match '<div\s+id="redirectUrl"\s+data-content="([^"]*)"') {
    $newfidoRedirectUrl = [System.Web.HttpUtility]::HtmlDecode($matches[1])
    $truncUrl = if ($newfidoRedirectUrl.Length -gt 80) { "$($newfidoRedirectUrl.Substring(0,80))..." } else { $newfidoRedirectUrl }
    Write-Host "    ✓ Redirect URL: $truncUrl" -ForegroundColor Green
} else {
    Write-Host "    ⚠ Could not extract redirectUrl div from newfido HTML" -ForegroundColor DarkYellow
}

# Navigate to the redirect URL to establish proper session state (simulates browser redirect)
if ($newfidoRedirectUrl) {
    $navUrl = $newfidoRedirectUrl -replace '#.*$', ''  # Strip fragment (not sent in HTTP)
    Write-Host "    Loading security-info page (simulating browser redirect)..." -ForegroundColor Gray
    try {
        $navResp = Invoke-WebRequest -Uri $navUrl -Method GET -UseBasicParsing -WebSession $webSession
        Write-Host "    ✓ Security-info page loaded: $($navResp.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "    ⚠ Navigation to redirect URL failed (continuing): $_" -ForegroundColor DarkYellow
    }
}

# ── Step 2: Finalize registration via authenticationmethods/verify ──
Write-Host ""
Write-Host "  Step 2: Finalizing registration (authenticationmethods/verify)..." -ForegroundColor Yellow

# Re-authorize session (the SPA does this after returning from fido/create flow)
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

# Build the verification payload matching the SPA's completeFidoRegistration call
$verificationData = @{
    Name                   = $DisplayName
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

# Browser verify call uses SessionCtxV2 + cookies, NO Authorization Bearer header
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

    # VerificationState 2 = verified (success)
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
    throw "Registration failed - could not confirm success. Check mysignins.microsoft.com"
}
Write-Host ""

# ══════════════════════════════════════════════════════════════════════
# Save Credential
# ══════════════════════════════════════════════════════════════════════
Write-Host "=== Saving Credential ===" -ForegroundColor Cyan

if (-not $OutputPath) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputPath = Join-Path (Get-Location) "$($UserPrincipalName.Split('@')[0])_passkey_$timestamp.json"
}

$pkcs8Bytes = $ecDsa.ExportPkcs8PrivateKey()
$pemBase64 = [Convert]::ToBase64String($pkcs8Bytes, [Base64FormattingOptions]::InsertLineBreaks)
$pem = "-----BEGIN PRIVATE KEY-----`n$pemBase64`n-----END PRIVATE KEY-----"

$credential = @{
    credentialId     = $credentialIdB64Url
    relyingParty     = $rpId
    url              = "https://$rpId"
    userName         = $UserPrincipalName
    userHandle       = $fidoUserId
    displayName      = $DisplayName
    privateKey       = $pem
    createdDateTime  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

$credential | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "  ✓ Credential saved to: $OutputPath" -ForegroundColor Green
Write-Host ""

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  Passkey registration complete!" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
Write-Host "  Use the private key from $OutputPath to sign" -ForegroundColor Gray
Write-Host "  WebAuthn assertions for authentication." -ForegroundColor Gray
Write-Host ""

} finally {
    $ecDsa.Dispose()
}
