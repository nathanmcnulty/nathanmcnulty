#Requires -Version 7.0

<#
.SYNOPSIS
    Standalone script for Entra ID Passkey authentication with Azure Key Vault support.

.DESCRIPTION
    This script performs FIDO2 passkey authentication to Entra ID without requiring the TokenTactics module.
    It supports both loading passkey details from a JSON file or providing them manually.
    
    **NEW**: Supports passkeys with private keys secured in Azure Key Vault. When the credential JSON
    contains a 'keyVault' property, the script automatically uses Key Vault Sign API instead of local signing.

.PARAMETER KeyFilePath
    Path to JSON file containing passkey details.
    
    The JSON file should contain the following properties:
    - credentialId: FIDO2 credential ID (base64url encoded or UUID format)
    - privateKey: Private key in PEM format (with BEGIN/END PRIVATE KEY headers) OR
    - keyVault: Object with vaultName, keyName, keyId (for Key Vault-backed passkeys)
    - relyingParty: Relying party identifier (e.g., "login.microsoft.com")
    - url: Authentication URL (e.g., "https://login.microsoft.com")
    - userHandle: FIDO2 user handle (base64url encoded)
    - username: User principal name (e.g., "user@domain.com")
    
    Example format (local private key):
    {
        "credentialId": "AbCd1234EfGh5678IjKl",
        "privateKey": "-----BEGIN PRIVATE KEY-----MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...-----END PRIVATE KEY-----",
        "relyingParty": "login.microsoft.com",
        "url": "https://login.microsoft.com",
        "userHandle": "ExAmPlE_UsErHaNdLe_BaSe64UrLeNcOdEd",
        "username": "user@example.com"
    }
    
    Example format (Key Vault-backed passkey):
    {
        "credentialId": "AbCd1234EfGh5678IjKl",
        "relyingParty": "login.microsoft.com",
        "url": "https://login.microsoft.com",
        "userHandle": "ExAmPlE_UsErHaNdLe_BaSe64UrLeNcOdEd",
        "username": "user@example.com",
        "keyVault": {
            "vaultName": "kv-passkey-1234",
            "keyName": "passkey-user-20260206-224956",
            "keyId": "https://kv-passkey-1234.vault.azure.net/keys/passkey-user-20260206-224956/a050db6e3e6747be808639e45aa0f714"
        }
    }

.PARAMETER UserPrincipalName
    User principal name for authentication.

.PARAMETER UserHandle
    FIDO2 user handle (base64url encoded).

.PARAMETER CredentialId
    FIDO2 credential ID (base64url encoded or UUID format).

.PARAMETER PrivateKey
    Private key in PEM format or base64 encoded (as SecureString).
    Can be created with: ConvertTo-SecureString 'key-data' -AsPlainText -Force

.PARAMETER RelyingParty
    Relying party identifier. Defaults to "login.microsoft.com".

.PARAMETER AuthUrl
    OAuth authorization URL. Defaults to Microsoft Azure CLI endpoint.

.PARAMETER UserAgent
    User agent string for HTTP requests.

.PARAMETER Proxy
    Proxy server URL if needed.

.PARAMETER KeyVaultName
    Name of the Azure Key Vault containing the passkey private key.
    Required for manual Key Vault authentication (without JSON file).
    Can override value from JSON file.

.PARAMETER KeyVaultKeyName
    Name of the key in Azure Key Vault.
    Required for manual Key Vault authentication (without JSON file).
    Can override value from JSON file.

.PARAMETER KeyVaultClientId
    Service principal client ID for Key Vault authentication.
    Required when using Key Vault-backed passkeys.

.PARAMETER KeyVaultClientSecret
    Service principal client secret for Key Vault authentication.
    Required when using Key Vault-backed passkeys.

.PARAMETER KeyVaultTenantId
    Tenant ID for Key Vault authentication.
    Required when using Key Vault-backed passkeys.

.PARAMETER PassThru
    Output authentication result as PSCustomObject for pipeline support.

.EXAMPLE
    .\PasskeyLogin.ps1 -KeyFilePath .\passkey.json
    
    Authenticate using a JSON file containing all passkey details.

.EXAMPLE
    $privateKey = ConvertTo-SecureString "-----BEGIN PRIVATE KEY-----..." -AsPlainText -Force
    .\PasskeyLogin.ps1 -UserPrincipalName user@domain.com -UserHandle "base64handle" -CredentialId "base64id" -PrivateKey $privateKey
    
    Authenticate using manual parameters with a local private key.
    Note: PrivateKey must be provided as a SecureString.

.EXAMPLE
    .\PasskeyLogin.ps1 -UserPrincipalName user@domain.com -UserHandle "base64handle" -CredentialId "base64id" -KeyVaultName "my-keyvault" -KeyVaultKeyName "passkey-key" -KeyVaultClientId "clientid" -KeyVaultClientSecret $secret -KeyVaultTenantId "tenantid"
    
    Authenticate using manual parameters with a Key Vault-backed private key.

.EXAMPLE
    $auth = .\PasskeyLogin.ps1 -KeyFilePath .\passkey.json -PassThru
    if ($auth.Success) {
        Write-Host "Authentication successful for $($auth.UserPrincipalName)"
    }
    
    Authenticate and capture result for pipeline or programmatic use.

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
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [PSCustomObject]$CredentialFromPipeline,
    
    [Parameter(Mandatory = $false)]
    [string]$KeyFilePath,

    [Alias('UserName')]
    [Parameter(Mandatory = $false)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $false)]
    [string]$UserHandle,

    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification='CredentialId is a FIDO2 identifier, not a credential')]
    [Parameter(Mandatory = $false)]
    [string]$CredentialId,

    [Parameter(Mandatory = $false)]
    [SecureString]$PrivateKey,

    [Parameter(Mandatory = $false)]
    $RelyingParty = "login.microsoft.com",

    [Parameter(Mandatory = $false)]
    $AuthUrl = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=msauth.com.msauth.unsignedapp://auth&scope=https://graph.microsoft.com/.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46",

    [Parameter(Mandatory = $false)]
    $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0',

    [Parameter(Mandatory = $false)]
    [string]$Proxy,
    
    # Key Vault parameters (can be provided for manual mode or to override JSON values)
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultKeyName,
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultClientId,
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultClientSecret,
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultTenantId,
    
    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

#region Helper Functions

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function ConvertFrom-Base64Url {
    param([string]$Base64Url)
    $base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
    # Add padding
    $padding = (4 - ($base64.Length % 4)) % 4
    $base64 += '=' * $padding
    return [Convert]::FromBase64String($base64)
}

function ConvertFrom-UuidToBase64Url {
    param([string]$Uuid)
    
    if ($Uuid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        return $Uuid  # Not a UUID, return as-is
    }
    
    Write-Verbose "Converting UUID format credential ID to base64url"
    $hexString = $Uuid.Replace('-', '')
    $rawBytes = [byte[]]::new($hexString.Length / 2)
    for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        $rawBytes[$i / 2] = [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    $base64 = [Convert]::ToBase64String($rawBytes)
    return $base64.Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function ConvertFrom-IeeeToDer {
    param([byte[]]$IeeeSignature)
    
    # IEEE P1363 format for ES256 is r || s (32 + 32 bytes)
    # DER format is: 0x30 <length> 0x02 <r-length> <r> 0x02 <s-length> <s>
    
    if ($IeeeSignature.Length -ne 64) {
        throw "Invalid IEEE P1363 signature length: $($IeeeSignature.Length). Expected 64 bytes for ES256."
    }
    
    $r = $IeeeSignature[0..31]
    $s = $IeeeSignature[32..63]
    
    # Remove leading zero bytes but keep at least one byte
    while ($r.Length -gt 1 -and $r[0] -eq 0) { $r = $r[1..($r.Length-1)] }
    while ($s.Length -gt 1 -and $s[0] -eq 0) { $s = $s[1..($s.Length-1)] }
    
    # Add leading zero if high bit is set (to keep it positive)
    if ($r[0] -ge 0x80) { $r = @(0) + $r }
    if ($s[0] -ge 0x80) { $s = @(0) + $s }
    
    # Build DER sequence
    $der = @(
        0x30,  # SEQUENCE tag
        ($r.Length + $s.Length + 4),  # Total length
        0x02,  # INTEGER tag for r
        $r.Length
    ) + $r + @(
        0x02,  # INTEGER tag for s
        $s.Length
    ) + $s
    
    return [byte[]]$der
}

function Get-KeyVaultToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )
    
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $tokenBody = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://vault.azure.net/.default"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorMessage = if ($_.ErrorDetails.Message) { 
            try { ($_.ErrorDetails.Message | ConvertFrom-Json).error_description } catch { $_.ErrorDetails.Message }
        } else { 
            $_.Exception.Message 
        }
        
        Write-Error "Failed to acquire Key Vault token (HTTP $statusCode): $errorMessage"
        
        if ($statusCode -eq 401 -or $statusCode -eq 400) {
            Write-Host "  → Check ClientId, ClientSecret, and TenantId are correct" -ForegroundColor Yellow
        }
        throw
    }
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
        [Parameter()]
        [string]$PrivateKeyPem,
        [Parameter()]
        $KeyVaultInfo,  # Accept any object type
        [Parameter()]
        [string]$KeyVaultToken
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
    Write-Verbose "AuthData length: $($AuthDataBytes.Length) bytes"
    Write-Verbose "ClientHash length: $($clientHash.Length) bytes"
    Write-Verbose "Combined data to sign length: $($dataToSign.Length) bytes"

    # 3. Generate Signature (Key Vault or Local)
    # CRITICAL: Both must sign the SAME data in the SAME way
    # - Key Vault: We hash the data, send hash, KV signs the hash
    # - Local: We hash the data, then sign the hash (matching Key Vault)
    
    # Pre-hash the data for consistent signing
    $dataHash = [System.Security.Cryptography.SHA256]::HashData($dataToSign)
    Write-Verbose "Pre-computed hash length: $($dataHash.Length) bytes"
    
    if ($KeyVaultInfo -and $KeyVaultToken) {
        Write-Host "    🔒 Signing with Azure Key Vault" -ForegroundColor Cyan
        
        # Key Vault expects base64url encoded hash
        $dataBase64Url = ConvertTo-Base64Url -Bytes $dataHash
        $signUri = "https://$($KeyVaultInfo.vaultName).vault.azure.net/keys/$($KeyVaultInfo.keyName)/sign?api-version=7.4"
        $headers = @{
            "Authorization" = "Bearer $KeyVaultToken"
            "Content-Type"  = "application/json"
        }
        $body = @{
            alg   = "ES256"
            value = $dataBase64Url
        } | ConvertTo-Json
        
        # Retry logic for Key Vault signing (network issues, throttling, etc.)
        $maxRetries = 3
        $retryDelay = 1000  # Start with 1 second
        $sigBytes = $null
        
        for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
            try {
                Write-Verbose "Key Vault sign attempt $attempt of $maxRetries..."
                $result = Invoke-RestMethod -Uri $signUri -Method POST -Headers $headers -Body $body -ErrorAction Stop
                
                # Validate response
                if (-not $result.value) {
                    throw "Key Vault returned empty signature"
                }
                
                # Convert base64url signature back to bytes (IEEE P1363 format)
                $ieeeSignature = ConvertFrom-Base64Url -Base64Url $result.value
                Write-Verbose "Key Vault signature length (IEEE): $($ieeeSignature.Length) bytes"
                
                # Validate signature length (ES256 should be 64 bytes in IEEE format)
                if ($ieeeSignature.Length -ne 64) {
                    Write-Warning "Unexpected IEEE signature length: $($ieeeSignature.Length) bytes (expected 64)"
                }
                
                # Convert to DER format to match local signing
                $sigBytes = ConvertFrom-IeeeToDer -IeeeSignature $ieeeSignature
                Write-Verbose "Converted signature length (DER): $($sigBytes.Length) bytes"
                
                # Success - break retry loop
                Write-Verbose "Key Vault signing succeeded on attempt $attempt"
                break
                
            } catch {
                $errorMsg = $_.Exception.Message
                Write-Warning "Key Vault sign attempt $attempt failed: $errorMsg"
                
                if ($attempt -lt $maxRetries) {
                    Write-Verbose "Retrying in $($retryDelay)ms..."
                    Start-Sleep -Milliseconds $retryDelay
                    $retryDelay *= 2  # Exponential backoff
                } else {
                    Write-Error "Key Vault signing failed after $maxRetries attempts: $errorMsg"
                    throw
                }
            }
        }
        
        if (-not $sigBytes) {
            throw "Key Vault signing failed: No signature generated"
        }
        
        Write-Host "    📊 Signature length (DER): $($sigBytes.Length) bytes" -ForegroundColor Gray
    } else {
        Write-Host "    🔑 Signing with local private key" -ForegroundColor Cyan
        
        # Sign the pre-computed hash (matching Key Vault behavior)
        $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
        $ecdsa.ImportFromPem($PrivateKeyPem)
        
        # Sign the hash directly without additional hashing
        $sigBytes = $ecdsa.SignHash(
            $dataHash,
            [System.Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence
        )
        Write-Verbose "Local signature length (DER): $($sigBytes.Length) bytes"
        $ecdsa.Dispose()
        
        Write-Host "    📊 Signature length (DER): $($sigBytes.Length) bytes" -ForegroundColor Gray
    }

    return @{
        Signature  = $sigBytes
        ClientData = $clientBytes
    }
}

#endregion

#region Main Script

Write-Host "`n╭────────────────────────────────────────────────────────────╮" -ForegroundColor Cyan
Write-Host "│           Entra ID Passkey Authentication (Key Vault)          │" -ForegroundColor Cyan
Write-Host "╰────────────────────────────────────────────────────────────╯" -ForegroundColor Cyan

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7 (Core) for ECDsa PEM support. Current version: $($PSVersionTable.PSVersion)"
    throw "Unsupported PowerShell version"
}

# Apply pipeline configuration if provided
if ($CredentialFromPipeline) {
    if (-not $KeyFilePath -and $CredentialFromPipeline.CredentialFilePath) {
        $KeyFilePath = $CredentialFromPipeline.CredentialFilePath
    }
    if (-not $KeyVaultClientId -and $CredentialFromPipeline.ClientId) {
        $KeyVaultClientId = $CredentialFromPipeline.ClientId
    }
    if (-not $KeyVaultClientSecret -and $CredentialFromPipeline.ClientSecret) {
        $KeyVaultClientSecret = $CredentialFromPipeline.ClientSecret
    }
    if (-not $KeyVaultTenantId -and $CredentialFromPipeline.TenantId) {
        $KeyVaultTenantId = $CredentialFromPipeline.TenantId
    }

    # Wait for Entra ID passkey propagation if the passkey was just registered
    if ($CredentialFromPipeline.RegistrationTime) {
        $PropagationDelay = 30 # seconds
        $elapsed = ((Get-Date) - [datetime]$CredentialFromPipeline.RegistrationTime).TotalSeconds
        if ($elapsed -lt $PropagationDelay) {
            $waitTime = [math]::Ceiling($PropagationDelay - $elapsed)
            Write-Host "`n⏳ Waiting $waitTime seconds for Entra ID passkey propagation..." -ForegroundColor Yellow
            Start-Sleep -Seconds $waitTime
            Write-Host "  ✓ Propagation wait complete`n" -ForegroundColor Green
        }
    }
}

# Validate required parameters
if (-not $KeyFilePath -and (-not $UserPrincipalName -or -not $UserHandle -or -not $CredentialId)) {
    throw "Either provide -KeyFilePath or specify manual parameters (-UserPrincipalName, -UserHandle, -CredentialId, and either -PrivateKey or -KeyVaultName). Or pipe from New-KeyVaultPasskey.ps1 with -PassThru."
}
if (-not $KeyFilePath -and -not $PrivateKey -and -not $KeyVaultName) {
    throw "Either -PrivateKey or -KeyVaultName must be provided for manual authentication."
}

# Load key data if file provided
if ($KeyFilePath) {
    if (-not (Test-Path $KeyFilePath)) {
        Write-Error "Key file not found: $KeyFilePath"
        throw "Key file does not exist"
    }

    Write-Host "📂 Loading key data from file: $KeyFilePath" -ForegroundColor Cyan
    try {
        $keyData = Get-Content $KeyFilePath -Raw | ConvertFrom-Json
    } catch {
        Write-Error "Invalid JSON in key file: $($_.Exception.Message)"
        throw
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
    Write-Error "Username not found in JSON file or command line arguments"
    throw "Missing required parameter: Username"
}

# Validate username format
if ($targetUser -notmatch '^[^@]+@[^@]+\.[^@]+$') {
    Write-Warning "Username '$targetUser' does not appear to be a valid UPN format"
}

$rpId = $keyData.relyingParty ?? $keyData.rpId ?? $RelyingParty
$origin = $keyData.url ?? "https://$($rpId)"
$origin = [uri]"$origin" | Select-Object -ExpandProperty Host
$origin = "https://$($origin)"

$userHandle = $keyData.userHandle ?? $UserHandle
if (-not $userHandle) {
    Write-Error "UserHandle not found in JSON file or command line arguments"
    throw "Missing required parameter: UserHandle"
}

$credentialId = $keyData.credentialId ?? $CredentialId
if (-not $credentialId) {
    Write-Error "CredentialId not found in JSON file or command line arguments"
    throw "Missing required parameter: CredentialId"
}

# Convert UUID format to base64url if necessary
$credentialId = ConvertFrom-UuidToBase64Url -Uuid $credentialId

Write-Host "`n=== Authentication Configuration ===" -ForegroundColor Cyan
Write-Host "  User:            $targetUser" -ForegroundColor White
Write-Host "  RP ID:           $rpId" -ForegroundColor White
Write-Host "  Origin:          $origin" -ForegroundColor White
Write-Host "  Credential ID:   $($credentialId.Substring(0, [Math]::Min(20, $credentialId.Length)))..." -ForegroundColor White
Write-Host "  User Handle:     $($userHandle.Substring(0, [Math]::Min(20, $userHandle.Length)))..." -ForegroundColor White

# Check if using Key Vault
$useKeyVault = $false
$kvInfo = $null
$kvToken = $null

# Determine Key Vault configuration from parameters or JSON
$resolvedKvName = $KeyVaultName
$resolvedKvKeyName = $KeyVaultKeyName

if ($keyData.keyVault) {
    if (-not $resolvedKvName) { $resolvedKvName = $keyData.keyVault.vaultName }
    if (-not $resolvedKvKeyName) { $resolvedKvKeyName = $keyData.keyVault.keyName }
    
    # Build kvInfo object for use in signing
    $kvInfo = @{
        vaultName = $resolvedKvName
        keyName   = $resolvedKvKeyName
        keyId     = $keyData.keyVault.keyId
    }
} elseif ($KeyVaultName -and $KeyVaultKeyName) {
    # Manual Key Vault mode (no JSON keyVault object, but parameters provided)
    $kvInfo = @{
        vaultName = $KeyVaultName
        keyName   = $KeyVaultKeyName
        keyId     = $null
    }
}

if ($kvInfo) {
    Write-Host "`n=== Key Vault Configuration ===" -ForegroundColor Cyan
    Write-Host "  Vault Name:      $($kvInfo.vaultName)" -ForegroundColor White
    Write-Host "  Key Name:        $($kvInfo.keyName)" -ForegroundColor White
    if ($kvInfo.keyId) {
        Write-Host "  Key ID:          $($kvInfo.keyId)" -ForegroundColor Gray
    }
    Write-Host "  🔒 Private key secured in Azure Key Vault (in HSM for Premium SKU)" -ForegroundColor Green
    $useKeyVault = $true
    
    # Get Key Vault authentication
    $kvClientId = $KeyVaultClientId
    $kvClientSecret = $KeyVaultClientSecret
    $kvTenantId = $KeyVaultTenantId
    
    if (-not $kvClientId -or -not $kvClientSecret -or -not $kvTenantId) {
        Write-Error "Key Vault passkey detected but authentication parameters not provided"
        Write-Host "  Required parameters:" -ForegroundColor Yellow
        Write-Host "    -KeyVaultClientId" -ForegroundColor Gray
        Write-Host "    -KeyVaultClientSecret" -ForegroundColor Gray
        Write-Host "    -KeyVaultTenantId" -ForegroundColor Gray
        throw "Missing Key Vault authentication parameters"
    }
    
    Write-Host "`n  🔑 Authenticating to Key Vault..." -ForegroundColor Cyan
    $kvToken = Get-KeyVaultToken -TenantId $kvTenantId -ClientId $kvClientId -ClientSecret $kvClientSecret
    Write-Host "  ✓ Key Vault authenticated successfully" -ForegroundColor Green
} else {
    Write-Host "`n  🔑 Using local private key" -ForegroundColor Cyan
}

# Private Key (for local signing)
[int]$SignCount = $keyData.signCount ?? $keyData.counter ?? 0
$PrivateKeyPem = $null

if (-not $useKeyVault) {
    # Get private key from JSON or parameter
    $privateKeySource = $keyData.privateKey ?? $keyData.keyValue ?? $null
    
    # If no JSON key and we have a parameter, convert SecureString to plain text
    if (-not $privateKeySource -and $PrivateKey) {
        $privateKeySource = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PrivateKey)
        )
    }
    
    if (-not $privateKeySource) {
        Write-Error "Private key not found in JSON file or command line arguments"
        throw "Missing required parameter: PrivateKey"
    }
    
    try {
        $PrivateKeyPem = ConvertTo-PEMPrivateKey -PrivateKey $privateKeySource
        if (-not $PrivateKeyPem) {
            Write-Error "Private key conversion failed - invalid key format"
            throw "Private key conversion error"
        }
    } finally {
        # Clear plain text key from memory
        if ($privateKeySource -and -not ($keyData.privateKey -or $keyData.keyValue)) {
            Remove-Variable -Name privateKeySource -ErrorAction SilentlyContinue
        }
    }
}

# Configure Session
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = $UserAgent

# Validate auth URL
try {
    $uriBuilder = [System.UriBuilder]$AuthUrl
    $query = [System.Web.HttpUtility]::ParseQueryString($uriBuilder.Query)
} catch {
    Write-Error "Invalid auth URL format: $AuthUrl"
    Write-Error "Error: $($_.Exception.Message)"
    throw
}

if ($AuthUrl -notmatch "^https://login.microsoftonline.com/") {
    Write-Error "Auth URL must start with 'https://login.microsoftonline.com/'. Current: $AuthUrl"
    throw "Invalid auth URL"
}

# Check required parameters
$RequiredParams = @("client_id", "response_type", "redirect_uri")
foreach ($param in $RequiredParams) {
    if (-not $query.Get($param)) {
        Write-Error "Missing required parameter '$param' in auth URL"
        throw "Invalid auth URL: Missing $param"
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
Write-Host "`n=== Initiating Authentication Flow ===" -ForegroundColor Cyan
Write-Host "  Establishing session with login.microsoftonline.com..." -ForegroundColor Gray
$InitialResponse = Invoke-WebRequest -UseBasicParsing -Uri $AuthUrl -Method Get -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck
if ($InitialResponse.Content -match '{(.*)}') {
    $SessionInformation = $Matches[0] | ConvertFrom-Json
}
Write-Host "  ✓ Session established" -ForegroundColor Green

# Validate FIDO2 support
Write-Host "  Validating FIDO2 credentials..." -ForegroundColor Gray
if (-not $SessionInformation.oGetCredTypeResult.Credentials.HasFido -or -not $SessionInformation.sFidoChallenge) {
    Write-Error "User does not have FIDO2 credentials registered or server did not provide a challenge"
    Write-Host "  User: $targetUser" -ForegroundColor Yellow
    Write-Host "  HasFido: $($SessionInformation.oGetCredTypeResult.Credentials.HasFido)" -ForegroundColor Yellow
    Write-Host "  Challenge present: $([bool]$SessionInformation.sFidoChallenge)" -ForegroundColor Yellow
    throw "FIDO2 authentication not available"
}

$serverChallenge = [System.Text.Encoding]::ASCII.GetBytes($SessionInformation.sFidoChallenge)
Write-Host "  ✓ FIDO2 challenge received" -ForegroundColor Green

# Generate FIDO Assertion
Write-Host "`n=== Generating FIDO2 Assertion ===" -ForegroundColor Cyan
Write-Host "  Creating authenticator data..." -ForegroundColor Gray

try {
    $authData = New-FidoAuthenticatorData -RpId $rpId -SignCount $SignCount
    
    if ($useKeyVault) {
        $crypto = New-FidoSignature `
            -Challenge (ConvertTo-Base64Url $serverChallenge) `
            -Origin $origin `
            -AuthDataBytes $authData `
            -KeyVaultInfo $kvInfo `
            -KeyVaultToken $kvToken
    } else {
        $crypto = New-FidoSignature `
            -Challenge (ConvertTo-Base64Url $serverChallenge) `
            -Origin $origin `
            -AuthDataBytes $authData `
            -PrivateKeyPem $PrivateKeyPem
    }

    $fidoPayload = [ordered]@{
        id                = $credentialId
        clientDataJSON    = (ConvertTo-Base64Url $crypto.ClientData)
        authenticatorData = (ConvertTo-Base64Url $authData)
        signature         = (ConvertTo-Base64Url $crypto.Signature)
        userHandle        = $userHandle
    }

    $credentialsJson = $SessionInformation.oGetCredTypeResult.Credentials.FidoParams.AllowList -join ','
    Write-Host "  ✓ FIDO2 assertion generated successfully" -ForegroundColor Green
} catch {
    Write-Error "FIDO Assertion generation failed: $($_.Exception.Message)"
    Write-Host "  → Check private key or Key Vault access" -ForegroundColor Yellow
    throw
}

# Submit verification request
Write-Host "`n=== Submitting Authentication ===" -ForegroundColor Cyan
Write-Host "  Getting pre-verification information..." -ForegroundColor Gray
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
    $respVerify = Invoke-WebRequest -UseBasicParsing -Uri $verifyUrl -Method Post -Body $bodyVerify -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck
    
    if ($respVerify.StatusCode -ge 400) {
        Write-Error "Verification request failed with HTTP $($respVerify.StatusCode)"
        Write-Verbose "Response: $($respVerify.Content)"
        throw "Pre-verification failed"
    }
    
    if (-not ($respVerify.Content -match '{(.*)}')){        Write-Error "Unexpected response format from verification endpoint"
        Write-Verbose "Response: $($respVerify.Content)"
        throw "Invalid verification response"
    }
    
    $ResponseInformation = $Matches[0] | ConvertFrom-Json
    Write-Host "  ✓ Pre-verification completed" -ForegroundColor Green
} catch {
    Write-Error "Verification request failed: $($_.Exception.Message)"
    throw
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

Write-Host "  Submitting FIDO2 assertion..." -ForegroundColor Gray
Write-Verbose "Assertion payload: $($fidoPayload | ConvertTo-Json -Compress)"
Write-Verbose "Login URI: $LoginUri"

$respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $LoginUri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck

Write-Verbose "Initial response status: $($respFinalize.StatusCode)"
if ($respFinalize.StatusCode -ge 400) {
    Write-Warning "Assertion submission returned HTTP $($respFinalize.StatusCode)"
    Write-Verbose "Response content: $($respFinalize.Content)"
}

# Key Vault signatures may need processing time
if ($useKeyVault) {
    Write-Verbose "Key Vault flow: allowing processing time"
    Start-Sleep -Milliseconds 500
}

# Submit with sso_reload
$LoginUri = "https://login.microsoftonline.com/common/login?sso_reload=true"
$Payload.flowToken = $SessionInformation.oGetCredTypeResult.FlowToken

Write-Host "  Submitting with SSO reload..." -ForegroundColor Gray
Write-Verbose "SSO reload URI: $LoginUri"

$respFinalize = Invoke-WebRequest -UseBasicParsing -Uri $LoginUri -Method Post -Body $Payload -WebSession $session -MaximumRedirection 0 -SkipHttpErrorCheck

Write-Verbose "SSO reload response status: $($respFinalize.StatusCode)"
if ($respFinalize.StatusCode -ge 400) {
    Write-Warning "SSO reload returned HTTP $($respFinalize.StatusCode)"
    Write-Verbose "Response content: $($respFinalize.Content)"
}

# Key Vault signatures may need processing time before parsing
if ($useKeyVault) {
    Write-Verbose "Key Vault flow: allowing processing time before parsing"
    Start-Sleep -Milliseconds 500
}

# Parse response with validation
if (-not ($respFinalize.Content -match '{(.*)}')) {
    Write-Verbose "No JSON response received from server. Login may have completed."
    $Debug = @{ pgid = $null }
} else {
    try {
        $Debug = $Matches[0] | ConvertFrom-Json
        if ($Debug.pgid) {
            Write-Verbose "PageID: $($Debug.pgid)"
            $CurrentPageId = $Debug.pgid
        }
    } catch {
        Write-Verbose "Failed to parse response JSON: $($_.Exception.Message)"
        $Debug = @{ pgid = $null }
    }
}

# Handle interrupts (CMSI, KMSI, etc.)
$LoopCount = 0
$authenticationFailed = $false
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
        $authenticationFailed = $true
        Write-Error "$(if ($CurrentPageId -eq $LastPageId) { 'Stuck in' } else { 'Exceeded maximum' }) interrupt loop. Authentication failed."
        Write-Verbose "LastPageId: $LastPageId, CurrentPageId: $CurrentPageId, LoopCount: $LoopCount"
        if ($useKeyVault) {
            Write-Host "`n⚠️  Key Vault Signature Issue Detected" -ForegroundColor Yellow
            Write-Host "  This may indicate:" -ForegroundColor Yellow
            Write-Host "    • Invalid or malformed signature from Key Vault" -ForegroundColor Yellow
            Write-Host "    • Key Vault permission or access issues" -ForegroundColor Yellow
            Write-Host "    • Network latency affecting signature validation" -ForegroundColor Yellow
        }
        break
    }
    $LastPageId = $CurrentPageId

    $handler = $InterruptHandlers[$Debug.pgid]
    Write-Verbose "Handling interrupt: $($handler.Message)"
    
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
            Write-Verbose "PageID: $($Debug.pgid)"
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

Write-Host "  ✓ Authentication flow completed" -ForegroundColor Green

# Check if authentication failed during interrupt handling
if ($authenticationFailed) {
    Write-Host "`n╭────────────────────────────────────────────────────────────╮" -ForegroundColor Red
    Write-Host "│                  ✗ Authentication Failed!                     │" -ForegroundColor Red
    Write-Host "╰────────────────────────────────────────────────────────────╯" -ForegroundColor Red
    Write-Host "`nPossible causes:" -ForegroundColor Yellow
    Write-Host "  • Invalid or malformed FIDO2 signature" -ForegroundColor Yellow
    if ($useKeyVault) {
        Write-Host "  • Key Vault signing issue or permission problem" -ForegroundColor Yellow
        Write-Host "  • Network latency affecting Key Vault operation" -ForegroundColor Yellow
        Write-Host "  • Key Vault service propagation delay (permissions, keys)" -ForegroundColor Yellow
        Write-Host "`nRecommended action:" -ForegroundColor Cyan
        Write-Host "  1. Wait 30-60 seconds for Azure AD/Key Vault propagation" -ForegroundColor White
        Write-Host "  2. Verify Key Vault permissions: Crypto User or Sign permission" -ForegroundColor White
        Write-Host "  3. Re-run authentication command" -ForegroundColor White
    } else {
        Write-Host "  • Credential ID mismatch or expired passkey" -ForegroundColor Yellow
        Write-Host "  • Server-side authentication validation failure" -ForegroundColor Yellow
    }
    throw "Authentication failed: stuck in interrupt loop during FIDO2 validation"
}

# Key Vault flow may need time for final cookie propagation
if ($useKeyVault) {
    Write-Verbose "Key Vault flow: allowing cookie propagation time"
    Start-Sleep -Milliseconds 500
}

# Check success
Write-Host "`n=== Verifying Authentication Result ===" -ForegroundColor Cyan
$allCookies = $session.Cookies.GetCookies("https://login.microsoftonline.com")
Write-Verbose "Checking cookies: $($allCookies.Name -join ', ')"

if ($allCookies | Where-Object Name -Like "ESTS*") {
    Write-Host "`n╭────────────────────────────────────────────────────────────╮" -ForegroundColor Green
    Write-Host "│                  ✓ Authentication Successful!                 │" -ForegroundColor Green
    Write-Host "╰────────────────────────────────────────────────────────────╯" -ForegroundColor Green
    
    $ESTSAUTH = $allCookies | Where-Object Name -EQ "ESTSAUTH"
    $ESTSAUTHPERSISTENT = $allCookies | Where-Object Name -EQ "ESTSAUTHPERSISTENT"
    $ESTSAUTHLIGHT = $allCookies | Where-Object Name -EQ "ESTSAUTHLIGHT"
    
    $ests = @($ESTSAUTH, $ESTSAUTHPERSISTENT, $ESTSAUTHLIGHT) | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1
    
    if ($ests) {
        Write-Host "`nAuthentication Details:" -ForegroundColor Cyan
        Write-Host "  User:               $targetUser" -ForegroundColor White
        Write-Host "  Authentication:     FIDO2 Passkey" -ForegroundColor White
        if ($useKeyVault) {
            Write-Host "  Signature Method:   Azure Key Vault ($($kvInfo.vaultName))" -ForegroundColor White
        } else {
            Write-Host "  Signature Method:   Local Private Key" -ForegroundColor White
        }
        Write-Host "  Cookie Type:        $($ests.Name)" -ForegroundColor White
        
        Write-Host "`nSession Information:" -ForegroundColor Cyan
        Write-Host "  Token saved to:     `$global:ESTSAUTH" -ForegroundColor Gray
        Write-Host "  Session saved to:   `$global:webSession" -ForegroundColor Gray
        Write-Host "  Token preview:      $($ests.Value.Substring(0, [Math]::Min(40, $ests.Value.Length)))..." -ForegroundColor Gray
        
        $global:ESTSAUTH = $ests.Value
        $global:webSession = $session
        
        Write-Host "`n✓ Ready to use authenticated session for API calls" -ForegroundColor Green
        Write-Host ""
        
        # Output authentication result for pipeline support
        if ($PassThru) {
            $output = [PSCustomObject]@{
                UserPrincipalName     = $targetUser
                AuthenticationMethod  = "FIDO2 Passkey"
                SignatureMethod       = if ($useKeyVault) { "Azure Key Vault" } else { "Local Private Key" }
                KeyVaultName          = if ($useKeyVault) { $kvInfo.vaultName } else { $null }
                CookieType            = $ests.Name
                TokenVariable         = 'ESTSAUTH'
                SessionVariable       = 'webSession'
                AuthenticationTime    = Get-Date
                Success               = $true
            }
            Write-Output $output
        }
    }
} else {
    Write-Warning "Login flow completed but authentication success could not be verified"
    Write-Host "  Session may still be usable - saved to `$global:webSession" -ForegroundColor Yellow
    $global:webSession = $session
    
    # Output incomplete result for pipeline support
    if ($PassThru) {
        $output = [PSCustomObject]@{
            UserPrincipalName     = $targetUser
            AuthenticationMethod  = "FIDO2 Passkey"
            SignatureMethod       = if ($useKeyVault) { "Azure Key Vault" } else { "Local Private Key" }
            KeyVaultName          = if ($useKeyVault) { $kvInfo.vaultName } else { $null }
            CookieType            = $null
            TokenVariable         = $null
            SessionVariable       = 'webSession'
            AuthenticationTime    = Get-Date
            Success               = $false
        }
        Write-Output $output
    }
}

#endregion
