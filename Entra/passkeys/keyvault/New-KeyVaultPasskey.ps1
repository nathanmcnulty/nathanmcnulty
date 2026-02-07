#Requires -Version 7.0
<#
.SYNOPSIS
    Generates a software-based passkey (FIDO2) and registers it in Entra ID.

.DESCRIPTION
    Creates a software passkey with "none" attestation format. Does NOT use a hardware
    security key - the private key is generated locally and saved for future authentication.
    
    **IMPORTANT**: Requires application permissions (UserAuthenticationMethod.ReadWrite.All).
    Also requires attestation enforcement disabled in Entra ID FIDO2 settings.
    
    Supports three authentication methods (mutually exclusive):
    1. Managed Identity (recommended) - No credentials needed, automatic token management
    2. Certificate-based Service Principal (recommended for non-Azure) - Most secure with certificate
    3. Client Secret Service Principal - Less secure, use only when other methods aren't available

.PARAMETER UserUpn
    The user's UPN in Entra ID.

.PARAMETER DisplayName
    The display name for the passkey (default: "Software Passkey").

.PARAMETER ClientId
    The application (client) ID with UserAuthenticationMethod.ReadWrite.All application permission.
    Required for Certificate and ClientSecret parameter sets.

.PARAMETER ClientSecret
    The client secret for service principal authentication (as SecureString).
    Parameter Set: ClientSecret
    NOTE: Less secure than certificate-based authentication. Consider using -ClientCertificatePath instead.
    Can be created with: ConvertTo-SecureString 'secret' -AsPlainText -Force

.PARAMETER ClientCertificatePath
    Path to the PFX certificate file for service principal authentication.
    Parameter Set: Certificate
    Recommended over client secrets per Microsoft Security Benchmark IM-3.2.

.PARAMETER ClientCertificatePassword
    Password for the PFX certificate file (if encrypted).
    Parameter Set: Certificate

.PARAMETER UseManagedIdentity
    Use Azure Managed Identity for authentication.
    Parameter Set: ManagedIdentity
    Most secure option - no credential management required.
    Must be run from an Azure resource with managed identity enabled (VM, App Service, Function App, etc.).

.PARAMETER OutputPath
    Path to save the credential JSON file. Defaults to current directory.

.EXAMPLE
    $secret = ConvertTo-SecureString "your-secret" -AsPlainText -Force
    .\New-KeyVaultPasskey.ps1 -UserUpn "user@contoso.com" -DisplayName "Test Key" `
        -ClientId "your-app-id" -ClientSecret $secret
    
    Authenticates using client secret (least secure method).
    Note: ClientSecret must be provided as a SecureString.

.EXAMPLE
    .\New-KeyVaultPasskey.ps1 -UserUpn "user@contoso.com" -DisplayName "Test Key" `
        -ClientId "your-app-id" -ClientCertificatePath "C:\certs\app.pfx" `
        -ClientCertificatePassword "cert-password"
    
    Authenticates using certificate (more secure, recommended for service principals).

.EXAMPLE
    .\New-KeyVaultPasskey.ps1 -UserUpn "user@contoso.com" -DisplayName "Test Key" `
        -UseManagedIdentity -UseKeyVault -KeyVaultName "my-keyvault" -TenantId "tenant-id"
    
    Authenticates using Managed Identity (most secure, no credential management).

.NOTES
    Author: Nathan McNulty
    Based on work by Jos Lieben (Lieben Consultancy)
    Date: February 6, 2026
    
    Security Best Practices (Microsoft Security Benchmark):
    - IM-3: Prefer Managed Identity when running on Azure resources
    - IM-3.2: Use certificate-based auth over client secrets for service principals
    - Managed Identity eliminates credential exposure and rotation needs
    - Certificates enable phishing-resistant authentication with Conditional Access
#>

[CmdletBinding(DefaultParameterSetName = 'ClientSecret', SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [PSCustomObject]$ConfigFromPipeline,
    
    [Parameter(Mandatory = $true)]
    [string]$UserUpn,
    
    [Parameter(Mandatory = $false)]
    [string]$DisplayName = "Software Passkey",
    
    # Authentication - ClientSecret Parameter Set
    [Parameter(Mandatory = $false, ParameterSetName = 'ClientSecret')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
    [string]$ClientId,
    
    [Parameter(Mandatory = $false, ParameterSetName = 'ClientSecret')]
    [SecureString]$ClientSecret,
    
    # Authentication - Certificate Parameter Set
    [Parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ClientCertificatePath,
    
    [Parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
    [SecureString]$ClientCertificatePassword,
    
    # Authentication - Managed Identity Parameter Set
    [Parameter(Mandatory = $false, ParameterSetName = 'ManagedIdentity')]
    [switch]$UseManagedIdentity,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    # Key Vault options
    [Parameter(Mandatory = $false)]
    [switch]$UseKeyVault,
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

$ErrorActionPreference = "Stop"

# Apply pipeline configuration if provided
if ($ConfigFromPipeline) {
    if (-not $ClientId -and $ConfigFromPipeline.ApplicationId) { $ClientId = $ConfigFromPipeline.ApplicationId }
    if (-not $ClientSecret -and $ConfigFromPipeline.ClientSecret) { 
        # Convert plain text from pipeline to SecureString
        $ClientSecret = ConvertTo-SecureString $ConfigFromPipeline.ClientSecret -AsPlainText -Force
    }
    if (-not $TenantId -and $ConfigFromPipeline.TenantId) { $TenantId = $ConfigFromPipeline.TenantId }
    if (-not $KeyVaultName -and $ConfigFromPipeline.KeyVaultName) { $KeyVaultName = $ConfigFromPipeline.KeyVaultName }
    if (-not $UseKeyVault -and $ConfigFromPipeline.UseKeyVault) { $UseKeyVault = $true }
}

# Validate authentication parameters
if (-not $UseManagedIdentity) {
    if (-not $ClientId) {
        throw "ClientId is required. Provide via -ClientId parameter or Initialize-PasskeyKeyVault pipeline."
    }
    if ($PSCmdlet.ParameterSetName -eq 'ClientSecret' -and -not $ClientSecret) {
        throw "ClientSecret is required for ClientSecret authentication."
    }
    if ($PSCmdlet.ParameterSetName -eq 'Certificate' -and -not $ClientCertificatePath) {
        throw "ClientCertificatePath is required for Certificate authentication."
    }
}

# Validate UserUpn format
if ($UserUpn -notmatch '^[^@]+@[^@]+\.[^@]+$') {
    throw "Invalid UserUpn format. Expected format: user@domain.com"
}

# Validate Key Vault parameters
if ($UseKeyVault) {
    if (-not $KeyVaultName) {
        throw "KeyVaultName is required when UseKeyVault is specified"
    }
    if (-not $TenantId -and -not $UseManagedIdentity) {
        throw "TenantId is required when UseKeyVault is specified (not needed for Managed Identity)"
    }
    Write-Host "Using Azure Key Vault: $KeyVaultName" -ForegroundColor Cyan
    Write-Host "Private key will remain in Key Vault HSM" -ForegroundColor Green
} else {
    Write-Host "Using local key generation" -ForegroundColor Cyan
    Write-Host "Private key will be exported to file" -ForegroundColor Yellow
}

# Display authentication method
Write-Host "Authentication Method: " -NoNewline -ForegroundColor Cyan
switch ($PSCmdlet.ParameterSetName) {
    'ManagedIdentity' {
        Write-Host "Managed Identity (Most Secure)" -ForegroundColor Green
        Write-Host "  ✓ No credential management required" -ForegroundColor Gray
        Write-Host "  ✓ Automatic token rotation" -ForegroundColor Gray
    }
    'Certificate' {
        Write-Host "Certificate-based Service Principal (Recommended)" -ForegroundColor Green
        Write-Host "  ✓ Phishing-resistant authentication" -ForegroundColor Gray
        Write-Host "  ✓ Supports Conditional Access" -ForegroundColor Gray
    }
    'ClientSecret' {
        Write-Host "Client Secret (Less Secure)" -ForegroundColor Yellow
        Write-Warning "Consider using Managed Identity or Certificate authentication for better security"
    }
}

#region Helper Functions

function Get-ManagedIdentityToken {
    param([string]$Scope)
    
    $apiVersion = "2019-08-01"
    $resource = $Scope -replace '/.default$', ''
    $endpoint = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=$apiVersion&resource=$resource"
    
    try {
        $response = Invoke-RestMethod -Uri $endpoint -Method GET -Headers @{ Metadata = "true" }
        return $response.access_token
    } catch {
        $errorMessage = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        Write-Error "Failed to acquire Managed Identity token for scope $Scope : $errorMessage"
        Write-Error "Ensure this script is running on an Azure resource with Managed Identity enabled"
        throw
    }
}

function Get-ServicePrincipalToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [SecureString]$ClientSecret,
        [string]$ClientCertificatePath,
        [SecureString]$ClientCertificatePassword,
        [string]$Scope,
        [switch]$UseManagedIdentity
    )
    
    if ($UseManagedIdentity) {
        return Get-ManagedIdentityToken -Scope $Scope
    }
    
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    if ($ClientSecret) {
        # Client Secret authentication - convert SecureString to plain text for API call
        $plainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
        )
        
        $tokenBody = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $plainSecret
            scope         = $Scope
        }
        
        try {
            $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            $errorDetails = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            Write-Error "Failed to acquire token with client secret for scope $Scope : $errorDetails"
            throw
        } finally {
            # Clear the plain text secret from memory
            if ($plainSecret) { Remove-Variable -Name plainSecret -ErrorAction SilentlyContinue }
        }
    } elseif ($ClientCertificatePath) {
        # Certificate-based authentication
        try {
            # Load certificate
            $cert = if ($ClientCertificatePassword) {
                $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientCertificatePassword))
                [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ClientCertificatePath, $plainPassword)
            } else {
                [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ClientCertificatePath)
            }
            
            # Check certificate validity
            $now = Get-Date
            if ($cert.NotBefore -gt $now) {
                Write-Warning "Certificate is not yet valid. Valid from: $($cert.NotBefore)"
            }
            if ($cert.NotAfter -lt $now) {
                throw "Certificate has expired on $($cert.NotAfter). Please use a valid certificate."
            }
            $daysUntilExpiry = ($cert.NotAfter - $now).Days
            if ($daysUntilExpiry -lt 30) {
                Write-Warning "Certificate expires soon ($daysUntilExpiry days remaining). Consider renewing."
            }
            
            # Create JWT assertion
            $thumbprint = $cert.Thumbprint
            $header = @{
                alg = "RS256"
                typ = "JWT"
                x5t = [Convert]::ToBase64String([System.Convert]::FromHexString($thumbprint))
            } | ConvertTo-Json -Compress
            
            $now = [Math]::Floor([decimal](Get-Date -UFormat "%s"))
            $nbf = $now
            $exp = $now + 600  # 10 minutes validity
            
            $payload = @{
                aud = $tokenUrl
                iss = $ClientId
                sub = $ClientId
                jti = [guid]::NewGuid().ToString()
                nbf = $nbf
                exp = $exp
            } | ConvertTo-Json -Compress
            
            # Base64Url encode
            $headerBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $payloadBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            $dataToSign = "$headerBase64.$payloadBase64"
            
            # Sign with certificate private key
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            $signature = $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($dataToSign), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $signatureBase64 = [Convert]::ToBase64String($signature).TrimEnd('=').Replace('+', '-').Replace('/', '_')
            
            $assertion = "$dataToSign.$signatureBase64"
            
            # Request token
            $tokenBody = @{
                grant_type            = "client_credentials"
                client_id             = $ClientId
                client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                client_assertion      = $assertion
                scope                 = $Scope
            }
            
            $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        } catch {
            $errorDetails = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            Write-Error "Failed to acquire token with certificate for scope $Scope : $errorDetails"
            throw
        }
    }
    
    throw "No valid authentication method provided"
}

function New-KeyVaultKey {
    param(
        [string]$KeyVaultName,
        [string]$KeyName,
        [string]$AccessToken
    )
    
    $createUri = "https://$KeyVaultName.vault.azure.net/keys/$KeyName/create?api-version=7.4"
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    $body = @{
        kty     = "EC"
        crv     = "P-256"
        key_ops = @("sign", "verify")
    } | ConvertTo-Json
    
    try {
        $result = Invoke-RestMethod -Uri $createUri -Method POST -Headers $headers -Body $body
        return $result
    } catch {
        Write-Error "Failed to create key in Key Vault: $_"
        throw
    }
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    $base64 = [Convert]::ToBase64String($Bytes)
    return $base64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url {
    param([string]$Base64Url)
    $base64 = $Base64Url.Replace('-', '+').Replace('_', '/')
    # Add padding
    $padding = (4 - ($base64.Length % 4)) % 4
    $base64 += '=' * $padding
    return [Convert]::FromBase64String($base64)
}

function Get-TokenParameters {
    param(
        [string]$Scope,
        [string]$ResolvedTenantId,
        [string]$ClientId,
        [SecureString]$ClientSecret,
        [string]$ClientCertificatePath,
        [SecureString]$ClientCertificatePassword,
        [string]$ParameterSetName,
        [switch]$UseManagedIdentity
    )
    
    $tokenParams = @{
        Scope = $Scope
    }
    
    if ($UseManagedIdentity) {
        $tokenParams['UseManagedIdentity'] = $true
    } else {
        $tokenParams['TenantId'] = $ResolvedTenantId
        $tokenParams['ClientId'] = $ClientId
        if ($ParameterSetName -eq 'ClientSecret') {
            $tokenParams['ClientSecret'] = $ClientSecret
        } elseif ($ParameterSetName -eq 'Certificate') {
            $tokenParams['ClientCertificatePath'] = $ClientCertificatePath
            if ($ClientCertificatePassword) {
                $tokenParams['ClientCertificatePassword'] = $ClientCertificatePassword
            }
        }
    }
    
    return $tokenParams
}

function New-CBOREncoded {
    param($Value)

    $byteListType = 'System.Collections.Generic.List[byte]'

    if ($Value -is [hashtable] -or $Value -is [System.Collections.Specialized.OrderedDictionary]) {
        $entries = New-Object $byteListType
        foreach ($entry in $Value.GetEnumerator()) {
            $keyEncoded = New-CBOREncoded $entry.Key
            $valEncoded = New-CBOREncoded $entry.Value
            $entries.AddRange([byte[]]$keyEncoded)
            $entries.AddRange([byte[]]$valEncoded)
        }
        $result = New-Object $byteListType
        $mapCount = $Value.Count
        if ($mapCount -lt 24) {
            $result.Add([byte](0xA0 + $mapCount))
        } else {
            $result.Add([byte]0xB8)
            $result.Add([byte]$mapCount)
        }
        $result.AddRange($entries)
        return , $result.ToArray()
    }

    if ($Value -is [byte[]]) {
        $len = $Value.Length
        $result = New-Object $byteListType
        if ($len -lt 24) {
            $result.Add([byte](0x40 + $len))
        } elseif ($len -lt 256) {
            $result.Add([byte]0x58)
            $result.Add([byte]$len)
        } elseif ($len -lt 65536) {
            $result.Add([byte]0x59)
            $u16 = [uint16]$len
            $lenBytes = [System.BitConverter]::GetBytes($u16)
            if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }
            $result.AddRange([byte[]]$lenBytes)
        }
        $result.AddRange([byte[]]$Value)
        return , $result.ToArray()
    }

    if ($Value -is [string]) {
        $strBytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $len = $strBytes.Length
        $result = New-Object $byteListType
        if ($len -lt 24) {
            $result.Add([byte](0x60 + $len))
        } elseif ($len -lt 256) {
            $result.Add([byte]0x78)
            $result.Add([byte]$len)
        } elseif ($len -lt 65536) {
            $result.Add([byte]0x79)
            $u16 = [uint16]$len
            $lenBytes = [System.BitConverter]::GetBytes($u16)
            if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }
            $result.AddRange([byte[]]$lenBytes)
        }
        $result.AddRange([byte[]]$strBytes)
        return , $result.ToArray()
    }

    if ($Value -is [int] -or $Value -is [long]) {
        if ($Value -ge 0) {
            if ($Value -lt 24) {
                return , [byte[]]@([byte]$Value)
            } elseif ($Value -lt 256) {
                return , [byte[]]@(0x18, [byte]$Value)
            } elseif ($Value -lt 65536) {
                $u16 = [uint16]$Value
                $numBytes = [System.BitConverter]::GetBytes($u16)
                if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($numBytes) }
                $out = [byte[]]::new(3)
                $out[0] = 0x19
                $out[1] = $numBytes[0]
                $out[2] = $numBytes[1]
                return , $out
            }
        } else {
            $posVal = -1 - $Value
            if ($posVal -lt 24) {
                return , [byte[]]@([byte](0x20 + $posVal))
            } elseif ($posVal -lt 256) {
                return , [byte[]]@(0x38, [byte]$posVal)
            } elseif ($posVal -lt 65536) {
                $u16 = [uint16]$posVal
                $numBytes = [System.BitConverter]::GetBytes($u16)
                if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($numBytes) }
                $out = [byte[]]::new(3)
                $out[0] = 0x39
                $out[1] = $numBytes[0]
                $out[2] = $numBytes[1]
                return , $out
            }
        }
    }

    if ($Value -is [array]) {
        $arrCount = $Value.Count
        $result = New-Object $byteListType
        if ($arrCount -lt 24) {
            $result.Add([byte](0x80 + $arrCount))
        } else {
            $result.Add([byte]0x98)
            $result.Add([byte]$arrCount)
        }
        foreach ($item in $Value) {
            $encoded = New-CBOREncoded $item
            $result.AddRange([byte[]]$encoded)
        }
        return , $result.ToArray()
    }

    throw "Unsupported CBOR type: $($Value.GetType().Name)"
}

function New-AttestationObject {
    param([byte[]]$AuthData)
    $attObj = [ordered]@{
        "fmt"      = "none"
        "attStmt"  = [ordered]@{}
        "authData" = $AuthData
    }
    return New-CBOREncoded $attObj
}

function New-AuthenticatorData {
    param(
        [byte[]]$RpIdHash,
        [byte[]]$CredentialId,
        [byte[]]$PublicKeyX,
        [byte[]]$PublicKeyY
    )

    $result = New-Object 'System.Collections.Generic.List[byte]'
    $result.AddRange($RpIdHash)
    $result.Add([byte]0x5D)
    $result.AddRange([byte[]]@(0, 0, 0, 0))
    $result.AddRange([byte[]]::new(16))

    $credIdLen = $CredentialId.Length
    $result.Add([byte](($credIdLen -shr 8) -band 0xFF))
    $result.Add([byte]($credIdLen -band 0xFF))
    $result.AddRange($CredentialId)

    $coseKey = [ordered]@{
        [int]1  = [int]2
        [int]3  = [int]-7
        [int]-1 = [int]1
        [int]-2 = [byte[]]$PublicKeyX
        [int]-3 = [byte[]]$PublicKeyY
    }
    $result.AddRange([byte[]](New-CBOREncoded $coseKey))

    return $result.ToArray()
}

#endregion

#region Main

Write-Host "`n=== Authenticating ===" -ForegroundColor Cyan

# Determine tenant ID (not needed for Managed Identity)
if ($UseManagedIdentity) {
    $resolvedTenantId = $null  # Managed Identity doesn't need explicit tenant
    Write-Host "  Using Managed Identity - tenant discovery not required" -ForegroundColor Gray
} elseif ($UseKeyVault) {
    # Use provided TenantId for Key Vault mode
    $resolvedTenantId = $TenantId
} else {
    # Auto-discover tenant ID from domain
    $resolvedTenantId = (Invoke-RestMethod "https://login.microsoftonline.com/$($UserUpn.Split('@')[1])/.well-known/openid-configuration").userinfo_endpoint.Split("/")[3]
}

if ($UseKeyVault) {
    # Get tokens for both Key Vault and Graph API
    Write-Host "  Getting Key Vault token..." -ForegroundColor Gray
    
    $kvTokenParams = Get-TokenParameters -Scope "https://vault.azure.net/.default" `
        -ResolvedTenantId $resolvedTenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -ClientCertificatePath $ClientCertificatePath -ClientCertificatePassword $ClientCertificatePassword `
        -ParameterSetName $PSCmdlet.ParameterSetName -UseManagedIdentity:$UseManagedIdentity
    
    $kvToken = Get-ServicePrincipalToken @kvTokenParams
    Write-Host "  ✓ Key Vault token acquired" -ForegroundColor Green
    
    Write-Host "  Getting Graph API token..." -ForegroundColor Gray
    $graphTokenParams = Get-TokenParameters -Scope "https://graph.microsoft.com/.default" `
        -ResolvedTenantId $resolvedTenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -ClientCertificatePath $ClientCertificatePath -ClientCertificatePassword $ClientCertificatePassword `
        -ParameterSetName $PSCmdlet.ParameterSetName -UseManagedIdentity:$UseManagedIdentity
    
    $graphToken = Get-ServicePrincipalToken @graphTokenParams
    Write-Host "  ✓ Graph API token acquired" -ForegroundColor Green
} else {
    # Get token for Graph API only (non-Key Vault mode)
    Write-Host "  Getting Graph API token..." -ForegroundColor Gray
    
    $graphTokenParams = Get-TokenParameters -Scope "https://graph.microsoft.com/.default" `
        -ResolvedTenantId $resolvedTenantId -ClientId $ClientId -ClientSecret $ClientSecret `
        -ClientCertificatePath $ClientCertificatePath -ClientCertificatePassword $ClientCertificatePassword `
        -ParameterSetName $PSCmdlet.ParameterSetName -UseManagedIdentity:$UseManagedIdentity
    
    try {
        $graphToken = Get-ServicePrincipalToken @graphTokenParams
        Write-Host "  ✓ Graph API token acquired" -ForegroundColor Green
    } catch {
        Write-Error "Failed to acquire token: $_"
        throw
    }
}

$headers = @{ "Authorization" = "Bearer $graphToken" }

Write-Host "`n=== Retrieving creation options ===" -ForegroundColor Cyan
$creationOptionsUri = "https://graph.microsoft.com/beta/users/$UserUpn/authentication/fido2Methods/creationOptions(challengeTimeoutInMinutes=10)"

try {
    $creationOptions = Invoke-RestMethod -Method GET -Uri $creationOptionsUri -Headers $headers
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    $errorMessage = if ($_.ErrorDetails.Message) { 
        ($_.ErrorDetails.Message | ConvertFrom-Json).error.message 
    } else { 
        $_.Exception.Message 
    }
    
    Write-Error "Failed to retrieve creation options from Graph API (HTTP $statusCode): $errorMessage"
    
    if ($statusCode -eq 401) {
        Write-Host "  → Check that the service principal has UserAuthenticationMethod.ReadWrite.All permission" -ForegroundColor Yellow
        Write-Host "  → Ensure admin consent has been granted" -ForegroundColor Yellow
    } elseif ($statusCode -eq 403) {
        Write-Host "  → Verify the application has the correct Graph API permissions" -ForegroundColor Yellow
        Write-Host "  → Check that attestation enforcement is disabled in Entra ID FIDO2 settings" -ForegroundColor Yellow
    } elseif ($statusCode -eq 404) {
        Write-Host "  → Verify the user exists: $UserUpn" -ForegroundColor Yellow
        Write-Host "  → Check tenant ID is correct" -ForegroundColor Yellow
    }
    throw
}

$challenge = $creationOptions.publicKey.challenge
$rpId = $creationOptions.publicKey.rp.id
$userId = $creationOptions.publicKey.user.id
$userName = $creationOptions.publicKey.user.name
$userDisplayName = $creationOptions.publicKey.user.displayName

Write-Host "  RP ID: $rpId" -ForegroundColor Gray
Write-Host "  User: $userName ($userDisplayName)" -ForegroundColor Gray
Write-Host "  Challenge expires: $($creationOptions.challengeTimeoutDateTime)" -ForegroundColor Gray

Write-Host "`n=== Generating key pair ===" -ForegroundColor Cyan

if ($UseKeyVault) {
    # Create key in Key Vault
    $keyName = "passkey-$($UserUpn.Split('@')[0])-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Host "  Creating key in Key Vault: $keyName" -ForegroundColor Gray
    
    $kvKey = New-KeyVaultKey -KeyVaultName $KeyVaultName -KeyName $keyName -AccessToken $kvToken
    
    # Extract X and Y coordinates from Key Vault response (base64url encoded)
    $publicKeyXB64Url = $kvKey.key.x
    $publicKeyYB64Url = $kvKey.key.y
    
    # Convert from base64url to bytes
    $publicKeyX = ConvertFrom-Base64Url $publicKeyXB64Url
    $publicKeyY = ConvertFrom-Base64Url $publicKeyYB64Url
    
    Write-Host "  ✓ Key created in Key Vault (private key secured in HSM)" -ForegroundColor Green
    Write-Host "  Key ID: $($kvKey.key.kid)" -ForegroundColor Gray
    
    $ecDsa = $null  # No local key object when using Key Vault
} else {
    # Generate key locally
    $ecDsa = [System.Security.Cryptography.ECDsa]::Create()
    $ecDsa.KeySize = 256
    $ecParams = $ecDsa.ExportParameters($true)
    
    $publicKeyX = $ecParams.Q.X
    $publicKeyY = $ecParams.Q.Y
    
    Write-Host "  ✓ Key pair generated locally" -ForegroundColor Green
}

$credentialIdBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($credentialIdBytes)
$credentialIdB64Url = ConvertTo-Base64Url $credentialIdBytes

Write-Host "`n=== Building WebAuthn response ===" -ForegroundColor Cyan

$clientData = @{
    type      = "webauthn.create"
    challenge = $challenge
    origin    = "https://login.microsoft.com"
} | ConvertTo-Json -Compress

$clientDataBytes = [System.Text.Encoding]::UTF8.GetBytes($clientData)
$clientDataB64Url = ConvertTo-Base64Url $clientDataBytes

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$rpIdHash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($rpId))

$authData = New-AuthenticatorData -RpIdHash $rpIdHash -CredentialId $credentialIdBytes -PublicKeyX $publicKeyX -PublicKeyY $publicKeyY
$attestationObjectBytes = New-AttestationObject -AuthData $authData
$attestationObjectB64Url = ConvertTo-Base64Url $attestationObjectBytes

Write-Host "  Authenticator data: $($authData.Length) bytes" -ForegroundColor Gray
Write-Host "  Attestation object: $($attestationObjectBytes.Length) bytes" -ForegroundColor Gray

Write-Host "`n=== Registering passkey ===" -ForegroundColor Cyan

$registrationBody = @{
    displayName         = $DisplayName
    publicKeyCredential = @{
        id       = $credentialIdB64Url
        response = @{
            clientDataJSON    = $clientDataB64Url
            attestationObject = $attestationObjectB64Url
        }
    }
} | ConvertTo-Json -Depth 10

$registerUri = "https://graph.microsoft.com/beta/users/$UserUpn/authentication/fido2Methods"

if ($PSCmdlet.ShouldProcess("$UserUpn", "Register passkey '$DisplayName'")) {
    try {
        $registerResponse = Invoke-RestMethod -Method POST -Uri $registerUri -Headers $headers -Body $registrationBody -ContentType "application/json; charset=utf-8"
        Write-Host "  ✓ Passkey registered successfully!" -ForegroundColor Green
        Write-Host "    Method ID: $($registerResponse.id)" -ForegroundColor Gray
        Write-Host "    Display Name: $($registerResponse.displayName)" -ForegroundColor Gray
        Write-Host "    Created: $($registerResponse.createdDateTime)" -ForegroundColor Gray
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorMessage = if ($_.ErrorDetails.Message) { 
            try { ($_.ErrorDetails.Message | ConvertFrom-Json).error.message } catch { $_.ErrorDetails.Message }
        } else { 
            $_.Exception.Message 
        }
        
        Write-Error "Failed to register passkey (HTTP $statusCode): $errorMessage"
        
        if ($statusCode -eq 400) {
            Write-Host "  → Check that attestation enforcement is disabled in Entra ID FIDO2 settings" -ForegroundColor Yellow
            Write-Host "  → Verify the authenticator data and attestation object are correctly formatted" -ForegroundColor Yellow
        } elseif ($statusCode -eq 409) {
            Write-Host "  → A passkey with this credential ID may already exist" -ForegroundColor Yellow
        }
        throw
    }
} else {
    Write-Host "  WhatIf: Would register passkey '$DisplayName' for user $UserUpn" -ForegroundColor Yellow
    return
}

Write-Host "`n=== Saving credential ===" -ForegroundColor Cyan

if (-not $OutputPath) {
    $OutputPath = Join-Path (Get-Location) "$($UserUpn.Split('@')[0])_$($DisplayName.Replace(' ', '_'))_credential.json"
} elseif (Test-Path $OutputPath -PathType Container) {
    # If OutputPath is a directory, append default filename
    $OutputPath = Join-Path $OutputPath "$($UserUpn.Split('@')[0])_$($DisplayName.Replace(' ', '_'))_credential.json"
}

# Check if file already exists and warn user
if (Test-Path $OutputPath -PathType Leaf) {
    Write-Warning "Output file already exists: $OutputPath"
    $overwrite = Read-Host "Overwrite? (y/N)"
    if ($overwrite -ne 'y' -and $overwrite -ne 'Y') {
        Write-Host "Operation cancelled by user" -ForegroundColor Yellow
        return
    }
}

$credential = @{
    credentialId    = $credentialIdB64Url
    relyingParty    = $rpId
    url             = "https://$rpId"
    userHandle      = $userId
    userName        = $userName
    displayName     = $DisplayName
    methodId        = $registerResponse.id
    createdDateTime = $registerResponse.createdDateTime
}

if ($UseKeyVault) {
    # Save Key Vault reference instead of private key
    $credential.keyVault = @{
        vaultName = $KeyVaultName
        keyName   = $keyName
        keyId     = $kvKey.key.kid
    }
    $credential.authenticationNote = "Private key secured in Azure Key Vault. Use Key Vault Sign API for authentication."
    
    $credential | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host "  ✓ Credential metadata saved: $OutputPath" -ForegroundColor Green
    Write-Host "  🔒 Private key remains in Key Vault HSM" -ForegroundColor Green
} else {
    # Save private key to file
    $pkcs8Bytes = $ecDsa.ExportPkcs8PrivateKey()
    $pemBase64 = [Convert]::ToBase64String($pkcs8Bytes, [Base64FormattingOptions]::InsertLineBreaks)
    $pem = "-----BEGIN PRIVATE KEY-----`n$pemBase64`n-----END PRIVATE KEY-----"
    
    $credential.privateKey = $pem
    
    $credential | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    Write-Host "  Credential saved: $OutputPath" -ForegroundColor Green
    Write-Host "  ⚠️  WARNING: The file contains the private key. Keep it secure!" -ForegroundColor Yellow
    
    $ecDsa.Dispose()
}

$sha256.Dispose()

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    ✓ Passkey Registration Complete             ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`nPasskey Details:" -ForegroundColor Cyan
Write-Host "  User:         $userName" -ForegroundColor White
Write-Host "  Display Name: $DisplayName" -ForegroundColor White
Write-Host "  Method ID:    $($registerResponse.id)" -ForegroundColor White
Write-Host "  Output File:  $OutputPath" -ForegroundColor White

if ($UseKeyVault) {
    Write-Host "`nKey Vault Integration:" -ForegroundColor Cyan
    Write-Host "  Vault:    $KeyVaultName" -ForegroundColor White
    Write-Host "  Key Name: $keyName" -ForegroundColor White
    Write-Host "  🔒 Private key secured in HSM" -ForegroundColor Green
} else {
    Write-Host "`n⚠️  Security Notice:" -ForegroundColor Yellow
    Write-Host "  Private key saved to file - protect this file carefully!" -ForegroundColor Yellow
    Write-Host "  Consider using Key Vault for production scenarios." -ForegroundColor Gray
}

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "  1. Test authentication with PasskeyLogin.ps1" -ForegroundColor White
Write-Host "  2. Backup the credential file securely" -ForegroundColor White
if (-not $UseKeyVault) {
    Write-Host "  3. Consider migrating to Key Vault for enhanced security" -ForegroundColor White
}

Write-Host ""

# Output credential info for pipeline support
if ($PassThru) {
    # Convert SecureString to plain text for pipeline output (needed by PasskeyLogin.ps1)
    $plainSecret = if ($ClientSecret) {
        [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
        )
    } else { $null }
    
    $output = [PSCustomObject]@{
        CredentialFilePath    = $OutputPath
        UserUpn               = $UserUpn
        DisplayName           = $DisplayName
        KeyVaultName          = if ($UseKeyVault) { $KeyVaultName } else { $null }
        KeyName               = if ($UseKeyVault) { $keyName } else { $null }
        ClientId              = $ClientId
        ClientSecret          = $plainSecret
        TenantId              = $TenantId
        UsesKeyVault          = $UseKeyVault
        RegistrationTime      = Get-Date
    }
    Write-Output $output
}

#endregion
