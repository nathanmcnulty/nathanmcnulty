<#
.SYNOPSIS
    Automates setup of TLS inspection for Microsoft Global Secure Access Internet Access.

.DESCRIPTION
    This script automates the complete workflow for setting up TLS inspection in Microsoft Global Secure Access:
    - Provisions Azure Key Vault with Microsoft Security Benchmark compliance (DP-8, LT-4)
    - Creates self-signed root CA certificate with non-exportable private key
    - Generates CSR in Global Secure Access via Graph API
    - Signs CSR using Azure Key Vault signing operations (private key never leaves vault)
    - Uploads signed certificate to Global Secure Access
    - Creates Intune trusted root certificate policies for all platforms
    
    Security Features:
    - RBAC authorization (not access policies)
    - Soft delete enabled (90 days retention)
    - Purge protection enabled
    - Private keys non-exportable (HSM-backed with Premium SKU)
    - Optional diagnostic logging to Log Analytics
    - Optional Microsoft Defender for Key Vault
    - Optional private endpoint support

.PARAMETER SubscriptionId
    Azure subscription ID. Defaults to current context subscription.

.PARAMETER ResourceGroupName
    Resource group name for Key Vault. Default: 'rg-gsa-tls'

.PARAMETER KeyVaultName
    Key Vault name. If not provided, generates unique name 'kv-gsa-{random}'.
    If provided and exists, uses existing vault.

.PARAMETER KeyVaultSKU
    Key Vault SKU. 'Premium' (HSM-backed, FIPS 140-2 Level 2) or 'Standard' (software).
    Default: 'Premium'

.PARAMETER Location
    Azure region for resources. Default: 'eastus'

.PARAMETER CertificateCommonName
    Common Name (CN) for the CA certificate. Default: 'Global Secure Access TLS CA'

.PARAMETER OrganizationName
    Organization name (O) for the certificate. Required.

.PARAMETER LogAnalyticsWorkspaceId
    Full resource ID of Log Analytics workspace for diagnostic logs.
    Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}
    If provided, enables diagnostic logging with 2-year retention.

.PARAMETER EnableDefender
    Enable Microsoft Defender for Key Vault for threat detection.

.PARAMETER EnablePrivateEndpoint
    Restrict Key Vault to private network access only via private endpoint.
    Note: Requires VNet configuration (not implemented in this version).

.PARAMETER AssignIntunePolicies
    Automatically assign Intune policies to "All Devices" group.
    If not specified, policies are created but not assigned.

.PARAMETER Force
    Force recreation of existing resources after confirmation prompts.
    Uses ShouldContinue for per-resource confirmation.

.EXAMPLE
    .\Initialize-GSATLSInspection.ps1 -OrganizationName "Contoso"
    
    Creates Key Vault with Premium SKU and sets up TLS inspection with default settings.

.EXAMPLE
    .\Initialize-GSATLSInspection.ps1 -OrganizationName "Contoso" `
        -LogAnalyticsWorkspaceId "/subscriptions/.../workspaces/my-law" `
        -EnableDefender -AssignIntunePolicies -Verbose
    
    Full setup with logging, threat detection, and automatic policy assignment.

.EXAMPLE
    .\Initialize-GSATLSInspection.ps1 -OrganizationName "Contoso" `
        -KeyVaultName "existing-vault" -Force
    
    Uses existing Key Vault and recreates certificates if they exist.

.NOTES
    Author: Nathan McNulty
    Date: February 10, 2026
    Requires: PowerShell 7.0+, Microsoft.Graph.Authentication, Az.Accounts modules
    
    Prerequisites:
    - Microsoft Graph permissions: NetworkAccess.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All
    - Azure permissions: Contributor or Owner on subscription
    - Already authenticated via Connect-MgGraph and Connect-AzAccount
    
    Security:
    This script follows Microsoft Security Benchmark:
    - DP-8: Key and certificate repository security
    - LT-4: Logging for security investigation
    - LT-1: Threat detection capabilities (optional with -EnableDefender)
    
    References:
    - https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-transport-layer-security-settings
    - https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/key-vault-security-baseline
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Az.Accounts

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-gsa-tls",
    
    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Standard', 'Premium')]
    [string]$KeyVaultSKU = 'Premium',
    
    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",
    
    [Parameter(Mandatory = $false)]
    [string]$CertificateCommonName = "Global Secure Access TLS CA",
    
    [Parameter(Mandatory = $true)]
    [string]$OrganizationName,
    
    [Parameter(Mandatory = $false)]
    [string]$LogAnalyticsWorkspaceId,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableDefender,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnablePrivateEndpoint,
    
    [Parameter(Mandatory = $false)]
    [switch]$AssignIntunePolicies,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

#region Helper Functions

function Get-KeyVaultToken {
    # Az.Accounts 3.0+ returns SecureString for .Token
    $tokenResponse = Get-AzAccessToken -ResourceUrl "https://vault.azure.net"
    $tok = $tokenResponse.Token
    if ($tok -is [System.Security.SecureString]) {
        return $tok | ConvertFrom-SecureString -AsPlainText
    }
    return $tok
}

function Write-Info {
    param([string]$Message)
    Write-Host "  ℹ️  $Message" -ForegroundColor Gray
}

function Write-Success {
    param([string]$Message)
    Write-Host "  ✓ $Message" -ForegroundColor Green
}

function Write-StepHeader {
    param([string]$Title)
    Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  $($Title.PadRight(61)) ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
}

function Invoke-AzRestMethodWithRetry {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$Payload,
        [int]$MaxRetries = 5,
        [int]$InitialDelay = 2
    )
    
    $attempt = 0
    $delay = $InitialDelay
    
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $response = if ($Payload) {
                Invoke-AzRestMethod -Method $Method -Path $Uri -Payload $Payload
            } else {
                Invoke-AzRestMethod -Method $Method -Path $Uri
            }
            
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                return $response
            } elseif ($response.StatusCode -eq 429 -or $response.StatusCode -eq 503) {
                # Throttling or service unavailable - retry with backoff
                if ($attempt -lt $MaxRetries) {
                    Write-Verbose "Request throttled (429/503), retrying in $delay seconds... (attempt $attempt/$MaxRetries)"
                    Start-Sleep -Seconds $delay
                    $delay *= 2
                    continue
                }
            }
            
            # Other error - throw
            $errorContent = $response.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
            throw "Azure REST API error: $($response.StatusCode) - $($errorContent.error.message)"
            
        } catch {
            if ($attempt -lt $MaxRetries -and $_.Exception.Message -match "timeout|connection") {
                Write-Verbose "Transient error, retrying in $delay seconds... (attempt $attempt/$MaxRetries)"
                Start-Sleep -Seconds $delay
                $delay *= 2
                continue
            }
            throw
        }
    }
    
    throw "Failed after $MaxRetries attempts"
}

function Wait-KeyVaultOperation {
    param(
        [string]$VaultName,
        [string]$CertificateName,
        [int]$TimeoutSeconds = 120
    )
    
    Write-Host "  Waiting for certificate creation to complete..." -ForegroundColor Gray
    $startTime = Get-Date
    
    while (((Get-Date) - $startTime).TotalSeconds -lt $TimeoutSeconds) {
        try {
            $uri = "https://$VaultName.vault.azure.net/certificates/$CertificateName/pending?api-version=7.5"
            $token = Get-KeyVaultToken
            $headers = @{ Authorization = "Bearer $token" }
            
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
            
            if ($response.status -eq "completed") {
                Write-Success "Certificate created successfully"
                return $true
            } elseif ($response.status -eq "inProgress") {
                Write-Host "." -NoNewline -ForegroundColor Gray
                Start-Sleep -Seconds 5
                continue
            } else {
                throw "Certificate operation failed with status: $($response.status)"
            }
        } catch {
            if ($_.Exception.Message -match "404") {
                # Operation may have completed already
                return $true
            }
            throw
        }
    }
    
    throw "Certificate creation timed out after $TimeoutSeconds seconds"
}

function Get-KeyVaultCertificatePem {
    param(
        [string]$VaultName,
        [string]$CertificateName
    )
    
    $uri = "https://$VaultName.vault.azure.net/certificates/$CertificateName/?api-version=7.5"
    $token = Get-KeyVaultToken
    $headers = @{ Authorization = "Bearer $token" }
    
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    
    # Extract certificate in PEM format
    $certBytes = [Convert]::FromBase64String($response.cer)
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
    
    $base64Lines = [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks') -replace "`r`n", "`n"
    $pem = "-----BEGIN CERTIFICATE-----`n$base64Lines`n-----END CERTIFICATE-----"
    
    return @{
        Certificate = $cert
        Pem = $pem
        Thumbprint = $cert.Thumbprint
        Expiration = $cert.NotAfter
        KeyId = $response.kid
    }
}

function Enable-KeyVaultDiagnosticLogs {
    param(
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$VaultName,
        [string]$WorkspaceId
    )
    
    Write-Host "  Enabling diagnostic logs..." -ForegroundColor Gray
    
    $kvResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName"
    $diagnosticUri = "$kvResourceId/providers/microsoft.insights/diagnosticSettings/gsa-tls-audit?api-version=2021-05-01-preview"
    
    $diagnosticSettings = @{
        properties = @{
            workspaceId = $WorkspaceId
            logs = @(
                @{
                    category = "AuditEvent"
                    enabled = $true
                    retentionPolicy = @{
                        enabled = $true
                        days = 730  # 2 years per Microsoft Security Benchmark
                    }
                }
                @{
                    category = "AzurePolicyEvaluationDetails"
                    enabled = $true
                    retentionPolicy = @{
                        enabled = $true
                        days = 730
                    }
                }
            )
            metrics = @(
                @{
                    category = "AllMetrics"
                    enabled = $true
                    retentionPolicy = @{
                        enabled = $true
                        days = 730
                    }
                }
            )
        }
    } | ConvertTo-Json -Depth 10
    
    $response = Invoke-AzRestMethodWithRetry -Method PUT -Uri $diagnosticUri -Payload $diagnosticSettings
    
    if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
        Write-Success "Diagnostic logs enabled (2-year retention)"
        Write-Info "Logs will be sent to: $WorkspaceId"
    } else {
        Write-Warning "Failed to enable diagnostic logs: $($response.StatusCode)"
    }
}

function Enable-DefenderForKeyVault {
    param([string]$SubscriptionId)
    
    Write-Host "  Enabling Microsoft Defender for Key Vault..." -ForegroundColor Gray
    
    $defenderUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings/KeyVaults?api-version=2024-01-01"
    
    $defenderSettings = @{
        properties = @{
            pricingTier = "Standard"
        }
    } | ConvertTo-Json -Depth 5
    
    try {
        $response = Invoke-AzRestMethodWithRetry -Method PUT -Uri $defenderUri -Payload $defenderSettings
        
        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
            Write-Success "Microsoft Defender for Key Vault enabled"
            Write-Info "Threat detection and anomaly alerts are now active"
        } else {
            Write-Warning "Failed to enable Defender: $($response.StatusCode)"
        }
    } catch {
        Write-Warning "Could not enable Defender for Key Vault: $_"
        Write-Info "You may need 'Security Admin' role to enable Defender"
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
    switch ($Base64Url.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '=' }
    }
    return [Convert]::FromBase64String($base64)
}

function Get-DerLength {
    # Encode an integer as DER length bytes
    param([int]$Length)
    if ($Length -lt 128) {
        return [byte[]]@($Length)
    } elseif ($Length -lt 256) {
        return [byte[]]@(0x81, $Length)
    } elseif ($Length -lt 65536) {
        return [byte[]]@(0x82, [byte](($Length -shr 8) -band 0xFF), [byte]($Length -band 0xFF))
    } else {
        return [byte[]]@(0x83, [byte](($Length -shr 16) -band 0xFF), [byte](($Length -shr 8) -band 0xFF), [byte]($Length -band 0xFF))
    }
}

function New-SignedCertificateFromCSR {
    param(
        [string]$CsrPem,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IssuerCert,
        [string]$KeyVaultName,
        [string]$KeyVaultKeyId,
        [int]$ValidityYears = 5
    )
    
    Write-Host "`n  Creating signed certificate from CSR..." -ForegroundColor Cyan
    
    # Parse CSR
    Write-Verbose "Parsing CSR..."
    $csr = [System.Security.Cryptography.X509Certificates.CertificateRequest]::LoadSigningRequestPem(
        $CsrPem,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]::Default,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    
    Write-Info "CSR Subject: $($csr.SubjectName.Name)"
    Write-Info "Public Key Algorithm: $($csr.PublicKey.Oid.FriendlyName)"
    
    # Build certificate request with extensions for intermediate CA
    $certRequest = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        $csr.SubjectName,
        $csr.PublicKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    
    # Add Basic Constraints: CA=true, no pathLen constraint (matching OpenSSL signedCA_ext profile)
    $basicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
        $true,    # certificateAuthority = true
        $false,   # hasPathLengthConstraint = false (OpenSSL signedCA_ext omits pathlen)
        0,        # pathLengthConstraint (ignored when hasPathLengthConstraint is false)
        $true     # critical = true
    )
    $certRequest.CertificateExtensions.Add($basicConstraints)
    
    # Add Key Usage: digitalSignature, keyCertSign, cRLSign
    $keyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign,
        $true  # critical
    )
    $certRequest.CertificateExtensions.Add($keyUsage)
    
    # Add Enhanced Key Usage: serverAuth (1.3.6.1.5.5.7.3.1)
    $oidCollection = [System.Security.Cryptography.OidCollection]::new()
    [void]$oidCollection.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1"))  # serverAuth
    $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
        $oidCollection,
        $false  # not critical
    )
    $certRequest.CertificateExtensions.Add($eku)
    
    # Add Subject Key Identifier
    $ski = [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new(
        $certRequest.PublicKey,
        $false
    )
    $certRequest.CertificateExtensions.Add($ski)
    
    # Add Authority Key Identifier (from issuer cert)
    # Use proper .NET API instead of manual DER construction to ensure correct encoding
    $issuerSkiExt = $IssuerCert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.14" }
    if ($issuerSkiExt) {
        $skiTyped = [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]$issuerSkiExt
        $aki = [System.Security.Cryptography.X509Certificates.X509AuthorityKeyIdentifierExtension]::CreateFromSubjectKeyIdentifier($skiTyped)
        $certRequest.CertificateExtensions.Add($aki)
    } else {
        Write-Warning "Issuer certificate does not have SKI extension - AKI cannot be added"
    }
    
    # Generate serial number (16 random bytes)
    $serialBytes = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($serialBytes)
    $serialBytes[0] = $serialBytes[0] -band 0x7F  # Ensure positive
    $serialNumber = [byte[]]$serialBytes
    
    # Set validity period
    $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)  # 5 min clock skew tolerance
    $notAfter = [DateTimeOffset]::UtcNow.AddYears($ValidityYears)
    
    Write-Info "Validity: $($notBefore.DateTime.ToString('yyyy-MM-dd')) to $($notAfter.DateTime.ToString('yyyy-MM-dd'))"
    Write-Info "Serial Number: $([BitConverter]::ToString($serialNumber).Replace('-',''))"
    
    # Create certificate with dummy local RSA key to get a valid TBS structure
    # We'll extract the TBS bytes, sign them with Key Vault, and rebuild the cert
    Write-Verbose "Creating certificate structure with temporary signing key..."
    $dummyKey = [System.Security.Cryptography.RSA]::Create(4096)
    try {
        $dummyGenerator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA(
            $dummyKey,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $dummyCert = $certRequest.Create(
            $IssuerCert.SubjectName,
            $dummyGenerator,
            $notBefore,
            $notAfter,
            $serialNumber
        )
    } finally {
        $dummyKey.Dispose()
    }

    # Extract TBS (To Be Signed) bytes from the DER-encoded certificate
    # X.509 DER: SEQUENCE { TBSCertificate, SignatureAlgorithm, SignatureValue }
    $certDer = $dummyCert.RawData
    Write-Verbose "Temporary certificate DER size: $($certDer.Length) bytes"

    # Parse outer SEQUENCE tag + length to find TBS start
    $offset = 0
    if ($certDer[$offset] -ne 0x30) { throw "Invalid certificate: expected outer SEQUENCE tag (0x30)" }
    $offset++

    # Skip outer length
    if ($certDer[$offset] -band 0x80) {
        $lenByteCount = $certDer[$offset] -band 0x7F
        $offset += 1 + $lenByteCount
    } else {
        $offset++
    }

    # Now at TBS start - read tag + length to determine full TBS size
    $tbsStart = $offset
    if ($certDer[$offset] -ne 0x30) { throw "Invalid certificate: expected TBS SEQUENCE tag (0x30)" }
    $offset++

    if ($certDer[$offset] -band 0x80) {
        $lenByteCount = $certDer[$offset] -band 0x7F
        $offset++
        $tbsContentLen = 0
        for ($i = 0; $i -lt $lenByteCount; $i++) {
            $tbsContentLen = ($tbsContentLen -shl 8) + $certDer[$offset + $i]
        }
        $offset += $lenByteCount
    } else {
        $tbsContentLen = $certDer[$offset]
        $offset++
    }

    $tbsEnd = $offset + $tbsContentLen
    [byte[]]$tbsBytes = $certDer[$tbsStart..($tbsEnd - 1)]
    Write-Info "TBS certificate size: $($tbsBytes.Length) bytes"

    # Hash the TBS bytes with SHA-256
    [byte[]]$tbsHash = [System.Security.Cryptography.SHA256]::HashData($tbsBytes)
    Write-Verbose "TBS hash: $([BitConverter]::ToString($tbsHash).Replace('-',''))"

    # Sign TBS hash with Key Vault
    Write-Host "  Signing certificate with Key Vault..." -ForegroundColor Cyan

    $signUri = "$KeyVaultKeyId/sign?api-version=7.5"
    $token = Get-KeyVaultToken
    $headers = @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    }

    $signBody = @{
        alg   = "RS256"
        value = ConvertTo-Base64Url $tbsHash
    } | ConvertTo-Json

    try {
        $signResult = Invoke-RestMethod -Uri $signUri -Method POST -Headers $headers -Body $signBody
        [byte[]]$kvSignature = ConvertFrom-Base64Url $signResult.value
        Write-Success "Certificate signed successfully"
        Write-Info "Signature size: $($kvSignature.Length) bytes"
    } catch {
        Write-Error "Failed to sign certificate with Key Vault: $_"
        throw
    }

    # Rebuild certificate DER with the Key Vault signature
    # Structure: SEQUENCE { TBSCertificate, SignatureAlgorithm, SignatureValue }
    Write-Verbose "Constructing final signed certificate..."

    # Signature Algorithm Identifier: SHA256withRSA (OID 1.2.840.113549.1.1.11)
    [byte[]]$sigAlgId = @(0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00)

    # Signature Value as BIT STRING (tag 0x03, 0x00 prefix = no unused bits)
    [byte[]]$sigValueContent = @(0x00) + $kvSignature
    $sigBitString = [System.Collections.Generic.List[byte]]::new()
    $sigBitString.Add(0x03)  # BIT STRING tag
    [byte[]]$sigLenBytes = Get-DerLength $sigValueContent.Length
    $sigBitString.AddRange($sigLenBytes)
    $sigBitString.AddRange([byte[]]$sigValueContent)

    # Combine into inner content
    [byte[]]$innerContent = $tbsBytes + $sigAlgId + [byte[]]$sigBitString.ToArray()

    # Wrap in outer SEQUENCE
    $finalCert = [System.Collections.Generic.List[byte]]::new()
    $finalCert.Add(0x30)  # SEQUENCE tag
    [byte[]]$outerLenBytes = Get-DerLength $innerContent.Length
    $finalCert.AddRange($outerLenBytes)
    $finalCert.AddRange($innerContent)

    # Validate by loading as X509Certificate2
    [byte[]]$finalCertBytes = $finalCert.ToArray()
    $signedCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($finalCertBytes)
    Write-Success "Signed certificate created: $($signedCert.Subject)"
    Write-Info "Thumbprint: $($signedCert.Thumbprint)"

    # Verify signature using issuer's public key
    $issuerRsa = $IssuerCert.PublicKey.GetRSAPublicKey()
    $sigVerified = $issuerRsa.VerifyData($tbsBytes, $kvSignature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if ($sigVerified) {
        Write-Verbose "RSA signature verification: PASSED"
    } else {
        Write-Warning "RSA signature verification FAILED - certificate may be rejected"
    }

    # Convert to PEM (normalize to LF line endings)
    $base64Lines = [Convert]::ToBase64String($finalCertBytes, 'InsertLineBreaks') -replace "`r`n", "`n"
    $certPem = "-----BEGIN CERTIFICATE-----`n$base64Lines`n-----END CERTIFICATE-----"

    Write-Verbose "Certificate PEM length: $($certPem.Length) characters"

    return @{
        Certificate = $signedCert
        Pem         = $certPem
        Thumbprint  = $signedCert.Thumbprint
    }
}

function New-IntuneTrustedRootCertPolicy {
    param(
        [string]$Platform,
        [string]$RootCertBase64,
        [bool]$AssignToAllDevices
    )
    
    # Platform-specific @odata.type for deviceConfigurations API
    $typeMap = @{
        'Windows' = '#microsoft.graph.windows81TrustedRootCertificate'
        'macOS'   = '#microsoft.graph.macOSTrustedRootCertificate'
        'iOS'     = '#microsoft.graph.iosTrustedRootCertificate'
        'Android' = '#microsoft.graph.androidTrustedRootCertificate'
    }
    
    $policyName = "GSA TLS Root Certificate - $Platform"
    
    Write-Host "  Creating policy: $policyName" -ForegroundColor Gray
    
    # Build deviceConfiguration body with platform-specific type
    $policy = @{
        "@odata.type"          = $typeMap[$Platform]
        displayName            = $policyName
        description            = "Trusted root CA for Global Secure Access TLS Inspection - Do not delete"
        trustedRootCertificate = $RootCertBase64
        certFileName           = "gsa-tls-root-ca.cer"
    }
    
    # Platform-specific properties
    if ($Platform -eq 'Windows') {
        $policy['destinationStore'] = 'computerCertStoreRoot'
    }
    if ($Platform -eq 'macOS') {
        $policy['deploymentChannel'] = 'deviceChannel'
    }
    
    $policyJson = $policy | ConvertTo-Json -Depth 5
    
    try {
        $result = Invoke-MgGraphRequest -Method POST -Uri "/beta/deviceManagement/deviceConfigurations" -Body $policyJson -ContentType 'application/json'
        Write-Success "Policy created: $($result.id)"
        
        # Assign to All Devices if requested
        if ($AssignToAllDevices) {
            Write-Verbose "Assigning policy to All Devices..."
            $assignment = @{
                assignments = @(
                    @{
                        target = @{
                            "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"
                        }
                    }
                )
            } | ConvertTo-Json -Depth 5
            
            $assignUri = "/beta/deviceManagement/deviceConfigurations/$($result.id)/assign"
            Invoke-MgGraphRequest -Method POST -Uri $assignUri -Body $assignment | Out-Null
            Write-Info "Assigned to All Devices"
        }
        
        return $result.id
    } catch {
        Write-Warning "Failed to create Intune policy for $Platform : $_"
        return $null
    }
}

#endregion

#region Main Script

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║     Global Secure Access TLS Inspection Setup                 ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

# Verify PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This script requires PowerShell 7.0 or later for cross-platform .NET support"
    exit 1
}

# Verify required modules
$requiredModules = @('Microsoft.Graph.Authentication', 'Az.Accounts')
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Error "Required module '$module' is not installed. Run: Install-Module $module"
        exit 1
    }
}

Write-StepHeader "Step 1: Authentication & Context"

# Check Graph connection
try {
    $mgContext = Get-MgContext
    if (-not $mgContext) {
        throw "Not connected"
    }
    Write-Success "Connected to Microsoft Graph"
    Write-Info "Account: $($mgContext.Account)"
    Write-Info "Scopes: $($mgContext.Scopes -join ', ')"
    
    # Verify required scopes
    $requiredScopes = @('NetworkAccess.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All')
    $missingScopes = $requiredScopes | Where-Object { $_ -notin $mgContext.Scopes }
    if ($missingScopes) {
        Write-Warning "Missing required scopes: $($missingScopes -join ', ')"
        Write-Host "  Reconnecting with required scopes..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    }
} catch {
    Write-Error "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'NetworkAccess.ReadWrite.All','DeviceManagementConfiguration.ReadWrite.All'"
    exit 1
}

# Check Azure connection
try {
    $azContext = Get-AzContext
    if (-not $azContext) {
        throw "Not connected"
    }
    Write-Success "Connected to Azure"
    Write-Info "Account: $($azContext.Account.Id)"
    Write-Info "Tenant: $($azContext.Tenant.Id)"
} catch {
    Write-Error "Not connected to Azure. Run: Connect-AzAccount"
    exit 1
}

# Get subscription
if (-not $SubscriptionId) {
    $SubscriptionId = $azContext.Subscription.Id
    Write-Info "Using subscription from context: $($azContext.Subscription.Name)"
} else {
    Write-Info "Using specified subscription: $SubscriptionId"
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

# Generate Key Vault name if not provided
if (-not $KeyVaultName) {
    $random = -join ((97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
    $KeyVaultName = "kv-gsa-$random"
    Write-Info "Generated Key Vault name: $KeyVaultName"
}

Write-Host "`nConfiguration:" -ForegroundColor Cyan
Write-Host "  Subscription:     $SubscriptionId" -ForegroundColor White
Write-Host "  Resource Group:   $ResourceGroupName" -ForegroundColor White
Write-Host "  Key Vault:        $KeyVaultName ($KeyVaultSKU)" -ForegroundColor White
Write-Host "  Location:         $Location" -ForegroundColor White
Write-Host "  Certificate CN:   $CertificateCommonName" -ForegroundColor White
Write-Host "  Organization:     $OrganizationName" -ForegroundColor White
if ($LogAnalyticsWorkspaceId) {
    Write-Host "  Logging:          Enabled (2-year retention)" -ForegroundColor White
}
if ($EnableDefender) {
    Write-Host "  Defender:         Enabled" -ForegroundColor White
}
if ($AssignIntunePolicies) {
    Write-Host "  Intune Assign:    All Devices" -ForegroundColor White
}

Write-StepHeader "Step 2: Resource Group"

$rgUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName`?api-version=2021-04-01"

try {
    $existingRG = Invoke-AzRestMethod -Method GET -Path $rgUri
    if ($existingRG.StatusCode -eq 200) {
        Write-Success "Resource group exists"
        $rgData = $existingRG.Content | ConvertFrom-Json
        Write-Info "Location: $($rgData.location)"
        
        if ($Force -and $PSCmdlet.ShouldContinue("Delete and recreate resource group '$ResourceGroupName'?", "Force Deletion")) {
            Write-Host "  Deleting resource group..." -ForegroundColor Yellow
            Remove-AzResourceGroup -Name $ResourceGroupName -Force | Out-Null
            Start-Sleep -Seconds 5
            throw "Recreating after deletion"
        }
    } else {
        throw "Does not exist"
    }
} catch {
    Write-Host "  Creating resource group..." -ForegroundColor Yellow
    
    $rgBody = @{
        location = $Location
        tags = @{
            Purpose = "Global Secure Access TLS Inspection"
            ManagedBy = "Initialize-GSATLSInspection.ps1"
            CreatedDate = (Get-Date -Format "yyyy-MM-dd")
        }
    } | ConvertTo-Json -Depth 5
    
    $response = Invoke-AzRestMethodWithRetry -Method PUT -Uri $rgUri -Payload $rgBody
    
    if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
        Write-Success "Resource group created"
    } else {
        Write-Error "Failed to create resource group: $($response.StatusCode)"
        exit 1
    }
}

Write-StepHeader "Step 3: Key Vault (Microsoft Security Benchmark DP-8)"

$kvUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName`?api-version=2023-07-01"

try {
    $existingKV = Invoke-AzRestMethod -Method GET -Path $kvUri
    if ($existingKV.StatusCode -eq 200) {
        Write-Success "Key Vault exists"
        $kvData = $existingKV.Content | ConvertFrom-Json
        Write-Info "Location: $($kvData.location)"
        Write-Info "SKU: $($kvData.properties.sku.name)"
        
        if ($Force -and $PSCmdlet.ShouldContinue("Use existing Key Vault '$KeyVaultName'?", "Existing Resource")) {
            Write-Info "Using existing Key Vault"
        }
        
        $vaultUri = "https://$KeyVaultName.vault.azure.net"
    } else {
        throw "Does not exist"
    }
} catch {
    Write-Host "  Creating Key Vault with security hardening..." -ForegroundColor Yellow
    
    $kvBody = @{
        location = $Location
        properties = @{
            sku = @{
                family = "A"
                name = $KeyVaultSKU.ToLower()
            }
            tenantId = $azContext.Tenant.Id
            enableRbacAuthorization = $true
            enableSoftDelete = $true
            softDeleteRetentionInDays = 90
            enablePurgeProtection = $true
            publicNetworkAccess = if ($EnablePrivateEndpoint) { "Disabled" } else { "Enabled" }
            networkAcls = @{
                bypass = "AzureServices"
                defaultAction = "Allow"  # Can be restricted later
            }
        }
        tags = @{
            Purpose = "GSA TLS Inspection CA Certificates"
            SecurityBaseline = "Microsoft Security Benchmark DP-8"
            ManagedBy = "Initialize-GSATLSInspection.ps1"
        }
    } | ConvertTo-Json -Depth 10
    
    $response = Invoke-AzRestMethodWithRetry -Method PUT -Uri $kvUri -Payload $kvBody
    
    if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
        Write-Success "Key Vault created"
        $kvData = $response.Content | ConvertFrom-Json
        $vaultUri = $kvData.properties.vaultUri.TrimEnd('/')
        
        Write-Info "RBAC: Enabled"
        Write-Info "Soft Delete: Enabled (90 days)"
        Write-Info "Purge Protection: Enabled"
        Write-Info "SKU: $KeyVaultSKU $(if ($KeyVaultSKU -eq 'Premium') { '(HSM-backed, FIPS 140-2 Level 2)' })"
        
        # Wait for Key Vault to be accessible
        Write-Host "  Waiting for Key Vault to be accessible..." -ForegroundColor Gray
        $maxAttempts = 12
        $attempt = 0
        $kvReady = $false
        
        while (-not $kvReady -and $attempt -lt $maxAttempts) {
            $attempt++
            Start-Sleep -Seconds 5
            Write-Host "." -NoNewline -ForegroundColor Gray
            
            try {
                $kvCheck = Invoke-AzRestMethod -Method GET -Path $kvUri
                if ($kvCheck.StatusCode -eq 200) {
                    $kvReady = $true
                    Write-Host ""
                    Write-Success "Key Vault is accessible"
                }
            } catch {
                # Continue waiting
            }
        }
        
        if (-not $kvReady) {
            Write-Warning "Key Vault may not be fully accessible yet, continuing anyway..."
        }
    } else {
        Write-Error "Failed to create Key Vault: $($response.StatusCode)"
        exit 1
    }
}

# Assign RBAC roles
Write-Host "  Assigning RBAC roles..." -ForegroundColor Gray

$currentUser = $azContext.Account.Id
$currentObjectId = $null

# Extract OID from the Azure access token (most reliable - matches what Key Vault sees)
try {
    $azTokenResponse = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
    $azJwt = if ($azTokenResponse.Token -is [System.Security.SecureString]) {
        $azTokenResponse.Token | ConvertFrom-SecureString -AsPlainText
    } else { $azTokenResponse.Token }
    $jwtParts = $azJwt.Split('.')
    $b64 = $jwtParts[1].Replace('-','+').Replace('_','/')
    switch ($b64.Length % 4) { 2 { $b64 += '==' } 3 { $b64 += '=' } }
    $claims = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json
    if ($claims.oid) {
        $currentObjectId = $claims.oid
        Write-Verbose "Got OID from Azure token: $currentObjectId"
    }
} catch {
    Write-Verbose "Could not extract OID from Azure token: $_"
}

# Fallback: try Microsoft Graph /me
if (-not $currentObjectId) {
    try {
        $mgUser = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/me" -ErrorAction SilentlyContinue
        if ($mgUser.id) { $currentObjectId = $mgUser.id }
    } catch { }
}

# Fallback: Az AD cmdlets
if (-not $currentObjectId) {
    $currentObjectId = (Get-AzADUser -UserPrincipalName $currentUser -ErrorAction SilentlyContinue).Id
}

# Fallback: service principal lookup if Account.Id is a GUID
if (-not $currentObjectId) {
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if ($currentUser -match $guidPattern) {
        $currentObjectId = (Get-AzADServicePrincipal -ApplicationId $currentUser -ErrorAction SilentlyContinue).Id
    }
}

if ($currentObjectId) {
    Write-Info "Principal ID: $currentObjectId"
    
    $roles = @(
        @{ Name = "Key Vault Certificates Officer"; Id = "a4417e6f-fecd-4de8-b567-7b0420556985" }
        @{ Name = "Key Vault Crypto Officer"; Id = "14b46e9e-c2b7-41b4-b07b-48a6ebf60603" }
    )
    
    $kvScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName"
    $newAssignments = $false
    
    foreach ($role in $roles) {
        # Check if role is already assigned to this principal
        $existingUri = "${kvScope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$currentObjectId' and roleDefinitionId eq '/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$($role.Id)'"
        $existingCheck = Invoke-AzRestMethod -Method GET -Path $existingUri
        $existingAssignments = ($existingCheck.Content | ConvertFrom-Json).value
        
        if ($existingAssignments -and $existingAssignments.Count -gt 0) {
            Write-Info "Already assigned: $($role.Name)"
            continue
        }
        
        $roleDefId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$($role.Id)"
        $assignmentGuid = [guid]::NewGuid().ToString()
        $roleUri = "$kvScope/providers/Microsoft.Authorization/roleAssignments/$assignmentGuid`?api-version=2022-04-01"
        
        $roleBody = @{
            properties = @{
                roleDefinitionId = $roleDefId
                principalId = $currentObjectId
                principalType = "User"
            }
        } | ConvertTo-Json -Depth 5
        
        try {
            $roleResponse = Invoke-AzRestMethod -Method PUT -Path $roleUri -Payload $roleBody
            if ($roleResponse.StatusCode -in @(200, 201)) {
                Write-Success "Assigned: $($role.Name)"
                $newAssignments = $true
            } elseif ($roleResponse.StatusCode -eq 409) {
                Write-Info "Already assigned: $($role.Name)"
            }
        } catch {
            Write-Warning "Could not assign $($role.Name): $_"
        }
        
        Start-Sleep -Seconds 2  # Brief delay for Azure to propagate
    }
    
    # Wait for RBAC propagation only if new assignments were created
    if ($newAssignments) {
        Write-Info "Waiting 90 seconds for RBAC role assignments to propagate..."
        Start-Sleep -Seconds 90
    }
} else {
    Write-Warning "Could not determine current user object ID for RBAC assignment"
    Write-Info "You may need to manually assign Key Vault Certificates Officer and Crypto Officer roles"
}

# Enable diagnostic logs if workspace provided
if ($LogAnalyticsWorkspaceId) {
    Write-StepHeader "Step 4: Diagnostic Logging (LT-4)"
    Enable-KeyVaultDiagnosticLogs -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -WorkspaceId $LogAnalyticsWorkspaceId
} else {
    Write-Info "Skipping diagnostic logs (no Log Analytics workspace specified)"
}

# Enable Defender if requested
if ($EnableDefender) {
    Write-StepHeader "Step 5: Microsoft Defender for Key Vault (LT-1)"
    Enable-DefenderForKeyVault -SubscriptionId $SubscriptionId
}

Write-StepHeader "Step $(if ($LogAnalyticsWorkspaceId -or $EnableDefender) { 6 } else { 4 }): Root CA Certificate"

$certName = "gsa-tls-root-ca"

# Check if certificate exists
$certCheckUri = "https://$KeyVaultName.vault.azure.net/certificates/$certName`?api-version=7.5"
try {
    $token = Get-KeyVaultToken
    $headers = @{ Authorization = "Bearer $token" }
    $existingCert = Invoke-RestMethod -Uri $certCheckUri -Headers $headers -Method Get -ErrorAction Stop
    
    Write-Success "Certificate exists: $certName"
    Write-Info "Thumbprint: $($existingCert.x5t)"
    
    if ($Force -and $PSCmdlet.ShouldContinue("Delete and recreate certificate '$certName'?", "Force Deletion")) {
        Write-Host "  Deleting existing certificate..." -ForegroundColor Yellow
        $deleteUri = "https://$KeyVaultName.vault.azure.net/certificates/$certName`?api-version=7.5"
        Invoke-RestMethod -Uri $deleteUri -Headers $headers -Method DELETE | Out-Null
        Start-Sleep -Seconds 5
        throw "Recreating certificate"
    }
    
    # Get existing certificate details
    $rootCertInfo = Get-KeyVaultCertificatePem -VaultName $KeyVaultName -CertificateName $certName
    
} catch {
    Write-Host "  Creating root CA certificate..." -ForegroundColor Yellow
    Write-Info "Subject: CN=$CertificateCommonName, O=$OrganizationName"
    Write-Info "Key: RSA 4096-bit (non-exportable)"
    Write-Info "Validity: 10 years"
    
    $certPolicy = @{
        policy = @{
            key_props = @{
                exportable = $false
                kty = "RSA"
                key_size = 4096
                reuse_key = $false
            }
            secret_props = @{
                contentType = "application/x-pem-file"
            }
            x509_props = @{
                subject = "CN=$CertificateCommonName, O=$OrganizationName"
                ekus = @("1.3.6.1.5.5.7.3.1")  # serverAuth
                key_usage = @(
                    "digitalSignature"
                    "keyCertSign"
                    "cRLSign"
                )
                validity_months = 120  # 10 years
                basic_constraints = @{
                    ca = $true
                    path_len_constraint = 1
                }
            }
            issuer = @{
                name = "Self"
            }
            attributes = @{
                enabled = $true
            }
        }
    } | ConvertTo-Json -Depth 10
    
    $createUri = "https://$KeyVaultName.vault.azure.net/certificates/$certName/create?api-version=7.5"
    
    try {
        Invoke-RestMethod -Uri $createUri -Method POST -Headers $headers -Body $certPolicy -ContentType "application/json" | Out-Null
        Write-Success "Certificate creation initiated"
        
        # Wait for completion
        Wait-KeyVaultOperation -VaultName $KeyVaultName -CertificateName $certName
        
        # Get certificate details
        $rootCertInfo = Get-KeyVaultCertificatePem -VaultName $KeyVaultName -CertificateName $certName
        
        Write-Success "Root CA certificate created"
        Write-Info "Thumbprint: $($rootCertInfo.Thumbprint)"
        Write-Info "Expires: $($rootCertInfo.Expiration.ToString('yyyy-MM-dd'))"
        Write-Info "Key ID: $($rootCertInfo.KeyId)"
        
    } catch {
        Write-Error "Failed to create certificate: $_"
        exit 1
    }
}

Write-StepHeader "Step $(if ($LogAnalyticsWorkspaceId -or $EnableDefender) { 7 } else { 5 }): Global Secure Access CSR"

# Check for existing GSA certificates
$gsaCertId = $null
$csrPem = $null
try {
    $existingGsaCerts = Invoke-MgGraphRequest -Method GET -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates"
    
    if ($existingGsaCerts.value -and $existingGsaCerts.value.Count -gt 0) {
        Write-Host "  Found $($existingGsaCerts.value.Count) existing certificate(s) in GSA" -ForegroundColor Gray
        
        foreach ($cert in $existingGsaCerts.value) {
            Write-Info "Name: $($cert.name), Status: $($cert.status)"
            
            # CSR is only available in the POST response, not in subsequent GET calls
            # Certificates in csrGenerated status need to be deleted and recreated
            if ($cert.status -eq "csrGenerated") {
                Write-Warning "Certificate '$($cert.name)' has a pending CSR that was not yet signed."
                Write-Host "  Deleting unsigned certificate to create a fresh CSR..." -ForegroundColor Yellow
                Invoke-MgGraphRequest -Method DELETE -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($cert.id)" | Out-Null
                Start-Sleep -Seconds 5
            } elseif ($cert.status -in @("active", "enabled")) {
                if ($Force -and $PSCmdlet.ShouldContinue("Delete existing active GSA certificate '$($cert.name)'?", "Force Deletion")) {
                    Write-Host "  Deleting: $($cert.name)" -ForegroundColor Yellow
                    Invoke-MgGraphRequest -Method DELETE -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($cert.id)" | Out-Null
                    Start-Sleep -Seconds 5
                } else {
                    Write-Warning "Active certificate exists. Use -Force to delete and recreate."
                    $gsaCertId = $cert.id
                }
            } elseif ($Force) {
                Write-Host "  Deleting: $($cert.name) (status: $($cert.status))" -ForegroundColor Yellow
                Invoke-MgGraphRequest -Method DELETE -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($cert.id)" | Out-Null
                Start-Sleep -Seconds 5
            }
        }
    }
} catch {
    # No existing certificates or error checking
}

if (-not $gsaCertId) {
    Write-Host "  Creating Certificate Signing Request..." -ForegroundColor Yellow

    $csrBody = @{
        "@odata.type" = "#microsoft.graph.networkaccess.externalCertificateAuthorityCertificate"
        name = "GSATLS" + -join ((48..57) + (97..102) | Get-Random -Count 6 | ForEach-Object { [char]$_ })  # ≤12 chars, no spaces, unique
        commonName = $CertificateCommonName
        organizationName = $OrganizationName
    } | ConvertTo-Json

    try {
        $csrResponse = Invoke-MgGraphRequest -Method POST -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates" -Body $csrBody
        
        Write-Success "CSR created"
        Write-Info "Certificate ID: $($csrResponse.id)"
        Write-Info "Common Name: $($csrResponse.commonName)"
        
        $gsaCertId = $csrResponse.id
        $csrPem = $csrResponse.certificateSigningRequest
    
    } catch {
    $errorMsg = "$_"
    if ($errorMsg -match "internal certificate already exists") {
        Write-Error "A legacy internal TLS certificate exists in this tenant, blocking external certificate creation."
        Write-Host ""
        Write-Host "  To resolve this, delete the legacy certificate using one of these methods:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Method 1 (Entra Portal):" -ForegroundColor Cyan
        Write-Host "    1. Sign in to https://entra.microsoft.com as a Global Secure Access Administrator" -ForegroundColor White
        Write-Host "    2. Navigate to Global Secure Access > Secure > TLS inspection policies" -ForegroundColor White
        Write-Host "    3. Switch to the 'TLS inspection settings' tab" -ForegroundColor White
        Write-Host "    4. Select Actions > Delete" -ForegroundColor White
        Write-Host ""
        Write-Host "  Method 2 (Preview Portal):" -ForegroundColor Cyan
        Write-Host "    1. Sign in to https://aka.ms/tlspreview-portal as a Global Secure Access Administrator" -ForegroundColor White
        Write-Host "    2. Navigate to Global Secure Access > Settings > Session management" -ForegroundColor White
        Write-Host "    3. Select the 'TLS Inspection' tab" -ForegroundColor White
        Write-Host "    4. Delete the Certificate URL and click Save" -ForegroundColor White
        Write-Host ""
        Write-Host "  After deleting the legacy certificate, re-run this script." -ForegroundColor Yellow
    } else {
        Write-Error "Failed to create CSR in GSA: $_"
    }
    exit 1
}
}

# Save CSR to temp file for debugging
$csrPath = Join-Path $env:TEMP "gsa-tls-csr-$(Get-Date -Format 'yyyyMMdd-HHmmss').csr"
$csrPem | Out-File -FilePath $csrPath -Encoding ASCII
Write-Verbose "CSR saved to: $csrPath"

Write-StepHeader "Step $(if ($LogAnalyticsWorkspaceId -or $EnableDefender) { 8 } else { 6 }): Sign Certificate (Key Vault)"

Write-Host "  Private key remains in Key Vault (never exported)" -ForegroundColor Green

try {
    $signedCertResult = New-SignedCertificateFromCSR `
        -CsrPem $csrPem `
        -IssuerCert $rootCertInfo.Certificate `
        -KeyVaultName $KeyVaultName `
        -KeyVaultKeyId $rootCertInfo.KeyId
    
    Write-Success "Certificate signed successfully"
    Write-Info "Thumbprint: $($signedCertResult.Thumbprint)"
    
    # Build chain (root CA only — the signed cert is sent separately in 'certificate')
    $chainPem = $rootCertInfo.Pem
    
    # Verify the signed cert chains to the root CA
    $testChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $testChain.ChainPolicy.ExtraStore.Add($rootCertInfo.Certificate)
    $testChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $testChain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
    $chainValid = $testChain.Build($signedCertResult.Certificate)
    if ($chainValid) {
        Write-Verbose "Certificate chain validation passed"
    } else {
        $testChain.ChainStatus | ForEach-Object { Write-Warning "Chain status: $($_.Status) - $($_.StatusInformation)" }
    }
    $testChain.Dispose()
    
} catch {
    Write-Error "Failed to sign certificate: $_"
    Write-Host "`nYou can sign the CSR manually using your enterprise PKI:" -ForegroundColor Yellow
    Write-Host "  CSR file: $csrPath" -ForegroundColor White
    Write-Host "  Required extensions: CA=true, pathLen=0, serverAuth EKU" -ForegroundColor White
    exit 1
}

Write-StepHeader "Step $(if ($LogAnalyticsWorkspaceId -or $EnableDefender) { 9 } else { 7 }): Upload to Global Secure Access"

Write-Host "  Uploading signed certificate and chain..." -ForegroundColor Yellow

$uploadBody = @{
    certificate = $signedCertResult.Pem
    chain       = $chainPem
}

Write-Verbose "Certificate PEM lines: $(($signedCertResult.Pem -split "`n").Count)"
Write-Verbose "Chain PEM lines: $(($chainPem -split "`n").Count)"
Write-Verbose "GSA Cert ID: $gsaCertId"

try {
    Invoke-MgGraphRequest -Method PATCH -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$gsaCertId" -Body $uploadBody -ContentType 'application/json' | Out-Null
    
    Write-Success "Certificate uploaded"
    
    # Enable certificate
    Start-Sleep -Seconds 5
    
    Write-Host "  Enabling certificate..." -ForegroundColor Yellow
    $enableBody = @{ status = "enabled" } | ConvertTo-Json
    Invoke-MgGraphRequest -Method PATCH -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$gsaCertId" -Body $enableBody | Out-Null
    
    # Re-query to confirm status (PATCH returns empty response)
    Start-Sleep -Seconds 3
    $certStatus = Invoke-MgGraphRequest -Method GET -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$gsaCertId"
    
    if ($certStatus.status -eq "enabled") {
        Write-Success "Certificate enabled in GSA"
    } else {
        Write-Warning "Certificate status after enable: $($certStatus.status)"
    }
    
} catch {
    Write-Error "Failed to upload certificate to GSA: $_"
    exit 1
}

Write-StepHeader "Step $(if ($LogAnalyticsWorkspaceId -or $EnableDefender) { 10 } else { 8 }): Intune Trusted Root Policies"

# Get root certificate as base64 (without PEM headers)
$rootCertBase64 = [Convert]::ToBase64String($rootCertInfo.Certificate.RawData)

$platforms = @('Windows', 'macOS', 'iOS', 'Android')
$intunePolicyIds = @{}

foreach ($platform in $platforms) {
    $policyId = New-IntuneTrustedRootCertPolicy -Platform $platform -RootCertBase64 $rootCertBase64 -AssignToAllDevices $AssignIntunePolicies.IsPresent
    
    if ($policyId) {
        $intunePolicyIds[$platform] = $policyId
    } else {
        Write-Warning "Failed to create policy for $platform"
    }
    
    Start-Sleep -Seconds 2
}

Write-Host "`n  Created $($intunePolicyIds.Count) of $($platforms.Count) policies" -ForegroundColor $(if ($intunePolicyIds.Count -eq $platforms.Count) { 'Green' } else { 'Yellow' })

# Final Output
Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║              ✓ Setup Complete!                                 ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

$result = [PSCustomObject]@{
    Status = "Success"
    Timestamp = (Get-Date)
    
    # Key Vault
    KeyVaultName = $KeyVaultName
    KeyVaultUri = $vaultUri
    KeyVaultSKU = $KeyVaultSKU
    KeyVaultResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName"
    DiagnosticLoggingEnabled = ($null -ne $LogAnalyticsWorkspaceId)
    DefenderEnabled = $EnableDefender.IsPresent
    
    # Certificates
    RootCACertificateName = $certName
    RootCAThumbprint = $rootCertInfo.Thumbprint
    RootCAExpiration = $rootCertInfo.Expiration
    IntermediateCertThumbprint = $signedCertResult.Thumbprint
    
    # GSA
    GSACertificateId = $gsaCertId
    GSACertificateName = $csrResponse.name
    GSAStatus = "enabled"
    GSAPortalLink = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GlobalSecureAccessMenuBlade/~/TLSInspection"
    
    # Intune
    IntunePolicyIds = $intunePolicyIds
    IntunePoliciesAssigned = $AssignIntunePolicies.IsPresent
    
    # Next Steps
    NextSteps = @(
        "1. Verify certificate in GSA portal: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GlobalSecureAccessMenuBlade/~/TLSInspection"
        if (-not $AssignIntunePolicies) {
            "2. Assign Intune policies to device groups in Intune portal"
        } else {
            "2. Verify Intune policy deployment to devices"
        }
        "3. Enable TLS inspection for test users/groups in GSA portal"
        if ($LogAnalyticsWorkspaceId) {
            "4. Monitor Key Vault audit logs in Log Analytics"
        }
        "5. Set calendar reminder for Root CA renewal (expires: $($rootCertInfo.Expiration.ToString('yyyy-MM-dd')))"
    )
}

Write-Host "`n📋 Summary:" -ForegroundColor Cyan
Write-Host "  Key Vault:        $KeyVaultName ($KeyVaultSKU)" -ForegroundColor White
Write-Host "  Root CA:          $($rootCertInfo.Thumbprint)" -ForegroundColor White
Write-Host "  Expires:          $($rootCertInfo.Expiration.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "  GSA Certificate:  $($csrResponse.name)" -ForegroundColor White
Write-Host "  Intune Policies:  $($intunePolicyIds.Count) created" -ForegroundColor White

Write-Host "`n🔗 Quick Links:" -ForegroundColor Cyan
Write-Host "  GSA TLS Settings: $($result.GSAPortalLink)" -ForegroundColor Blue
Write-Host "  Key Vault:        https://portal.azure.com/#@/resource$($result.KeyVaultResourceId)" -ForegroundColor Blue

Write-Host "`n📌 Next Steps:" -ForegroundColor Cyan
$result.NextSteps | ForEach-Object { Write-Host "  $_" -ForegroundColor White }

Write-Host ""

# Return result object for pipeline/automation
return $result

#endregion
