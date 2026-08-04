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
    - Provisions CRL Distribution Point via Azure Storage static website

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
    Key Vault Premium SKU. The root uses a non-exportable RSA-HSM key.
    Default: 'Premium'

.PARAMETER RootCertificateName
    Name of the Key Vault root certificate. Choose a new name when introducing a
    replacement root during an on-premises CA migration. Default: 'gsa-tls-root-ca'

.PARAMETER Location
    Azure region for resources. Default: 'eastus'

.PARAMETER CertificateCommonName
    Common Name (CN) for the CA certificate. Default: 'Global Secure Access TLS CA'

.PARAMETER OrganizationName
    Organization name (O) for the certificate. Required.

.PARAMETER LogAnalyticsWorkspaceId
    Full resource ID of Log Analytics workspace for diagnostic logs.
    Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}
    If provided, enables diagnostic logging. Configure retention on the workspace tables.

.PARAMETER EnableDefender
    Enable Microsoft Defender for Key Vault for threat detection.

.PARAMETER EnablePrivateEndpoint
    Restrict Key Vault data-plane access to a private endpoint. Requires both
    PrivateEndpointSubnetId and PrivateDnsZoneId. The script verifies private
    DNS resolution before disabling public access.

.PARAMETER PrivateEndpointSubnetId
    Resource ID of the subnet in which the Key Vault private endpoint is created.

.PARAMETER PrivateDnsZoneId
    Resource ID of an existing privatelink.vaultcore.azure.net private DNS zone.

.PARAMETER CrlHostname
    Optional custom hostname for the CRL Distribution Point (e.g., 'crl.sharemylabs.com').
    A CRL is always created and hosted on an Azure Storage static website.

    When provided:
    - The CDP URL in the certificate uses this hostname (http://{CrlHostname}/gsa-tls-root-ca.crl)
    - The script outputs CNAME instructions to map this hostname to the storage static website

    When omitted:
    - The CDP URL uses the Azure Storage static website URL directly

    The CRL is served over HTTP (not HTTPS) per RFC 5280 best practice.
    CRLs are cryptographically signed, so transport security is not needed
    and HTTPS could create a circular dependency for revocation checking.

.PARAMETER StorageAccountName
    Azure Storage Account name for CRL hosting. Must be 3-24 characters, lowercase
    letters and numbers only. If not provided, derives a name from OrganizationName
    (e.g., 'sagsacrlcontoso') and verifies availability.

.PARAMETER AssignIntunePolicies
    Automatically assign Intune policies to "All Devices" group.
    DEFAULT: Policies are created but NOT assigned (requires manual assignment).
    RECOMMENDATION: Manual assignment to specific groups is the best practice for production.
    Only use this switch for testing/lab environments where broad deployment is acceptable.

.PARAMETER IntunePlatforms
    Intune enrollment platforms for trusted-root deployment. Android Device
    Administrator is intentionally excluded.

.PARAMETER RotateGsaCertificate
    Create and upload a new Key Vault-backed GSA certificate while preserving the
    currently active certificate until GSA enables the replacement.

.PARAMETER RenewCrlOnly
    Renew and publish the CRL using existing Azure resources and the existing
    Key Vault root CA. Does not create a GSA CSR or modify Intune policies.

.PARAMETER Force
    Permit replacement of a conflicting pending GSA CSR after confirmation.
    Never deletes the resource group or an active GSA certificate.

.EXAMPLE
    .\Initialize-GSATLSInspection.ps1 -OrganizationName "sharemylabs"

    Sets up TLS inspection with CRL hosted on Azure Storage static website.
    The CDP URL uses the storage account's static website URL directly.

.EXAMPLE
    .\Initialize-GSATLSInspection.ps1 -OrganizationName "sharemylabs" `
        -CrlHostname "crl.sharemylabs.com" -Verbose

    Sets up TLS inspection with CRL published under a custom hostname.
    Outputs CNAME instructions to map the hostname to the storage static website.

.EXAMPLE
    .\Initialize-GSATLSInspection.ps1 -OrganizationName "sharemylabs" `
        -LogAnalyticsWorkspaceId "/subscriptions/.../workspaces/my-law" `
        -EnableDefender -AssignIntunePolicies -Verbose

    Full setup with logging, threat detection, and automatic policy assignment.

.EXAMPLE
    .\Initialize-GSATLSInspection.ps1 -OrganizationName "sharemylabs" `
        -KeyVaultName "existing-vault" -RootCertificateName "gsa-tls-root-ca-v2" -RotateGsaCertificate

    Stages a Key Vault-backed replacement while preserving any active GSA certificate.

.NOTES
    Author: Nathan McNulty
    Date: August 3, 2026
    Requires: PowerShell 7.0+, Microsoft.Graph.Authentication, Az.Accounts modules

    Prerequisites:
    - Microsoft Graph permissions: NetworkAccess.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All
    - Azure permissions: Contributor for resources plus User Access Administrator
      or Owner when the script must create its own RBAC assignments
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
    [ValidateSet('Premium')]
    [string]$KeyVaultSKU = 'Premium',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[0-9A-Za-z-]{1,127}$')]
    [string]$RootCertificateName = 'gsa-tls-root-ca',

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
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/virtualNetworks/[^/]+/subnets/[^/]+$')]
    [string]$PrivateEndpointSubnetId,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/privateDnsZones/privatelink\.vaultcore\.azure\.net$')]
    [string]$PrivateDnsZoneId,

    [Parameter(Mandatory = $false)]
    [string]$CrlHostname,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $false)]
    [switch]$AssignIntunePolicies,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Windows', 'macOS', 'iOS/iPadOS', 'AndroidEnterpriseDeviceOwner', 'AndroidEnterpriseWorkProfile', 'AndroidAOSP')]
    [string[]]$IntunePlatforms = @('Windows', 'macOS', 'iOS/iPadOS', 'AndroidEnterpriseDeviceOwner', 'AndroidEnterpriseWorkProfile', 'AndroidAOSP'),

    [Parameter(Mandatory = $false)]
    [switch]$RotateGsaCertificate,

    [Parameter(Mandatory = $false)]
    [switch]$RenewCrlOnly,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

if ($EnablePrivateEndpoint -and (-not $PrivateEndpointSubnetId -or -not $PrivateDnsZoneId)) {
    throw '-EnablePrivateEndpoint requires -PrivateEndpointSubnetId and -PrivateDnsZoneId.'
}

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
                        enabled = $false
                        days = 0  # Retention is configured on Log Analytics tables
                    }
                }
                @{
                    category = "AzurePolicyEvaluationDetails"
                    enabled = $true
                    retentionPolicy = @{
                        enabled = $false
                        days = 0
                    }
                }
            )
            metrics = @(
                @{
                    category = "AllMetrics"
                    enabled = $true
                    retentionPolicy = @{
                        enabled = $false
                        days = 0
                    }
                }
            )
        }
    } | ConvertTo-Json -Depth 10

    $response = Invoke-AzRestMethodWithRetry -Method PUT -Uri $diagnosticUri -Payload $diagnosticSettings

    if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
        Write-Success "Diagnostic logs enabled; retention is managed by Log Analytics tables"
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

function Assert-KeyVaultRootCertificate {
    param(
        [Parameter(Mandatory)][hashtable]$CertificateInfo,
        [Parameter(Mandatory)][string]$ExpectedKeyType
    )

    $certificate = $CertificateInfo.Certificate
    $basic = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' } | Select-Object -First 1
    if (-not $basic) { throw 'Root certificate has no Basic Constraints extension.' }
    $basic = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$basic
    if (-not $basic.CertificateAuthority) { throw 'Existing Key Vault certificate is not a CA certificate.' }
    if ($basic.HasPathLengthConstraint -and $basic.PathLengthConstraint -lt 2) {
        throw "Existing root pathLen=$($basic.PathLengthConstraint) cannot support GSA's two subordinate CA tiers. Use a new -RootCertificateName."
    }

    $usage = $certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' } | Select-Object -First 1
    if (-not $usage) { throw 'Root certificate has no Key Usage extension.' }
    $usage = [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]$usage
    $requiredUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
    if (($usage.KeyUsages -band $requiredUsage) -ne $requiredUsage) { throw 'Root certificate must allow keyCertSign and cRLSign.' }

    $keyResponse = Invoke-RestMethod -Method GET -Uri "$($CertificateInfo.KeyId)?api-version=7.5" -Headers @{ Authorization = "Bearer $(Get-KeyVaultToken)" }
    if ($keyResponse.key.kty -ne $ExpectedKeyType) {
        throw "Existing root uses '$($keyResponse.key.kty)', expected '$ExpectedKeyType'. Use a new -RootCertificateName to migrate safely."
    }
    if ($certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddMonths(6)) {
        throw 'Existing root CA expires too soon to meet the GSA six-month certificate minimum.'
    }
    Write-Success "Validated root CA: $ExpectedKeyType, CA=true, keyCertSign, cRLSign"
}
function Enable-KeyVaultPrivateEndpoint {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroupName,
        [Parameter(Mandatory)][string]$Location,
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$SubnetId,
        [Parameter(Mandatory)][string]$PrivateDnsZoneId
    )

    $vaultId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName"
    $endpointName = "pe-$VaultName"
    $endpointPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Network/privateEndpoints/$endpointName`?api-version=2024-05-01"
    $endpoint = Invoke-AzRestMethod -Method GET -Path $endpointPath
    if ($endpoint.StatusCode -eq 404) {
        $endpointBody = @{
            location = $Location
            properties = @{
                subnet = @{ id = $SubnetId }
                privateLinkServiceConnections = @(@{
                    name = "plsc-$VaultName"
                    properties = @{
                        privateLinkServiceId = $vaultId
                        groupIds = @('vault')
                        requestMessage = 'GSA TLS CA signing and CRL renewal'
                    }
                })
            }
        } | ConvertTo-Json -Depth 10
        if (-not $PSCmdlet.ShouldProcess($endpointName, 'Create Key Vault private endpoint')) { return }
        $endpoint = Invoke-AzRestMethodWithRetry -Method PUT -Uri $endpointPath -Payload $endpointBody
    } elseif ($endpoint.StatusCode -ne 200) {
        throw "Unable to inspect private endpoint '$endpointName': HTTP $($endpoint.StatusCode) $($endpoint.Content)"
    }

    $zoneGroupPath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Network/privateEndpoints/$endpointName/privateDnsZoneGroups/default?api-version=2024-05-01"
    $zoneGroup = Invoke-AzRestMethod -Method GET -Path $zoneGroupPath
    if ($zoneGroup.StatusCode -eq 404) {
        $zoneBody = @{ properties = @{ privateDnsZoneConfigs = @(@{ name = 'vault'; properties = @{ privateDnsZoneId = $PrivateDnsZoneId } }) } } | ConvertTo-Json -Depth 8
        if ($PSCmdlet.ShouldProcess($endpointName, 'Attach Key Vault private DNS zone')) {
            Invoke-AzRestMethodWithRetry -Method PUT -Uri $zoneGroupPath -Payload $zoneBody | Out-Null
        }
    } elseif ($zoneGroup.StatusCode -ne 200) {
        throw "Unable to inspect private DNS zone group: HTTP $($zoneGroup.StatusCode) $($zoneGroup.Content)"
    }

    $endpointReady = $false
    for ($attempt = 1; $attempt -le 24; $attempt++) {
        Start-Sleep -Seconds 5
        $endpointResponse = Invoke-AzRestMethod -Method GET -Path $endpointPath
        if ($endpointResponse.StatusCode -ne 200) { continue }
        $endpointData = $endpointResponse.Content | ConvertFrom-Json
        $connectionState = $endpointData.properties.privateLinkServiceConnections[0].properties.privateLinkServiceConnectionState.status
        if ($connectionState -eq 'Rejected') { throw 'The Key Vault private endpoint connection was rejected.' }
        if ($connectionState -eq 'Approved' -and $endpointData.properties.provisioningState -eq 'Succeeded') {
            $endpointReady = $true
            break
        }
    }
    if (-not $endpointReady) { throw 'Key Vault private endpoint did not become ready within two minutes.' }

    $endpointIps = @($endpointData.properties.customDnsConfigs | ForEach-Object { $_.ipAddresses } | Where-Object { $_ })
    if (-not $endpointIps) {
        foreach ($nicReference in @($endpointData.properties.networkInterfaces)) {
            $nicResponse = Invoke-AzRestMethod -Method GET -Path "$($nicReference.id)?api-version=2024-05-01"
            if ($nicResponse.StatusCode -eq 200) {
                $nicData = $nicResponse.Content | ConvertFrom-Json
                $endpointIps += @($nicData.properties.ipConfigurations.properties.privateIPAddress | Where-Object { $_ })
            }
        }
    }
    $resolvedIps = @([System.Net.Dns]::GetHostAddresses("$VaultName.vault.azure.net") | ForEach-Object IPAddressToString)
    if (-not ($resolvedIps | Where-Object { $_ -in $endpointIps })) {
        throw "Private DNS validation failed. Resolved [$($resolvedIps -join ', ')] but endpoint uses [$($endpointIps -join ', ')]. Public access remains enabled."
    }

    $vaultPath = "$vaultId`?api-version=2023-07-01"
    $vaultResponse = Invoke-AzRestMethod -Method GET -Path $vaultPath
    if ($vaultResponse.StatusCode -ne 200) { throw "Unable to read Key Vault before network hardening: HTTP $($vaultResponse.StatusCode)" }
    $vaultBody = $vaultResponse.Content | ConvertFrom-Json
    $vaultBody.properties.publicNetworkAccess = 'Disabled'
    $vaultBody.properties.networkAcls.defaultAction = 'Deny'
    if ($PSCmdlet.ShouldProcess($VaultName, 'Disable Key Vault public network access')) {
        Invoke-AzRestMethodWithRetry -Method PUT -Uri $vaultPath -Payload ($vaultBody | ConvertTo-Json -Depth 20) | Out-Null
        Start-Sleep -Seconds 5
        try {
            $token = Get-KeyVaultToken
            Invoke-RestMethod -Method GET -Uri "https://$VaultName.vault.azure.net/certificates?api-version=7.5&maxresults=1" -Headers @{ Authorization = "Bearer $token" } | Out-Null
        } catch {
            $vaultBody.properties.publicNetworkAccess = 'Enabled'
            $vaultBody.properties.networkAcls.defaultAction = 'Allow'
            Invoke-AzRestMethodWithRetry -Method PUT -Uri $vaultPath -Payload ($vaultBody | ConvertTo-Json -Depth 20) | Out-Null
            throw "Private Key Vault data-plane validation failed; public access was restored. $($_.Exception.Message)"
        }
        Write-Success 'Key Vault private endpoint and private DNS validated; public access disabled'
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
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CsrPem,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IssuerCert,
        [Parameter(Mandatory)]
        [string]$KeyVaultKeyId,
        [int]$ValidityYears = 5,
        [string]$CrlDistributionPointUrl
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

    # GSA creates one additional short-lived issuing CA below this CA. RFC 5280
    # pathLen=1 permits that tier, but prevents GSA's CA from creating a deeper hierarchy.
    $basicConstraints = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
        $true,  # certificateAuthority
        $true,  # hasPathLengthConstraint
        1,      # one non-self-issued intermediate CA may follow
        $true   # critical
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

    # Add CRL Distribution Points if URL provided
    if ($CrlDistributionPointUrl) {
        Write-Info "Adding CDP: $CrlDistributionPointUrl"
        $cdpExtension = [System.Security.Cryptography.X509Certificates.CertificateRevocationListBuilder]::BuildCrlDistributionPointExtension(
            [string[]]@($CrlDistributionPointUrl),
            $false  # not critical
        )
        $certRequest.CertificateExtensions.Add($cdpExtension)
    }

    # Generate serial number (16 random bytes)
    $serialBytes = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($serialBytes)
    $serialBytes[0] = $serialBytes[0] -band 0x7F  # Ensure positive
    $serialNumber = [byte[]]$serialBytes

    # Set validity period
    $notBefore = [DateTimeOffset]::UtcNow.AddMinutes(-5)  # 5 min clock skew tolerance
    $requestedNotAfter = [DateTimeOffset]::UtcNow.AddYears($ValidityYears)
    $issuerLimit = [DateTimeOffset]::new($IssuerCert.NotAfter.ToUniversalTime()).AddMinutes(-5)
    $notAfter = if ($requestedNotAfter -lt $issuerLimit) { $requestedNotAfter } else { $issuerLimit }
    if ($notAfter -le [DateTimeOffset]::UtcNow.AddMonths(6)) {
        throw 'The issuer does not have enough remaining validity to meet the GSA six-month minimum.'
    }

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
        throw 'RSA signature verification failed; refusing to return an invalid certificate.'
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


function Get-StorageToken {
    $tokenResponse = Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/'
    if ($tokenResponse.Token -is [System.Security.SecureString]) {
        return $tokenResponse.Token | ConvertFrom-SecureString -AsPlainText
    }
    return $tokenResponse.Token
}

function Set-AzureStorageBlob {
    param(
        [Parameter(Mandatory)][string]$StorageAccountName,
        [Parameter(Mandatory)][string]$ContainerName,
        [Parameter(Mandatory)][string]$BlobName,
        [Parameter(Mandatory)][byte[]]$Content,
        [Parameter(Mandatory)][string]$ContentType
    )

    $encodedBlobName = ($BlobName.Split('/') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
    $uri = "https://$StorageAccountName.blob.core.windows.net/$ContainerName/$encodedBlobName"
    for ($attempt = 1; $attempt -le 12; $attempt++) {
        $headers = @{
            Authorization = "Bearer $(Get-StorageToken)"
            'x-ms-version' = '2023-11-03'
            'x-ms-blob-type' = 'BlockBlob'
            'Content-Type' = $ContentType
        }
        try {
            Invoke-RestMethod -Uri $uri -Method PUT -Headers $headers -Body $Content -ContentType $ContentType | Out-Null
            return
        } catch {
            $statusCode = [int]$_.Exception.Response.StatusCode
            if ($statusCode -eq 403 -and $attempt -lt 12) {
                Write-Verbose "Storage RBAC has not propagated; retrying blob upload ($attempt/12)."
                Start-Sleep -Seconds 5
                continue
            }
            throw
        }
    }
}
function New-CrlFromKeyVault {
    <#
    .SYNOPSIS
        Generates an empty CRL signed by the root CA key in Azure Key Vault.
    .DESCRIPTION
        Uses the same dummy-key + DER-extraction + Key Vault re-signing pattern as
        New-SignedCertificateFromCSR. The private key never leaves Key Vault.

        CRL structure: SEQUENCE { TBSCertList, SignatureAlgorithm, SignatureValue }
        (same outer structure as an X.509 certificate)
    #>
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IssuerCert,
        [string]$KeyVaultKeyId,
        [System.Numerics.BigInteger]$CrlNumber = 1,
        [int]$NextUpdateDays = 30
    )

    Write-Host "  Generating CRL signed by Key Vault..." -ForegroundColor Cyan

    # Build an empty CRL using .NET 7+ CertificateRevocationListBuilder
    $crlBuilder = [System.Security.Cryptography.X509Certificates.CertificateRevocationListBuilder]::new()

    $crlNum = $CrlNumber
    $nextUpdate = [DateTimeOffset]::UtcNow.AddDays($NextUpdateDays)
    $thisUpdate = [DateTimeOffset]::UtcNow
    $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $rsaPadding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1

    # Build CRL with a temporary local RSA key to get the TBS structure.
    # We'll extract the TBS bytes, sign them with Key Vault, and rebuild the CRL.
    Write-Verbose "Creating CRL structure with temporary signing key..."

    # Build AKI from the issuer's Subject Key Identifier
    $issuerSkiExt = $IssuerCert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.14" }
    if (-not $issuerSkiExt) {
        throw "Issuer certificate does not have a Subject Key Identifier extension"
    }
    $skiTyped = [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]$issuerSkiExt
    $aki = [System.Security.Cryptography.X509Certificates.X509AuthorityKeyIdentifierExtension]::CreateFromSubjectKeyIdentifier($skiTyped)

    # Build CRL with proper issuer DN and AKI, signed by dummy key
    $dummyKey = [System.Security.Cryptography.RSA]::Create(4096)
    try {
        $dummyGenerator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA(
            $dummyKey,
            $rsaPadding
        )
        [byte[]]$dummyCrlBytes = $crlBuilder.Build(
            $IssuerCert.SubjectName,
            $dummyGenerator,
            $crlNum,
            $nextUpdate,
            $hashAlgorithm,
            $aki,
            $thisUpdate
        )
    } finally {
        $dummyKey.Dispose()
    }

    Write-Verbose "CRL with real issuer DN, size: $($dummyCrlBytes.Length) bytes"

    # Extract TBS (To Be Signed) portion from the CRL DER
    # CRL DER: SEQUENCE { TBSCertList, SignatureAlgorithm, SignatureValue }
    $offset = 0
    if ($dummyCrlBytes[$offset] -ne 0x30) { throw "Invalid CRL: expected outer SEQUENCE tag (0x30)" }
    $offset++

    # Skip outer length
    if ($dummyCrlBytes[$offset] -band 0x80) {
        $lenByteCount = $dummyCrlBytes[$offset] -band 0x7F
        $offset += 1 + $lenByteCount
    } else {
        $offset++
    }

    # Now at TBSCertList start
    $tbsStart = $offset
    if ($dummyCrlBytes[$offset] -ne 0x30) { throw "Invalid CRL: expected TBSCertList SEQUENCE tag (0x30)" }
    $offset++

    if ($dummyCrlBytes[$offset] -band 0x80) {
        $lenByteCount = $dummyCrlBytes[$offset] -band 0x7F
        $offset++
        $tbsContentLen = 0
        for ($i = 0; $i -lt $lenByteCount; $i++) {
            $tbsContentLen = ($tbsContentLen -shl 8) + $dummyCrlBytes[$offset + $i]
        }
        $offset += $lenByteCount
    } else {
        $tbsContentLen = $dummyCrlBytes[$offset]
        $offset++
    }

    $tbsEnd = $offset + $tbsContentLen
    [byte[]]$tbsBytes = $dummyCrlBytes[$tbsStart..($tbsEnd - 1)]
    Write-Info "TBS CertList size: $($tbsBytes.Length) bytes"

    # Hash TBS with SHA-256
    [byte[]]$tbsHash = [System.Security.Cryptography.SHA256]::HashData($tbsBytes)
    Write-Verbose "TBS hash: $([BitConverter]::ToString($tbsHash).Replace('-',''))"

    # Sign with Key Vault
    Write-Host "  Signing CRL with Key Vault..." -ForegroundColor Cyan

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
        Write-Info "CRL signature size: $($kvSignature.Length) bytes"
    } catch {
        Write-Error "Failed to sign CRL with Key Vault: $_"
        throw
    }

    # Rebuild CRL DER with Key Vault signature
    # Structure: SEQUENCE { TBSCertList, SignatureAlgorithm, SignatureValue }
    Write-Verbose "Constructing final signed CRL..."

    # Signature Algorithm Identifier: SHA256withRSA (OID 1.2.840.113549.1.1.11)
    [byte[]]$sigAlgId = @(0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00)

    # Signature Value as BIT STRING
    [byte[]]$sigValueContent = @(0x00) + $kvSignature
    $sigBitString = [System.Collections.Generic.List[byte]]::new()
    $sigBitString.Add(0x03)
    [byte[]]$sigLenBytes = Get-DerLength $sigValueContent.Length
    $sigBitString.AddRange($sigLenBytes)
    $sigBitString.AddRange([byte[]]$sigValueContent)

    # Combine into inner content
    [byte[]]$innerContent = $tbsBytes + $sigAlgId + [byte[]]$sigBitString.ToArray()

    # Wrap in outer SEQUENCE
    $finalCrl = [System.Collections.Generic.List[byte]]::new()
    $finalCrl.Add(0x30)
    [byte[]]$outerLenBytes = Get-DerLength $innerContent.Length
    $finalCrl.AddRange($outerLenBytes)
    $finalCrl.AddRange($innerContent)

    [byte[]]$finalCrlBytes = $finalCrl.ToArray()

    # Verify signature
    $issuerRsa = $IssuerCert.PublicKey.GetRSAPublicKey()
    $sigVerified = $issuerRsa.VerifyData($tbsBytes, $kvSignature, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    if ($sigVerified) {
        Write-Success "CRL signed and verified successfully"
    } else {
        throw 'CRL signature verification failed; refusing to publish an invalid CRL.'
    }

    Write-Info "CRL Number: $CrlNumber"
    Write-Info "This Update: $($thisUpdate.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    Write-Info "Next Update: $($nextUpdate.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    Write-Info "CRL size: $($finalCrlBytes.Length) bytes"

    return $finalCrlBytes
}

function New-IntuneTrustedRootCertPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Windows', 'macOS', 'iOS/iPadOS', 'AndroidEnterpriseDeviceOwner', 'AndroidEnterpriseWorkProfile', 'AndroidAOSP')]
        [string]$Platform,
        [Parameter(Mandatory)]
        [string]$RootCertBase64,
        [bool]$AssignToAllDevices
    )

    $platformMap = @{
        'Windows' = @{ Type = '#microsoft.graph.windows81TrustedRootCertificate'; Label = 'Windows' }
        'macOS' = @{ Type = '#microsoft.graph.macOSTrustedRootCertificate'; Label = 'macOS' }
        'iOS/iPadOS' = @{ Type = '#microsoft.graph.iosTrustedRootCertificate'; Label = 'iOS-iPadOS' }
        'AndroidEnterpriseDeviceOwner' = @{ Type = '#microsoft.graph.androidDeviceOwnerTrustedRootCertificate'; Label = 'Android Enterprise Device Owner' }
        'AndroidEnterpriseWorkProfile' = @{ Type = '#microsoft.graph.androidWorkProfileTrustedRootCertificate'; Label = 'Android Enterprise Work Profile' }
        'AndroidAOSP' = @{ Type = '#microsoft.graph.aospDeviceOwnerTrustedRootCertificate'; Label = 'Android AOSP' }
    }

    $platformInfo = $platformMap[$Platform]
    $policyName = "GSA TLS Root Certificate - $($platformInfo.Label)"
    $policy = @{
        '@odata.type' = $platformInfo.Type
        displayName = $policyName
        description = 'Trusted root CA for Global Secure Access TLS inspection - managed by Initialize-GSATLSInspection.ps1'
        trustedRootCertificate = $RootCertBase64
        certFileName = 'gsa-tls-root-ca.cer'
    }
    if ($Platform -eq 'Windows') { $policy.destinationStore = 'computerCertStoreRoot' }
    if ($Platform -eq 'macOS') { $policy.deploymentChannel = 'deviceChannel' }

    $escapedName = $policyName.Replace("'", "''")
    $encodedFilter = [uri]::EscapeDataString("displayName eq '$escapedName'")
    $existingResponse = Invoke-MgGraphRequest -Method GET -Uri "/beta/deviceManagement/deviceConfigurations?`$filter=$encodedFilter"
    $policyMatches = @($existingResponse.value | Where-Object { $_.'@odata.type' -eq $platformInfo.Type })
    if ($policyMatches.Count -gt 1) {
        throw "Multiple managed Intune policies named '$policyName' exist; resolve duplicates before continuing."
    }

    if ($policyMatches.Count -eq 1) {
        $result = $policyMatches[0]
        if ($result.trustedRootCertificate -ne $RootCertBase64) {
            if ($PSCmdlet.ShouldProcess($policyName, 'Update Intune trusted-root certificate')) {
                Invoke-MgGraphRequest -Method PATCH -Uri "/beta/deviceManagement/deviceConfigurations/$($result.id)" -Body ($policy | ConvertTo-Json -Depth 5) -ContentType 'application/json' | Out-Null
                Write-Success "Policy updated: $($result.id)"
            }
        } else {
            Write-Info "Policy already current: $policyName"
        }
    } else {
        if (-not $PSCmdlet.ShouldProcess($policyName, 'Create Intune trusted-root policy')) { return $null }
        $result = Invoke-MgGraphRequest -Method POST -Uri '/beta/deviceManagement/deviceConfigurations' -Body ($policy | ConvertTo-Json -Depth 5) -ContentType 'application/json'
        Write-Success "Policy created: $($result.id)"
    }

    if ($AssignToAllDevices) {
        $assignmentResponse = Invoke-MgGraphRequest -Method GET -Uri "/beta/deviceManagement/deviceConfigurations/$($result.id)/assignments"
        $assignments = @($assignmentResponse.value | ForEach-Object { @{ target = $_.target } })
        $alreadyAssigned = @($assignmentResponse.value | Where-Object { $_.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget' }).Count -gt 0
        if (-not $alreadyAssigned -and $PSCmdlet.ShouldProcess($policyName, 'Assign Intune policy to All Devices')) {
            $assignments += @{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
            $assignmentBody = @{ assignments = $assignments } | ConvertTo-Json -Depth 8
            Invoke-MgGraphRequest -Method POST -Uri "/beta/deviceManagement/deviceConfigurations/$($result.id)/assign" -Body $assignmentBody -ContentType 'application/json' | Out-Null
            Write-Info 'Assigned to All Devices while preserving existing assignments'
        }
    }

    return $result.id
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

$stepNum = 1

Write-StepHeader "Step $($stepNum): Authentication & Context"
$stepNum++

# CRL-only renewal is an Azure operation and intentionally requires no Graph session.
$mgContext = $null
if (-not $RenewCrlOnly) {
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
        $mgContext = Get-MgContext
        $missingScopes = $requiredScopes | Where-Object { $_ -notin $mgContext.Scopes }
        if ($missingScopes) { throw "Graph consent is still missing: $($missingScopes -join ', ')" }
    }
} catch {
    Write-Error "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'NetworkAccess.ReadWrite.All','DeviceManagementConfiguration.ReadWrite.All'"
    exit 1
}
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
    throw 'Not connected to Azure. Run: Connect-AzAccount'
}

if ($mgContext -and $mgContext.TenantId -and $mgContext.TenantId -ne $azContext.Tenant.Id) {
    throw "Microsoft Graph tenant '$($mgContext.TenantId)' does not match Azure tenant '$($azContext.Tenant.Id)'."
}

# Get subscription
if (-not $SubscriptionId) {
    $SubscriptionId = $azContext.Subscription.Id
    Write-Info "Using subscription from context: $($azContext.Subscription.Name)"
} else {
    Write-Info "Using specified subscription: $SubscriptionId"
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $azContext = Get-AzContext
    if ($azContext.Subscription.Id -ne $SubscriptionId) { throw "Failed to select Azure subscription '$SubscriptionId'." }
}

# Generate Key Vault name if not provided
if (-not $KeyVaultName) {
    $random = -join ((97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
    $KeyVaultName = "kv-gsa-$random"
    Write-Info "Generated Key Vault name: $KeyVaultName"
}

# Generate Storage Account name for CRL hosting
if (-not $StorageAccountName) {
    # Derive from OrganizationName: lowercase, alphanumeric only, prefixed with 'sagsacrl'
    $sanitizedOrg = ($OrganizationName -replace '[^a-zA-Z0-9]', '').ToLower()
    $saPrefix = "sagsacrl"
    $maxOrgLen = 24 - $saPrefix.Length  # 16 chars available for org name
    $orgPart = $sanitizedOrg.Substring(0, [Math]::Min($sanitizedOrg.Length, $maxOrgLen))
    $candidateName = "$saPrefix$orgPart"

    # Ensure minimum length of 3
    if ($candidateName.Length -lt 3) {
        $candidateName = "sagsacrl$((-join ((97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object { [char]$_ })))"
    }

    # Check name availability via Azure REST API
    $checkUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Storage/checkNameAvailability?api-version=2023-05-01"
    $checkBody = @{ name = $candidateName; type = "Microsoft.Storage/storageAccounts" } | ConvertTo-Json
    $checkResponse = Invoke-AzRestMethod -Method POST -Path $checkUri -Payload $checkBody
    $availability = ($checkResponse.Content | ConvertFrom-Json)

    if ($availability.nameAvailable) {
        $StorageAccountName = $candidateName
    } else {
        # Name taken or invalid - append random suffix for uniqueness
        Write-Verbose "Storage account name '$candidateName' unavailable: $($availability.reason). Adding random suffix."
        $random = -join ((97..122) + (48..57) | Get-Random -Count 4 | ForEach-Object { [char]$_ })
        $maxOrgLen = 24 - $saPrefix.Length - 4  # 12 chars for org
        $orgPart = $sanitizedOrg.Substring(0, [Math]::Min($sanitizedOrg.Length, $maxOrgLen))
        $StorageAccountName = "$saPrefix$orgPart$random"
    }

    Write-Info "Generated Storage Account name: $StorageAccountName"
}

# Construct CRL URL (deferred to after storage account creation if no custom hostname)
$crlFileName = "gsa-tls-root-ca.crl"
$crlUrl = if ($CrlHostname) { "http://$CrlHostname/$crlFileName" } else { $null }

Write-Host "`nConfiguration:" -ForegroundColor Cyan
Write-Host "  Subscription:     $SubscriptionId" -ForegroundColor White
Write-Host "  Resource Group:   $ResourceGroupName" -ForegroundColor White
Write-Host "  Key Vault:        $KeyVaultName ($KeyVaultSKU)" -ForegroundColor White
Write-Host "  Location:         $Location" -ForegroundColor White
Write-Host "  Certificate CN:   $CertificateCommonName" -ForegroundColor White
Write-Host "  Organization:     $OrganizationName" -ForegroundColor White
if ($LogAnalyticsWorkspaceId) {
    Write-Host "  Logging:          Enabled (workspace/table retention)" -ForegroundColor White
}
if ($EnableDefender) {
    Write-Host "  Defender:         Enabled" -ForegroundColor White
}
if ($AssignIntunePolicies) {
    Write-Host "  Intune Assign:    All Devices" -ForegroundColor White
}
Write-Host "  Storage Account:  $StorageAccountName" -ForegroundColor White
if ($CrlHostname) {
    Write-Host "  CRL Hostname:     $CrlHostname" -ForegroundColor White
    Write-Host "  CRL URL:          $crlUrl" -ForegroundColor White
} else {
    Write-Host "  CRL URL:          (auto - storage static website)" -ForegroundColor White
}

if ($WhatIfPreference) {
    Write-Host "`nWhatIf deployment plan:" -ForegroundColor Cyan
    Write-Info "Ensure resource group '$ResourceGroupName', Premium Key Vault '$KeyVaultName', and storage account '$StorageAccountName'"
    Write-Info "Ensure RSA-HSM root CA '$RootCertificateName' and publish a new signed CRL"
    if ($EnablePrivateEndpoint) { Write-Info "Create and validate a Key Vault private endpoint, then disable public access" }
    if ($RenewCrlOnly) {
        Write-Info 'Stop after CRL renewal'
    } else {
        Write-Info "Ensure trusted-root profiles for: $($IntunePlatforms -join ', ')"
        Write-Info "Preserve any active GSA certificate$(if ($RotateGsaCertificate) { ' until the replacement is uploaded and enabled' })"
    }
    return [PSCustomObject]@{ Status = 'WhatIf'; KeyVaultName = $KeyVaultName; StorageAccountName = $StorageAccountName; RotateGsaCertificate = $RotateGsaCertificate.IsPresent; RenewCrlOnly = $RenewCrlOnly.IsPresent }
}

Write-StepHeader "Step $($stepNum): Resource Group"
$stepNum++

$rgUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName`?api-version=2021-04-01"

try {
    $existingRG = Invoke-AzRestMethod -Method GET -Path $rgUri
    if ($existingRG.StatusCode -eq 200) {
        Write-Success "Resource group exists"
        $rgData = $existingRG.Content | ConvertFrom-Json
        Write-Info "Location: $($rgData.location)"


    } elseif ($existingRG.StatusCode -eq 404) {
        throw "Does not exist"
    } else {
        throw "Unable to inspect resource group: HTTP $($existingRG.StatusCode) $($existingRG.Content)"
    }
} catch {
    if ($_.Exception.Message -ne 'Does not exist') { throw }
    if ($RenewCrlOnly) { throw "Resource group '$ResourceGroupName' does not exist; -RenewCrlOnly never creates resources." }
    Write-Host "  Creating resource group..." -ForegroundColor Yellow

    $rgBody = @{
        location = $Location
        tags = @{
            Purpose = "Global Secure Access TLS Inspection"
            ManagedBy = "Initialize-GSATLSInspection.ps1"
            CreatedDate = (Get-Date -Format "yyyy-MM-dd")
        }
    } | ConvertTo-Json -Depth 5

    if (-not $PSCmdlet.ShouldProcess($ResourceGroupName, 'Create Azure resource group')) { throw 'Resource group creation was declined.' }
    $response = Invoke-AzRestMethodWithRetry -Method PUT -Uri $rgUri -Payload $rgBody

    if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 201) {
        Write-Success "Resource group created"
    } else {
        Write-Error "Failed to create resource group: $($response.StatusCode)"
        exit 1
    }
}

Write-StepHeader "Step $($stepNum): Key Vault (Microsoft Security Benchmark DP-8)"
$stepNum++

$kvUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName`?api-version=2023-07-01"

try {
    $existingKV = Invoke-AzRestMethod -Method GET -Path $kvUri
    if ($existingKV.StatusCode -eq 200) {
        Write-Success "Key Vault exists"
        $kvData = $existingKV.Content | ConvertFrom-Json
        Write-Info "Location: $($kvData.location)"
        Write-Info "SKU: $($kvData.properties.sku.name)"
        if ($kvData.properties.sku.name -ne 'premium') { throw "Existing Key Vault '$KeyVaultName' is not Premium and cannot host RSA-HSM certificate keys." }
        if (-not $kvData.properties.enableRbacAuthorization) { throw "Existing Key Vault '$KeyVaultName' does not use Azure RBAC authorization." }
        if (-not $kvData.properties.enablePurgeProtection) { throw "Existing Key Vault '$KeyVaultName' does not have purge protection enabled." }
        if ($kvData.properties.softDeleteRetentionInDays -lt 90) { throw "Existing Key Vault '$KeyVaultName' has less than 90 days of soft-delete retention." }
        $vaultUri = $kvData.properties.vaultUri.TrimEnd('/')
    } elseif ($existingKV.StatusCode -eq 404) {
        throw "Does not exist"
    } else {
        throw "Unable to inspect Key Vault: HTTP $($existingKV.StatusCode) $($existingKV.Content)"
    }
} catch {
    if ($_.Exception.Message -ne 'Does not exist') { throw }
    if ($RenewCrlOnly) { throw "Key Vault '$KeyVaultName' does not exist; -RenewCrlOnly never creates resources." }
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
            publicNetworkAccess = "Enabled"  # Disabled only after private endpoint and DNS validation
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

    if (-not $PSCmdlet.ShouldProcess($KeyVaultName, 'Create Premium Azure Key Vault')) { throw 'Key Vault creation was declined.' }
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
                Write-Verbose "Key Vault readiness check failed: $($_.Exception.Message)"
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

$currentObjectId = $null
$currentPrincipalType = 'User'

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
        $currentPrincipalType = if ($claims.idtyp -eq 'app') { 'ServicePrincipal' } else { 'User' }
        Write-Verbose "Got OID from Azure token: $currentObjectId ($currentPrincipalType)"
    }
} catch {
    Write-Verbose "Could not extract OID from Azure token: $_"
}

# Fallback: try Microsoft Graph /me
if (-not $currentObjectId -and $mgContext) {
    try {
        $mgUser = Invoke-MgGraphRequest -Method GET -Uri "/v1.0/me" -ErrorAction SilentlyContinue
        if ($mgUser.id) { $currentObjectId = $mgUser.id; $currentPrincipalType = 'User' }
    } catch {
        Write-Verbose "Microsoft Graph /me fallback failed: $($_.Exception.Message)"
    }
}


if ($currentObjectId) {
    Write-Info "Principal ID: $currentObjectId"

    $roles = @(
        @{ Name = "Key Vault Certificates Officer"; Id = "a4417e6f-fecd-4de8-b567-7b0420556985" }
        @{ Name = "Key Vault Crypto User"; Id = "12338af0-0e69-4776-bea7-57ae8d297424" }
    )

    $kvScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName"
    $newAssignments = $false

    foreach ($role in $roles) {
        # Azure RBAC supports filtering role assignments by principal. Filter the
        # role definition locally because combined OData predicates are not accepted
        # consistently at nested resource scopes.
        $roleDefId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$($role.Id)"
        $existingUri = "${kvScope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$currentObjectId'"
        $existingCheck = Invoke-AzRestMethod -Method GET -Path $existingUri
        if ($existingCheck.StatusCode -ne 200) { throw "Could not inspect Key Vault RBAC assignments: HTTP $($existingCheck.StatusCode) $($existingCheck.Content)" }
        $existingAssignments = @(($existingCheck.Content | ConvertFrom-Json).value | Where-Object { $_.properties.roleDefinitionId -eq $roleDefId })

        if ($existingAssignments.Count -gt 0) {
            Write-Info "Already assigned: $($role.Name)"
            continue
        }

        $assignmentGuid = [guid]::NewGuid().ToString()
        $roleUri = "$kvScope/providers/Microsoft.Authorization/roleAssignments/$assignmentGuid`?api-version=2022-04-01"

        $roleBody = @{
            properties = @{
                roleDefinitionId = $roleDefId
                principalId = $currentObjectId
                principalType = $currentPrincipalType
            }
        } | ConvertTo-Json -Depth 5

        try {
            if (-not $PSCmdlet.ShouldProcess("$KeyVaultName/$($role.Name)", "Assign role to $currentObjectId")) { throw 'Key Vault role assignment was declined.' }
            $roleResponse = Invoke-AzRestMethod -Method PUT -Path $roleUri -Payload $roleBody
            if ($roleResponse.StatusCode -in @(200, 201)) {
                Write-Success "Assigned: $($role.Name)"
                $newAssignments = $true
            } elseif ($roleResponse.StatusCode -eq 409) {
                Write-Info "Already assigned: $($role.Name)"
            }
        } catch {
            throw "Could not assign $($role.Name). Owner, User Access Administrator, or equivalent role-assignment rights are required: $($_.Exception.Message)"
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
    Write-Info "Manually assign Key Vault Certificates Officer and Key Vault Crypto User roles"
}

if ($EnablePrivateEndpoint) {
    Write-StepHeader "Step $($stepNum): Key Vault Private Endpoint"
    $stepNum++
    Enable-KeyVaultPrivateEndpoint -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -Location $Location -VaultName $KeyVaultName -SubnetId $PrivateEndpointSubnetId -PrivateDnsZoneId $PrivateDnsZoneId -WhatIf:$WhatIfPreference
}

# Enable diagnostic logs if workspace provided
if ($LogAnalyticsWorkspaceId) {
    Write-StepHeader "Step $($stepNum): Diagnostic Logging (LT-4)"
    $stepNum++
    if ($PSCmdlet.ShouldProcess($KeyVaultName, 'Enable Key Vault diagnostic logging')) {
        Enable-KeyVaultDiagnosticLogs -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -WorkspaceId $LogAnalyticsWorkspaceId
    }
} else {
    Write-Info "Skipping diagnostic logs (no Log Analytics workspace specified)"
}

# Enable Defender if requested
if ($EnableDefender) {
    Write-StepHeader "Step $($stepNum): Microsoft Defender for Key Vault (LT-1)"
    $stepNum++
    if ($PSCmdlet.ShouldProcess($SubscriptionId, 'Enable Defender for Key Vault subscription plan')) {
        Enable-DefenderForKeyVault -SubscriptionId $SubscriptionId
    }
}

# Provision Storage Account for CRL hosting
$staticWebsiteHostname = $null
Write-StepHeader "Step $($stepNum): Storage Account for CRL Hosting"
$stepNum++

$saUri = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName`?api-version=2023-05-01"

try {
    $existingSA = Invoke-AzRestMethod -Method GET -Path $saUri
    if ($existingSA.StatusCode -eq 200) {
        Write-Success "Storage account exists: $StorageAccountName"
        $saData = $existingSA.Content | ConvertFrom-Json
        $storageNeedsHardening = $saData.properties.allowSharedKeyAccess -ne $false -or $saData.properties.allowBlobPublicAccess -ne $false -or $saData.properties.minimumTlsVersion -ne 'TLS1_2' -or $saData.properties.supportsHttpsTrafficOnly -ne $false
        if ($storageNeedsHardening -and $PSCmdlet.ShouldProcess($StorageAccountName, 'Harden existing CRL storage account')) {
            $storagePatch = @{ properties = @{ allowSharedKeyAccess = $false; allowBlobPublicAccess = $false; minimumTlsVersion = 'TLS1_2'; supportsHttpsTrafficOnly = $false } } | ConvertTo-Json -Depth 5
            $patchResponse = Invoke-AzRestMethod -Method PATCH -Path $saUri -Payload $storagePatch
            if ($patchResponse.StatusCode -notin @(200, 202)) { throw "Failed to harden storage account: HTTP $($patchResponse.StatusCode) $($patchResponse.Content)" }
        }
        $staticWebsiteHostname = ($saData.properties.primaryEndpoints.web -replace 'https?://', '').TrimEnd('/')
        Write-Info "Static website endpoint: $staticWebsiteHostname"
    } elseif ($existingSA.StatusCode -eq 404) {
        throw "Does not exist"
    } else {
        throw "Unable to inspect storage account: HTTP $($existingSA.StatusCode) $($existingSA.Content)"
    }
} catch {
    if ($_.Exception.Message -ne 'Does not exist') { throw }
    if ($RenewCrlOnly) { throw "Storage account '$StorageAccountName' does not exist; -RenewCrlOnly never creates resources." }
    Write-Host "  Creating storage account for CRL hosting..." -ForegroundColor Yellow

    $saBody = @{
        kind = "StorageV2"
        location = $Location
        sku = @{ name = "Standard_LRS" }
        properties = @{
            allowBlobPublicAccess = $false
            minimumTlsVersion = "TLS1_2"
            supportsHttpsTrafficOnly = $false  # Required for HTTP CRL access
            allowSharedKeyAccess = $false
        }
        tags = @{
            Purpose = "GSA TLS CRL Distribution Point"
            ManagedBy = "Initialize-GSATLSInspection.ps1"
        }
    } | ConvertTo-Json -Depth 10

    if (-not $PSCmdlet.ShouldProcess($StorageAccountName, 'Create CRL storage account')) { throw 'Storage account creation was declined.' }
    $response = Invoke-AzRestMethodWithRetry -Method PUT -Uri $saUri -Payload $saBody

    if ($response.StatusCode -in @(200, 201, 202)) {
        Write-Success "Storage account created"

        # Wait for provisioning to complete
        Write-Host "  Waiting for storage account provisioning..." -ForegroundColor Gray
        $maxAttempts = 24
        $attempt = 0
        $saReady = $false

        while (-not $saReady -and $attempt -lt $maxAttempts) {
            $attempt++
            Start-Sleep -Seconds 5
            Write-Host "." -NoNewline -ForegroundColor Gray

            try {
                $saCheck = Invoke-AzRestMethod -Method GET -Path $saUri
                if ($saCheck.StatusCode -eq 200) {
                    $saCheckData = $saCheck.Content | ConvertFrom-Json
                    if ($saCheckData.properties.provisioningState -eq "Succeeded") {
                        $saReady = $true
                        Write-Host ""
                        Write-Success "Storage account is ready"
                    }
                }
            } catch {
                Write-Verbose "Storage account readiness check failed: $($_.Exception.Message)"
            }
        }

        if (-not $saReady) {
            Write-Error "Storage account provisioning timed out"
            exit 1
        }
    } else {
        Write-Error "Failed to create storage account: $($response.StatusCode) - $($response.Content)"
        exit 1
    }
}

# Static website configuration is a Blob service data-plane operation. Authenticate
# with Microsoft Entra ID; never retrieve or use a Storage Shared Key.
if ($PSCmdlet.ShouldProcess($StorageAccountName, 'Enable Azure Storage static website')) {
    $storageToken = Get-StorageToken
    $servicePropertiesUri = "https://$StorageAccountName.blob.core.windows.net/?restype=service&comp=properties"
    $servicePropertiesXml = @'
<?xml version="1.0" encoding="utf-8"?>
<StorageServiceProperties>
  <StaticWebsite>
    <Enabled>true</Enabled>
    <IndexDocument>index.html</IndexDocument>
  </StaticWebsite>
</StorageServiceProperties>
'@
    $serviceHeaders = @{
        Authorization = "Bearer $storageToken"
        'x-ms-date' = [DateTime]::UtcNow.ToString('R')
        'x-ms-version' = '2023-11-03'
    }
    try {
        Invoke-RestMethod -Method PUT -Uri $servicePropertiesUri -Headers $serviceHeaders -ContentType 'application/xml' -Body $servicePropertiesXml | Out-Null
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($statusCode -ne 403) { throw }
        Write-Info 'Waiting for Azure Storage authorization to propagate...'
        Start-Sleep -Seconds 30
        $serviceHeaders.Authorization = "Bearer $(Get-StorageToken)"
        Invoke-RestMethod -Method PUT -Uri $servicePropertiesUri -Headers $serviceHeaders -ContentType 'application/xml' -Body $servicePropertiesXml | Out-Null
    }
    Write-Success 'Static website enabled using Microsoft Entra authorization'
}

# Grant only blob data write access to the current principal; account keys remain disabled.
if (-not $currentObjectId -and $mgContext) { throw 'Cannot assign Storage Blob Data Contributor because the current Azure principal ID is unknown.' }
$storageScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName"
$blobRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
$blobRoleDefinitionId = "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions/$blobRoleId"
$blobAssignmentsPath = "$storageScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$currentObjectId'"
$blobAssignmentsResponse = Invoke-AzRestMethod -Method GET -Path $blobAssignmentsPath
if ($blobAssignmentsResponse.StatusCode -ne 200) { throw "Could not inspect storage RBAC assignments: HTTP $($blobAssignmentsResponse.StatusCode) $($blobAssignmentsResponse.Content)" }
$blobAssignments = @(($blobAssignmentsResponse.Content | ConvertFrom-Json).value | Where-Object { $_.properties.roleDefinitionId -eq $blobRoleDefinitionId })
if ($blobAssignments.Count -eq 0 -and $PSCmdlet.ShouldProcess($StorageAccountName, 'Assign Storage Blob Data Contributor')) {
    $assignmentId = [guid]::NewGuid().ToString()
    $assignmentPath = "$storageScope/providers/Microsoft.Authorization/roleAssignments/$assignmentId`?api-version=2022-04-01"
    $assignmentBody = @{ properties = @{ roleDefinitionId = $blobRoleDefinitionId; principalId = $currentObjectId; principalType = $currentPrincipalType } } | ConvertTo-Json -Depth 5
    $assignmentResponse = Invoke-AzRestMethod -Method PUT -Path $assignmentPath -Payload $assignmentBody
    if ($assignmentResponse.StatusCode -notin @(200, 201)) { throw "Failed to assign Storage Blob Data Contributor: HTTP $($assignmentResponse.StatusCode) $($assignmentResponse.Content)" }
    Write-Success 'Assigned Storage Blob Data Contributor (storage account scope)'
}
# Wait for Azure to publish the exact static website endpoint; never guess its zone number.
for ($endpointAttempt = 1; $endpointAttempt -le 12 -and -not $staticWebsiteHostname; $endpointAttempt++) {
    $saGetResponse = Invoke-AzRestMethod -Method GET -Path $saUri
    if ($saGetResponse.StatusCode -eq 200) {
        $saGetData = $saGetResponse.Content | ConvertFrom-Json
        $webEndpoint = $saGetData.properties.primaryEndpoints.web
        if ($webEndpoint) { $staticWebsiteHostname = ($webEndpoint -replace 'https?://', '').TrimEnd('/') }
    }
    if (-not $staticWebsiteHostname) { Start-Sleep -Seconds 5 }
}
if (-not $staticWebsiteHostname) { throw 'Azure did not publish the static website endpoint within one minute.' }
Write-Success "Static website URL: http://$staticWebsiteHostname"
# Set CRL URL based on whether custom hostname was provided
if ($CrlHostname) {
    Write-Info "CRL will be published to: $crlUrl"
    Write-Info "CNAME required: $CrlHostname -> $staticWebsiteHostname"
} else {
    $crlUrl = "http://$staticWebsiteHostname/$crlFileName"
    Write-Info "CRL URL: $crlUrl"
}

Write-StepHeader "Step $($stepNum): Root CA Certificate"
$stepNum++

$certName = $RootCertificateName

# Check if certificate exists
$certCheckUri = "https://$KeyVaultName.vault.azure.net/certificates/$certName`?api-version=7.5"
try {
    $token = Get-KeyVaultToken
    $headers = @{ Authorization = "Bearer $token" }
    $existingCert = Invoke-RestMethod -Uri $certCheckUri -Headers $headers -Method Get -ErrorAction Stop

    Write-Success "Certificate exists: $certName"
    Write-Info "Thumbprint: $($existingCert.x5t)"


    # Get existing certificate details
    $rootCertInfo = Get-KeyVaultCertificatePem -VaultName $KeyVaultName -CertificateName $certName

} catch {
    $certificateStatusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
    if ($certificateStatusCode -ne 404) { throw }
    if ($RenewCrlOnly) { throw "Root certificate '$certName' does not exist; -RenewCrlOnly never creates certificates." }
    Write-Host "  Creating root CA certificate..." -ForegroundColor Yellow
    Write-Info "Subject: CN=$CertificateCommonName, O=$OrganizationName"
    Write-Info "Key: RSA-HSM 4096-bit (non-exportable)"
    Write-Info "Validity: 10 years"

    $certPolicy = @{
        policy = @{
            key_props = @{
                exportable = $false
                kty = "RSA-HSM"
                key_size = 4096
                reuse_key = $false
            }
            secret_props = @{
                contentType = "application/x-pem-file"
            }
            x509_props = @{
                subject = "CN=$CertificateCommonName, O=$OrganizationName"
                # Root CA intentionally has no EKU; the GSA subordinate is constrained to serverAuth.
                key_usage = @(
                    "digitalSignature"
                    "keyCertSign"
                    "cRLSign"
                )
                validity_months = 120  # 10 years
                # GSA adds two CA tiers below this dedicated root. Omitting pathLen
                # is compatible with that hierarchy; the GSA subordinate is pathLen=1.
                basic_constraints = @{ ca = $true }
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
        if (-not $PSCmdlet.ShouldProcess("$KeyVaultName/$certName", 'Create RSA-HSM root CA certificate')) { throw 'Root CA creation was declined.' }
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

Assert-KeyVaultRootCertificate -CertificateInfo $rootCertInfo -ExpectedKeyType 'RSA-HSM'

# Generate and upload CRL
Write-StepHeader "Step $($stepNum): CRL Generation & Upload"
$stepNum++

try {
    # Persist the previous value publicly beside the CRL. The state is not trusted for
    # authorization; it only prevents CRL-number reuse if the local clock moves backwards.
    $previousCrlNumber = [System.Numerics.BigInteger]::Zero
    $crlStateFileName = 'gsa-tls-root-ca.crl-state.json'
    try {
        $stateBlobUri = "https://$StorageAccountName.blob.core.windows.net/`$web/$crlStateFileName"
        $stateHeaders = @{
            Authorization = "Bearer $(Get-StorageToken)"
            'x-ms-date' = [DateTime]::UtcNow.ToString('R')
            'x-ms-version' = '2023-11-03'
        }
        $previousState = Invoke-RestMethod -Uri $stateBlobUri -Headers $stateHeaders -Method GET -TimeoutSec 10
        if ($previousState.crlNumber) { $previousCrlNumber = [System.Numerics.BigInteger]::Parse([string]$previousState.crlNumber) }
    } catch {
        Write-Verbose 'No prior CRL state was available; starting from the current Unix time in milliseconds.'
    }
    $timeBasedCrlNumber = [System.Numerics.BigInteger]::new([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    $crlNumber = if ($timeBasedCrlNumber -gt $previousCrlNumber) { $timeBasedCrlNumber } else { $previousCrlNumber + 1 }

    # Generate empty CRL signed by Key Vault
    [byte[]]$crlBytes = New-CrlFromKeyVault `
        -IssuerCert $rootCertInfo.Certificate `
        -KeyVaultKeyId $rootCertInfo.KeyId `
        -CrlNumber $crlNumber `
        -NextUpdateDays 30

    # Upload CRL to storage account $web container
    Write-Host "  Uploading CRL to storage account..." -ForegroundColor Yellow

    $blobUri = "https://$StorageAccountName.blob.core.windows.net/`$web/$crlFileName"
    if (-not $PSCmdlet.ShouldProcess($blobUri, 'Upload signed CRL')) { throw 'CRL upload was declined.' }
    Set-AzureStorageBlob -StorageAccountName $StorageAccountName -ContainerName '$web' -BlobName $crlFileName -Content $crlBytes -ContentType 'application/pkix-crl'
    $stateJson = @{ crlNumber = $crlNumber.ToString(); thisUpdateUtc = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress
    Set-AzureStorageBlob -StorageAccountName $StorageAccountName -ContainerName '$web' -BlobName $crlStateFileName -Content ([Text.Encoding]::UTF8.GetBytes($stateJson)) -ContentType 'application/json'
    Write-Success "CRL uploaded to: http://$staticWebsiteHostname/$crlFileName"

    # Save CRL locally for verification
    $crlLocalPath = Join-Path $env:TEMP "gsa-tls-root-ca-$(Get-Date -Format 'yyyyMMdd-HHmmss').crl"
    [System.IO.File]::WriteAllBytes($crlLocalPath, $crlBytes)
    Write-Verbose "CRL saved locally: $crlLocalPath"
    Write-Info "Verify with: openssl crl -in '$crlLocalPath' -inform DER -text -noout"

    # Verify CRL is accessible via the public static website. If local DNS policy
    # intercepts web.core.windows.net, resolve through a public resolver and send
    # the original Host header directly to the Azure endpoint.
    Write-Host "  Verifying CRL is accessible via storage endpoint..." -ForegroundColor Gray
    $storageUrl = "http://$staticWebsiteHostname/$crlFileName"
    $verifyAttempts = 0
    $crlAccessible = $false
    while (-not $crlAccessible -and $verifyAttempts -lt 6) {
        $verifyAttempts++
        foreach ($resolver in @('1.1.1.1', '8.8.8.8')) {
            $publicIps = @(Resolve-DnsName -Name $staticWebsiteHostname -Type A -Server $resolver -DnsOnly -ErrorAction SilentlyContinue |
                Where-Object IPAddress | Select-Object -ExpandProperty IPAddress -Unique)
            foreach ($publicIp in $publicIps) {
                try {
                    $verifyResp = Invoke-WebRequest -Method HEAD -Uri "http://$publicIp/$crlFileName" -Headers @{ Host = $staticWebsiteHostname } -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                    $verifyType = [string]@($verifyResp.Headers['Content-Type'])[0]
                    $verifyLength = [int64]@($verifyResp.Headers['Content-Length'])[0]
                    if ($verifyResp.StatusCode -eq 200 -and $verifyType.Split(';')[0] -eq 'application/pkix-crl' -and $verifyLength -eq $crlBytes.Length) {
                        $crlAccessible = $true
                        Write-Success "CRL accessible through public DNS ($resolver -> $publicIp): $storageUrl ($verifyLength bytes)"
                        break
                    }
                } catch {
                    Write-Verbose "Public CRL verification via $resolver/$publicIp failed: $($_.Exception.Message)"
                }
            }
            if ($crlAccessible) { break }
        }
        if (-not $crlAccessible) {
            Write-Host "." -NoNewline -ForegroundColor Gray
            Start-Sleep -Seconds 5
        }
    }
    if (-not $crlAccessible) {
        throw "CRL was uploaded but is not accessible at $storageUrl. Refusing to continue with a certificate containing this CDP."
    }

} catch {
    throw "Failed to generate, upload, or verify the CRL: $($_.Exception.Message)"
}


# Validate the custom CRL hostname before issuing any certificate that embeds it.
$cnameResolved = $false
$httpVerified = $false

# Helper: resolve CNAME trying local DNS first, then public resolvers as fallback
function Resolve-CnameWithFallback {
    param([string]$Hostname)
    $resolvers = @($null, '1.1.1.1', '8.8.8.8')  # $null = local/default resolver
    foreach ($server in $resolvers) {
        try {
            $params = @{ Name = $Hostname; Type = 'CNAME'; DnsOnly = $true; ErrorAction = 'Stop' }
            if ($server) { $params['Server'] = $server }
            $result = Resolve-DnsName @params
            $target = ($result | Where-Object { $_.QueryType -eq 'CNAME' }).NameHost
            if ($target) {
                $source = if ($server) { $server } else { 'local' }
                return [PSCustomObject]@{ Target = $target; Resolver = $source }
            }
        } catch {
            $resolverName = if ($server) { $server } else { 'local' }
            Write-Verbose "CNAME lookup through $resolverName failed: $($_.Exception.Message)"
        }
    }
    return $null
}

if ($CrlHostname) {
    Write-StepHeader "Step $($stepNum): DNS CNAME Validation"
    $stepNum++

    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host "  │  DNS CNAME Configuration Required                            │" -ForegroundColor Yellow
    Write-Host "  │                                                              │" -ForegroundColor Yellow
    Write-Host "  │  Create the following CNAME record in your DNS provider:     │" -ForegroundColor Yellow
    Write-Host "  │                                                              │" -ForegroundColor Yellow
    Write-Host "  │    Name:   $($CrlHostname.PadRight(48)) │" -ForegroundColor Cyan
    Write-Host "  │    Type:   CNAME                                             │" -ForegroundColor Cyan
    Write-Host "  │    Value:  $($staticWebsiteHostname.PadRight(48)) │" -ForegroundColor Cyan
    Write-Host "  │                                                              │" -ForegroundColor Yellow
    Write-Host "  │  The script will wait and verify DNS resolution.             │" -ForegroundColor Yellow
    Write-Host "  └──────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    Write-Host ""

    # Check if CNAME already resolves (user may have pre-configured it)
    $dnsLookup = Resolve-CnameWithFallback -Hostname $CrlHostname
    if ($dnsLookup) {
        Write-Success "CNAME already configured: $CrlHostname -> $($dnsLookup.Target) (via $($dnsLookup.Resolver))"
        $cnameResolved = $true
        if ($dnsLookup.Target.TrimEnd('.') -ne $staticWebsiteHostname) {
            Write-Warning "CNAME target '$($dnsLookup.Target)' does not match expected '$staticWebsiteHostname'"
            Write-Info "The CRL may not be accessible via the custom hostname"
        }
    } else {
        Write-Info "CNAME not yet configured. Waiting for you to create the DNS record..."
    }

    if (-not $cnameResolved) {
        # Poll for CNAME resolution with user-friendly countdown
        $maxWaitMinutes = 10
        $pollIntervalSec = 15
        $maxPolls = ($maxWaitMinutes * 60) / $pollIntervalSec
        $pollCount = 0
        $startTime = Get-Date

        Write-Host "  Checking DNS every ${pollIntervalSec}s (timeout: ${maxWaitMinutes} min)..." -ForegroundColor Gray
        Write-Host "  Press Ctrl+C to skip DNS validation and continue." -ForegroundColor Gray
        Write-Host ""

        while (-not $cnameResolved -and $pollCount -lt $maxPolls) {
            $pollCount++
            $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds)
            Write-Host "`r  ⏳ Waiting for DNS... (${elapsed}s elapsed) " -NoNewline -ForegroundColor Gray

            $dnsLookup = Resolve-CnameWithFallback -Hostname $CrlHostname
            if ($dnsLookup) {
                Write-Host ""
                Write-Success "CNAME resolved: $CrlHostname -> $($dnsLookup.Target) (via $($dnsLookup.Resolver))"
                $cnameResolved = $true

                if ($dnsLookup.Target.TrimEnd('.') -ne $staticWebsiteHostname) {
                    Write-Warning "CNAME target '$($dnsLookup.Target)' does not match expected '$staticWebsiteHostname'"
                }
            }

            # Always sleep between polls (unless CNAME just resolved)
            if (-not $cnameResolved) {
                Start-Sleep -Seconds $pollIntervalSec
            }
        }

        if (-not $cnameResolved) {
            Write-Host ""
            Write-Warning "DNS validation timed out after $maxWaitMinutes minutes"
            Write-Info "You can verify manually later: nslookup $CrlHostname"
        }
    }

    # If CNAME resolved, register the custom domain on the storage account then verify HTTP
    if ($cnameResolved) {
        # Register custom domain so Azure Storage accepts requests with the custom Host header
        Write-Host "  Registering custom domain on storage account..." -ForegroundColor Yellow
        try {
            $customDomainBody = @{
                properties = @{
                    customDomain = @{
                        name = $CrlHostname
                        useSubDomainName = $false
                    }
                }
            } | ConvertTo-Json -Depth 4

            if (-not $PSCmdlet.ShouldProcess($StorageAccountName, "Register CRL custom domain '$CrlHostname'")) { throw 'Custom-domain registration was declined.' }
            $regResult = Invoke-AzRestMethod -Method PATCH `
                -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName`?api-version=2023-05-01" `
                -Payload $customDomainBody

            if ($regResult.StatusCode -in 200, 202) {
                Write-Success "Custom domain registered: $CrlHostname"
            } else {
                $regError = ($regResult.Content | ConvertFrom-Json -ErrorAction SilentlyContinue).error.message
                Write-Warning "Custom domain registration returned $($regResult.StatusCode): $regError"
                Write-Info "Register it manually in the Azure portal: Storage account > Networking > Custom domain."
            }
        } catch {
            Write-Warning "Failed to register custom domain: $_"
            Write-Info "Register it manually in the Azure portal: Storage account > Networking > Custom domain."
        }

        # Brief pause for registration to take effect
        Start-Sleep -Seconds 3

        # Verify CRL is accessible via custom hostname
        Write-Host "  Verifying CRL is accessible via custom hostname..." -ForegroundColor Gray
        $customUrl = "http://$CrlHostname/$crlFileName"
        $httpAttempts = 0

        # Allow a few retries since DNS propagation and HTTP routing may lag
        while (-not $httpVerified -and $httpAttempts -lt 6) {
            $httpAttempts++
            try {
                $httpResp = Invoke-WebRequest -Uri $customUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                if ($httpResp.StatusCode -eq 200) {
                    $httpVerified = $true
                    Write-Success "CRL verified at: $customUrl ($($httpResp.Content.Length) bytes)"

                    # Validate content-type
                    $contentType = $httpResp.Headers['Content-Type']
                    if ($contentType -eq 'application/pkix-crl') {
                        Write-Success "Content-Type: application/pkix-crl"
                    } else {
                        Write-Warning "Unexpected Content-Type: $contentType (expected application/pkix-crl)"
                    }
                }
            } catch {
                if ($httpAttempts -lt 6) {
                    Write-Host "." -NoNewline -ForegroundColor Gray
                    Start-Sleep -Seconds 5
                }
            }
        }

        if (-not $httpVerified) {
            Write-Warning "CRL not accessible at $customUrl"
            Write-Info "DNS resolved but HTTP request failed — this may resolve with time"
            Write-Info "The CRL is accessible directly at: http://$staticWebsiteHostname/$crlFileName"
        }
    } else {
        Write-Info "Skipping HTTP verification (CNAME not resolved)"
        Write-Info "The CRL is accessible directly at: http://$staticWebsiteHostname/$crlFileName"
    }

    if (-not ($cnameResolved -and $httpVerified)) {
        throw "Custom CRL hostname '$CrlHostname' is not fully operational. Refusing to issue a certificate with an unreachable CDP."
    }
}


if ($RenewCrlOnly) {
    Write-Success 'CRL renewal completed; GSA certificate and Intune policies were not modified.'
    return [PSCustomObject]@{
        Status = 'Success'
        Operation = 'RenewCrlOnly'
        KeyVaultName = $KeyVaultName
        RootCAThumbprint = $rootCertInfo.Thumbprint
        CrlUrl = $crlUrl
        CrlNumber = $crlNumber.ToString()
    }
}
Write-StepHeader "Step $($stepNum): Global Secure Access Certificate"
$stepNum++

$gsaCertId = $null
$gsaCertName = $null
$gsaStatus = $null
$signedCertResult = $null
$csrPem = $null
$skipCertificateUpload = $false

$gsaHeaders = @{ Prefer = 'include-unknown-enum-members' }
$existingGsaResponse = Invoke-MgGraphRequest -Method GET -Uri '/beta/networkAccess/tls/externalCertificateAuthorityCertificates' -Headers $gsaHeaders
$existingGsaCertificates = @($existingGsaResponse.value)
$activeCertificates = @($existingGsaCertificates | Where-Object { $_.status -in @('active', 'enabled') })
if ($activeCertificates.Count -gt 1) { throw 'GSA returned more than one active TLS certificate; resolve this service state before continuing.' }

if ($activeCertificates.Count -eq 1 -and -not $RotateGsaCertificate) {
    $activeCertificate = $activeCertificates[0]
    $gsaCertId = $activeCertificate.id
    $gsaCertName = $activeCertificate.name
    $gsaStatus = $activeCertificate.status
    $skipCertificateUpload = $true
    Write-Info "Preserving active GSA certificate '$gsaCertName'. Use -RotateGsaCertificate to stage the Key Vault-backed replacement."
}

if (-not $skipCertificateUpload) {
    $pendingCertificates = @($existingGsaCertificates | Where-Object {
        $_.name -like 'GSAKV*' -and $_.status -in @('csrGenerated', 'enrolling', 'disabled', 'unknownFutureValue')
    })
    if ($pendingCertificates.Count -gt 1) {
        throw 'Multiple pending GSAKV certificates exist. Resolve them in the portal before continuing.'
    }

    if ($pendingCertificates.Count -eq 1) {
        $pending = Invoke-MgGraphRequest -Method GET -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($pendingCertificates[0].id)?`$select=id,name,status,certificateSigningRequest,certificate,chain" -Headers $gsaHeaders
        if ($pending.certificate -or $pending.chain -or $pending.status -in @('enrolling', 'disabled') -or
            ($pending.status -eq 'unknownFutureValue' -and -not $pending.certificateSigningRequest)) {
            $gsaCertId = $pending.id
            $gsaCertName = $pending.name
            $gsaStatus = $pending.status
            $skipCertificateUpload = $true
            Write-Info "Certificate '$gsaCertName' is already uploaded with status '$gsaStatus'; continuing with activation."
        } elseif ($pending.certificateSigningRequest) {
            $gsaCertId = $pending.id
            $gsaCertName = $pending.name
            $csrPem = $pending.certificateSigningRequest
            Write-Info "Resuming pending CSR: $gsaCertName"
        } elseif ($Force -and $PSCmdlet.ShouldContinue("Delete unusable pending GSA certificate '$($pending.name)'?", 'Pending certificate replacement')) {
            if ($PSCmdlet.ShouldProcess($pending.name, 'Delete pending GSA certificate')) {
                Invoke-MgGraphRequest -Method DELETE -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$($pending.id)" | Out-Null
                Start-Sleep -Seconds 5
            }
        } else {
            throw "Pending certificate '$($pending.name)' cannot be resumed. Review it in the portal or rerun with -Force to replace only this pending certificate."
        }
    }

    if (-not $skipCertificateUpload -and -not $csrPem) {
        $gsaCertName = 'GSAKV' + -join ((48..57) + (97..102) | Get-Random -Count 7 | ForEach-Object { [char]$_ })
        $csrBody = @{
            '@odata.type' = '#microsoft.graph.networkaccess.externalCertificateAuthorityCertificate'
            name = $gsaCertName
            commonName = $CertificateCommonName
            organizationName = $OrganizationName
        } | ConvertTo-Json
        if (-not $PSCmdlet.ShouldProcess($gsaCertName, 'Create GSA certificate signing request')) { throw 'GSA CSR creation was declined.' }
        $csrResponse = Invoke-MgGraphRequest -Method POST -Uri '/beta/networkAccess/tls/externalCertificateAuthorityCertificates' -Body $csrBody -ContentType 'application/json'
        $gsaCertId = $csrResponse.id
        $csrPem = $csrResponse.certificateSigningRequest
        if (-not $csrPem) { throw 'GSA created the certificate object but did not return a CSR.' }
        Write-Success "CSR created: $gsaCertName ($gsaCertId)"
    }

    if (-not $skipCertificateUpload) {
        $csrPath = Join-Path $env:TEMP "gsa-tls-csr-$(Get-Date -Format 'yyyyMMdd-HHmmss').csr"
        $csrPem | Out-File -FilePath $csrPath -Encoding ASCII
        Write-Verbose "CSR saved to: $csrPath"

        $signedCertResult = New-SignedCertificateFromCSR -CsrPem $csrPem -IssuerCert $rootCertInfo.Certificate -KeyVaultKeyId $rootCertInfo.KeyId -CrlDistributionPointUrl $crlUrl
        $chainPem = $rootCertInfo.Pem

        $testChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        try {
            [void]$testChain.ChainPolicy.ExtraStore.Add($rootCertInfo.Certificate)
            $testChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $testChain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
            if (-not $testChain.Build($signedCertResult.Certificate)) {
                $chainErrors = ($testChain.ChainStatus | ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }) -join '; '
                throw "Signed GSA certificate chain validation failed: $chainErrors"
            }
        } finally {
            $testChain.Dispose()
        }

        $uploadBody = @{ certificate = $signedCertResult.Pem; chain = $chainPem }
        if (-not $PSCmdlet.ShouldProcess($gsaCertName, 'Upload signed certificate and chain to GSA')) { throw 'GSA certificate upload was declined.' }
        Invoke-MgGraphRequest -Method PATCH -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$gsaCertId" -Body ($uploadBody | ConvertTo-Json -Depth 4) -ContentType 'application/json' | Out-Null
        for ($statusAttempt = 1; $statusAttempt -le 12; $statusAttempt++) {
            Start-Sleep -Seconds 5
            $certificateState = Invoke-MgGraphRequest -Method GET -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$gsaCertId" -Headers $gsaHeaders
            $gsaStatus = $certificateState.status
            if ($gsaStatus -ne 'unknownFutureValue') { break }
            Write-Verbose "GSA is still reporting the transitional status unknownFutureValue ($statusAttempt/12)."
        }
        if ($gsaStatus -notin @('enrolling', 'disabled', 'active', 'enabled', 'unknownFutureValue')) {
            throw "Unexpected GSA certificate status after upload: '$gsaStatus'"
        }
        Write-Success "Certificate uploaded with status '$gsaStatus'."
    }
}

# The portal enables an uploaded certificate with this beta Graph PATCH. Although
# the resource metadata currently describes status as read-only, this is the
# service-supported transition used by the first-party portal.
if ($gsaCertId -and $gsaStatus -notin @('active', 'enabled')) {
    if (-not $PSCmdlet.ShouldProcess($gsaCertName, 'Enable GSA TLS certificate')) { throw 'GSA certificate activation was declined.' }
    $enableBody = @{ status = 'enabled' } | ConvertTo-Json -Compress
    Invoke-MgGraphRequest -Method PATCH -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$gsaCertId" -Body $enableBody -ContentType 'application/json' | Out-Null

    for ($statusAttempt = 1; $statusAttempt -le 60; $statusAttempt++) {
        Start-Sleep -Seconds 5
        $certificateState = Invoke-MgGraphRequest -Method GET -Uri "/beta/networkAccess/tls/externalCertificateAuthorityCertificates/$gsaCertId" -Headers $gsaHeaders
        $gsaStatus = $certificateState.status
        if ($gsaStatus -in @('active', 'enabled')) { break }
        if ($gsaStatus -notin @('enrolling', 'disabled', 'unknownFutureValue')) {
            throw "Unexpected GSA certificate status during activation: '$gsaStatus'"
        }
        Write-Verbose "Waiting for GSA certificate activation; current status '$gsaStatus' ($statusAttempt/60)."
    }
    if ($gsaStatus -notin @('active', 'enabled')) {
        throw "GSA accepted the enable request but certificate '$gsaCertName' did not become active within five minutes (status '$gsaStatus')."
    }
    Write-Success "GSA certificate enabled: $gsaCertName"
}
Write-StepHeader "Step $($stepNum): Intune Trusted Root Policies"
$stepNum++

# Get root certificate as base64 (without PEM headers)
$rootCertBase64 = [Convert]::ToBase64String($rootCertInfo.Certificate.RawData)

$platforms = $IntunePlatforms
$intunePolicyIds = @{}

foreach ($platform in $platforms) {
    $policyId = New-IntuneTrustedRootCertPolicy -Platform $platform -RootCertBase64 $rootCertBase64 -AssignToAllDevices $AssignIntunePolicies.IsPresent -WhatIf:$WhatIfPreference

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
Write-Host $(if ($gsaStatus -in @('active', 'enabled')) { "║              ✓ Setup Complete!                                 ║" } else { "║              ✓ Setup Staged - Activation Required              ║" }) -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

$result = [PSCustomObject]@{
    Status = if ($gsaStatus -in @('active', 'enabled')) { 'Success' } else { 'PendingActivation' }
    Timestamp = (Get-Date)

    # Key Vault
    KeyVaultName = $KeyVaultName
    KeyVaultUri = $vaultUri
    KeyVaultSKU = $KeyVaultSKU
    KeyVaultResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName"
    DiagnosticLoggingEnabled = [bool]$LogAnalyticsWorkspaceId
    DefenderEnabled = $EnableDefender.IsPresent

    # Certificates
    RootCACertificateName = $certName
    RootCAThumbprint = $rootCertInfo.Thumbprint
    RootCAExpiration = $rootCertInfo.Expiration
    IntermediateCertThumbprint = if ($signedCertResult) { $signedCertResult.Thumbprint } else { $null }

    # CRL
    CrlUrl = $crlUrl
    CrlHostname = $CrlHostname
    StorageAccountName = $StorageAccountName
    StaticWebsiteHostname = $staticWebsiteHostname

    # GSA
    GSACertificateId = $gsaCertId
    GSACertificateName = $gsaCertName
    GSAStatus = $gsaStatus
    GSAPortalLink = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GlobalSecureAccessMenuBlade/~/TLSInspection"

    # Intune
    IntunePolicyIds = $intunePolicyIds
    IntunePoliciesAssigned = $AssignIntunePolicies.IsPresent

    # Next Steps
    NextSteps = @(
        "1. Confirm CRL availability: $crlUrl"
        if (-not $AssignIntunePolicies) {
            "2. Assign the Intune trusted-root policies to pilot device groups and confirm installation"
        } else {
            "2. Confirm the trusted root reached pilot devices"
        }
        if ($gsaStatus -notin @('active', 'enabled')) {
            "3. After trust deployment, enable '$gsaCertName' in the GSA TLS inspection settings portal"
        } else {
            "3. Verify active GSA certificate '$gsaCertName' in the portal"
        }
        "4. Test TLS inspection with a pilot security profile before broad assignment"
        "5. Schedule -RenewCrlOnly before the 30-day CRL nextUpdate value"
        "6. Plan root CA rotation before $($rootCertInfo.Expiration.ToString('yyyy-MM-dd'))"    )
}

Write-Host "`n📋 Summary:" -ForegroundColor Cyan
Write-Host "  Key Vault:        $KeyVaultName ($KeyVaultSKU)" -ForegroundColor White
Write-Host "  Root CA:          $($rootCertInfo.Thumbprint)" -ForegroundColor White
Write-Host "  Expires:          $($rootCertInfo.Expiration.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "  GSA Certificate:  $gsaCertName ($gsaStatus)" -ForegroundColor White
Write-Host "  Intune Policies:  $($intunePolicyIds.Count) created" -ForegroundColor White
Write-Host "  CRL URL:          $crlUrl" -ForegroundColor White
Write-Host "  Storage Account:  $StorageAccountName" -ForegroundColor White

Write-Host "`n🔗 Quick Links:" -ForegroundColor Cyan
Write-Host "  GSA TLS Settings: $($result.GSAPortalLink)" -ForegroundColor Blue
Write-Host "  Key Vault:        https://portal.azure.com/#@/resource$($result.KeyVaultResourceId)" -ForegroundColor Blue
Write-Host "  Storage Account:  https://portal.azure.com/#@/resource/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName" -ForegroundColor Blue

if ($CrlHostname) {
    if ($cnameResolved -and $httpVerified) {
        Write-Host "`n✅ DNS CNAME Validated:" -ForegroundColor Green
        Write-Host "  $CrlHostname  ->  $staticWebsiteHostname" -ForegroundColor Cyan
        Write-Host "  CRL accessible at: http://$CrlHostname/$crlFileName" -ForegroundColor Cyan
    } elseif ($cnameResolved) {
        Write-Host "`n⚠️  DNS CNAME Resolved (HTTP verification pending):" -ForegroundColor Yellow
        Write-Host "  $CrlHostname  ->  $staticWebsiteHostname" -ForegroundColor Cyan
        Write-Host "  Verify CRL access: curl http://$CrlHostname/$crlFileName" -ForegroundColor Cyan
        Write-Host "  Direct fallback:   http://$staticWebsiteHostname/$crlFileName" -ForegroundColor Cyan
    } else {
        Write-Host "`n⚠️  DNS Configuration Still Required:" -ForegroundColor Yellow
        Write-Host "  Create a CNAME record in your DNS:" -ForegroundColor White
        Write-Host "    $CrlHostname  CNAME  $staticWebsiteHostname" -ForegroundColor Cyan
        Write-Host "  Then verify the CRL is accessible:" -ForegroundColor White
        Write-Host "    curl http://$CrlHostname/$crlFileName" -ForegroundColor Cyan
        Write-Host "  Until DNS is configured, the CRL is available at:" -ForegroundColor White
        Write-Host "    http://$staticWebsiteHostname/$crlFileName" -ForegroundColor Cyan
    }
}

Write-Host "`n📌 Next Steps:" -ForegroundColor Cyan
$result.NextSteps | ForEach-Object { Write-Host "  $_" -ForegroundColor White }

Write-Host ""

# Return result object for pipeline/automation
return $result

#endregion
