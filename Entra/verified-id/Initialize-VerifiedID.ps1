#Requires -Version 7.0
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
    Performs advanced setup of Microsoft Entra Verified ID with a customer-managed Key Vault
    and DID document hosted on Azure Static Web Apps.

.DESCRIPTION
    This script automates the complete advanced setup for Microsoft Entra Verified ID:

    1.  Creates Azure Key Vault with Vault Access Policy permission model (required by Verified ID)
    2.  Uses Microsoft Graph with an Az-acquired token to create a temporary app registration
    3.  Grants the temporary app the delegated Verified ID permission and signs in via browser auth code
    4.  Onboards the Verified ID service (creates Entra enterprise applications)
    5.  Assigns Key Vault access policies to the current admin and Verified ID service principals
    6.  Creates the Verified ID authority using the did:web DID method
    7.  Generates the DID document and well-known DID configuration
    8.  Creates an Azure Static Web App
    9.  Deploys DID documents with StaticSitesClient using a deployment token
    10. Configures the Static Web App custom domain and validates public TLS
    11. Guides DNS completion, then validates the well-known DID configuration
    12. Deletes the temporary app registration, service principal, and delegated permission grant during cleanup

    Prerequisites:
    - Authentication Policy Administrator role in Microsoft Entra ID
    - Owner or Contributor role on Azure subscription
    - Ability to create app registrations and grant delegated permission grants
    - Az.Accounts module installed

    Advanced setup vs Quick setup:
    - Advanced uses a customer-managed Key Vault - you control the signing keys
    - Supports any custom FQDN (not limited to an Entra-verified domain)
    - No credential validity limits or rate limiting constraints
    - Supports multiple authorities per tenant

.PARAMETER DisplayName
    Organization display name used as the Verified ID authority name.
    Example: "Contoso Corporation"

.PARAMETER FQDN
    Fully qualified domain name for the DID:web identifier.
    Recommended format: https://<subdomain>.<domain>.<tld>
    Allowed format: https://<domain>.<tld>
    Example: https://did.contoso.com

.PARAMETER SubscriptionId
    Azure subscription ID. Uses current Az context if not specified.

.PARAMETER ResourceGroupName
    Resource group name for all Verified ID Azure resources.
    Default: rg-verifiedid

.PARAMETER KeyVaultName
    Azure Key Vault name. Must be globally unique, 3-24 chars.
    Default: kv-vid-[random]

.PARAMETER StaticWebAppName
    Azure Static Web App name. Must be globally unique in the resource group.
    Default: swa-verifiedid-[random]

.PARAMETER Location
    Azure region for all resources. Default: westus2

.PARAMETER KeyVaultSku
    Key Vault SKU. Valid values: standard, premium. Default: premium

.PARAMETER VerifiedIdAccessToken
    Optional override token for the Microsoft Entra Verified ID Admin API.
    If omitted, the script creates a temporary public-client app registration, grants the required delegated permission,
    and acquires the token interactively using browser auth code with PKCE.

.PARAMETER SkipDnsValidationLoop
    Skips the interactive DNS/HTTPS confirmation loop after document upload.
    Use this only for unattended runs when you plan to complete domain binding and validation later.

.EXAMPLE
    .\Initialize-VerifiedID.ps1 -DisplayName "Contoso Corporation" -FQDN "https://did.contoso.com"

.EXAMPLE
    .\Initialize-VerifiedID.ps1 -DisplayName "Contoso" -FQDN "https://did.contoso.com" `
        -ResourceGroupName "rg-vid-prod" -Location "westus2" -KeyVaultSku "premium"


.NOTES
    Author: Nathan McNulty
    Date: March 2026

    Required Entra ID role: Authentication Policy Administrator
    Required Azure role: Owner or Contributor on target subscription

    Additional Entra requirements for automatic token acquisition:
    - Graph delegated permissions sufficient to create applications and delegated permission grants
    - An eligible Entra role such as Cloud Application Administrator, Application Administrator, or Global Administrator

    Key Vault permission model:
    Verified ID REQUIRES the Vault Access Policy permission model, NOT Azure RBAC.
    This is enforced during authority creation - the API will fail if RBAC is enabled.

    TLS note:
    The script accepts either Azure-managed TLS from Static Web Apps or a manually attached
    certificate that already matches the hostname, including a one-label wildcard such as *.contoso.com.

    References:
    - https://learn.microsoft.com/en-us/entra/verified-id/verifiable-credentials-configure-tenant
    - https://learn.microsoft.com/en-us/entra/verified-id/admin-api
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,

    [Parameter(Mandatory = $true)]
    [string]$FQDN,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-verifiedid",

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $false)]
    [string]$StaticWebAppName,

    [Parameter(Mandatory = $false)]
    [string]$Location = "westus2",

    [Parameter(Mandatory = $false)]
    [ValidateSet("standard", "premium")]
    [string]$KeyVaultSku = "premium",

    [Parameter(Mandatory = $false)]
    [string]$VerifiedIdAccessToken

    ,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDnsValidationLoop
)

$ErrorActionPreference = "Stop"

$verifiedIdAdminAppId = "6a8b4b39-c021-437c-b060-5a14a3fd65f3"
$verifiedIdAdminDelegatedScope = "full_access"

#region Helper Functions

function Write-StepHeader {
    param([string]$Message)
    Write-Host "`n==================================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
}

function Request-AdditionalPollingWindow {
    param(
        [string]$PhaseDescription,
        [int]$WindowSeconds = 60
    )

    Write-Host ""
    Write-Host "  $PhaseDescription is still pending." -ForegroundColor Yellow
    Write-Host "  Press Enter to keep checking for another $WindowSeconds seconds." -ForegroundColor White
    Write-Host "  Type 'skip' to finish now and validate later." -ForegroundColor White
    $choice = Read-Host "  Continue"

    return -not ($choice -match '^(skip|s)$')
}

function Write-ActivityTick {
    param([switch]$EndLine)

    if ($EndLine) {
        Write-Host ""
        return
    }

    Write-Host "." -NoNewline -ForegroundColor DarkGray
}

function Write-ObservedState {
    param(
        [hashtable]$StateBag,
        [string]$Key,
        [string]$Message,
        [switch]$Warning
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        return
    }

    if ($StateBag.ContainsKey($Key) -and $StateBag[$Key] -eq $Message) {
        return
    }

    $StateBag[$Key] = $Message
    Write-ActivityTick -EndLine

    if ($Warning) {
        Write-Warning $Message
    } else {
        Write-Info $Message
    }
}

function Invoke-InteractivePollingLoop {
    param(
        [string]$PhaseDescription,
        [string]$WindowMessage,
        [int]$IntervalSeconds,
        [int]$InitialWindowAttempts,
        [int]$RepeatWindowAttempts,
        [scriptblock]$PollScript
    )

    $continuePolling = $true
    $useInitialWindow = $true
    $lastResult = $null

    while ($continuePolling) {
        $windowAttempts = if ($useInitialWindow) { $InitialWindowAttempts } else { $RepeatWindowAttempts }

        if ($WindowMessage) {
            Write-Host ""
            Write-Host "  $WindowMessage" -ForegroundColor Gray
        }

        for ($attempt = 1; $attempt -le $windowAttempts; $attempt++) {
            $lastResult = & $PollScript $attempt $windowAttempts
            if ($lastResult -and $lastResult.Completed) {
                Write-ActivityTick -EndLine
                return $lastResult
            }

            if ($attempt -lt $windowAttempts) {
                Write-ActivityTick
                Start-Sleep -Seconds $IntervalSeconds
            }
        }

        Write-ActivityTick -EndLine
        $continuePolling = Request-AdditionalPollingWindow -PhaseDescription $PhaseDescription -WindowSeconds ($RepeatWindowAttempts * $IntervalSeconds)
        $useInitialWindow = $false
    }

    return [pscustomobject]@{
        Completed  = $false
        LastResult = $lastResult
    }
}

function Write-Success {
    param([string]$Message)
    Write-Host "  ✓ $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "    $Message" -ForegroundColor Gray
}

function ConvertTo-PlainText {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [securestring]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    return [string]$Value
}

function Get-AzBearerToken {
    param(
        [string]$TenantId,
        [string]$ResourceUrl,
        [string]$ResourceTypeName
    )

    $tokenResponse = if ($ResourceTypeName) {
        Get-AzAccessToken -TenantId $TenantId -ResourceTypeName $ResourceTypeName -WarningAction SilentlyContinue
    } else {
        Get-AzAccessToken -TenantId $TenantId -ResourceUrl $ResourceUrl -WarningAction SilentlyContinue
    }

    return ConvertTo-PlainText -Value $tokenResponse.Token
}

function Invoke-AzRestMethodWithRetry {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$Payload,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 5
    )

    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $params = @{ Method = $Method; Uri = $Uri }
            if ($Payload) { $params.Payload = $Payload }

            $result = Invoke-AzRestMethod @params

            if ($result.StatusCode -ge 200 -and $result.StatusCode -lt 300) {
                return $result
            }

            if ($result.StatusCode -in @(429, 500, 502, 503, 504) -and $attempt -lt $MaxRetries) {
                Write-Warning "Request failed HTTP $($result.StatusCode) (attempt $attempt/$MaxRetries), retrying in $RetryDelaySeconds seconds..."
                Start-Sleep -Seconds $RetryDelaySeconds
                continue
            }

            throw "HTTP $($result.StatusCode): $($result.Content)"
        } catch {
            $statusCode = Get-HttpStatusCodeFromException -ErrorRecord $_
            if ($statusCode -in @(429, 500, 502, 503, 504) -and $attempt -lt $MaxRetries) {
                Write-Warning "Request failed (attempt $attempt/$MaxRetries): $($_.Exception.Message)"
                Start-Sleep -Seconds $RetryDelaySeconds
                continue
            }

            throw
        }
    }
}

function Invoke-VerifiedIdApi {
    param(
        [string]$Method,
        [string]$Path,
        [hashtable]$Body,
        [string]$AccessToken
    )

    $uri = "https://verifiedid.did.msidentity.com$Path"
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }

    $params = @{ Method = $Method; Uri = $uri; Headers = $headers }
    if ($Body) { $params.Body = ($Body | ConvertTo-Json -Depth 10) }

    $attempt = 0
    $maxRetries = 3
    while ($attempt -lt $maxRetries) {
        $attempt++
        try {
            return Invoke-RestMethod @params -ErrorAction Stop
        } catch {
            $statusCode = Get-HttpStatusCodeFromException -ErrorRecord $_
            if ($statusCode -in @(429, 500, 502, 503, 504) -and $attempt -lt $maxRetries) {
                Write-Warning "VID API call failed $statusCode (attempt $attempt/$maxRetries), retrying..."
                Start-Sleep -Seconds 5
            } else {
                $errDetail = $_.Exception.Message
                try {
                    $errBody = $_.ErrorDetails.Message | ConvertFrom-Json
                    $errDetail = "$($errBody.error.code): $($errBody.error.message)"
                } catch {
                    Write-Verbose "Verified ID API returned a non-JSON error body."
                }
                throw "Verified ID API error ($Method $Path): $errDetail"
            }
        }
    }
}

function Wait-VerifiedIdAuthorityReady {
    param(
        [string]$AuthorityId,
        [string]$AccessToken,
        [int]$MaxAttempts = 12,
        [int]$DelaySeconds = 5
    )

    Write-Host "  Waiting for Verified ID authority availability" -NoNewline -ForegroundColor Gray

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Start-Sleep -Seconds $DelaySeconds
        Write-Host "." -NoNewline -ForegroundColor Gray

        try {
            $authorities = Invoke-VerifiedIdApi -Method "GET" -Path "/v1.0/verifiableCredentials/authorities" -AccessToken $AccessToken
            $authority = $authorities.value | Where-Object { $_.id -eq $AuthorityId } | Select-Object -First 1
            if ($authority) {
                Write-Host " ✓" -ForegroundColor Green
                return $authority
            }
        } catch {
            Write-Verbose "Authority readiness check failed: $($_.Exception.Message)"
        }
    }

    Write-Host " x" -ForegroundColor Red
    throw "Verified ID authority '$AuthorityId' was not visible from the API within the expected time."
}

function Get-StaticSitesClientPlatformId {
    if ($IsWindows) { return "win-x64" }
    if ($IsLinux)   { return "linux-x64" }
    if ($IsMacOS)   { return "osx-x64" }

    throw "StaticSitesClient download is not supported on this platform."
}

function Get-StaticSitesClientBinary {
    param([string]$CacheRoot = (Join-Path (Join-Path $HOME ".verifiedid-tools") "StaticSitesClient"))

    $platform = Get-StaticSitesClientPlatformId
    $metadata = Invoke-RestMethod -Method GET -Uri "https://aka.ms/swalocaldeploy" -ErrorAction Stop
    $release  = @($metadata | Where-Object { $_.version -eq "stable" })[0]
    if (-not $release) {
        throw "Could not locate the stable StaticSitesClient release metadata."
    }

    $platformFile = $release.files.$platform
    if (-not $platformFile -or -not $platformFile.url -or -not $platformFile.sha) {
        throw "StaticSitesClient metadata did not include a download for platform '$platform'."
    }

    $fileName = Split-Path -Path $platformFile.url -Leaf
    $buildDir = Join-Path $CacheRoot $release.buildId
    $binaryPath = Join-Path $buildDir $fileName

    $downloadRequired = -not (Test-Path $binaryPath)
    if (-not $downloadRequired) {
        $currentHash = (Get-FileHash -Path $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($currentHash -ne $platformFile.sha.ToLowerInvariant()) {
            $downloadRequired = $true
        }
    }

    if ($downloadRequired) {
        New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
        Write-Host "  Downloading StaticSitesClient ($platform)..." -ForegroundColor Gray
        Invoke-WebRequest -Uri $platformFile.url -OutFile $binaryPath -ErrorAction Stop

        $downloadedHash = (Get-FileHash -Path $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($downloadedHash -ne $platformFile.sha.ToLowerInvariant()) {
            Remove-Item -Path $binaryPath -Force -ErrorAction SilentlyContinue
            throw "StaticSitesClient checksum validation failed."
        }

        if (-not $IsWindows) {
            & chmod +x $binaryPath
        }
    }

    return [pscustomobject]@{
        BinaryPath = $binaryPath
        BuildId    = $release.buildId
        Platform   = $platform
    }
}

function New-StaticWebAppContent {
    param(
        [string]$RootPath,
        [string]$DidDocumentJson,
        [string]$DidConfigurationJson
    )

    New-Item -ItemType Directory -Force -Path $RootPath | Out-Null
    $wellKnownPath = Join-Path $RootPath ".well-known"
    New-Item -ItemType Directory -Force -Path $wellKnownPath | Out-Null

    Set-Content -Path (Join-Path $wellKnownPath "did.json") -Value $DidDocumentJson -Encoding UTF8
    Set-Content -Path (Join-Path $wellKnownPath "did-configuration.json") -Value $DidConfigurationJson -Encoding UTF8
    Set-Content -Path (Join-Path $RootPath "index.html") -Value "<!doctype html><html><body><p>Verified ID well-known endpoints only.</p></body></html>" -Encoding UTF8
    Set-Content -Path (Join-Path $RootPath "404.html") -Value "Not found" -Encoding UTF8
}

function Invoke-StaticSitesClientDeploy {
    param(
        [string]$BinaryPath,
        [string]$AppLocation,
        [string]$DeploymentToken
    )

    $previousEnv = @{}
    $deployEnv = @{
        DEPLOYMENT_ACTION   = "upload"
        DEPLOYMENT_PROVIDER = "VerifiedIdSetup"
        SKIP_APP_BUILD      = "true"
        SKIP_API_BUILD      = "true"
        DEPLOYMENT_TOKEN    = $DeploymentToken
        APP_LOCATION        = (Resolve-Path -Path $AppLocation).Path
        VERBOSE             = "false"
    }

    foreach ($key in $deployEnv.Keys) {
        $previousEnv[$key] = [Environment]::GetEnvironmentVariable($key, "Process")
        [Environment]::SetEnvironmentVariable($key, $deployEnv[$key], "Process")
    }

    try {
        $output = & $BinaryPath 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw "StaticSitesClient exited with code $LASTEXITCODE. Output: $output"
        }

        return $output.Trim()
    } finally {
        foreach ($key in $deployEnv.Keys) {
            [Environment]::SetEnvironmentVariable($key, $previousEnv[$key], "Process")
        }
    }
}

function Get-StaticWebAppCustomDomain {
    param([string]$CustomDomainUri)

    try {
        return ((Invoke-AzRestMethod -Method GET -Uri $CustomDomainUri).Content | ConvertFrom-Json)
    } catch {
        if (Test-HttpNotFound -ErrorRecord $_) {
            return $null
        }

        throw
    }
}

function Get-StaticWebAppCustomDomainState {
    param([string]$CustomDomainUri)

    $customDomain = Get-StaticWebAppCustomDomain -CustomDomainUri $CustomDomainUri
    $status = $null
    $validationToken = $null
    $errorMessage = $null

    if ($customDomain) {
        $status = $customDomain.properties.status
        $validationToken = $customDomain.properties.validationToken
        $errorMessage = $customDomain.properties.errorMessage
    }

    [pscustomobject]@{
        CustomDomain    = $customDomain
        Status          = $status
        ValidationToken = $validationToken
        ErrorMessage    = $errorMessage
    }
}

function Request-StaticWebAppCustomDomainValidation {
    param(
        [string]$CustomDomainUri,
        [string]$CustomDomainValidateUri,
        [string]$CustomDomainBody
    )

    try {
        Invoke-AzRestMethodWithRetry -Method POST -Uri $CustomDomainValidateUri -Payload $CustomDomainBody | Out-Null
    } catch {
        $message = $_.Exception.Message
        if ($message -notmatch "CNAME Record is invalid|TXT Record is invalid|validation token|Cannot find Hostname") {
            Write-Warning "Could not refresh Static Web App custom-domain validation state: $message"
        }
    }

    return Get-StaticWebAppCustomDomainState -CustomDomainUri $CustomDomainUri
}

function Test-HostnamePatternMatch {
    param(
        [string]$Hostname,
        [string]$Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Hostname) -or [string]::IsNullOrWhiteSpace($Pattern)) {
        return $false
    }

    $normalizedHostname = $Hostname.Trim().TrimEnd('.')
    $normalizedPattern = $Pattern.Trim().TrimEnd('.')

    if ($normalizedPattern.StartsWith("*.")) {
        $hostnameLabels = $normalizedHostname.Split('.')
        $patternSuffixLabels = $normalizedPattern.Substring(2).Split('.')

        if ($hostnameLabels.Count -ne ($patternSuffixLabels.Count + 1)) {
            return $false
        }

        $hostnameSuffix = ($hostnameLabels[1..($hostnameLabels.Count - 1)] -join '.')
        $patternSuffix = ($patternSuffixLabels -join '.')
        return $hostnameSuffix.Equals($patternSuffix, [System.StringComparison]::OrdinalIgnoreCase)
    }

    return $normalizedHostname.Equals($normalizedPattern, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-CertificateDnsName {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $dnsNames = New-Object System.Collections.Generic.List[string]

    foreach ($extension in @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' })) {
        foreach ($match in [regex]::Matches($extension.Format($true), 'DNS Name=(?<name>[^,\r\n]+)')) {
            $dnsName = $match.Groups['name'].Value.Trim()
            if ($dnsName) {
                $dnsNames.Add($dnsName)
            }
        }
    }

    foreach ($match in [regex]::Matches($Certificate.Subject, 'CN=(?<name>[^,]+)')) {
        $dnsName = $match.Groups['name'].Value.Trim()
        if ($dnsName) {
            $dnsNames.Add($dnsName)
        }
    }

    return @($dnsNames | Where-Object { $_ } | Select-Object -Unique)
}

function Test-PublicTlsCertificate {
    param(
        [string]$Hostname,
        [int]$Port = 443,
        [int]$ConnectTimeoutMilliseconds = 10000
    )

    $tcpClient = $null
    $sslStream = $null

    try {
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        $connectTask = $tcpClient.ConnectAsync($Hostname, $Port)
        if (-not $connectTask.Wait($ConnectTimeoutMilliseconds)) {
            throw "Timed out connecting to $Hostname`:$Port"
        }

        $sslStream = [System.Net.Security.SslStream]::new($tcpClient.GetStream(), $false, ({ $true }))
        $sslStream.AuthenticateAsClient($Hostname)

        if (-not $sslStream.RemoteCertificate) {
            throw "No TLS certificate was presented by $Hostname`:$Port"
        }

        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
        $dnsNames = @(Get-CertificateDnsName -Certificate $certificate)
        $matchedDnsName = @($dnsNames | Where-Object { Test-HostnamePatternMatch -Hostname $Hostname -Pattern $_ } | Select-Object -First 1)
        $matchesHostname = $matchedDnsName.Count -gt 0

        [pscustomobject]@{
            Success           = $matchesHostname
            Hostname          = $Hostname
            Port              = $Port
            PresentedDnsName  = if ($matchesHostname) { $matchedDnsName[0] } elseif ($dnsNames.Count -gt 0) { $dnsNames[0] } else { $null }
            PresentedDnsNames = $dnsNames
            Subject           = $certificate.Subject
            Issuer            = $certificate.Issuer
            NotAfter          = $certificate.NotAfter
            Message           = if ($matchesHostname) {
                "TLS certificate matches the public hostname."
            } else {
                if ($dnsNames.Count -gt 0) {
                    "TLS certificate does not match the public hostname. Presented names: $($dnsNames -join ', ')"
                } else {
                    "TLS certificate does not contain DNS names that match the public hostname."
                }
            }
        }
    } catch {
        [pscustomobject]@{
            Success           = $false
            Hostname          = $Hostname
            Port              = $Port
            PresentedDnsName  = $null
            PresentedDnsNames = @()
            Subject           = $null
            Issuer            = $null
            NotAfter          = $null
            Message           = $_.Exception.Message
        }
    } finally {
        if ($sslStream) {
            $sslStream.Dispose()
        }
        if ($tcpClient) {
            $tcpClient.Dispose()
        }
    }
}

function Get-DnsResolutionSnapshot {
    param(
        [string]$Hostname,
        [string]$ExpectedTarget
    )

    $resolvedNames = New-Object System.Collections.Generic.List[string]
    $addresses = New-Object System.Collections.Generic.List[string]
    $rawOutput = $null

    $nslookup = Get-Command nslookup -ErrorAction SilentlyContinue
    if ($nslookup) {
        try {
            $rawOutput = (& $nslookup.Source $Hostname 2>&1 | Out-String)
            $lines = $rawOutput -split "`r?`n"
            $inAnswer = $false
            $inAliases = $false

            foreach ($line in $lines) {
                if ($line -match '^(Non-authoritative answer:|Authoritative answers can be found from:)$') {
                    $inAnswer = $true
                    $inAliases = $false
                    continue
                }

                if (-not $inAnswer -and $line -match '^\s*Name:\s*(.+)$') {
                    $inAnswer = $true
                }

                if (-not $inAnswer) {
                    continue
                }

                if ($line -match '^\s*Name:\s*(.+)$') {
                    $resolvedNames.Add($Matches[1].Trim())
                    $inAliases = $false
                    continue
                }

                if ($line -match '^\s*Aliases:\s*(.+)$') {
                    $resolvedNames.Add($Matches[1].Trim())
                    $inAliases = $true
                    continue
                }

                if ($inAliases -and $line -match '^\s+([A-Za-z0-9\.\-]+)\s*$') {
                    $resolvedNames.Add($Matches[1].Trim())
                    continue
                }

                $inAliases = $false

                if ($line -match '^\s*Address:\s*(.+)$') {
                    $addresses.Add($Matches[1].Trim())
                    continue
                }
            }
        } catch {
            Write-Verbose "nslookup failed for ${Hostname}: $($_.Exception.Message)"
        }
    }

    $distinctNames = @($resolvedNames | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('.') } | Select-Object -Unique)
    $distinctAddresses = @($addresses | Where-Object { $_ } | Select-Object -Unique)
    $matchesExpected = $false
    if ($ExpectedTarget) {
        $matchesExpected = @($distinctNames | Where-Object { $_.Equals($ExpectedTarget.TrimEnd('.'), [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
    }

    [pscustomobject]@{
        Hostname        = $Hostname
        ExpectedTarget  = $ExpectedTarget
        ResolvedNames   = $distinctNames
        Addresses       = $distinctAddresses
        MatchesExpected = $matchesExpected
        RawOutput       = $rawOutput
    }
}

function Get-DnsTxtSnapshot {
    param(
        [string]$Hostname,
        [string]$ExpectedValue
    )

    $txtValues = New-Object System.Collections.Generic.List[string]
    $rawOutput = $null

    $resolveDnsName = Get-Command Resolve-DnsName -ErrorAction SilentlyContinue
    if ($resolveDnsName) {
        try {
            $records = Resolve-DnsName -Name $Hostname -Type TXT -ErrorAction Stop
            foreach ($record in @($records)) {
                if ($record.Strings) {
                    $txtValues.Add(($record.Strings -join ""))
                }
            }
        } catch {
            Write-Verbose "Resolve-DnsName TXT lookup failed for ${Hostname}: $($_.Exception.Message)"
        }
    }

    if ($txtValues.Count -eq 0) {
        $nslookup = Get-Command nslookup -ErrorAction SilentlyContinue
        if ($nslookup) {
            try {
                $rawOutput = (& $nslookup.Source "-type=TXT" $Hostname 2>&1 | Out-String)
                foreach ($line in ($rawOutput -split "`r?`n")) {
                    if ($line -match 'text = "(.*)"') {
                        $txtValues.Add($Matches[1])
                    }
                }
            } catch {
                Write-Verbose "nslookup TXT lookup failed for ${Hostname}: $($_.Exception.Message)"
            }
        }
    }

    $distinctValues = @($txtValues | Where-Object { $_ } | Select-Object -Unique)
    $matchesExpected = $false
    if ($ExpectedValue) {
        $matchesExpected = @($distinctValues | Where-Object { $_.Equals($ExpectedValue, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
    }

    [pscustomobject]@{
        Hostname        = $Hostname
        ExpectedValue   = $ExpectedValue
        Values          = $distinctValues
        MatchesExpected = $matchesExpected
        RawOutput       = $rawOutput
    }
}

function Get-HttpStatusCodeFromException {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    if (-not $ErrorRecord -or -not $ErrorRecord.Exception) {
        return $null
    }

    $response = $ErrorRecord.Exception.Response
    if ($null -eq $response) {
        return $null
    }

    try {
        if ($response.StatusCode) {
            return [int]$response.StatusCode
        }
    } catch {
        Write-Verbose "Could not read HTTP status code directly from the exception response."
    }

    try {
        return [int]$response.StatusCode.value__
    } catch {
        return $null
    }
}

function Test-HttpNotFound {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $statusCode = Get-HttpStatusCodeFromException -ErrorRecord $ErrorRecord
    if ($statusCode -eq 404) {
        return $true
    }

    return $ErrorRecord.Exception.Message -match "NotFound|Not found|ResourceNotFound|404"
}

function Get-HttpErrorMessage {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    if (-not $ErrorRecord) {
        return "Unknown error"
    }

    $statusCode = Get-HttpStatusCodeFromException -ErrorRecord $ErrorRecord

    try {
        $errorBody = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
        if ($errorBody.error.code -and $errorBody.error.message) {
            if ($statusCode) {
                return "HTTP ${statusCode}: $($errorBody.error.code): $($errorBody.error.message)"
            }
            return "$($errorBody.error.code): $($errorBody.error.message)"
        }
    } catch {
        Write-Verbose "HTTP error body was not JSON."
    }

    if ($statusCode) {
        return "HTTP ${statusCode}: $($ErrorRecord.Exception.Message)"
    }

    return $ErrorRecord.Exception.Message
}

function Test-PublicHttpsDocument {
    param(
        [string]$Uri,
        [ValidateSet("did", "didConfiguration")]
        [string]$DocumentType,
        [string]$ExpectedDid,
        [string]$ExpectedOrigin
    )

    $result = [ordered]@{
        Uri        = $Uri
        Success    = $false
        StatusCode = $null
        Message    = $null
    }

    try {
        $response = Invoke-WebRequest -Uri $Uri -Method GET -MaximumRedirection 5 -ErrorAction Stop
        $result.StatusCode = [int]$response.StatusCode

        $contentJson = $null
        try {
            $contentJson = $response.Content | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $result.Message = "Downloaded successfully, but the content was not valid JSON."
            return [pscustomobject]$result
        }

        if ($DocumentType -eq "did") {
            if (-not $contentJson.id -or $contentJson.id -ne $ExpectedDid) {
                $result.Message = "Downloaded successfully, but the DID document id did not match the expected DID."
                return [pscustomobject]$result
            }
        }

        if ($DocumentType -eq "didConfiguration") {
            $expectedOriginNormalized = if ($ExpectedOrigin) { $ExpectedOrigin.TrimEnd('/') + '/' } else { $null }
            $linkedDids = @($contentJson.linked_dids)
            if ($linkedDids.Count -eq 0) {
                $result.Message = "Downloaded successfully, but linked_dids was empty."
                return [pscustomobject]$result
            }

            $matchingLinkedDid = $false
            foreach ($linkedDidJwt in $linkedDids) {
                $payload = Get-JwtPayload -AccessToken $linkedDidJwt
                if (-not $payload) {
                    continue
                }

                $payloadDidCandidates = @(
                    $payload.iss,
                    $payload.sub,
                    $payload.vc.issuer,
                    $payload.vc.credentialSubject.id
                ) | Where-Object { $_ }

                $originCandidates = @(
                    $payload.vc.credentialSubject.origin
                ) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('/') + '/' }

                $didMatches = $ExpectedDid -and (@($payloadDidCandidates | Where-Object { $_ -eq $ExpectedDid }).Count -gt 0)
                $originMatches = (-not $expectedOriginNormalized) -or (@($originCandidates | Where-Object { $_ -eq $expectedOriginNormalized }).Count -gt 0)

                if ($didMatches -and $originMatches) {
                    $matchingLinkedDid = $true
                    break
                }
            }

            if (-not $matchingLinkedDid) {
                $result.Message = "Downloaded successfully, but linked_dids did not contain the expected DID/origin binding."
                return [pscustomobject]$result
            }
        }

        $result.Success = $true
        $result.Message = "Reachable over HTTPS."
        return [pscustomobject]$result
    } catch {
        $result.StatusCode = Get-HttpStatusCodeFromException -ErrorRecord $_
        $result.Message = Get-HttpErrorMessage -ErrorRecord $_

        if ($_.Exception.Message -match "security certificate is from |remote certificate is invalid|authentication failed because the remote party has closed the transport stream") {
            $result.Message = "TLS certificate mismatch. The custom hostname is not yet presenting the expected certificate. Wait for the Static Web App custom-domain binding to reach Ready, then try again."
        }

        return [pscustomobject]$result
    }
}

function Invoke-GraphApi {
    param(
        [string]$Method,
        [string]$Path,
        [hashtable]$Body,
        [string]$AccessToken
    )

    $uri = "https://graph.microsoft.com$Path"
    $headers = @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }

    $params = @{ Method = $Method; Uri = $uri; Headers = $headers; ErrorAction = "Stop" }
    if ($Body) {
        $params.Body = $Body | ConvertTo-Json -Depth 10
    }

    return Invoke-RestMethod @params
}

function Get-GraphApiErrorMessage {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $message = $ErrorRecord.Exception.Message

    try {
        $errorBody = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
        if ($errorBody.error.code -and $errorBody.error.message) {
            return "$($errorBody.error.code): $($errorBody.error.message)"
        }
    } catch {
        Write-Verbose "Graph error body was not JSON."
    }

    return $message
}

function Get-JwtPayload {
    param([string]$AccessToken)

    if (-not $AccessToken) {
        return $null
    }

    $parts = $AccessToken.Split('.')
    if ($parts.Count -lt 2) {
        return $null
    }

    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }

    try {
        $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))
        return $json | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Verbose "Unable to decode JWT payload."
        return $null
    }
}

function Assert-GraphDelegatedScopes {
    param(
        [string]$AccessToken,
        [string[]]$RequiredScopes
    )

    $payload = Get-JwtPayload -AccessToken $AccessToken
    if (-not $payload -or -not $payload.scp) {
        Write-Verbose "Could not determine Graph delegated scopes from token."
        return
    }

    $grantedScopes = @($payload.scp -split ' ')
    $missingScopes = @($RequiredScopes | Where-Object { $_ -notin $grantedScopes })
    if ($missingScopes.Count -gt 0) {
        throw @"
The Microsoft Graph token acquired from Get-AzAccessToken does not include the delegated scope(s) required for automatic temporary app creation: $($missingScopes -join ', ').
This flow requires admin consent for those Graph delegated permissions on the client application used by Connect-AzAccount.
Either grant those permissions to the Azure PowerShell client application in your tenant, or pass -VerifiedIdAccessToken explicitly.
"@
    }
}

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-PkcePair {
    $randomBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($randomBytes)

    $verifier = ConvertTo-Base64Url -Bytes $randomBytes
    $challengeBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($verifier))
    $challenge = ConvertTo-Base64Url -Bytes $challengeBytes

    return [pscustomobject]@{
        Verifier  = $verifier
        Challenge = $challenge
    }
}

function Get-LoopbackRedirectUri {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }

    return "http://localhost:$port/"
}

function Open-SystemBrowser {
    param([string]$Url)

    try {
        if ($IsWindows) {
            Start-Process $Url | Out-Null
        } elseif ($IsMacOS) {
            Start-Process "open" -ArgumentList $Url | Out-Null
        } else {
            Start-Process "xdg-open" -ArgumentList $Url | Out-Null
        }
        return $true
    } catch {
        Write-Warning "Failed to open the system browser automatically. Open this URL manually:`n$Url"
        return $false
    }
}

function New-QueryString {
    param([hashtable]$Parameters)

    return ($Parameters.GetEnumerator() | ForEach-Object {
        "{0}={1}" -f [System.Uri]::EscapeDataString([string]$_.Key), [System.Uri]::EscapeDataString([string]$_.Value)
    }) -join "&"
}

function Invoke-BrowserAuthorizationCodeFlow {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$Scope
    )

    $redirectUri = Get-LoopbackRedirectUri
    $pkce = New-PkcePair
    $state = [guid]::NewGuid().ToString("N")

    $query = New-QueryString -Parameters @{
        client_id             = $ClientId
        response_type         = "code"
        redirect_uri          = $redirectUri
        response_mode         = "query"
        scope                 = $Scope
        code_challenge        = $pkce.Challenge
        code_challenge_method = "S256"
        state                 = $state
        prompt                = "select_account"
    }

    $authorizeUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/authorize?$query"

    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($redirectUri)
    $listener.Start()

    try {
        Write-Host ""
        Write-Host "  Opening browser for temporary Verified ID sign-in..." -ForegroundColor Yellow
        Open-SystemBrowser -Url $authorizeUri | Out-Null
        Write-Info "If the browser does not open, browse to: $authorizeUri"

        $contextTask = $listener.GetContextAsync()
        if (-not $contextTask.Wait([TimeSpan]::FromMinutes(5))) {
            throw "Timed out waiting for the browser sign-in to complete."
        }

        $context = $contextTask.Result
        $request = $context.Request
        $response = $context.Response

        $responseHtml = "<html><body><h2>Verified ID setup sign-in completed.</h2><p>You can return to PowerShell.</p></body></html>"
        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($responseHtml)
        $response.ContentType = "text/html; charset=utf-8"
        $response.ContentLength64 = $responseBytes.Length
        $response.OutputStream.Write($responseBytes, 0, $responseBytes.Length)
        $response.OutputStream.Close()

        $authError = $request.QueryString["error"]
        if ($authError) {
            $errorDescription = $request.QueryString["error_description"]
            throw "Authorization failed: $authError. $errorDescription"
        }

        if ($request.QueryString["state"] -ne $state) {
            throw "Authorization response state did not match the original request."
        }

        $code = $request.QueryString["code"]
        if (-not $code) {
            throw "Authorization response did not include an authorization code."
        }

        $tokenResponse = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body @{
                client_id     = $ClientId
                grant_type    = "authorization_code"
                code          = $code
                redirect_uri  = $redirectUri
                code_verifier = $pkce.Verifier
                scope         = $Scope
            } `
            -ErrorAction Stop

        if (-not $tokenResponse.access_token) {
            throw "The Microsoft identity platform token endpoint did not return an access token."
        }

        return $tokenResponse
    } finally {
        if ($listener.IsListening) {
            $listener.Stop()
        }
        $listener.Close()
    }
}

function Wait-GraphServicePrincipal {
    param(
        [string]$AppId,
        [string]$AccessToken,
        [int]$MaxAttempts = 12,
        [int]$DelaySeconds = 5
    )

    for ($i = 0; $i -lt $MaxAttempts; $i++) {
        $spResult = Invoke-GraphApi -Method "GET" `
            -Path "/v1.0/servicePrincipals?`$filter=appId eq '$AppId'" `
            -AccessToken $AccessToken

        if ($spResult.value -and $spResult.value.Count -gt 0) {
            return $spResult.value[0]
        }

        Start-Sleep -Seconds $DelaySeconds
    }

    throw "Timed out waiting for service principal creation for appId $AppId."
}

function New-TemporaryVerifiedIdAdminApp {
    param(
        [string]$TenantId,
        [string]$GraphAccessToken
    )

    $requiredScopes = @(
        "Application.ReadWrite.All",
        "DelegatedPermissionGrant.ReadWrite.All"
    )

    Assert-GraphDelegatedScopes -AccessToken $GraphAccessToken -RequiredScopes $requiredScopes

    $app = $null
    $servicePrincipal = $null
    $permissionGrant = $null
    $currentUser = $null
    $displayName = "Initialize-VerifiedID-Temp-{0}" -f ([guid]::NewGuid().ToString("N").Substring(0, 8))

    try {
        $currentUser = Invoke-GraphApi -Method "GET" -Path "/v1.0/me" -AccessToken $GraphAccessToken
        if (-not $currentUser.id) {
            throw "Could not determine the current signed-in user for the delegated permission grant."
        }

        $verifiedIdResourceSpResult = Invoke-GraphApi -Method "GET" `
            -Path "/v1.0/servicePrincipals?`$filter=appId eq '$verifiedIdAdminAppId'" `
            -AccessToken $GraphAccessToken

        if (-not $verifiedIdResourceSpResult.value -or $verifiedIdResourceSpResult.value.Count -eq 0) {
            throw "The 'Verifiable Credentials Service Admin' service principal was not found in the tenant."
        }

        $verifiedIdResourceSp = $verifiedIdResourceSpResult.value[0]
        $fullAccessScope = $verifiedIdResourceSp.oauth2PermissionScopes | Where-Object {
            $_.value -eq "full_access" -and $_.isEnabled -eq $true
        } | Select-Object -First 1

        if (-not $fullAccessScope) {
            throw "Could not find the delegated full_access scope on the Verifiable Credentials Service Admin service principal."
        }

        $app = Invoke-GraphApi -Method "POST" `
            -Path "/v1.0/applications" `
            -Body @{
                displayName    = $displayName
                signInAudience = "AzureADMyOrg"
                publicClient   = @{
                    redirectUris = @(
                        "http://localhost"
                    )
                }
            } `
            -AccessToken $GraphAccessToken

        $servicePrincipal = Invoke-GraphApi -Method "POST" `
            -Path "/v1.0/servicePrincipals" `
            -Body @{
                appId = $app.appId
            } `
            -AccessToken $GraphAccessToken

        if (-not $servicePrincipal.id) {
            $servicePrincipal = Wait-GraphServicePrincipal -AppId $app.appId -AccessToken $GraphAccessToken
        }

        $permissionGrant = Invoke-GraphApi -Method "POST" `
            -Path "/v1.0/oauth2PermissionGrants" `
            -Body @{
                clientId    = $servicePrincipal.id
                consentType = "Principal"
                principalId = $currentUser.id
                resourceId  = $verifiedIdResourceSp.id
                scope       = $fullAccessScope.value
            } `
            -AccessToken $GraphAccessToken

        $tokenResponse = Invoke-BrowserAuthorizationCodeFlow `
            -TenantId $TenantId `
            -ClientId $app.appId `
            -Scope "$verifiedIdAdminAppId/$verifiedIdAdminDelegatedScope openid profile offline_access"

        if (-not $tokenResponse.access_token) {
            throw "The Microsoft identity platform token endpoint did not return a delegated access token."
        }

        return [pscustomobject]@{
            DisplayName         = $displayName
            ApplicationObjectId = $app.id
            ServicePrincipalId = $servicePrincipal.id
            PermissionGrantId   = $permissionGrant.id
            VerifiedIdToken     = $tokenResponse.access_token
        }
    } catch {
        $partialApp = [pscustomobject]@{
            ApplicationObjectId = $app.id
            ServicePrincipalId  = $servicePrincipal.id
            PermissionGrantId   = $permissionGrant.id
        }

        if ($partialApp.ApplicationObjectId -or $partialApp.ServicePrincipalId -or $partialApp.PermissionGrantId) {
            Write-Warning "Cleaning up partially created temporary Verified ID setup app resources"
            Remove-TemporaryVerifiedIdAdminApp -GraphAccessToken $GraphAccessToken -TemporaryApp $partialApp
        }

        throw @"
Failed to create or authorize the temporary app registration used for Verified ID setup.
The signed-in user must be able to create applications and grant delegated permission grants.
This flow uses a temporary public client app and browser-based auth code sign-in because authority setup requires a delegated token that contains the user's Entra role claims (wids).

Original error: $(Get-GraphApiErrorMessage -ErrorRecord $_)
"@
    }
}

function Remove-TemporaryVerifiedIdAdminApp {
    param(
        [string]$GraphAccessToken,
        [object]$TemporaryApp
    )

    if (-not $TemporaryApp) {
        return
    }

    if ($TemporaryApp.PermissionGrantId) {
        try {
            Invoke-GraphApi -Method "DELETE" `
                -Path "/v1.0/oauth2PermissionGrants/$($TemporaryApp.PermissionGrantId)" `
                -AccessToken $GraphAccessToken | Out-Null
            Write-Success "Temporary delegated permission grant removed"
        } catch {
            if (-not (Test-HttpNotFound -ErrorRecord $_)) {
                Write-Warning "Failed to remove temporary delegated permission grant: $(Get-GraphApiErrorMessage -ErrorRecord $_)"
            }
        }
    }

    if ($TemporaryApp.ServicePrincipalId) {
        try {
            Invoke-GraphApi -Method "DELETE" `
                -Path "/v1.0/servicePrincipals/$($TemporaryApp.ServicePrincipalId)" `
                -AccessToken $GraphAccessToken | Out-Null
            Write-Success "Temporary service principal removed"
        } catch {
            if (-not (Test-HttpNotFound -ErrorRecord $_)) {
                Write-Warning "Failed to remove temporary service principal: $(Get-GraphApiErrorMessage -ErrorRecord $_)"
            }
        }
    }

    if ($TemporaryApp.ApplicationObjectId) {
        try {
            Invoke-GraphApi -Method "DELETE" `
                -Path "/v1.0/applications/$($TemporaryApp.ApplicationObjectId)" `
                -AccessToken $GraphAccessToken | Out-Null
            Write-Success "Temporary app registration removed"
        } catch {
            if (-not (Test-HttpNotFound -ErrorRecord $_)) {
                Write-Warning "Failed to remove temporary app registration: $(Get-GraphApiErrorMessage -ErrorRecord $_)"
            }
        }
    }
}

function Wait-AzResourceProvisioning {
    param(
        [string]$Uri,
        [string]$ResourceName,
        [int]$MaxAttempts = 24,
        [int]$DelaySeconds = 5
    )

    Write-Host "  Waiting for $ResourceName provisioning" -NoNewline -ForegroundColor Gray
    $lastState = $null

    for ($i = 0; $i -lt $MaxAttempts; $i++) {
        Start-Sleep -Seconds $DelaySeconds
        Write-Host "." -NoNewline -ForegroundColor Gray

        try {
            $response = Invoke-AzRestMethod -Method GET -Uri $Uri
            if ($response.StatusCode -eq 200) {
                $resource = $response.Content | ConvertFrom-Json
                $lastState = $resource.properties.provisioningState
                if (-not $lastState -or $lastState -eq "Succeeded") {
                    Write-Host " ✓" -ForegroundColor Green
                    return
                }
            }
        } catch {
            Write-Verbose "Provisioning check failed for ${ResourceName}: $($_.Exception.Message)"
        }
    }

    Write-Host " x" -ForegroundColor Red
    if ($lastState) {
        throw "$ResourceName did not reach provisioning state 'Succeeded'. Last state: $lastState"
    }

    throw "$ResourceName did not become available within the expected time."
}

function New-KeyVaultPermissionsObject {
    param([object]$Permissions)

    $sanitized = [ordered]@{}
    foreach ($permissionType in @("certificates", "keys", "secrets", "storage")) {
        $values = @($Permissions.$permissionType | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($values.Count -gt 0) {
            $sanitized[$permissionType] = $values
        }
    }

    return $sanitized
}

function Merge-KeyVaultPermissionSets {
    param(
        [object]$ExistingPermissions,
        [object]$DesiredPermissions
    )

    $merged = [ordered]@{}

    foreach ($permissionType in @("certificates", "keys", "secrets", "storage")) {
        $values = @()
        $values += @($ExistingPermissions.$permissionType)
        $values += @($DesiredPermissions.$permissionType)
        $normalizedValues = @($values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        if ($normalizedValues.Count -gt 0) {
            $merged[$permissionType] = $normalizedValues
        }
    }

    return $merged
}

function Merge-KeyVaultAccessPolicies {
    param(
        [object[]]$ExistingPolicies,
        [hashtable[]]$DesiredPolicies
    )

    $policyMap = [ordered]@{}

    foreach ($policy in @($ExistingPolicies)) {
        if ($null -eq $policy.objectId) {
            continue
        }

        $policyMap[$policy.objectId] = @{
            tenantId    = $policy.tenantId
            objectId    = $policy.objectId
            permissions = New-KeyVaultPermissionsObject -Permissions $policy.permissions
        }
    }

    foreach ($policy in $DesiredPolicies) {
        if ($policy.permissions) {
            $policy.permissions = New-KeyVaultPermissionsObject -Permissions $policy.permissions
        }

        if ($policyMap.Contains($policy.objectId)) {
            $existingPolicy = $policyMap[$policy.objectId]
            $policyMap[$policy.objectId] = @{
                tenantId    = if ($policy.tenantId) { $policy.tenantId } else { $existingPolicy.tenantId }
                objectId    = $policy.objectId
                permissions = Merge-KeyVaultPermissionSets -ExistingPermissions $existingPolicy.permissions -DesiredPermissions $policy.permissions
            }
            continue
        }

        $policyMap[$policy.objectId] = @{
            tenantId    = $policy.tenantId
            objectId    = $policy.objectId
            permissions = $policy.permissions
        }
    }

    return @($policyMap.Values)
}

function Set-KeyVaultAccessPolicies {
    param(
        [string]$KeyVaultResourceUri,
        [hashtable[]]$Policies
    )

    $currentVault = (Invoke-AzRestMethod -Method GET -Uri $KeyVaultResourceUri).Content | ConvertFrom-Json
    $mergedPolicies = @(Merge-KeyVaultAccessPolicies -ExistingPolicies $currentVault.properties.accessPolicies -DesiredPolicies $Policies)

    $replaceUri = "$($KeyVaultResourceUri -replace '\?api-version=.*$', '')/accessPolicies/replace?api-version=2023-02-01"
    $replaceBody = @{
        properties = @{
            accessPolicies = $mergedPolicies
        }
    } | ConvertTo-Json -Depth 20

    Invoke-AzRestMethodWithRetry -Method PUT -Uri $replaceUri -Payload $replaceBody | Out-Null
}

#endregion

#region Main Script

$temporaryVerifiedIdApp = $null
$cleanupGraphToken = $null
$resumeExistingAuthority = $false

try {

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║     Microsoft Entra Verified ID - Advanced Setup               ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

# ── Validate and parse FQDN ──────────────────────────────────────────────────
if ($FQDN -notmatch '^https://[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+/?$') {
    throw "FQDN must start with 'https://' and be a valid domain. Example: https://did.contoso.com"
}
$fqdnUri  = [System.Uri]$FQDN.TrimEnd('/')
$hostname = $fqdnUri.Host                   # e.g. did.contoso.com
$fqdnClean = "https://$hostname"            # normalized, no trailing slash

Write-Host "`n  Display Name : $DisplayName" -ForegroundColor White
Write-Host "  FQDN         : $fqdnClean" -ForegroundColor White
Write-Host "  DID          : did:web:$hostname" -ForegroundColor White
Write-Host "  Location     : $Location" -ForegroundColor White

# ── Generate resource names ───────────────────────────────────────────────────
if (-not $KeyVaultName) {
    $KeyVaultName = "kv-vid-$(Get-Random -Minimum 1000 -Maximum 9999)"
}
if (-not $StaticWebAppName) {
    $StaticWebAppName = "swa-verifiedid-$(Get-Random -Minimum 1000 -Maximum 9999)"
}

# ── Validate resource names ───────────────────────────────────────────────────
if ($KeyVaultName.Length -lt 3 -or $KeyVaultName.Length -gt 24) {
    throw "Key Vault name must be 3-24 characters. Current: '$KeyVaultName' ($($KeyVaultName.Length) chars)"
}
if ($KeyVaultName -notmatch '^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$') {
    throw "Key Vault name must start with a letter, end with letter/digit, alphanumeric and hyphens only."
}
if ($StaticWebAppName.Length -lt 2 -or $StaticWebAppName.Length -gt 60) {
    throw "Static Web App name must be 2-60 characters. Current: '$StaticWebAppName' ($($StaticWebAppName.Length) chars)"
}
if ($StaticWebAppName -notmatch '^[a-zA-Z0-9-]+$') {
    throw "Static Web App name must contain only letters, digits, and hyphens: $StaticWebAppName"
}

Write-Host "  Key Vault    : $KeyVaultName" -ForegroundColor White
Write-Host "  Static Web App: $StaticWebAppName" -ForegroundColor White

# ============================================================
# Step 1: Validate Connections
# ============================================================
Write-StepHeader "Step 1: Validate Connections"

# Azure
$azContext = Get-AzContext
if (-not $azContext -or -not $azContext.Account) {
    Write-Host "  Connecting to Azure..." -ForegroundColor Yellow
    Connect-AzAccount -WarningAction SilentlyContinue | Out-Null
    $azContext = Get-AzContext
}
if (-not $azContext -or -not $azContext.Account) {
    throw "Azure connection failed. Run: Connect-AzAccount"
}

if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId -Tenant $azContext.Tenant.Id | Out-Null
    $azContext = Get-AzContext
}
$tenantId = $azContext.Tenant.Id
$SubscriptionId = $azContext.Subscription.Id
Write-Success "Connected to Azure"
Write-Info "Tenant ID: $tenantId"
Write-Info "Subscription: $($azContext.Subscription.Name) ($SubscriptionId)"

# Microsoft Graph via Az token
$graphToken = $null
try {
    Write-Host "  Acquiring Microsoft Graph token..." -ForegroundColor Gray
    $graphToken = Get-AzBearerToken -TenantId $tenantId -ResourceTypeName "MSGraph"
    if (-not $graphToken) { throw "Token was null" }
    Write-Success "Microsoft Graph token acquired"
} catch {
    throw "Failed to acquire Microsoft Graph token from Az context. Error: $($_.Exception.Message)"
}

# Get current user object ID for Key Vault access policy
$currentUserObjectId = $null
try {
    $me = Invoke-GraphApi -Method "GET" -Path "/v1.0/me" -AccessToken $graphToken
    $currentUserObjectId = $me.id
    Write-Info "Signed-in user: $($me.userPrincipalName)"
} catch {
    Write-Warning "Could not retrieve current user object ID - admin Key Vault access policy will be skipped"
}

# Acquire Verified ID API token
Write-Host "  Acquiring Verified ID API token..." -ForegroundColor Gray
try {
    if ($VerifiedIdAccessToken) {
        $vidToken = $VerifiedIdAccessToken
        Write-Info "Using caller-provided Verified ID access token"
    } else {
        Write-Host "  Creating temporary app registration for Verified ID Admin API..." -ForegroundColor Gray
        $temporaryVerifiedIdApp = New-TemporaryVerifiedIdAdminApp -TenantId $tenantId -GraphAccessToken $graphToken
        $cleanupGraphToken = $graphToken
        $vidToken = $temporaryVerifiedIdApp.VerifiedIdToken
        Write-Success "Temporary app registration created for Verified ID setup"
        Write-Info "Temp app     : $($temporaryVerifiedIdApp.DisplayName)"
        Write-Info "Auth flow    : Browser auth code delegated full_access for the current signed-in user only"
    }
    if (-not $vidToken) { throw "Token was null" }
    Write-Success "Verified ID API token acquired"
} catch {
    throw "Failed to acquire Verified ID API token. $($_.Exception.Message)"
}

# Preflight existing authority state before creating Azure resources.
try {
    $authorities = Invoke-VerifiedIdApi -Method "GET" -Path "/v1.0/verifiableCredentials/authorities" -AccessToken $vidToken
    $existingAuthority = $authorities.value | Where-Object {
        ($_.didModel.linkedDomainUrls -contains "$fqdnClean/") -or
        ($_.didModel.linkedDomainUrls -contains $fqdnClean) -or
        ($_.name -eq $DisplayName)
    } | Select-Object -First 1

    if ($existingAuthority) {
        $existingKvMetadata = $existingAuthority.keyVaultMetadata
        if (-not $existingKvMetadata -or -not $existingKvMetadata.resourceName -or -not $existingKvMetadata.resourceGroup -or -not $existingKvMetadata.subscriptionId) {
            throw "An existing Verified ID authority already exists for '$hostname', but it is not tied to a supported dedicated Key Vault configuration. Delete the existing authority before running setup again."
        }

        if ($SubscriptionId -and $SubscriptionId -ne $existingKvMetadata.subscriptionId) {
            throw "The existing authority for '$hostname' is tied to subscription '$($existingKvMetadata.subscriptionId)'. Switch to that subscription to resume this authority, or delete it before creating a new one."
        }

        if ($SubscriptionId -ne $existingKvMetadata.subscriptionId) {
            Set-AzContext -SubscriptionId $existingKvMetadata.subscriptionId -Tenant $tenantId | Out-Null
            $azContext = Get-AzContext
            $SubscriptionId = $azContext.Subscription.Id
            Write-Info "Switched to existing authority subscription: $($azContext.Subscription.Name) ($SubscriptionId)"
        }

        if ($ResourceGroupName -and $ResourceGroupName -ne $existingKvMetadata.resourceGroup) {
            throw "The existing authority for '$hostname' is tied to resource group '$($existingKvMetadata.resourceGroup)'. Use that resource group to resume this authority, or delete it before creating a new one."
        }

        if ($KeyVaultName -and $KeyVaultName -ne $existingKvMetadata.resourceName) {
            throw "The existing authority for '$hostname' is tied to Key Vault '$($existingKvMetadata.resourceName)'. This script will only resume the dedicated Key Vault already bound to that authority."
        }

        $ResourceGroupName = $existingKvMetadata.resourceGroup
        $KeyVaultName = $existingKvMetadata.resourceName
        $resumeExistingAuthority = $true
        Write-Info "Existing authority found. Resuming with its dedicated Key Vault '$KeyVaultName'."
    }
} catch {
    throw "Existing authority preflight failed: $($_.Exception.Message)"
}

# ============================================================
# Step 2: Create Resource Group
# ============================================================
Write-StepHeader "Step 2: Resource Group"

$rgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName`?api-version=2021-04-01"
try {
    $check = Invoke-AzRestMethod -Method GET -Uri $rgUri
    if ($check.StatusCode -eq 200) {
        Write-Success "Resource group already exists: $ResourceGroupName"
    } else {
        throw "Not found"
    }
} catch {
    if (-not (Test-HttpNotFound -ErrorRecord $_)) {
        throw
    }

    Write-Host "  Creating resource group: $ResourceGroupName..." -ForegroundColor Yellow
    $body = @{ location = $Location } | ConvertTo-Json
    Invoke-AzRestMethodWithRetry -Method PUT -Uri $rgUri -Payload $body | Out-Null
    Write-Success "Resource group created: $ResourceGroupName ($Location)"
}

# ============================================================
# Step 3: Create Key Vault (Vault Access Policy - NOT RBAC)
# ============================================================
Write-StepHeader "Step 3: Azure Key Vault"

$kvUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName`?api-version=2023-02-01"
$kvUrl = "https://$KeyVaultName.vault.azure.net/"

try {
    $check = Invoke-AzRestMethod -Method GET -Uri $kvUri
    if ($check.StatusCode -eq 200) {
        if (-not $resumeExistingAuthority) {
            throw "Key Vault '$KeyVaultName' already exists. This script requires a new, dedicated Key Vault for each new authority and will not attach a new setup to an arbitrary existing vault."
        }

        $kvData = $check.Content | ConvertFrom-Json
        Write-Success "Using dedicated Key Vault from the existing authority: $KeyVaultName"
        Write-Info "Location: $($kvData.location)"
        if ($kvData.properties.enableRbacAuthorization -eq $true) {
            throw "Key Vault RBAC is enabled - incompatible with Verified ID"
        }
        Write-Info "Permission model: Vault Access Policy (compatible)"
    } else {
        throw "Not found"
    }
} catch {
    if (-not (Test-HttpNotFound -ErrorRecord $_)) { throw }

    Write-Host "  Creating Key Vault (Vault Access Policy permission model)..." -ForegroundColor Yellow
    Write-Info "NOTE: Verified ID requires Access Policy model, not Azure RBAC"

    $kvBody = @{
        location   = $Location
        properties = @{
            tenantId                = $tenantId
            sku                     = @{ family = "A"; name = $KeyVaultSku.ToLower() }
            accessPolicies          = @()
            enableRbacAuthorization = $false   # REQUIRED: Verified ID does not support RBAC model
            softDeleteRetentionInDays = 90
        }
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-AzRestMethodWithRetry -Method PUT -Uri $kvUri -Payload $kvBody | Out-Null
    } catch {
        if ($_.Exception.Message -match "VaultAlreadyExists") {
            throw "Key Vault name '$KeyVaultName' is already taken globally. Use a different name."
        }
        throw
    }

    Write-Success "Key Vault created: $KeyVaultName"
    Write-Info "SKU: $KeyVaultSku | Permission model: Vault Access Policy | Soft-delete: 90 days"

    Wait-AzResourceProvisioning -Uri $kvUri -ResourceName "Key Vault"
}

# ============================================================
# Step 4: Assign Key Vault Access Policy to Current Admin User
# ============================================================
Write-StepHeader "Step 4: Key Vault Access Policy - Admin User"

if ($currentUserObjectId) {
    $adminPolicy = @{
        tenantId    = $tenantId
        objectId    = $currentUserObjectId
        permissions = @{
            # Sign is required for domain binding; full set for key management
            keys = @("Get", "Create", "Delete", "List", "Sign", "Recover", "Backup", "Restore")
        }
    }

    Set-KeyVaultAccessPolicies -KeyVaultResourceUri $kvUri -Policies @($adminPolicy)
    Write-Success "Access policy set for current admin user"
    Write-Info "Key permissions: Get, Create, Delete, List, Sign, Recover, Backup, Restore"
} else {
    Write-Warning "Skipping admin user access policy - could not determine user object ID"
    Write-Warning "Add an access policy manually in the Azure Portal for your admin account"
}

# ============================================================
# Step 5: Onboard Verified ID Service
# ============================================================
Write-StepHeader "Step 5: Onboard Verified ID Service"

$vidAdminSpId    = $null
$vidServiceSpId  = $null
$vidRequestSpId  = $null

Write-Host "  Calling Verified ID onboard API..." -ForegroundColor Gray
try {
    $onboard = Invoke-VerifiedIdApi -Method "POST" -Path "/v1.0/verifiableCredentials/onboard" -AccessToken $vidToken
    Write-Success "Verified ID service onboarded (status: $($onboard.status))"
    $vidAdminSpId   = $onboard.verifiableCredentialAdminServicePrincipalId
    $vidServiceSpId = $onboard.verifiableCredentialServicePrincipalId
    $vidRequestSpId = $onboard.verifiableCredentialRequestServicePrincipalId
    Write-Info "VID Admin SP ID   : $vidAdminSpId"
    Write-Info "VID Service SP ID : $vidServiceSpId"
    Write-Info "VID Request SP ID : $vidRequestSpId"
} catch {
    throw "Verified ID onboard API failed. The script no longer falls back to display-name service principal lookups because they are not stable identifiers. Error: $($_.Exception.Message)"
}

# ============================================================
# Step 6: Assign Key Vault Access Policy to Verified ID SPs
# ============================================================
Write-StepHeader "Step 6: Key Vault Access Policy - Verified ID Service"

$vidPolicies = @()
if ($vidAdminSpId) {
    $vidPolicies += @{
        tenantId    = $tenantId
        objectId    = $vidAdminSpId
        permissions = @{
            # Full key management access for the admin service principal
            keys = @("Get", "Create", "Delete", "List", "Sign", "Recover", "Backup", "Restore")
        }
    }
}
if ($vidServiceSpId -and $vidServiceSpId -ne $vidAdminSpId) {
    $vidPolicies += @{
        tenantId    = $tenantId
        objectId    = $vidServiceSpId
        permissions = @{
            keys = @("Get", "List", "Sign")
        }
    }
}
if ($vidRequestSpId -and $vidRequestSpId -notin @($vidAdminSpId, $vidServiceSpId)) {
    $vidPolicies += @{
        tenantId    = $tenantId
        objectId    = $vidRequestSpId
        permissions = @{
            # Request service signs credentials using the existing key set.
            keys = @("Get", "List", "Sign")
        }
    }
}

if ($vidPolicies.Count -gt 0) {
    Set-KeyVaultAccessPolicies -KeyVaultResourceUri $kvUri -Policies $vidPolicies
    Write-Success "Key Vault access policies set for Verified ID service principals"
    if ($vidAdminSpId)   { Write-Info "Admin SP  : Get, Create, Delete, List, Sign, Recover, Backup, Restore" }
    if ($vidServiceSpId -and $vidServiceSpId -ne $vidAdminSpId) {
                           Write-Info "Service SP: Get, List, Sign" }
    if ($vidRequestSpId -and $vidRequestSpId -notin @($vidAdminSpId, $vidServiceSpId)) {
                           Write-Info "Request SP: Get, List, Sign" }
} else {
    Write-Warning "No Verified ID service principal IDs available - manually add access policies in the Azure Portal"
    Write-Warning "Navigate to: Key Vault -> Access Policies -> Add"
    Write-Warning "Principal: 'Verifiable Credentials Service Admin' | Key permissions: Get, Create, Delete, List, Sign"
    Write-Warning "Principal: 'Verifiable Credentials Service Request' | Key permissions: Get, List, Sign"
}

# Brief pause for Key Vault access policy propagation
Write-Host "  Waiting for access policy propagation (30s)..." -ForegroundColor Gray
Start-Sleep -Seconds 30

# ============================================================
# Step 7: Create Verified ID Authority
# ============================================================
Write-StepHeader "Step 7: Create Verified ID Authority"

# Check for an existing authority with this domain or name
$authority   = $null
$authorityId = $null
$authorityJustCreated = $false

try {
    $existing = Invoke-VerifiedIdApi -Method "GET" -Path "/v1.0/verifiableCredentials/authorities" -AccessToken $vidToken
    $authority = $existing.value | Where-Object {
        ($_.didModel.linkedDomainUrls -contains "$fqdnClean/") -or
        ($_.didModel.linkedDomainUrls -contains $fqdnClean) -or
        ($_.name -eq $DisplayName)
    } | Select-Object -First 1
} catch {
    Write-Warning "Could not check existing authorities: $($_.Exception.Message)"
}

if ($authority) {
    if (-not $resumeExistingAuthority) {
        throw "A Verified ID authority already exists for '$hostname' or display name '$DisplayName'. This script requires a fresh authority and dedicated Key Vault for each new setup."
    }

    Write-Success "Authority already exists"
    $authorityId = $authority.id
    Write-Info "Authority ID: $authorityId"
    Write-Info "DID         : $($authority.didModel.did)"
    Write-Info "Existing authority detected. Resuming validation and document deployment."
} else {
    Write-Host "  Creating Verified ID authority with did:web..." -ForegroundColor Yellow

    $authorityBody = @{
        name             = $DisplayName
        linkedDomainUrl  = "$fqdnClean/"
        didMethod        = "web"
        keyVaultMetadata = @{
            subscriptionId = $SubscriptionId
            resourceGroup  = $ResourceGroupName
            resourceName   = $KeyVaultName
            resourceUrl    = $kvUrl
        }
    }

    try {
        $authority = Invoke-VerifiedIdApi -Method "POST" -Path "/v1.0/verifiableCredentials/authorities" -Body $authorityBody -AccessToken $vidToken
        $authorityId = $authority.id
        $authorityJustCreated = $true
        Write-Success "Verified ID authority created"
        Write-Info "Authority ID: $authorityId"
        Write-Info "DID         : $($authority.didModel.did)"
        Write-Info "Status      : $($authority.status)"
    } catch {
        Write-Error "Failed to create Verified ID authority."
        Write-Error "Common causes:"
        Write-Error "  - Key Vault access policies have not propagated yet (try re-running in 1-2 minutes)"
        Write-Error "  - The Verified ID service principal does not have Sign permission on the Key Vault"
        Write-Error "  - The Key Vault has RBAC enabled (must use Vault Access Policy model)"
        throw
    }
}

if ($authorityJustCreated) {
    $authority = Wait-VerifiedIdAuthorityReady -AuthorityId $authorityId -AccessToken $vidToken
    if ($authority.status) {
        Write-Info "Authority status: $($authority.status)"
    }
}

# ============================================================
# Step 8: Generate DID Document
# ============================================================
Write-StepHeader "Step 8: Generate DID Document"

Write-Host "  Generating DID document..." -ForegroundColor Gray
try {
    $didDoc = $null
    $maxDidDocAttempts = 12

    for ($attempt = 1; $attempt -le $maxDidDocAttempts -and -not $didDoc; $attempt++) {
        try {
            $didDoc = Invoke-VerifiedIdApi -Method "POST" `
                -Path "/v1.0/verifiableCredentials/authorities/$authorityId/generateDidDocument" `
                -AccessToken $vidToken
        } catch {
            $isIssuerPropagationError = $_.Exception.Message -match "failedToFindSpecifiedIssuerInDb|issuer id"
            $isKeyVaultPropagationError = $_.Exception.Message -match "keyVaultOperationForbidden|KeyVault server failed"
            if (($isIssuerPropagationError -or $isKeyVaultPropagationError) -and $attempt -lt $maxDidDocAttempts) {
                if ($isKeyVaultPropagationError) {
                    Write-Warning "Key Vault access is not fully available yet (attempt $attempt/$maxDidDocAttempts). Retrying DID document generation in 15 seconds..."
                    Start-Sleep -Seconds 15
                    continue
                }

                Write-Warning "Verified ID authority is not fully available yet (attempt $attempt/$maxDidDocAttempts). Retrying DID document generation in 10 seconds..."
                Start-Sleep -Seconds 10
                continue
            }

            throw
        }
    }

    if (-not $didDoc) {
        throw "DID document generation did not return a document after $maxDidDocAttempts attempts."
    }

    Write-Success "DID document generated"
    Write-Info "DID: $($didDoc.id)"
    $didDocJson = $didDoc | ConvertTo-Json -Depth 20
} catch {
    throw "Failed to generate DID document: $($_.Exception.Message)"
}

# ============================================================
# Step 9: Generate Well-Known DID Configuration
# ============================================================
Write-StepHeader "Step 9: Generate Well-Known DID Configuration"

Write-Host "  Generating well-known DID configuration..." -ForegroundColor Gray
try {
    $wellKnown = Invoke-VerifiedIdApi -Method "POST" `
        -Path "/v1.0/verifiableCredentials/authorities/$authorityId/generateWellknownDidConfiguration" `
        -Body @{ domainUrl = "$fqdnClean/" } `
        -AccessToken $vidToken
    Write-Success "Well-known DID configuration generated"
    $wellKnownJson = $wellKnown | ConvertTo-Json -Depth 20
} catch {
    throw "Failed to generate well-known DID configuration: $($_.Exception.Message)"
}

# Save copies locally for reference
$tempDir       = [System.IO.Path]::GetTempPath()
$didJsonPath   = Join-Path $tempDir "did.json"
$didConfigPath = Join-Path $tempDir "did-configuration.json"

$didDocJson    | Set-Content -Path $didJsonPath   -Encoding UTF8
$wellKnownJson | Set-Content -Path $didConfigPath -Encoding UTF8

Write-Info "Local copy - DID document  : $didJsonPath"
Write-Info "Local copy - DID config    : $didConfigPath"

# ============================================================
# Step 10: Azure Static Web App
# ============================================================
Write-StepHeader "Step 10: Azure Static Web App"

$staticWebAppApiVersion = "2024-11-01"
$staticWebAppUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/staticSites/$StaticWebAppName`?api-version=$staticWebAppApiVersion"
$staticWebAppLocation = $Location

try {
    $check = Invoke-AzRestMethod -Method GET -Uri $staticWebAppUri
    if ($check.StatusCode -eq 200) {
        $staticWebApp = $check.Content | ConvertFrom-Json
        Write-Success "Static Web App already exists: $StaticWebAppName"
        Write-Info "Location: $($staticWebApp.location)"
    } else {
        throw "Not found"
    }
} catch {
    if (-not (Test-HttpNotFound -ErrorRecord $_)) { throw }

    Write-Host "  Creating Static Web App: $StaticWebAppName..." -ForegroundColor Yellow

    $newStaticWebAppBody = {
        param([string]$RequestedLocation)

        @{
            location = $RequestedLocation
            sku      = @{
                name = "Free"
                tier = "Free"
            }
            properties = @{
                buildProperties = @{
                    appLocation    = ""
                    outputLocation = ""
                    apiLocation    = ""
                }
            }
        } | ConvertTo-Json -Depth 10
    }

    try {
        $staticWebAppBody = & $newStaticWebAppBody $staticWebAppLocation
        Invoke-AzRestMethodWithRetry -Method PUT -Uri $staticWebAppUri -Payload $staticWebAppBody | Out-Null
    } catch {
        if ($_.Exception.Message -match "LocationNotAvailableForResourceType" -and $staticWebAppLocation -ne "eastus2") {
            $staticWebAppLocation = "eastus2"
            Write-Warning "Static Web Apps are not available in '$Location'. Retrying the Static Web App in '$staticWebAppLocation'."
            $staticWebAppBody = & $newStaticWebAppBody $staticWebAppLocation
            Invoke-AzRestMethodWithRetry -Method PUT -Uri $staticWebAppUri -Payload $staticWebAppBody | Out-Null
        } else {
            throw
        }
    }

    Write-Success "Static Web App created: $StaticWebAppName"
    Write-Info "SKU: Free"
    Write-Info "Location: $staticWebAppLocation"
}

Wait-AzResourceProvisioning -Uri $staticWebAppUri -ResourceName "Static Web App" -MaxAttempts 36

$staticWebApp = $null
for ($attempt = 1; $attempt -le 24; $attempt++) {
    $staticWebApp = (Invoke-AzRestMethod -Method GET -Uri $staticWebAppUri).Content | ConvertFrom-Json
    if ($staticWebApp.properties.defaultHostname) {
        break
    }

    Start-Sleep -Seconds 5
}

if (-not $staticWebApp.properties.defaultHostname) {
    throw "Static Web App '$StaticWebAppName' did not expose a default hostname in the expected time."
}

$staticWebAppDefaultHostname = $staticWebApp.properties.defaultHostname
$staticWebAppDefaultUrl = "https://$staticWebAppDefaultHostname"
Write-Info "Default hostname: $staticWebAppDefaultHostname"

# ============================================================
# Step 11: Deploy DID Documents to Azure Static Web App
# ============================================================
Write-StepHeader "Step 11: Deploy DID Documents"

$secretsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/staticSites/$StaticWebAppName/listSecrets`?api-version=$staticWebAppApiVersion"
$deploymentToken = $null

try {
    Write-Host "  Retrieving Static Web App deployment token..." -ForegroundColor Gray
    $secrets = (Invoke-AzRestMethodWithRetry -Method POST -Uri $secretsUri).Content | ConvertFrom-Json
    $deploymentToken = $secrets.properties.apiKey
    if (-not $deploymentToken) {
        throw "The Static Web App did not return a deployment token."
    }
    Write-Success "Deployment token acquired"
} catch {
    throw "Failed to retrieve the Static Web App deployment token: $($_.Exception.Message)"
}

$staticSitesClient = Get-StaticSitesClientBinary
$staticWebAppContentRoot = Join-Path $tempDir "verifiedid-swa-$authorityId"
New-StaticWebAppContent -RootPath $staticWebAppContentRoot -DidDocumentJson $didDocJson -DidConfigurationJson $wellKnownJson
Write-Info "Static Web App content root: $staticWebAppContentRoot"

try {
    Write-Host "  Deploying .well-known content with StaticSitesClient..." -ForegroundColor Gray
    $deployOutput = Invoke-StaticSitesClientDeploy -BinaryPath $staticSitesClient.BinaryPath -AppLocation $staticWebAppContentRoot -DeploymentToken $deploymentToken
    Write-Success "Static Web App deployment completed"
    if ($deployOutput) {
        Write-Verbose $deployOutput
    }
} catch {
    throw "Failed to deploy the DID documents to Azure Static Web Apps: $($_.Exception.Message)"
}

$customDomainUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/staticSites/$StaticWebAppName/customDomains/$hostname`?api-version=$staticWebAppApiVersion"
$customDomainValidateUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/staticSites/$StaticWebAppName/customDomains/$hostname/validate`?api-version=$staticWebAppApiVersion"
$customDomainBody = @{
    properties = @{
        validationMethod = "dns-txt-token"
    }
} | ConvertTo-Json -Depth 10

$hostParts   = $hostname.Split('.')
$dnsHostName = if ($hostParts.Count -gt 2) { ($hostParts[0..($hostParts.Count - 3)] -join '.') } else { "@" }
$txtRecordLabel = $dnsHostName
$txtRecordFqdn = $hostname
$publicDnsTarget = $staticWebAppDefaultHostname
$publicDidJsonUrl = "$fqdnClean/.well-known/did.json"
$publicDidConfigurationUrl = "$fqdnClean/.well-known/did-configuration.json"
$staticWebAppResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/staticSites/$StaticWebAppName"
$staticWebAppPortalUrl = "https://portal.azure.com/#@$tenantId/resource$staticWebAppResourceId"
$staticWebAppCustomDomainsPortalUrl = "$staticWebAppPortalUrl/customDomains"
$customDomain = $null
$domainValidationToken = $null

# ============================================================
# Step 12: DNS Phase 1 - TXT Validation
# ============================================================
Write-StepHeader "Step 12: DNS Phase 1 - TXT Validation"

$didValidationSucceeded = $false
$didValidationSkipped = $false
$didValidationMessage = "Validation not attempted."
$cnameValidated = $false
$txtValidated = $false
$dnsSnapshot = $null

if ($SkipDnsValidationLoop) {
    $didValidationSkipped = $true
    $didValidationMessage = "Skipped DNS and HTTPS validation loop by request."
    Write-Warning "Skipping DNS and HTTPS validation loop because -SkipDnsValidationLoop was specified."
} else {
    $txtTokenStateBag = @{}
    $txtDnsStateBag = @{}
    $cnameStateBag = @{}
    $swaReadyStateBag = @{}
    $didValidationStateBag = @{}

    Write-Host ""
    Write-Host "  Azure Static Web Apps validates this hostname by issuing a TXT token first." -ForegroundColor Gray

    $hostnameBindingRequested = $false
    $txtTokenResult = Invoke-InteractivePollingLoop `
        -PhaseDescription "TXT token retrieval" `
        -WindowMessage "The script will query Azure every 5 seconds until the TXT value is available." `
        -IntervalSeconds 5 `
        -InitialWindowAttempts 12 `
        -RepeatWindowAttempts 12 `
        -PollScript {
            if (-not $hostnameBindingRequested) {
                try {
                    Invoke-AzRestMethodWithRetry -Method PUT -Uri $customDomainUri -Payload $customDomainBody | Out-Null
                    $hostnameBindingRequested = $true
                } catch {
                    $putMessage = $_.Exception.Message
                    if ($putMessage -notmatch "already exists|Conflict") {
                        throw "Failed to create the Static Web App custom-domain resource: $putMessage"
                    }

                    $hostnameBindingRequested = $true
                }
            }

            $currentState = Request-StaticWebAppCustomDomainValidation -CustomDomainUri $customDomainUri -CustomDomainValidateUri $customDomainValidateUri -CustomDomainBody $customDomainBody

            if (-not $currentState.CustomDomain) {
                Write-ObservedState -StateBag $txtTokenStateBag -Key "resource" -Message "Static Web App custom-domain resource is not visible yet."
            } else {
                Write-ObservedState -StateBag $txtTokenStateBag -Key "status" -Message "Static Web App custom-domain status: $($currentState.Status)"
            }

            if ($currentState.ErrorMessage) {
                Write-ObservedState -StateBag $txtTokenStateBag -Key "error" -Message "Static Web App custom-domain message: $($currentState.ErrorMessage)" -Warning
            }

            if ($currentState.ValidationToken) {
                return [pscustomobject]@{
                    Completed = $true
                    State     = $currentState
                }
            }

            return [pscustomobject]@{
                Completed = $false
                State     = $currentState
            }
        }

    if ($txtTokenResult.Completed) {
        $customDomain = $txtTokenResult.State.CustomDomain
        $domainValidationToken = $txtTokenResult.State.ValidationToken
    } else {
        $didValidationSkipped = $true
        $didValidationMessage = "Skipped before TXT validation. Run validation later when the public URLs are reachable."
        Write-Warning "Skipping DID validation for now."
    }

    if (-not $didValidationSkipped -and -not $txtValidated -and $domainValidationToken) {
        Write-Host ""
        Write-Host "  TXT record required by Azure Static Web Apps:" -ForegroundColor Yellow
        Write-Host "    TXT Host/Name   : $txtRecordLabel" -ForegroundColor White
        Write-Host "    TXT FQDN        : $txtRecordFqdn" -ForegroundColor Gray
        Write-Host "    TXT Value       : $domainValidationToken" -ForegroundColor White
        Write-Host ""
        Write-Host "  Press Enter when you want the script to check public DNS for up to 1 minute." -ForegroundColor Gray
        Write-Host "  Type 'skip' to finish now and validate later." -ForegroundColor White
        $txtDnsChoice = Read-Host "  Continue"

        if ($txtDnsChoice -match '^(skip|s)$') {
            $didValidationSkipped = $true
            $didValidationMessage = "Skipped after TXT guidance. Complete the TXT record and rerun validation later."
            Write-Warning "Skipping DID validation for now."
        } else {
            $txtDnsResult = Invoke-InteractivePollingLoop `
                -PhaseDescription "TXT validation" `
                -WindowMessage "Checking public TXT DNS every 10 seconds for up to 1 minute." `
                -IntervalSeconds 10 `
                -InitialWindowAttempts 6 `
                -RepeatWindowAttempts 6 `
                -PollScript {
                    $txtSnapshot = Get-DnsTxtSnapshot -Hostname $txtRecordFqdn -ExpectedValue $domainValidationToken
                    $customDomainState = Get-StaticWebAppCustomDomainState -CustomDomainUri $customDomainUri

                    if ($txtSnapshot.Values.Count -gt 0) {
                        Write-ObservedState -StateBag $txtDnsStateBag -Key "txtValues" -Message "Public TXT values: $($txtSnapshot.Values -join ', ')"
                    } else {
                        Write-ObservedState -StateBag $txtDnsStateBag -Key "txtValues" -Message "No public TXT values found for $txtRecordFqdn yet."
                    }

                    Write-ObservedState -StateBag $txtDnsStateBag -Key "status" -Message "Static Web App custom-domain status: $($customDomainState.Status)"
                    if ($customDomainState.ErrorMessage) {
                        Write-ObservedState -StateBag $txtDnsStateBag -Key "error" -Message "Static Web App custom-domain message: $($customDomainState.ErrorMessage)" -Warning
                    }

                    if ($txtSnapshot.MatchesExpected) {
                        return [pscustomobject]@{
                            Completed = $true
                            Snapshot  = $txtSnapshot
                            State     = $customDomainState
                        }
                    }

                    return [pscustomobject]@{
                        Completed = $false
                        Snapshot  = $txtSnapshot
                        State     = $customDomainState
                    }
                }

            if ($txtDnsResult.Completed) {
                $txtValidated = $true
                $didValidationMessage = "TXT validation record is visible. Proceeding to CNAME validation."
                Write-Success $didValidationMessage
            } else {
                $didValidationSkipped = $true
                $didValidationMessage = "Skipped after TXT guidance. Complete the TXT record and rerun validation later."
                Write-Warning "Skipping DID validation for now."
            }
        }
    }

    if (-not $txtValidated -and -not $didValidationSkipped) {
        if (-not $domainValidationToken) {
            $didValidationMessage = "Azure Static Web Apps did not issue the TXT validation token within the expected time. Wait a few minutes and rerun the script."
        } else {
            $didValidationMessage = "The expected TXT record is not visible in public DNS yet. Wait for propagation and rerun the script."
        }
        throw $didValidationMessage
    }
}

# ============================================================
# Step 13: DNS Phase 2 - CNAME Validation
# ============================================================
if (-not $didValidationSkipped -and $txtValidated) {
    Write-StepHeader "Step 13: DNS Phase 2 - CNAME Validation"

    Write-Host ""
    Write-Host "  After the TXT validation record is visible, point your public hostname to the Static Web App." -ForegroundColor Gray
    if ($hostParts.Count -ge 3) {
        Write-Host "    CNAME Host/Name : $dnsHostName" -ForegroundColor White
        Write-Host "    CNAME Value     : $publicDnsTarget" -ForegroundColor White
    } else {
        Write-Host "    CNAME/ALIAS Host: @ (root domain)" -ForegroundColor White
        Write-Host "    CNAME/ALIAS Val : $publicDnsTarget" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "  The DNS answer chain must include:" -ForegroundColor Gray
    Write-Host "    $publicDnsTarget" -ForegroundColor White
    Write-Host ""
    Write-Host "  Press Enter when you want the script to check public DNS for up to 1 minute." -ForegroundColor Gray
    Write-Host "  Type 'skip' to finish now and validate later." -ForegroundColor White
    $cnameChoice = Read-Host "  Continue"

    if ($cnameChoice -match '^(skip|s)$') {
        $didValidationSkipped = $true
        $didValidationMessage = "Skipped after TXT validation. Update the public DNS mapping and rerun validation later."
        Write-Warning "Skipping DID validation for now."
    } else {
        $cnameResult = Invoke-InteractivePollingLoop `
            -PhaseDescription "CNAME validation" `
            -WindowMessage "Checking public DNS resolution every 10 seconds for up to 1 minute." `
            -IntervalSeconds 10 `
            -InitialWindowAttempts 6 `
            -RepeatWindowAttempts 6 `
            -PollScript {
                $dnsSnapshot = Get-DnsResolutionSnapshot -Hostname $hostname -ExpectedTarget $publicDnsTarget
                $customDomainState = Get-StaticWebAppCustomDomainState -CustomDomainUri $customDomainUri
                $isApexDomain = $hostParts.Count -lt 3
                $hasPublicDnsAnswer = $dnsSnapshot.ResolvedNames.Count -gt 0 -or $dnsSnapshot.Addresses.Count -gt 0
                $dnsMappingReady = $dnsSnapshot.MatchesExpected -or ($isApexDomain -and $hasPublicDnsAnswer)

                if ($dnsSnapshot.ResolvedNames.Count -gt 0) {
                    Write-ObservedState -StateBag $cnameStateBag -Key "dnsNames" -Message "DNS chain: $($dnsSnapshot.ResolvedNames -join ' -> ')"
                } else {
                    Write-ObservedState -StateBag $cnameStateBag -Key "dnsNames" -Message "No DNS answer chain was found for $hostname yet." -Warning
                }

                if ($dnsSnapshot.Addresses.Count -gt 0) {
                    Write-ObservedState -StateBag $cnameStateBag -Key "dnsIps" -Message "Resolved IPs: $($dnsSnapshot.Addresses -join ', ')"
                }

                Write-ObservedState -StateBag $cnameStateBag -Key "status" -Message "Static Web App custom-domain status: $($customDomainState.Status)"
                if ($customDomainState.ErrorMessage) {
                    Write-ObservedState -StateBag $cnameStateBag -Key "error" -Message "Static Web App custom-domain message: $($customDomainState.ErrorMessage)" -Warning
                }

                if ($isApexDomain -and $hasPublicDnsAnswer) {
                    Write-ObservedState -StateBag $cnameStateBag -Key "apexMode" -Message "Apex domain detected. Proceeding once the hostname resolves publicly; Azure custom-domain readiness and HTTPS validation will confirm the final binding."
                }

                if ($dnsMappingReady) {
                    return [pscustomobject]@{
                        Completed = $true
                        Snapshot  = $dnsSnapshot
                        State     = $customDomainState
                    }
                }

                return [pscustomobject]@{
                    Completed = $false
                    Snapshot  = $dnsSnapshot
                    State     = $customDomainState
                }
            }

        if ($cnameResult.Completed) {
            $cnameValidated = $true
            $dnsSnapshot = $cnameResult.Snapshot
            if ($hostParts.Count -ge 3) {
                $didValidationMessage = "CNAME validation completed successfully."
                Write-Success "DNS chain includes the Static Web App hostname."
            } else {
                $didValidationMessage = "Apex-domain DNS is resolving publicly. Proceeding to Azure custom-domain and TLS validation."
                Write-Success $didValidationMessage
            }
        } else {
            $didValidationSkipped = $true
            $didValidationMessage = "Skipped after TXT validation. Update the public DNS mapping and rerun validation later."
            Write-Warning "Skipping DID validation for now."
        }
    }

    if (-not $cnameValidated -and -not $didValidationSkipped) {
        if ($hostParts.Count -ge 3) {
            $didValidationMessage = "Public DNS did not reach the Static Web App hostname within the expected time. Wait for propagation and rerun the script."
        } else {
            $didValidationMessage = "Public apex-domain DNS did not return any public answers within the expected time. Wait for propagation and rerun the script."
        }
        throw $didValidationMessage
    }
}

# ============================================================
# Step 14: Static Web App Custom Domain Ready
# ============================================================
if (-not $didValidationSkipped -and $txtValidated -and $cnameValidated) {
    Write-StepHeader "Step 14: Static Web App Custom Domain Ready"

    Write-Host ""
    Write-Host "  The DNS records are in place. Azure Static Web Apps still needs to finish validating the custom domain and issuing the managed certificate." -ForegroundColor Gray
    Write-Host "  Managed certificate issuance can take up to 10 minutes." -ForegroundColor Gray
    Write-Host "  The script will keep polling Azure and the public hostname every 10 seconds." -ForegroundColor Gray
    Write-Host "  If you prefer to use your own certificate, including a one-label wildcard certificate, manage it here:" -ForegroundColor Gray
    Write-Host "    $staticWebAppCustomDomainsPortalUrl" -ForegroundColor White

    $swaReadyResult = Invoke-InteractivePollingLoop `
        -PhaseDescription "Static Web App custom-domain readiness" `
        -WindowMessage "Polling Azure and the public TLS certificate every 10 seconds for up to 10 minutes." `
        -IntervalSeconds 10 `
        -InitialWindowAttempts 60 `
        -RepeatWindowAttempts 6 `
        -PollScript {
            $customDomainState = Get-StaticWebAppCustomDomainState -CustomDomainUri $customDomainUri
            $tlsProbe = Test-PublicTlsCertificate -Hostname $hostname

            Write-ObservedState -StateBag $swaReadyStateBag -Key "status" -Message "Static Web App custom-domain status: $($customDomainState.Status)"
            if ($customDomainState.ErrorMessage) {
                Write-ObservedState -StateBag $swaReadyStateBag -Key "error" -Message "Static Web App custom-domain message: $($customDomainState.ErrorMessage)" -Warning
            }

            $tlsMessage = if ($tlsProbe.Success) {
                "Public TLS certificate matches '$($tlsProbe.PresentedDnsName)' and expires $($tlsProbe.NotAfter.ToString('u'))."
            } else {
                "Public TLS certificate check: $($tlsProbe.Message)"
            }
            Write-ObservedState -StateBag $swaReadyStateBag -Key "tls" -Message $tlsMessage

            if ($customDomainState.Status -eq "Ready" -and $tlsProbe.Success) {
                return [pscustomobject]@{
                    Completed = $true
                    State     = $customDomainState
                    TlsProbe  = $tlsProbe
                }
            }

            return [pscustomobject]@{
                Completed = $false
                State     = $customDomainState
                TlsProbe  = $tlsProbe
            }
        }

    if ($swaReadyResult.Completed) {
        $didValidationMessage = "Static Web App custom domain is Ready and the public TLS certificate matches the hostname."
        Write-Success $didValidationMessage
    } else {
        $didValidationSkipped = $true
        $didValidationMessage = "Azure Static Web Apps is still finalizing the custom domain and certificate. Rerun the script in a few minutes to continue."
        Write-Warning $didValidationMessage
    }
}

# ============================================================
# Step 15: DID Configuration Validation
# ============================================================
if (-not $didValidationSkipped -and $txtValidated -and $cnameValidated) {
    Write-StepHeader "Step 15: DID Configuration Validation"

    Write-Host "  Target URLs:" -ForegroundColor Gray
    Write-Host "    $publicDidJsonUrl" -ForegroundColor White
    Write-Host "    $publicDidConfigurationUrl" -ForegroundColor White
    Write-Host ""
    $didValidationResult = Invoke-InteractivePollingLoop `
        -PhaseDescription "DID configuration validation" `
        -WindowMessage "Checking the public HTTPS endpoints every 30 seconds for up to 3 minutes." `
        -IntervalSeconds 30 `
        -InitialWindowAttempts 6 `
        -RepeatWindowAttempts 2 `
        -PollScript {
            $didJsonProbe = Test-PublicHttpsDocument -Uri $publicDidJsonUrl -DocumentType "did" -ExpectedDid "did:web:$hostname"
            $didConfigurationProbe = Test-PublicHttpsDocument -Uri $publicDidConfigurationUrl -DocumentType "didConfiguration" -ExpectedDid "did:web:$hostname" -ExpectedOrigin $fqdnClean

            foreach ($probe in @($didJsonProbe, $didConfigurationProbe)) {
                $stateKey = if ($probe.Uri -eq $publicDidJsonUrl) { "didJson" } else { "didConfiguration" }
                if ($probe.Success) {
                    Write-ObservedState -StateBag $didValidationStateBag -Key $stateKey -Message "$($probe.Uri) [$($probe.StatusCode)] $($probe.Message)"
                } else {
                    Write-ObservedState -StateBag $didValidationStateBag -Key $stateKey -Message "$($probe.Uri) $($probe.Message)" -Warning
                }
            }

            if (-not ($didJsonProbe.Success -and $didConfigurationProbe.Success)) {
                Write-ObservedState -StateBag $didValidationStateBag -Key "validationPending" -Message "Validation will continue until both URLs are reachable over HTTPS from your public hostname." -Warning
                return [pscustomobject]@{
                    Completed             = $false
                    DidJsonProbe          = $didJsonProbe
                    DidConfigurationProbe = $didConfigurationProbe
                }
            }

            try {
                Invoke-VerifiedIdApi -Method "POST" `
                    -Path "/v1.0/verifiableCredentials/authorities/$authorityId/validateWellKnownDidConfiguration" `
                    -AccessToken $vidToken | Out-Null

                return [pscustomobject]@{
                    Completed             = $true
                    DidJsonProbe          = $didJsonProbe
                    DidConfigurationProbe = $didConfigurationProbe
                }
            } catch {
                Write-ObservedState -StateBag $didValidationStateBag -Key "validate" -Message "Verified ID validation is not ready yet: $($_.Exception.Message)" -Warning
                return [pscustomobject]@{
                    Completed             = $false
                    DidJsonProbe          = $didJsonProbe
                    DidConfigurationProbe = $didConfigurationProbe
                }
            }
        }

    if ($didValidationResult.Completed) {
        $didValidationSucceeded = $true
        $didValidationMessage = "DID configuration validated successfully. Domain binding is active."
        Write-Success $didValidationMessage
    } else {
        $didValidationSkipped = $true
        $didValidationMessage = "Skipped after SWA custom domain became Ready. Run validation later when the public URLs are reachable."
        Write-Warning "Skipping DID validation for now."
    }
}

# ============================================================
# Final Summary
# ============================================================

$summaryColor = if ($didValidationSucceeded) { "Green" } else { "Yellow" }
$summaryTitle = if ($didValidationSucceeded) {
    "✓ Verified ID Advanced Setup Complete"
} else {
    "↺ Verified ID Advanced Setup Ready To Resume"
}

Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor $summaryColor
Write-Host ("║ {0,-60}   ║" -f $summaryTitle) -ForegroundColor $summaryColor
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor $summaryColor

Write-Host "`n📋 Summary:" -ForegroundColor Cyan
Write-Host "  Tenant ID       : $tenantId" -ForegroundColor White
Write-Host "  Subscription    : $($azContext.Subscription.Name)" -ForegroundColor White
Write-Host "  Resource Group  : $ResourceGroupName" -ForegroundColor White
Write-Host "  Key Vault       : $KeyVaultName (Vault Access Policy, $KeyVaultSku SKU)" -ForegroundColor White
Write-Host "  Static Web App  : $StaticWebAppName" -ForegroundColor White
Write-Host "  Default Host    : $staticWebAppDefaultHostname" -ForegroundColor White
Write-Host "  Authority ID    : $authorityId" -ForegroundColor White
Write-Host "  DID             : did:web:$hostname" -ForegroundColor White
Write-Host "  Validation      : $didValidationMessage" -ForegroundColor White

Write-Host "`n🔗 DID Document Endpoints:" -ForegroundColor Cyan
Write-Host "  SWA URL      : $staticWebAppDefaultUrl/.well-known/did.json" -ForegroundColor White
Write-Host "  Custom domain: $publicDidJsonUrl" -ForegroundColor White
Write-Host "  Local backup : $didJsonPath" -ForegroundColor Gray
Write-Host "  Portal       : $staticWebAppPortalUrl" -ForegroundColor Gray

Write-Host "`n🌐 DNS Records:" -ForegroundColor Yellow
if ($domainValidationToken) {
    Write-Host "  TXT Name  : $txtRecordLabel" -ForegroundColor White
    Write-Host "  TXT Value : $domainValidationToken" -ForegroundColor White
}
if ($hostParts.Count -ge 3) {
    Write-Host "  Host/Name : $dnsHostName" -ForegroundColor White
    Write-Host "  Type      : CNAME" -ForegroundColor White
} else {
    Write-Host "  Host/Name : @ (root - use ALIAS/ANAME if your provider supports it)" -ForegroundColor White
    Write-Host "  Type      : CNAME / ALIAS / ANAME" -ForegroundColor White
}
Write-Host "  Value     : $publicDnsTarget" -ForegroundColor White
Write-Host "  TTL       : 3600" -ForegroundColor White

Write-Host "`n📝 Next Steps:" -ForegroundColor Cyan
if ($didValidationSucceeded) {
    Write-Host "  1. Create verifiable credentials in the Microsoft Entra admin center:" -ForegroundColor White
} else {
    $postValidationStepNumber = 7
    if ($domainValidationToken) {
        Write-Host "  1. Create or confirm the TXT validation record above." -ForegroundColor White
        Write-Host "  2. Create or update the DNS CNAME record above so it points to the Static Web App." -ForegroundColor White
        Write-Host "  3. Wait for Azure Static Web Apps to finish validating the hostname and serving the certificate." -ForegroundColor White
        Write-Host "  4. Ensure $publicDidJsonUrl is reachable over HTTPS." -ForegroundColor White
        Write-Host "  5. Ensure $publicDidConfigurationUrl is reachable over HTTPS." -ForegroundColor White
        Write-Host "  6. Rerun this script or call validateWellKnownDidConfiguration once DNS and TLS are ready." -ForegroundColor White
    } else {
        $postValidationStepNumber = 8
        Write-Host "  1. Run the script again so it can request the Static Web App TXT validation token." -ForegroundColor White
        Write-Host "  2. Create the TXT validation record once the script displays it." -ForegroundColor White
        Write-Host "  3. Create or update the DNS CNAME record above so it points to the Static Web App." -ForegroundColor White
        Write-Host "  4. Wait for Azure Static Web Apps to finish validating the hostname and serving the certificate." -ForegroundColor White
        Write-Host "  5. Ensure $publicDidJsonUrl is reachable over HTTPS." -ForegroundColor White
        Write-Host "  6. Ensure $publicDidConfigurationUrl is reachable over HTTPS." -ForegroundColor White
        Write-Host "  7. Rerun this script or call validateWellKnownDidConfiguration once DNS and TLS are ready." -ForegroundColor White
    }
    Write-Host "  Custom certificate option:" -ForegroundColor White
    Write-Host "     $staticWebAppCustomDomainsPortalUrl" -ForegroundColor Gray
    Write-Host "     You can use your own certificate there, including a one-label wildcard certificate, and the script will accept it if it matches $hostname." -ForegroundColor Gray
    Write-Host "  $postValidationStepNumber. After validation succeeds, create verifiable credentials in the Microsoft Entra admin center:" -ForegroundColor White
}
Write-Host "     https://entra.microsoft.com -> Verified ID -> Credentials -> + Add credential" -ForegroundColor Gray

Write-Host ("`n{0}" -f $(if ($didValidationSucceeded) { "✅ Setup complete!" } else { "⏸ Setup paused. Resume when DNS/TLS is ready." })) -ForegroundColor $summaryColor
Write-Host ""

} finally {
    if ($temporaryVerifiedIdApp -and $cleanupGraphToken) {
        Write-StepHeader "Cleanup: Temporary Verified ID Setup App"
        Write-Info "Removing temporary app registration and service principal"
        Remove-TemporaryVerifiedIdAdminApp -GraphAccessToken $cleanupGraphToken -TemporaryApp $temporaryVerifiedIdApp
    }
}

#endregion
