#Requires -Version 7.6

<#
.SYNOPSIS
    Sets up Azure resources and permissions for Key Vault-backed passkey registration.

.DESCRIPTION
    This script automates the setup of all prerequisites needed to register passkeys
    with private keys secured in Azure Key Vault. It uses only Microsoft Graph and
    Azure REST APIs for maximum simplicity.

    The script:
    1. Creates or validates service principal
    2. Adds Microsoft Graph API permission for passkey management
    3. Attempts to grant admin consent automatically (if user has permissions)
    4. Creates resource group and Key Vault with RBAC authorization
    5. Assigns Key Vault Crypto Officer role to service principal
    6. Generates client secret
    7. Outputs all parameters needed for Register-EntraSoftwarePasskey.ps1

    The script checks for existing resources and reuses them when possible.
    Before any provisioning I/O, client-secret creation requires -PassThru to return
    its unrecoverable value. Otherwise use -SkipSecret or -SkipServicePrincipal.
    Default -WhatIf remains a no-I/O preview without those switches.

.PARAMETER SubscriptionId
    Azure subscription ID. If not provided, uses current context.

.PARAMETER ResourceGroupName
    Name of resource group for Key Vault. Default: rg-passkey-keyvault

.PARAMETER KeyVaultName
    Name of Key Vault. Must be globally unique. Default: kv-passkey-[random]

.PARAMETER Location
    Azure region for resources. Default: eastus

.PARAMETER ServicePrincipalName
    Display name for service principal. Default: KeyVault-Passkey-Service

.PARAMETER KeyVaultSku
    Key Vault SKU tier. Valid values: standard, premium. Default: standard
    Premium SKU is required for HSM-backed keys and provides additional security features.

.PARAMETER EnablePurgeProtection
    Enable purge protection to prevent permanent deletion during soft-delete retention period.
    Recommended for production environments. Once enabled, cannot be disabled. Default: true

.PARAMETER PassThru
    Returns the provisioning result, including a newly generated client secret when not skipped.
    Required when creating a new client secret. The secret is never printed to diagnostic
    streams; store the returned value securely.

.PARAMETER SecretExpirationMonths
    Client secret expiration in months. Default: 12

.EXAMPLE
    .\Initialize-EntraPasskeyKeyVault.ps1 -SkipSecret

    Uses defaults with Standard SKU and skips creating an unneeded client secret.

.EXAMPLE
    .\Initialize-EntraPasskeyKeyVault.ps1 -KeyVaultName "my-passkey-vault" -Location "westus2" -SkipSecret

    Creates resources with custom Key Vault name and location.

.EXAMPLE
    .\Initialize-EntraPasskeyKeyVault.ps1 -KeyVaultSku "premium" -SkipSecret

    Creates a Premium vault, which permits EC-HSM keys. Registration currently creates EC keys.

.EXAMPLE
    .\Initialize-EntraPasskeyKeyVault.ps1 -EnablePurgeProtection $false -SkipSecret

    Creates Key Vault without purge protection (not recommended for production).

.NOTES
    Author: Nathan McNulty
    Date: February 6, 2026

    Prerequisites:
    - Microsoft.Graph.Authentication and Az.Accounts modules installed
    - Logged in to Microsoft Graph and Azure
    - Application.ReadWrite.All permission (to create app)
    - AppRoleAssignment.ReadWrite.All permission (to grant consent, optional)
    - Contributor or Owner on Azure subscription (to create resources)

    Research provisioning uses RBAC and soft-delete configuration. It is not a
    supported security service and does not claim benchmark or production compliance.
    Premium vault SKU permits EC-HSM keys, but registration currently requests EC keys.

    WARNING: Purge protection cannot be disabled once enabled on a Key Vault.
    This is intentional to protect against insider threats and accidental deletion.

    Research-only command. WhatIf performs no authentication, network requests or output writes.
    Registration uses none attestation with AT-only flags (0x40), without UP or UV claims.
    Initialization may grant app permissions and create a client secret unless those steps are skipped.
    Client-secret creation requires -PassThru; otherwise use -SkipSecret or -SkipServicePrincipal.
    Capture the returned configuration and store the secret securely; it cannot be retrieved again.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-passkey-keyvault",

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",

    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalName = "KeyVault-Passkey-Service",

    [Parameter(Mandatory = $false)]
    [ValidateSet("standard", "premium")]
    [string]$KeyVaultSku = "standard",

    [Parameter(Mandatory = $false)]
    [bool]$EnablePurgeProtection = $true,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 24)]
    [int]$SecretExpirationMonths = 12,

    [Parameter(Mandatory = $false)]
    [switch]$SkipServicePrincipal,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSecret,

    [Parameter(Mandatory = $false)]
    [switch]$SkipKeyVault,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

# Generated by build/build.ps1. DO NOT EDIT.
# Passkey source version: 0.1.0
# Edit the following source files, then run build/build.ps1:
#   powershell/entrypoints/entra/Initialize-EntraPasskeyKeyVault.ps1
#   powershell/src/Common/Values.ps1
#   powershell/src/KeyVault/Reference.ps1
#   powershell/src/KeyVault/ProvisioningTransport.ps1
#   powershell/src/KeyVault/ProvisioningApplication.ps1
#   powershell/src/KeyVault/ProvisioningResources.ps1
#   powershell/src/KeyVault/ProvisioningSecrets.ps1
#   powershell/src/Public/Initialize-EntraPasskeyKeyVault.ps1

# Source: powershell/src/Common/Values.ps1
function ConvertTo-PlainTextValue {
    param(
        [Parameter(Mandatory = $false)]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string]) {
        return $Value
    }

    if ($Value -is [System.Security.SecureString]) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    throw "PrivateKey must be either a string or SecureString. Received: $($Value.GetType().FullName)"
}

function Normalize-OptionalString {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $trimmedValue = $Value.Trim()
    if ($trimmedValue.Length -eq 0) {
        return $null
    }

    return $trimmedValue
}

function Get-HttpErrorMessage {
    param(
        [Parameter(Mandatory)]
        $ErrorRecord
    )

    # Exceptions and server bodies may echo bearer material. Never forward them to logs.
    return 'Request failed; server details suppressed.'
}
# End source: powershell/src/Common/Values.ps1

# Source: powershell/src/KeyVault/Reference.ps1
function Resolve-KeyVaultReference {
    param(
        [string]$VaultName,
        [string]$KeyName,
        [string]$KeyId
    )

    $resolvedVaultName = Normalize-OptionalString $VaultName
    $resolvedKeyName = Normalize-OptionalString $KeyName
    $resolvedKeyId = Normalize-OptionalString $KeyId

    # Match the original text before URI normalization can hide escaped or dot segments.
    # Public Azure only: sovereign-cloud vaults require a separately reviewed audience/host policy.
    $referenceValue = if ($resolvedKeyId) { $resolvedKeyId } elseif ($resolvedKeyName -match '^https?://') { $resolvedKeyName } else { $null }
    if ($referenceValue) {
        if ($referenceValue -cnotmatch '^https://([a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9])\.vault\.azure\.net(?::443)?/keys/([a-zA-Z0-9-]{1,127})(?:/([a-fA-F0-9]{32}))?$') {
            throw 'Invalid Key Vault key reference: expected an HTTPS public-Azure vault key URL.'
        }
        $urlVault = $Matches[1]
        $urlKey = $Matches[2]
        $urlVersion = $Matches[3]
        if (($resolvedVaultName -and $resolvedVaultName -ine $urlVault) -or
            ($resolvedKeyName -and $resolvedKeyName -notmatch '^https?://' -and $resolvedKeyName -cne $urlKey) -or
            ($resolvedKeyId -and $resolvedKeyName -match '^https?://' -and $resolvedKeyName -cne $resolvedKeyId)) {
            throw 'Key Vault metadata conflicts with keyId. Refusing to change the registered signing key.'
        }
        $resolvedVaultName = $urlVault.ToLowerInvariant()
        $resolvedKeyName = $urlKey
        $resolvedKeyId = "https://$resolvedVaultName.vault.azure.net/keys/$resolvedKeyName"
        if ($urlVersion) { $resolvedKeyId += "/$urlVersion" }
    }
    if ($resolvedVaultName -cnotmatch '^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$' -or $resolvedVaultName -match '--' -or
        $resolvedKeyName -cnotmatch '^[a-zA-Z0-9-]{1,127}$') {
        throw 'Invalid or incomplete Key Vault vaultName/keyName.'
    }
    if (-not $resolvedKeyId) {
        $resolvedKeyId = "https://$($resolvedVaultName.ToLowerInvariant()).vault.azure.net/keys/$resolvedKeyName"
    }
    return @{ vaultName = $resolvedVaultName; keyName = $resolvedKeyName; keyId = $resolvedKeyId }
}
# End source: powershell/src/KeyVault/Reference.ps1

# Source: powershell/src/KeyVault/ProvisioningTransport.ps1
function Get-EntraKeyVaultProvisioningErrorMessage {
    param($Content)
    if (-not $Content) { return 'Unknown error' }
    try { $value = if ($Content -is [string]) { $Content | ConvertFrom-Json -ErrorAction Stop } else { $Content } }
    catch { return 'Azure returned a non-JSON error response.' }
    $errorBody = if ($value.error) { $value.error } else { $value }
    if ($errorBody.code -and $errorBody.message) { return "$($errorBody.code): $($errorBody.message)" }
    if ($errorBody.message) { return [string]$errorBody.message }
    return 'Azure returned an unspecified error.'
}

function Test-EntraKeyVaultProvisioningNotFound {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    if ($ErrorRecord.Exception.Response -and [int]$ErrorRecord.Exception.Response.StatusCode -eq 404) { return $true }
    ($ErrorRecord.Exception.Message + ' ' + $ErrorRecord.ErrorDetails.Message) -match '(^|\D)404(\D|$)|ResourceNotFound|was not found'
}

function Invoke-EntraKeyVaultProvisioningArmRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT', 'PATCH')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [string]$Payload,
        [ValidateRange(1, 10)][int]$MaxRetries = 3,
        [ValidateRange(0, 60)][int]$RetryDelaySeconds = 2
    )
    $parsed = [uri]$Uri
    if ($parsed.Scheme -ne 'https' -or $parsed.Host -ne 'management.azure.com' -or $parsed.Port -ne 443 -or $parsed.UserInfo) {
        throw 'Refusing untrusted Azure management endpoint.'
    }
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $parameters = @{ Method = $Method; Uri = $Uri; ErrorAction = 'Stop'; Verbose = $false; Debug = $false }
            if ($Payload) { $parameters.Payload = $Payload }
            $response = Invoke-AzRestMethod @parameters
            if ([int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 300) { return $response }
            $message = Get-EntraKeyVaultProvisioningErrorMessage -Content $response.Content
            throw "HTTP $($response.StatusCode): $message"
        } catch {
            $transient = $_.Exception.Message -match '^HTTP (429|500|502|503|504):|temporarily unavailable|timed out|timeout|connection.*closed|transport connection'
            if (-not $transient -or $attempt -eq $MaxRetries) { throw }
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

function Get-EntraKeyVaultProvisioningContext {
    [CmdletBinding()]
    param([string]$SubscriptionId, [switch]$SkipKeyVault)
    $graph = Get-MgContext -Verbose:$false -Debug:$false -ErrorAction Stop
    if (-not $graph -or -not $graph.TenantId) {
        Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All' -NoWelcome -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
        $graph = Get-MgContext -Verbose:$false -Debug:$false -ErrorAction Stop
    }
    if (-not $graph.TenantId) { throw 'Microsoft Graph connection did not establish a tenant context.' }
    $azure = $null
    if (-not $SkipKeyVault) {
        $azure = Get-AzContext -Verbose:$false -Debug:$false -ErrorAction Stop
        if (-not $azure -or -not $azure.Account) {
            Connect-AzAccount -WarningAction SilentlyContinue -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
            $azure = Get-AzContext -Verbose:$false -Debug:$false -ErrorAction Stop
        }
        if (-not $azure.Account) { throw 'Azure connection did not establish an account context.' }
        if ($azure.Tenant.Id -ne $graph.TenantId) {
            Set-AzContext -Tenant $graph.TenantId -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
            $azure = Get-AzContext -Verbose:$false -Debug:$false -ErrorAction Stop
        }
        if ($SubscriptionId -and $azure.Subscription.Id -ne $SubscriptionId) {
            Set-AzContext -SubscriptionId $SubscriptionId -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
            $azure = Get-AzContext -Verbose:$false -Debug:$false -ErrorAction Stop
        }
        if ($azure.Tenant.Id -ne $graph.TenantId -or ($SubscriptionId -and $azure.Subscription.Id -ne $SubscriptionId)) {
            throw 'Azure context does not match the requested subscription and Microsoft Graph tenant.'
        }
        $SubscriptionId = [string]$azure.Subscription.Id
        if (-not $SubscriptionId) { throw 'Azure context has no subscription.' }
    }
    [pscustomobject]@{
        TenantId = [string]$graph.TenantId; SubscriptionId = $SubscriptionId
        CanGrantConsent = $graph.Scopes -contains 'AppRoleAssignment.ReadWrite.All'
    }
}
# End source: powershell/src/KeyVault/ProvisioningTransport.ps1

# Source: powershell/src/KeyVault/ProvisioningApplication.ps1
function Initialize-EntraKeyVaultProvisioningApplication {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServicePrincipalName, [bool]$CanGrantConsent)
    $name = $ServicePrincipalName.Replace("'", "''")
    $filter = [uri]::EscapeDataString("displayName eq '$name'")
    $apps = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=$filter" -Verbose:$false -Debug:$false -ErrorAction Stop
    if (@($apps.value).Count -gt 1) { throw 'Multiple applications have this display name; refusing an ambiguous target.' }
    if ($apps.value) { $app = @($apps.value)[0] }
    else {
        $body = @{ displayName = $ServicePrincipalName } | ConvertTo-Json
        $app = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications' -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop
    }
    $filter = [uri]::EscapeDataString("appId eq '$($app.appId)'")
    $principals = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter" -Verbose:$false -Debug:$false -ErrorAction Stop
    if (@($principals.value).Count -gt 1) { throw 'Multiple service principals have this application ID.' }
    if ($principals.value) { $principal = @($principals.value)[0] }
    else {
        $body = @{ appId = $app.appId } | ConvertTo-Json
        $principal = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop
    }
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $filter = [uri]::EscapeDataString("appId eq '$graphAppId'")
    $graphPrincipals = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$filter" -Verbose:$false -Debug:$false -ErrorAction Stop
    $graph = @($graphPrincipals.value)[0]
    $permission = @($graph.appRoles | Where-Object { $_.value -eq 'UserAuthenticationMethod.ReadWrite.All' -and $_.allowedMemberTypes -contains 'Application' })[0]
    if (-not $permission.id) { throw 'Microsoft Graph passkey-management application role was not found.' }
    # Preserve permissions already present on a reused application.
    $required = [System.Collections.Generic.List[object]]::new()
    $graphAccess = [System.Collections.Generic.List[object]]::new()
    foreach ($resource in @($app.requiredResourceAccess)) {
        if ($null -eq $resource) { continue }
        if ($resource.resourceAppId -eq $graphAppId) {
            foreach ($access in @($resource.resourceAccess)) { $graphAccess.Add($access) }
        } else { $required.Add($resource) }
    }
    if (-not @($graphAccess | Where-Object { $_.id -eq $permission.id -and $_.type -eq 'Role' }).Count) {
        $graphAccess.Add(@{ id = $permission.id; type = 'Role' })
    }
    $required.Add(@{ resourceAppId = $graphAppId; resourceAccess = @($graphAccess.ToArray()) })
    $body = @{ requiredResourceAccess = @($required.ToArray()) } | ConvertTo-Json -Depth 10
    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
    $consentGranted = $false
    if ($CanGrantConsent) {
        try {
            $grants = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($principal.id)/appRoleAssignments" -Verbose:$false -Debug:$false -ErrorAction Stop
            $existing = $grants.value | Where-Object { $_.appRoleId -eq $permission.id -and $_.resourceId -eq $graph.id }
            if (-not $existing) {
                $body = @{ principalId = $principal.id; resourceId = $graph.id; appRoleId = $permission.id } | ConvertTo-Json
                Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($principal.id)/appRoleAssignments" -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop | Out-Null
            }
            $consentGranted = $true
        } catch { Write-Warning 'Automatic admin consent failed; manual consent is required.' }
    } else { Write-Warning 'Admin consent must be granted manually.' }
    [pscustomobject]@{ ApplicationId = [string]$app.appId; ApplicationObjectId = [string]$app.id; ServicePrincipalId = [string]$principal.id; ConsentGranted = $consentGranted }
}
# End source: powershell/src/KeyVault/ProvisioningApplication.ps1

# Source: powershell/src/KeyVault/ProvisioningResources.ps1
function Initialize-EntraKeyVaultProvisioningResourceGroup {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Location)
    $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$([uri]::EscapeDataString($ResourceGroupName))?api-version=2021-04-01"
    try { $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri }
    catch {
        if (-not (Test-EntraKeyVaultProvisioningNotFound -ErrorRecord $_)) { throw }
        $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method PUT -Uri $uri -Payload (@{ location = $Location } | ConvertTo-Json)
    }
}

function Initialize-EntraKeyVaultProvisioningVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$Location, [ValidateSet('standard', 'premium')][string]$Sku = 'standard',
        [bool]$EnablePurgeProtection = $true
    )
    $scope = "/subscriptions/$SubscriptionId/resourceGroups/$([uri]::EscapeDataString($ResourceGroupName))/providers/Microsoft.KeyVault/vaults/$VaultName"
    $uri = "https://management.azure.com$scope`?api-version=2023-02-01"
    try {
        $response = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri
        $vault = $response.Content | ConvertFrom-Json -ErrorAction Stop
        if ($vault.properties.tenantId -and $vault.properties.tenantId -ne $TenantId) { throw 'Existing Key Vault belongs to a different tenant.' }
        if (-not $vault.properties.enableRbacAuthorization) { throw 'Existing Key Vault must use RBAC authorization.' }
        if (-not $vault.properties.enablePurgeProtection) { Write-Warning 'Existing Key Vault does not have purge protection enabled.' }
    } catch {
        if (-not (Test-EntraKeyVaultProvisioningNotFound -ErrorRecord $_)) { throw }
        $nameUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2024-11-01"
        $body = @{ name = $VaultName; type = 'Microsoft.KeyVault/vaults' } | ConvertTo-Json
        $response = Invoke-EntraKeyVaultProvisioningArmRequest -Method POST -Uri $nameUri -Payload $body
        $available = $response.Content | ConvertFrom-Json -ErrorAction Stop
        if ($available.nameAvailable -ne $true) { throw 'Key Vault name is not available.' }
        $body = @{
            location = $Location
            properties = @{
                sku = @{ family = 'A'; name = $Sku.ToLowerInvariant() }; tenantId = $TenantId
                enableRbacAuthorization = $true; softDeleteRetentionInDays = 90; enablePurgeProtection = $EnablePurgeProtection
            }
        } | ConvertTo-Json -Depth 10
        $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method PUT -Uri $uri -Payload $body
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            try { $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri; break }
            catch { if ($attempt -eq 12) { Write-Warning 'Key Vault readiness could not be confirmed; allow time for provisioning.' } }
        }
    }
    $scope
}

function Initialize-EntraKeyVaultProvisioningRole {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$VaultScope, [Parameter(Mandatory)][string]$ServicePrincipalId)
    $filter = [uri]::EscapeDataString("roleName eq 'Key Vault Crypto Officer'")
    $definitionUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions?`$filter=$filter&api-version=2022-04-01"
    $definitions = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $definitionUri
    $roles = @(($definitions.Content | ConvertFrom-Json -ErrorAction Stop).value)
    if ($roles.Count -ne 1 -or -not $roles[0].id) { throw 'Key Vault Crypto Officer role definition was missing or ambiguous.' }
    $roleId = [string]$roles[0].id
    $uri = "https://management.azure.com$VaultScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    $response = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri
    $roles = ($response.Content | ConvertFrom-Json -ErrorAction Stop).value
    $existing = $roles | Where-Object { $_.properties.principalId -eq $ServicePrincipalId -and $_.properties.roleDefinitionId -eq $roleId }
    if ($existing) { return }
    $assignment = [guid]::NewGuid().ToString()
    $createUri = "https://management.azure.com$VaultScope/providers/Microsoft.Authorization/roleAssignments/$assignment`?api-version=2022-04-01"
    $body = @{ properties = @{ roleDefinitionId = $roleId; principalId = $ServicePrincipalId; principalType = 'ServicePrincipal' } } | ConvertTo-Json
    $null = Invoke-EntraKeyVaultProvisioningArmRequest -Method PUT -Uri $createUri -Payload $body
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        Start-Sleep -Seconds 5
        try {
            $response = Invoke-EntraKeyVaultProvisioningArmRequest -Method GET -Uri $uri
            $roles = ($response.Content | ConvertFrom-Json -ErrorAction Stop).value
            if ($roles | Where-Object { $_.properties.principalId -eq $ServicePrincipalId -and $_.properties.roleDefinitionId -eq $roleId }) { return }
        } catch { Write-Verbose 'Waiting for Key Vault role assignment propagation.' }
    }
    Write-Warning 'Key Vault role assignment propagation could not be confirmed.'
}
# End source: powershell/src/KeyVault/ProvisioningResources.ps1

# Source: powershell/src/KeyVault/ProvisioningSecrets.ps1
function New-EntraKeyVaultProvisioningSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ApplicationObjectId,
        [Parameter(Mandatory)][string]$ApplicationId,
        [Parameter(Mandatory)][string]$TenantId,
        [ValidateRange(1, 24)][int]$ExpirationMonths = 12,
        [switch]$SkipKeyVault
    )
    $expiration = (Get-Date).ToUniversalTime().AddMonths($ExpirationMonths).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $body = @{ passwordCredential = @{ displayName = 'Created by Initialize-EntraPasskeyKeyVault'; endDateTime = $expiration } } | ConvertTo-Json
    $secret = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$ApplicationObjectId/addPassword" -Body $body -Verbose:$false -Debug:$false -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace([string]$secret.secretText) -or $secret.secretText -match '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$') {
        throw 'Microsoft Graph did not return the new client secret value.'
    }
    foreach ($scope in @('https://graph.microsoft.com/.default', $(if (-not $SkipKeyVault) { 'https://vault.azure.net/.default' }))) {
        if (-not $scope) { continue }
        $ready = $false
        for ($attempt = 1; $attempt -le 12; $attempt++) {
            Start-Sleep -Seconds 5
            try {
                $token = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST `
                    -Body @{ grant_type = 'client_credentials'; client_id = $ApplicationId; client_secret = $secret.secretText; scope = $scope } `
                    -ContentType 'application/x-www-form-urlencoded' -MaximumRedirection 0 -ConnectionTimeoutSeconds 60 -OperationTimeoutSeconds 60 -Verbose:$false -Debug:$false -ErrorAction Stop
                if ($token.access_token) { $ready = $true; break }
            } catch { Write-Verbose 'Waiting for the new client credential to replicate.' }
        }
        if (-not $ready) { Write-Warning 'New client credential token acquisition could not be confirmed; allow time for replication.' }
    }
    [pscustomobject]@{ ClientSecret = [string]$secret.secretText; SecretExpiration = $expiration }
}
# End source: powershell/src/KeyVault/ProvisioningSecrets.ps1

# Source: powershell/src/Public/Initialize-EntraPasskeyKeyVault.ps1
<#
.SYNOPSIS
    Sets up Azure resources and permissions for Key Vault-backed passkey registration.
.DESCRIPTION
    Explicit research command. Supports WhatIf without authentication, network or output writes.
    Can provision resources and grant app permissions. Client secret creation requires -PassThru.
    Use -SkipSecret or -SkipServicePrincipal when no new client secret is needed.
#>
function Initialize-EntraPasskeyKeyVault {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$ResourceGroupName = "rg-passkey-keyvault",

    [Parameter(Mandatory = $false)]
    [string]$KeyVaultName,

    [Parameter(Mandatory = $false)]
    [string]$Location = "eastus",

    [Parameter(Mandatory = $false)]
    [string]$ServicePrincipalName = "KeyVault-Passkey-Service",

    [Parameter(Mandatory = $false)]
    [ValidateSet("standard", "premium")]
    [string]$KeyVaultSku = "standard",

    [Parameter(Mandatory = $false)]
    [bool]$EnablePurgeProtection = $true,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 24)]
    [int]$SecretExpirationMonths = 12,

    [Parameter(Mandatory = $false)]
    [switch]$SkipServicePrincipal,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSecret,

    [Parameter(Mandatory = $false)]
    [switch]$SkipKeyVault,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)
    if ($SkipServicePrincipal -and $SkipKeyVault) { throw 'Cannot skip both service-principal and Key Vault provisioning.' }
    if (-not $PSCmdlet.ShouldProcess("$ServicePrincipalName / $KeyVaultName", 'Connect, provision Azure and Graph resources, grant permissions, and generate a client secret unless skipped')) { return }
    if (-not $SkipServicePrincipal -and -not $SkipSecret -and -not $PassThru) {
        throw 'Client secret creation requires -PassThru to return its unrecoverable value. Otherwise specify -SkipSecret or -SkipServicePrincipal. No provisioning was started.'
    }
    $context = $null; $application = $null; $secret = $null
    try {
        if ($SkipServicePrincipal -and $SkipSecret) { Write-Warning 'SkipSecret is redundant when SkipServicePrincipal is set.' }
        if (-not $SkipKeyVault) {
            if (-not $KeyVaultName) { $KeyVaultName = "kv-passkey-$(Get-Random -Minimum 1000 -Maximum 9999)" }
            $null = Resolve-KeyVaultReference -VaultName $KeyVaultName -KeyName 'provisioning-validation'
        }
        $context = Get-EntraKeyVaultProvisioningContext -SubscriptionId $SubscriptionId -SkipKeyVault:$SkipKeyVault
        $application = $null; $secret = $null
        if (-not $SkipServicePrincipal) {
            $application = Initialize-EntraKeyVaultProvisioningApplication -ServicePrincipalName $ServicePrincipalName -CanGrantConsent $context.CanGrantConsent
        }
        if (-not $SkipKeyVault) {
            Initialize-EntraKeyVaultProvisioningResourceGroup -SubscriptionId $context.SubscriptionId -ResourceGroupName $ResourceGroupName -Location $Location
            $scope = Initialize-EntraKeyVaultProvisioningVault -SubscriptionId $context.SubscriptionId -TenantId $context.TenantId -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -Location $Location -Sku $KeyVaultSku -EnablePurgeProtection $EnablePurgeProtection
            if ($application) { Initialize-EntraKeyVaultProvisioningRole -SubscriptionId $context.SubscriptionId -VaultScope $scope -ServicePrincipalId $application.ServicePrincipalId }
        }
        if ($application -and -not $SkipSecret) {
            $secret = New-EntraKeyVaultProvisioningSecret -ApplicationObjectId $application.ApplicationObjectId -ApplicationId $application.ApplicationId -TenantId $context.TenantId -ExpirationMonths $SecretExpirationMonths -SkipKeyVault:$SkipKeyVault
            Write-Host "Client secret created; expires $($secret.SecretExpiration)."
        }
        Write-Host 'Explicit provisioning workflow complete. This research sample does not establish production readiness.'
        if ($PassThru) {
            [pscustomobject]@{
                TenantId = $context.TenantId; SubscriptionId = $context.SubscriptionId
                ResourceGroupName = if (-not $SkipKeyVault) { $ResourceGroupName } else { $null }
                KeyVaultName = if (-not $SkipKeyVault) { $KeyVaultName } else { $null }
                KeyVaultSku = if (-not $SkipKeyVault) { $KeyVaultSku } else { $null }
                Location = if (-not $SkipKeyVault) { $Location } else { $null }
                ServicePrincipalName = if ($application) { $ServicePrincipalName } else { $null }
                ApplicationId = $application.ApplicationId; ServicePrincipalId = $application.ServicePrincipalId
                ClientSecret = $secret.ClientSecret; SecretExpiration = $secret.SecretExpiration
                UseKeyVault = -not $SkipKeyVault; ConsentGranted = [bool]$application.ConsentGranted
            }
        }
    } catch {
        $exception = [System.InvalidOperationException]::new('Key Vault provisioning failed; service details suppressed. Resources, permissions or client credentials may already have been created. No rollback was attempted.')
        $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new($exception, 'KeyVaultProvisioningFailed', [System.Management.Automation.ErrorCategory]::InvalidOperation, $null))
    } finally {
        if ($secret) { $secret.ClientSecret = $null }
        $application = $null; $context = $null
    }

}
# End source: powershell/src/Public/Initialize-EntraPasskeyKeyVault.ps1

# Invoke public command
Initialize-EntraPasskeyKeyVault @PSBoundParameters
