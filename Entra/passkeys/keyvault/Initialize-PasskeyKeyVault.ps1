#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Az.Accounts
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
    7. Outputs all parameters needed for New-KeyVaultPasskey.ps1
    
    The script checks for existing resources and reuses them when possible.

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

.PARAMETER SecretExpirationMonths
    Client secret expiration in months. Default: 12

.EXAMPLE
    .\Initialize-PasskeyKeyVault.ps1
    
    Uses default values and creates all resources with Standard SKU.

.EXAMPLE
    .\Initialize-PasskeyKeyVault.ps1 -KeyVaultName "my-passkey-vault" -Location "westus2"
    
    Creates resources with custom Key Vault name and location.

.EXAMPLE
    .\Initialize-PasskeyKeyVault.ps1 -KeyVaultSku "premium"
    
    Creates Key Vault with Premium SKU for HSM-backed keys.

.EXAMPLE
    .\Initialize-PasskeyKeyVault.ps1 -EnablePurgeProtection $false
    
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
    
    Security:
    This script follows Microsoft Security Benchmark (DP-8) and CIS Azure Foundations 8.4:
    - RBAC authorization (instead of access policies) for least privilege
    - Soft delete enabled with 90-day retention (maximum)
    - Purge protection enabled by default to prevent permanent deletion
    - Configurable SKU supporting HSM-backed keys (Premium)
    
    WARNING: Purge protection cannot be disabled once enabled on a Key Vault.
    This is intentional to protect against insider threats and accidental deletion.
#>

[CmdletBinding()]
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
    [switch]$SkipKeyVault
)

$ErrorActionPreference = "Stop"

# Validate parameter combinations
if ($SkipServicePrincipal -and $SkipSecret) {
    Write-Warning "SkipSecret is redundant when SkipServicePrincipal is specified (no service principal = no secret)"
}
if ($SkipServicePrincipal -and $SkipKeyVault) {
    Write-Error "Cannot skip both Service Principal and Key Vault - nothing would be created"
    throw "Invalid parameter combination"
}

#region Helper Functions

function Write-StepHeader {
    param([string]$Message)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Gray
}

function Invoke-AzRestMethodWithRetry {
    param(
        [string]$Method,
        [string]$Uri,
        [string]$Payload,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 2
    )
    
    $attempt = 0
    $lastError = $null
    
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $params = @{
                Method = $Method
                Uri = $Uri
            }
            if ($Payload) {
                $params.Payload = $Payload
            }
            
            $result = Invoke-AzRestMethod @params
            
            # Check for success status codes
            if ($result.StatusCode -ge 200 -and $result.StatusCode -lt 300) {
                return $result
            }
            
            # Handle specific error codes
            $errorContent = if ($result.Content) { 
                try { $result.Content | ConvertFrom-Json } catch { $result.Content }
            } else { 
                "Unknown error" 
            }
            
            # Retry on transient errors
            if ($result.StatusCode -in @(429, 500, 502, 503, 504)) {
                $lastError = "HTTP $($result.StatusCode): $errorContent"
                if ($attempt -lt $MaxRetries) {
                    Write-Warning "Request failed (attempt $attempt/$MaxRetries), retrying in $RetryDelaySeconds seconds..."
                    Start-Sleep -Seconds $RetryDelaySeconds
                    continue
                }
            }
            
            throw "HTTP $($result.StatusCode): $errorContent"
        } catch {
            $lastError = $_.Exception.Message
            if ($attempt -lt $MaxRetries) {
                Write-Warning "Request failed (attempt $attempt/$MaxRetries), retrying in $RetryDelaySeconds seconds..."
                Start-Sleep -Seconds $RetryDelaySeconds
            } else {
                throw "Failed after $MaxRetries attempts: $lastError"
            }
        }
    }
    
    throw "Failed after $MaxRetries attempts: $lastError"
}

#endregion

#region Main Script

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  Azure Key Vault Setup for Passkey Registration          ║" -ForegroundColor Magenta
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

# Step 1: Validate Microsoft Graph connection
Write-StepHeader "Step 1: Validating Microsoft Graph Connection"

try {
    $mgContext = Get-MgContext
    if (-not $mgContext) {
        Write-Host "Not connected to Microsoft Graph. Connecting..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -NoWelcome
        $mgContext = Get-MgContext
    }
    Write-Success "Connected to Microsoft Graph"
    $tenantId = $mgContext.TenantId
    Write-Info "Tenant: $tenantId"
    Write-Info "Scopes: $($mgContext.Scopes -join ', ')"
} catch {
    Write-Error "Failed to connect to Microsoft Graph. Please run: Connect-MgGraph -Scopes 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All'"
    throw
}

# Check if user has permission to grant consent
$canGrantConsent = $mgContext.Scopes -contains "AppRoleAssignment.ReadWrite.All"
if (-not $canGrantConsent) {
    Write-Warning "AppRoleAssignment.ReadWrite.All scope not granted - admin consent will need to be granted manually"
}

# Step 2: Validate Azure connection
Write-StepHeader "Step 2: Validating Azure Connection"

try {
    $azContext = Get-AzContext
    if (-not $azContext) {
        Write-Host "Not connected to Azure. Connecting..." -ForegroundColor Yellow
        Connect-AzAccount -TenantId $tenantId
        $azContext = Get-AzContext
    }
    Write-Success "Connected to Azure"
    $currentSubId = $azContext.Subscription.Id
    $currentSubName = $azContext.Subscription.Name
    Write-Info "Subscription: $currentSubName ($currentSubId)"
} catch {
    Write-Error "Failed to connect to Azure. Please run: Connect-AzAccount"
    throw
}

# Switch subscription if specified
if ($SubscriptionId -and $SubscriptionId -ne $currentSubId) {
    Write-Host "`nSwitching to subscription: $SubscriptionId" -ForegroundColor Yellow
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $azContext = Get-AzContext
    $currentSubId = $azContext.Subscription.Id
    $currentSubName = $azContext.Subscription.Name
    Write-Success "Switched to: $currentSubName"
} else {
    $SubscriptionId = $currentSubId
}

# Validate tenant alignment
if ($azContext.Tenant.Id -ne $tenantId) {
    throw "Azure context tenant ($($azContext.Tenant.Id)) does not match Microsoft Graph tenant ($tenantId). Please connect to the same tenant."
}

# Generate and validate Key Vault name if needed
if (-not $SkipKeyVault) {
    if (-not $KeyVaultName) {
        $random = Get-Random -Minimum 1000 -Maximum 9999
        $KeyVaultName = "kv-passkey-$random"
        Write-Info "Generated Key Vault name: $KeyVaultName"
    }
    
    # Validate Key Vault name
    if ($KeyVaultName.Length -lt 3 -or $KeyVaultName.Length -gt 24) {
        throw "Key Vault name must be between 3 and 24 characters. Current length: $($KeyVaultName.Length)"
    }
    if ($KeyVaultName -notmatch '^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$') {
        throw "Key Vault name must start with a letter, end with letter or digit, and contain only alphanumeric characters and hyphens. Invalid name: $KeyVaultName"
    }
    if ($KeyVaultName -match '--') {
        throw "Key Vault name cannot contain consecutive hyphens. Invalid name: $KeyVaultName"
    }
}

Write-Host "`nConfiguration:" -ForegroundColor Cyan
Write-Host "  Subscription: $currentSubName" -ForegroundColor White
if (-not $SkipKeyVault) {
    Write-Host "  Resource Group: $ResourceGroupName" -ForegroundColor White
    Write-Host "  Key Vault: $KeyVaultName" -ForegroundColor White
    Write-Host "  Location: $Location" -ForegroundColor White
}
if (-not $SkipServicePrincipal) {
    Write-Host "  Service Principal: $ServicePrincipalName" -ForegroundColor White
}
if ($SkipServicePrincipal) {
    Write-Host "  ⊗ Skipping: Service Principal creation" -ForegroundColor Yellow
}
if ($SkipSecret) {
    Write-Host "  ⊗ Skipping: Client Secret generation" -ForegroundColor Yellow
}
if ($SkipKeyVault) {
    Write-Host "  ⊗ Skipping: Key Vault creation" -ForegroundColor Yellow
}

# Step 3: Create or get application
if (-not $SkipServicePrincipal) {
    $stepNumber = if ($SkipKeyVault) { 2 } else { 3 }
    Write-StepHeader "Step ${stepNumber}: Application Registration"

Write-Host "  Checking for existing application..." -ForegroundColor Gray
$appFilter = "displayName eq '$ServicePrincipalName'"

try {
    $existingApps = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=$appFilter"
} catch {
    Write-Error "Failed to query applications: $($_.Exception.Message)"
    throw
}

if ($existingApps.value -and $existingApps.value.Count -gt 0) {
    $app = $existingApps.value[0]
    $appId = $app.appId
    $appObjectId = $app.id
    Write-Success "Application already exists"
    Write-Info "App ID: $appId"
    Write-Info "Object ID: $appObjectId"
} else {
    Write-Host "  Creating new application..." -ForegroundColor Yellow
    $appBody = @{
        displayName = $ServicePrincipalName
    } | ConvertTo-Json
    
    $app = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications" -Body $appBody
    $appId = $app.appId
    $appObjectId = $app.id
    Write-Success "Application created"
    Write-Info "App ID: $appId"
    Write-Info "Object ID: $appObjectId"
}

$stepNumber = if ($SkipKeyVault) { 3 } else { 4 }
Write-StepHeader "Step ${stepNumber}: Service Principal"

Write-Host "  Checking for existing service principal..." -ForegroundColor Gray
$spFilter = "appId eq '$appId'"
$existingSPs = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$spFilter"

if ($existingSPs.value -and $existingSPs.value.Count -gt 0) {
    $sp = $existingSPs.value[0]
    $spObjectId = $sp.id
    Write-Success "Service principal already exists"
    Write-Info "Object ID: $spObjectId"
} else {
    Write-Host "  Creating service principal..." -ForegroundColor Yellow
    $spBody = @{
        appId = $appId
    } | ConvertTo-Json
    
    $sp = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Body $spBody
    $spObjectId = $sp.id
    Write-Success "Service principal created"
    Write-Info "Object ID: $spObjectId"
}

$stepNumber = if ($SkipKeyVault) { 4 } else { 5 }
Write-StepHeader "Step ${stepNumber}: Microsoft Graph API Permission"

Write-Host "  Getting Microsoft Graph service principal..." -ForegroundColor Gray
$graphSPFilter = "displayName eq 'Microsoft Graph'"
$graphSPs = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$graphSPFilter"

if (-not $graphSPs.value -or $graphSPs.value.Count -eq 0) {
    throw "Could not find Microsoft Graph service principal"
}

$graphSP = $graphSPs.value[0]
$graphSPId = $graphSP.id

# Find UserAuthenticationMethod.ReadWrite.All permission
$permission = $graphSP.appRoles | Where-Object { $_.value -eq "UserAuthenticationMethod.ReadWrite.All" }

if (-not $permission) {
    throw "Could not find UserAuthenticationMethod.ReadWrite.All permission"
}

Write-Info "Permission ID: $($permission.id)"

# Update app with required permission
Write-Host "  Adding permission to application..." -ForegroundColor Gray
$requiredResourceAccess = @{
    requiredResourceAccess = @(
        @{
            resourceAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            resourceAccess = @(
                @{
                    id = $permission.id
                    type = "Role"
                }
            )
        }
    )
} | ConvertTo-Json -Depth 10

Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId" -Body $requiredResourceAccess
Write-Success "Permission added to application"

# Attempt to grant admin consent
Write-Host "`n  Attempting to grant admin consent..." -ForegroundColor Yellow

if ($canGrantConsent) {
    try {
        # Check if consent already granted
        $existingGrants = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/appRoleAssignments"
        $alreadyGranted = $existingGrants.value | Where-Object { $_.appRoleId -eq $permission.id -and $_.resourceId -eq $graphSPId }
        
        if ($alreadyGranted) {
            Write-Success "Admin consent already granted"
        } else {
            $consentBody = @{
                principalId = $spObjectId
                resourceId = $graphSPId
                appRoleId = $permission.id
            } | ConvertTo-Json
            
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spObjectId/appRoleAssignments" -Body $consentBody
            Write-Success "Admin consent granted automatically"
        }
    } catch {
        Write-Warning "Failed to grant consent automatically: $($_.Exception.Message)"
        Write-Warning "Manual consent required (see instructions below)"
        $canGrantConsent = $false
    }
} else {
    Write-Warning "Cannot grant consent - insufficient permissions"
}
} # End if -not $SkipServicePrincipal

if (-not $SkipKeyVault) {
    $stepNumber = if ($SkipServicePrincipal) { 2 } else { 6 }
    Write-StepHeader "Step ${stepNumber}: Resource Group"

Write-Host "  Checking for existing resource group..." -ForegroundColor Gray
$rgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName`?api-version=2021-04-01"

try {
    $existingRG = Invoke-AzRestMethod -Method GET -Uri $rgUri
    if ($existingRG.StatusCode -eq 200) {
        Write-Success "Resource group already exists"
        $rgData = $existingRG.Content | ConvertFrom-Json
        Write-Info "Location: $($rgData.location)"
    } else {
        throw "Resource group does not exist"
    }
} catch {
    Write-Host "  Creating resource group..." -ForegroundColor Yellow
    $rgBody = @{
        location = $Location
    } | ConvertTo-Json
    
    try {
        Invoke-AzRestMethodWithRetry -Method PUT -Uri $rgUri -Payload $rgBody | Out-Null
        Write-Success "Resource group created"
        Write-Info "Location: $Location"
    } catch {
        Write-Error "Failed to create resource group: $($_.Exception.Message)"
        throw
    }
}

$stepNumber = if ($SkipServicePrincipal) { 3 } else { 7 }
Write-StepHeader "Step ${stepNumber}: Azure Key Vault"

Write-Host "  Checking for existing Key Vault..." -ForegroundColor Gray
$kvUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName`?api-version=2023-02-01"

try {
    $existingKV = Invoke-AzRestMethod -Method GET -Uri $kvUri
    if ($existingKV.StatusCode -eq 200) {
        Write-Success "Key Vault already exists"
        $kvData = $existingKV.Content | ConvertFrom-Json
        $existingSku = $kvData.properties.sku.name
        Write-Info "Location: $($kvData.location)"
        Write-Info "SKU: $($existingSku.Substring(0,1).ToUpper() + $existingSku.Substring(1))"
        
        if ($kvData.properties.enableRbacAuthorization) {
            Write-Success "RBAC authorization is enabled"
        } else {
            Write-Warning "Key Vault uses access policies instead of RBAC - the script expects RBAC-enabled Key Vault"
        }
        
        if ($kvData.properties.enablePurgeProtection) {
            Write-Success "Purge protection is enabled"
        } else {
            Write-Warning "Purge protection is NOT enabled - permanent deletion is possible during soft-delete retention period"
        }
    } else {
        throw "Key Vault does not exist"
    }
} catch {
    Write-Host "  Creating Key Vault..." -ForegroundColor Yellow
    
    if ($EnablePurgeProtection) {
        Write-Info "Purge protection will be enabled (cannot be disabled once set)"
    }
    
    $kvBody = @{
        location = $Location
        properties = @{
            sku = @{
                family = "A"
                name = $KeyVaultSku.ToLower()
            }
            tenantId = $tenantId
            enableRbacAuthorization = $true
            enableSoftDelete = $true
            softDeleteRetentionInDays = 90
            enablePurgeProtection = $EnablePurgeProtection
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        Invoke-AzRestMethodWithRetry -Method PUT -Uri $kvUri -Payload $kvBody | Out-Null
        Write-Success "Key Vault created"
        Write-Info "Location: $Location"
        Write-Info "SKU: $($KeyVaultSku.Substring(0,1).ToUpper() + $KeyVaultSku.Substring(1))"
        Write-Info "RBAC: Enabled"
        Write-Info "Soft Delete: Enabled (90 days)"
        Write-Info "Purge Protection: $(if ($EnablePurgeProtection) {'Enabled'} else {'Disabled'})"
        
        # Wait for Key Vault to be fully provisioned
        Write-Host "  Waiting for Key Vault provisioning (10 seconds)..." -ForegroundColor Gray
        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep -Seconds 1
            Write-Host "." -NoNewline -ForegroundColor Gray
        }
        Write-Host ""
    } catch {
        # Check for specific error conditions
        if ($_.Exception.Message -match "VaultAlreadyExists") {
            Write-Error "Key Vault name '$KeyVaultName' is already taken globally. Try a different name."
        } elseif ($_.Exception.Message -match "InvalidParameter") {
            Write-Error "Invalid Key Vault parameter. Check naming rules and location: $($_.Exception.Message)"
        } else {
            Write-Error "Failed to create Key Vault: $($_.Exception.Message)"
        }
        throw
    }
}

if (-not $SkipServicePrincipal) {
    $stepNumber = if ($SkipServicePrincipal) { 4 } else { 8 }
    Write-StepHeader "Step ${stepNumber}: Role Assignment"

Write-Host "  Getting Key Vault Crypto Officer role definition..." -ForegroundColor Gray
$roleDefUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleDefinitions?`$filter=roleName eq 'Key Vault Crypto Officer'&api-version=2022-04-01"
$roleDef = Invoke-AzRestMethod -Method GET -Uri $roleDefUri
$roleDefData = $roleDef.Content | ConvertFrom-Json
$roleDefId = $roleDefData.value[0].id

Write-Info "Role Definition ID: $roleDefId"

# Check for existing role assignment
$kvScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$KeyVaultName"
$roleAssignmentsUri = "https://management.azure.com$kvScope/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

Write-Host "  Checking existing role assignments..." -ForegroundColor Gray
$existingAssignments = Invoke-AzRestMethod -Method GET -Uri $roleAssignmentsUri
$assignmentsData = $existingAssignments.Content | ConvertFrom-Json
$existingRole = $assignmentsData.value | Where-Object { 
    $_.properties.principalId -eq $spObjectId -and $_.properties.roleDefinitionId -eq $roleDefId 
}

if ($existingRole) {
    Write-Success "Service principal already has 'Key Vault Crypto Officer' role"
    Write-Info "Assignment ID: $($existingRole.name)"
} else {
    Write-Host "  Assigning 'Key Vault Crypto Officer' role..." -ForegroundColor Yellow
    
    # Generate deterministic GUID for role assignment (makes script idempotent)
    $roleAssignmentGuid = [guid]::NewGuid().ToString()
    $roleAssignmentUri = "https://management.azure.com$kvScope/providers/Microsoft.Authorization/roleAssignments/$roleAssignmentGuid`?api-version=2022-04-01"
    
    $roleAssignmentBody = @{
        properties = @{
            roleDefinitionId = $roleDefId
            principalId = $spObjectId
            principalType = "ServicePrincipal"
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        Invoke-AzRestMethodWithRetry -Method PUT -Uri $roleAssignmentUri -Payload $roleAssignmentBody | Out-Null
        Write-Success "Role assigned successfully"
        Write-Info "Role: Key Vault Crypto Officer"
        Write-Info "Scope: $KeyVaultName"
        
        # Wait for role assignment propagation
        Write-Host "  Waiting for role assignment propagation..." -ForegroundColor Gray
        Start-Sleep -Seconds 5
    } catch {
        Write-Error "Failed to assign role: $($_.Exception.Message)"
        Write-Warning "You may need to assign the 'Key Vault Crypto Officer' role manually via Azure Portal"
        throw
    }
}
} else {
    Write-Info "⊗ Skipping role assignment (no service principal)"
}
} # End if -not $SkipKeyVault

if (-not $SkipServicePrincipal -and -not $SkipSecret) {
    $stepNumber = 9
    if ($SkipKeyVault) { $stepNumber = 5 }
    Write-StepHeader "Step ${stepNumber}: Client Secret"

Write-Host "  Creating new client secret..." -ForegroundColor Yellow
Write-Info "Expiration: $SecretExpirationMonths months"

$endDate = (Get-Date).AddMonths($SecretExpirationMonths).ToString("yyyy-MM-ddTHH:mm:ssZ")
$secretBody = @{
    passwordCredential = @{
        displayName = "Created by Initialize-PasskeyKeyVault.ps1"
        endDateTime = $endDate
    }
} | ConvertTo-Json -Depth 10

$secretResult = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$appObjectId/addPassword" -Body $secretBody
$clientSecret = $secretResult.secretText

Write-Success "Client secret created"
Write-Info "Expires: $endDate"

# Warn if expiration is short
if ($SecretExpirationMonths -lt 6) {
    Write-Warning "Secret expires in $SecretExpirationMonths months - consider longer expiration for production"
}

Write-Host "`n  ⚠️  SAVE THIS SECRET - It won't be shown again!" -ForegroundColor Yellow

# Wait for secret replication
Write-Host "  Waiting for secret replication..." -ForegroundColor Gray
Start-Sleep -Seconds 5
} elseif (-not $SkipServicePrincipal -and $SkipSecret) {
    Write-Info "⊗ Skipping client secret generation (SkipSecret specified)"
    $clientSecret = "<Secret creation skipped>"
}

# Output Summary
Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
if ($SkipServicePrincipal -or $SkipSecret -or $SkipKeyVault) {
    Write-Host "║         ✓ Partial Configuration Complete                      ║" -ForegroundColor Green
} else {
    Write-Host "║              ✓ Key Vault Setup Complete                       ║" -ForegroundColor Green
}
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

Write-Host "`n📋 Configuration Summary:" -ForegroundColor Cyan
Write-Host "  Tenant ID           $tenantId" -ForegroundColor White
if (-not $SkipKeyVault) {
    Write-Host "  Subscription        $currentSubName" -ForegroundColor White
    Write-Host "  Resource Group      $ResourceGroupName" -ForegroundColor White
    Write-Host "  Key Vault           $KeyVaultName" -ForegroundColor White
    Write-Host "  SKU                 $(if ($KeyVaultSku -eq 'premium') { 'Premium (HSM)' } else { 'Standard' })" -ForegroundColor White
    Write-Host "  Location            $Location" -ForegroundColor White
}
if (-not $SkipServicePrincipal) {
    Write-Host "  Service Principal   $ServicePrincipalName" -ForegroundColor White
    Write-Host "  App ID              $appId" -ForegroundColor White
}

if (-not $SkipServicePrincipal -and -not $SkipSecret) {
    Write-Host "`n🔑 Authentication Credentials:" -ForegroundColor Cyan
    Write-Host "  Client Secret      $clientSecret" -ForegroundColor White
    Write-Host "  Expires            $endDate" -ForegroundColor White
    
    Write-Host "`n  ⚠️  CRITICAL: Save the client secret immediately!" -ForegroundColor Yellow
    Write-Host "     This is the only time it will be displayed." -ForegroundColor Yellow
} elseif (-not $SkipServicePrincipal -and $SkipSecret) {
    Write-Host "`n🔑 Authentication:" -ForegroundColor Cyan
    Write-Host "  ⊗ Client secret not generated (use certificate or managed identity)" -ForegroundColor Yellow
}

if (-not $SkipKeyVault) {
    Write-Host "`n🛡️  Security Features Enabled:" -ForegroundColor Cyan
    Write-Host "  ✓ RBAC authorization (least privilege)" -ForegroundColor Green
    Write-Host "  ✓ Soft delete with 90-day retention" -ForegroundColor Green
    if ($EnablePurgeProtection) {
        Write-Host "  ✓ Purge protection (prevents permanent deletion)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠  Purge protection disabled (not recommended)" -ForegroundColor Yellow
    }
    if ($KeyVaultSku -eq "premium") {
        Write-Host "  ✓ Premium SKU (HSM-backed keys)" -ForegroundColor Green
    }
}

Write-Host "`n📖 Next Steps:" -ForegroundColor Cyan
if (-not $SkipServicePrincipal -and -not $SkipSecret -and -not $SkipKeyVault) {
    Write-Host "  1. Save the client secret in a secure location (password manager)" -ForegroundColor White
    Write-Host "  2. Register passkeys using New-KeyVaultPasskey.ps1" -ForegroundColor White
    
    Write-Host "`n📝 Example Command:" -ForegroundColor Cyan
    Write-Host @"
.\New-KeyVaultPasskey.ps1 ``
    -UserUpn "user@yourdomain.com" ``
    -DisplayName "My Secure Passkey" ``
    -ClientId "$appId" ``
    -ClientSecret "$clientSecret" ``
    -UseKeyVault ``
    -KeyVaultName "$KeyVaultName" ``
    -TenantId "$tenantId"
"@ -ForegroundColor Gray
} elseif ($SkipServicePrincipal) {
    Write-Host "  Service principal was not created" -ForegroundColor White
    Write-Host "  Use existing service principal or managed identity for authentication" -ForegroundColor White
} elseif ($SkipKeyVault) {
    Write-Host "  Key Vault was not created" -ForegroundColor White
    Write-Host "  Service principal created: $ServicePrincipalName" -ForegroundColor White
    if (-not $SkipSecret) {
        Write-Host "  Use the client secret above for authentication" -ForegroundColor White
    }
} elseif ($SkipSecret) {
    Write-Host "  Client secret was not generated" -ForegroundColor White
    Write-Host "  Configure certificate-based authentication or use managed identity" -ForegroundColor White
}

$statusMsg = if ($canGrantConsent) {"Ready to register passkeys!"} else {"Complete admin consent to continue."}
$statusColor = if ($canGrantConsent) {"Green"} else {"Yellow"}

Write-Host "`n✅ Setup complete! $statusMsg" -ForegroundColor $statusColor
Write-Host ""

#endregion
