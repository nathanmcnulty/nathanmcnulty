# Entra ID Passkey Management Scripts

A toolkit for setting up and using passwordless authentication with Azure Key Vault-backed passkeys in Microsoft Entra ID.

## Overview

This toolkit includes three PowerShell scripts that work together:

1. **Initialize-PasskeyKeyVault.ps1** - Sets up the Azure infrastructure and Service Principal
2. **New-KeyVaultPasskey.ps1** - Registers passkeys for users using the Service Principal
3. **PasskeyLogin.ps1** - Authenticates with the passkeys, optionally signing via Key Vault

## Prerequisites

### Software Requirements
- **PowerShell 7.0 or later** (not Windows PowerShell 5.1) — https://aka.ms/powershell
- **Required PowerShell Modules:**
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  Install-Module Az.Accounts -Scope CurrentUser
  ```

### Azure/Entra Permissions Needed

| Script | Permissions |
|--------|------------|
| Initialize (Setup) | `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All` (Graph), `Contributor`/`Owner` on Azure subscription |
| New-KeyVaultPasskey (Registration) | `UserAuthenticationMethod.ReadWrite.All` (application permission on the Service Principal) |
| PasskeyLogin (Authentication) | No special permissions — runs as the user |

### Entra ID Configuration

Passkey registration requires attestation enforcement to be disabled for the target users. The recommended approach is to create a dedicated passkey profile:

1. Go to: Entra ID → Authentication methods → Passkey (FIDO2)
2. Click "Configure" → "Add profile (preview)"
3. Create a new profile with attestation enforcement set to **No**
4. Assign only service accounts or automation users to this profile

This keeps attestation enabled for regular users while allowing software-based passkeys for automation.

---

## Quick Start Guide

### Step 1: Set Up Azure Infrastructure (~2 minutes)

```powershell
.\Initialize-PasskeyKeyVault.ps1
```

Creates the service principal, Azure Key Vault, RBAC assignments, and client secret. The script auto-detects your Graph tenant and switches Azure context to match (useful for multi-tenant accounts).

Save the displayed App ID, Client Secret, Key Vault name, and Tenant ID — you'll need them in Step 2. The example command shown at the end can be copied directly.

### Step 2: Register a Passkey (~30 seconds)

```powershell
$clientSecret = Read-Host -AsSecureString -Prompt "Enter client secret"
.\New-KeyVaultPasskey.ps1 `
    -UserUpn "user@yourdomain.com" `
    -DisplayName "My Test Passkey" `
    -UseKeyVault `
    -KeyVaultName "kv-passkey-XXXX" `
    -ClientId "your-app-id" `
    -ClientSecret $clientSecret `
    -TenantId "your-tenant-id"
```

Generates a key pair in Key Vault, registers the passkey with Entra ID, and saves credential metadata to a JSON file. The private key never leaves Azure.

### Step 3: Test Authentication (~10 seconds)

```powershell
.\PasskeyLogin.ps1 -KeyFilePath ".\user_My_Test_Passkey_credential.json"
```

> **Note:** Wait ~30 seconds after registration before authenticating. Entra ID needs time to propagate newly registered passkeys.

On success, `$global:ESTSAUTH` and `$global:webSession` are set for use in subsequent API calls.

---

## Pipeline Support

All three scripts support `-PassThru` for pipeline chaining:

```powershell
.\Initialize-PasskeyKeyVault.ps1 -PassThru |
    .\New-KeyVaultPasskey.ps1 -UserUpn "user@domain.com" -DisplayName "Automated Passkey" -PassThru |
    .\PasskeyLogin.ps1 -PassThru
```

When piped from New-KeyVaultPasskey, PasskeyLogin automatically waits ~30 seconds for Entra ID passkey propagation before attempting authentication.

**What flows through the pipeline:**

| Stage | Data Passed |
|-------|-------------|
| Initialize → New-KeyVaultPasskey | Tenant ID, Client ID, Client Secret, Key Vault Name |
| New-KeyVaultPasskey → PasskeyLogin | Credential file path, Client ID/Secret, Tenant ID, Registration time |

**Reusing configuration for multiple users:**
```powershell
$config = .\Initialize-PasskeyKeyVault.ps1 -PassThru

"user1@domain.com", "user2@domain.com" | ForEach-Object {
    $config | .\New-KeyVaultPasskey.ps1 -UserUpn $_ -DisplayName "Bulk Passkey" -PassThru
}
```

**Notes:**
- Without `-PassThru`, scripts display output to console only (backward compatible)
- Explicit parameters override pipeline values
- PasskeyLogin always sets `$global:ESTSAUTH` and `$global:webSession` regardless of `-PassThru`

---

## Script Reference

### Initialize-PasskeyKeyVault.ps1

One-time setup of Azure infrastructure. Auto-detects the Graph tenant and switches Azure context to match.

```powershell
# Defaults
.\Initialize-PasskeyKeyVault.ps1

# Customized
.\Initialize-PasskeyKeyVault.ps1 `
    -KeyVaultName "my-passkey-vault" `
    -ResourceGroupName "rg-passkeys" `
    -ServicePrincipalName "PasskeyService" `
    -Location "westus2"

# Premium SKU (HSM-backed keys)
.\Initialize-PasskeyKeyVault.ps1 -KeyVaultSku "premium"
```

**Skip options** for existing infrastructure: `-SkipServicePrincipal`, `-SkipKeyVault`, `-SkipSecret`

**Notes:**
- Purge protection enabled by default (cannot be disabled once set)
- Client secret expires after 12 months (configurable with `-SecretExpirationMonths`)
- If admin consent fails, instructions for manual consent are displayed

### New-KeyVaultPasskey.ps1

Registers a new passkey for a user in Entra ID.

```powershell
$clientSecret = Read-Host -AsSecureString -Prompt "Enter client secret"
.\New-KeyVaultPasskey.ps1 `
    -UserUpn "user@domain.com" `
    -DisplayName "My Laptop" `
    -UseKeyVault `
    -KeyVaultName "kv-passkey-XXXX" `
    -ClientId "app-id-from-step1" `
    -ClientSecret $clientSecret `
    -TenantId "your-tenant-id"
```

**Authentication methods:** Client Secret, Certificate (`-ClientCertificatePath`/`-ClientCertificatePassword`), or Managed Identity (`-UseManagedIdentity`).

**Local key generation** (without Key Vault): Omit `-UseKeyVault` and `-KeyVaultName`. The private key will be saved to the JSON file instead.

**Options:** `-OutputPath` (credential file location), `-TenantId` (required for Key Vault with client secret/certificate)

### PasskeyLogin.ps1

Authenticates to Entra ID using a registered passkey.

```powershell
# From file
.\PasskeyLogin.ps1 -KeyFilePath ".\user_credential.json"

# With Key Vault credentials (if not in JSON)
.\PasskeyLogin.ps1 `
    -KeyFilePath ".\user_credential.json" `
    -KeyVaultClientId "..." `
    -KeyVaultClientSecret "..." `
    -KeyVaultTenantId "..."
```

**Options:** `-Proxy` (HTTP proxy URL), `-UserPrincipalName` (override), manual params (`-UserHandle`, `-CredentialId`, `-PrivateKey`)

**Output:** Sets `$global:ESTSAUTH` (auth cookie) and `$global:webSession` (web session). With `-PassThru`, returns a result object with `Success`, `UserPrincipalName`, `AuthenticationMethod`, etc.

---

## Troubleshooting

### "Attestation enforcement must be disabled"
Create a passkey profile with attestation disabled and assign only the target users. See [Entra ID Configuration](#entra-id-configuration) above.

### "Permission denied" or "Forbidden"
- Verify the service principal has `UserAuthenticationMethod.ReadWrite.All` with admin consent granted
- For Managed Identity, verify "Key Vault Crypto Officer" role on the Key Vault

### "Key Vault not found"
- Verify the Key Vault name and that you're in the correct subscription (`Get-AzContext`)
- Ensure the service principal has the appropriate role assignment

### "Failed to retrieve challenge"
- Verify the user exists in Entra ID
- Ensure the Graph token uses application permissions (not delegated)

### Authentication fails after passkey registration
- Entra ID needs ~30 seconds to propagate newly registered passkeys
- When using the pipeline, this delay is handled automatically
- When running scripts manually, wait 30 seconds between registration and authentication

### Multi-tenant Azure account issues
- Initialize-PasskeyKeyVault.ps1 auto-detects your Graph tenant and switches Azure context to match
- If you have access to many tenants, the Azure login may show warnings about inaccessible tenants — these are harmless and suppressed automatically

---

## Security Best Practices

### ✅ DO:
- **Use Key Vault** for storing private keys (`-UseKeyVault`)
- **Use Managed Identity** when running on Azure resources
- **Use certificates** instead of client secrets for service principals
- **Use Premium SKU** Key Vault in production (HSM-backed keys)
- **Store credential JSON files securely** (treat like passwords)
- **Rotate client secrets** before they expire (default: 12 months)

### ❌ DON'T:
- Store client secrets in scripts or version control
- Share credential JSON files via unsecured channels
- Use local key generation for production workloads
- Disable soft delete or purge protection on Key Vault

---

## File Structure

```
passkeys/keyvault/
├── Initialize-PasskeyKeyVault.ps1          # Setup script
├── New-KeyVaultPasskey.ps1                 # Registration script
├── PasskeyLogin.ps1                        # Authentication script
├── README.md                               # This file
└── user_DisplayName_credential.json        # Generated credential file(s)
```

**Credential JSON format:**
```json
{
  "url": "https://login.microsoft.com",
  "userName": "user@domain.com",
  "methodId": "base64url-method-id",
  "displayName": "My Passkey",
  "relyingParty": "login.microsoft.com",
  "credentialId": "base64url-credential-id",
  "userHandle": "base64url-user-handle",
  "keyVault": {
    "vaultName": "kv-passkey-1234",
    "keyName": "passkey-user-20260207-120000",
    "keyId": "https://kv-passkey-1234.vault.azure.net/keys/passkey-user-20260207-120000/abc123"
  },
  "createdDateTime": "2026-02-07T12:00:00Z"
}
```

---

## Additional Resources

- [Passkeys in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-passkey-fido2)
- [Azure Key Vault Best Practices](https://learn.microsoft.com/azure/key-vault/general/best-practices)
- [Managed Identities](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)

---

**Author:** Nathan McNulty  
**Based on work by:** Fabian Bader (TokenTacticsV2), Jos Lieben (Lieben Consultancy)

For issues, questions, or contributions, please refer to the main repository.
