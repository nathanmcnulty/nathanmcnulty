# Entra ID Passkey Management Scripts

A complete toolkit for setting up and using passwordless authentication with Azure Key Vault-backed passkeys in Microsoft Entra ID.

## What Are Passkeys?

Passkeys are a modern, passwordless authentication method that replaces traditional passwords with cryptographic key pairs. They're more secure than passwords because:
- No password to forget, steal, or phish
- Protected by hardware or secure storage
- Only work on the websites they were created for
- Can't be reused across different services

## Overview

This toolkit includes three PowerShell scripts that work together:

1. **Initialize-PasskeyKeyVault.ps1** - Sets up the Azure infrastructure
2. **New-KeyVaultPasskey.ps1** - Registers passkeys for users
3. **PasskeyLogin.ps1** - Tests authentication with passkeys

## Prerequisites

Before you start, make sure you have:

### Software Requirements
- **PowerShell 7.0 or later** (not Windows PowerShell 5.1)
  - Download from: https://aka.ms/powershell
- **Required PowerShell Modules:**
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  Install-Module Az.Accounts -Scope CurrentUser
  ```

### Azure/Entra Permissions Needed

**For Setup (Script 1):**
- `Application.ReadWrite.All` - To create service principals
- `AppRoleAssignment.ReadWrite.All` - To grant API permissions (optional but recommended)
- `Contributor` or `Owner` role on Azure subscription - To create Key Vault

**For Registration (Script 2):**
- `UserAuthenticationMethod.ReadWrite.All` - To register passkeys (application permission)

**For Authentication (Script 3):**
- No special permissions needed - just runs as the user

### Entra ID Configuration
- **FIDO2 attestation enforcement must be disabled**
  - Go to: Entra ID → Protection → Authentication methods → FIDO2 Security Key
  - Set "Enforce attestation" to **No**

---

## Quick Start Guide

Follow these steps in order:

### Step 1: Set Up Azure Infrastructure (~2 minutes)

This creates the Azure Key Vault and service principal needed to register passkeys.

```powershell
.\Initialize-PasskeyKeyVault.ps1
```

**What it does:**
- Creates a service principal with permissions to register passkeys
- Creates an Azure resource group and Key Vault
- Assigns the service principal access to the Key Vault
- Generates a client secret for authentication

**What you'll get:**
At the end, you'll see important information displayed on screen:
- Tenant ID
- Service Principal App ID
- Client Secret (⚠️ **SAVE THIS!** It won't be shown again)
- Key Vault name
- Resource group name

💡 **Tip:** Copy the example command shown at the end - you'll use it in Step 2!

### Step 2: Register a Passkey (~30 seconds)

This registers a new passkey for a user and saves it to a file.

```powershell
.\New-KeyVaultPasskey.ps1 `
    -UserUpn "user@yourdomain.com" `
    -DisplayName "My Test Passkey" `
    -UseKeyVault `
    -KeyVaultName "kv-passkey-XXXX" `
    -ClientId "your-app-id" `
    -ClientSecret "your-client-secret" `
    -TenantId "your-tenant-id"
```

**What it does:**
- Connects to Microsoft Graph to get passkey challenge
- Generates a cryptographic key pair in Azure Key Vault
- Registers the passkey with Entra ID
- Saves credential information to a JSON file

**What you'll get:**
- A JSON file containing the passkey details (e.g., `user_My_Test_Passkey_credential.json`)
- The private key stays secure in Key Vault (never leaves Azure)

⚠️ **Important:** Keep the JSON file safe! You'll need it to authenticate.

### Step 3: Test Authentication (~10 seconds)

This tests logging in with the passkey you just created.

```powershell
.\PasskeyLogin.ps1 -KeyFilePath ".\user_My_Test_Passkey_credential.json"
```

**What it does:**
- Reads the passkey details from the JSON file
- Performs FIDO2 authentication with Entra ID
- Shows success if authentication works

**Success looks like:**
```
✓ Authentication successful! Cookies retrieved.
```

---

## Script Reference

### 1. Initialize-PasskeyKeyVault.ps1

**Purpose:** One-time setup of Azure infrastructure needed for passkey registration.

#### Basic Usage
```powershell
# Use all defaults
.\Initialize-PasskeyKeyVault.ps1

# Customize names and location
.\Initialize-PasskeyKeyVault.ps1 `
    -KeyVaultName "my-passkey-vault" `
    -ResourceGroupName "rg-passkeys" `
    -ServicePrincipalName "PasskeyService" `
    -Location "westus2"
```

#### Advanced Options

**Premium Key Vault (HSM-backed keys)**
```powershell
.\Initialize-PasskeyKeyVault.ps1 -KeyVaultSku "premium"
```
Use this for enhanced security where private keys are stored in hardware security modules (HSMs).

**Skip Options** (for existing infrastructure):
```powershell
# Create only Key Vault (you already have a service principal)
.\Initialize-PasskeyKeyVault.ps1 -SkipServicePrincipal

# Create only service principal (you already have a Key Vault)
.\Initialize-PasskeyKeyVault.ps1 -SkipKeyVault

# Create service principal without secret (using certificate instead)
.\Initialize-PasskeyKeyVault.ps1 -SkipSecret
```

#### Important Notes
- **Purge protection is enabled by default** - This prevents accidental deletion of keys
- **Secret expires after 12 months** - You can change this with `-SecretExpirationMonths`
- If admin consent fails, you'll see instructions to manually grant it in Azure Portal

---

### 2. New-KeyVaultPasskey.ps1

**Purpose:** Registers a new passkey for a user in Entra ID.

#### Basic Usage with Key Vault (Recommended)
```powershell
.\New-KeyVaultPasskey.ps1 `
    -UserUpn "user@domain.com" `
    -DisplayName "My Laptop" `
    -UseKeyVault `
    -KeyVaultName "kv-passkey-XXXX" `
    -ClientId "app-id-from-step1" `
    -ClientSecret "secret-from-step1" `
    -TenantId "your-tenant-id"
```

#### Authentication Methods

The script supports three ways to authenticate:

**1. Client Secret (Simplest)**
```powershell
-ClientId "..." -ClientSecret "..."
```
✅ Easy to use  
⚠️ Less secure - secrets can be stolen

**2. Certificate (More Secure)**
```powershell
-ClientId "..." `
-ClientCertificatePath "C:\certs\app-cert.pfx" `
-ClientCertificatePassword (ConvertTo-SecureString "password" -AsPlainText -Force)
```
✅ More secure than secrets  
✅ Supports Conditional Access policies

**3. Managed Identity (Most Secure)**
```powershell
-UseManagedIdentity `
-UseKeyVault `
-KeyVaultName "..."
```
✅ No credentials to manage  
✅ Automatic token rotation  
⚠️ Only works on Azure VMs, App Services, Function Apps

#### Local Key Generation (Without Key Vault)
```powershell
.\New-KeyVaultPasskey.ps1 `
    -UserUpn "user@domain.com" `
    -DisplayName "My Device" `
    -ClientId "..." `
    -ClientSecret "..."
```
⚠️ **Warning:** Private key is saved to the JSON file. Less secure than Key Vault.

#### Important Options
- `-OutputPath` - Where to save the credential file (default: current directory)
- `-TenantId` - Required when using Key Vault with client secret/certificate

---

### 3. PasskeyLogin.ps1

**Purpose:** Authenticate to Entra ID using a registered passkey.

#### Basic Usage
```powershell
# Load passkey from file
.\PasskeyLogin.ps1 -KeyFilePath ".\user_credential.json"

# Optionally specify username
.\PasskeyLogin.ps1 `
    -KeyFilePath ".\user_credential.json" `
    -UserPrincipalName "user@domain.com"
```

#### Advanced Usage (Manual Parameters)
If you don't have a JSON file, you can provide all details manually:
```powershell
.\PasskeyLogin.ps1 `
    -UserPrincipalName "user@domain.com" `
    -UserHandle "base64-user-handle" `
    -CredentialId "base64-credential-id" `
    -PrivateKey "-----BEGIN PRIVATE KEY-----..."
```

#### Proxy Support
```powershell
.\PasskeyLogin.ps1 `
    -KeyFilePath ".\user_credential.json" `
    -Proxy "http://proxy.company.com:8080"
```

#### Key Vault Authentication Parameters
If your passkey uses Key Vault and the JSON file doesn't have Key Vault credentials stored:
```powershell
.\PasskeyLogin.ps1 `
    -KeyFilePath ".\user_credential.json" `
    -KeyVaultClientId "..." `
    -KeyVaultClientSecret "..." `
    -KeyVaultTenantId "..."
```

---

## Common Scenarios

### Scenario 1: First-Time Setup for Testing

1. **Run setup** (creates everything with defaults):
   ```powershell
   .\Initialize-PasskeyKeyVault.ps1
   ```

2. **Copy the displayed values** (App ID, Client Secret, Key Vault name, Tenant ID)

3. **Register a test passkey**:
   ```powershell
   .\New-KeyVaultPasskey.ps1 `
       -UserUpn "testuser@yourdomain.com" `
       -DisplayName "Test Key" `
       -UseKeyVault `
       -KeyVaultName "kv-passkey-1234" `
       -ClientId "your-app-id" `
       -ClientSecret "your-secret" `
       -TenantId "your-tenant-id"
   ```

4. **Test it works**:
   ```powershell
   .\PasskeyLogin.ps1 -KeyFilePath ".\testuser_Test_Key_credential.json"
   ```

### Scenario 2: Production Deployment with Certificate

1. **Create a certificate** for the service principal:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=PasskeyService" `
       -CertStoreLocation "Cert:\CurrentUser\My" `
       -KeyExportPolicy Exportable `
       -KeySpec Signature `
       -KeyLength 2048 `
       -NotAfter (Get-Date).AddYears(2)
   
   $pwd = ConvertTo-SecureString -String "YourPassword" -Force -AsPlainText
   Export-PfxCertificate -Cert $cert -FilePath ".\passkey-cert.pfx" -Password $pwd
   ```

2. **Upload certificate to service principal** in Azure Portal:
   - Go to Entra ID → App Registrations → Your App → Certificates & secrets
   - Upload the .cer file (export from certificate)

3. **Use certificate for registration**:
   ```powershell
   .\New-KeyVaultPasskey.ps1 `
       -UserUpn "user@domain.com" `
       -DisplayName "Production Key" `
       -UseKeyVault `
       -KeyVaultName "kv-prod-passkeys" `
       -ClientId "your-app-id" `
       -ClientCertificatePath ".\passkey-cert.pfx" `
       -ClientCertificatePassword (ConvertTo-SecureString "YourPassword" -AsPlainText -Force) `
       -TenantId "your-tenant-id"
   ```

### Scenario 3: Using Managed Identity on Azure VM

1. **Create the service principal** (run this once from any machine):
   ```powershell
   .\Initialize-PasskeyKeyVault.ps1 -SkipSecret
   ```

2. **Assign managed identity to your Azure VM**:
   - In Azure Portal → VM → Identity → System assigned → On
   - Grant the managed identity "Key Vault Crypto Officer" role on the Key Vault

3. **Register passkeys from the VM** (no credentials needed!):
   ```powershell
   .\New-KeyVaultPasskey.ps1 `
       -UserUpn "user@domain.com" `
       -DisplayName "User Device" `
       -UseManagedIdentity `
       -UseKeyVault `
       -KeyVaultName "kv-passkey-1234"
   ```

---

## Troubleshooting

### "Attestation enforcement must be disabled"
**Problem:** Script fails with message about attestation.

**Solution:**
1. Go to Azure Portal → Entra ID → Protection → Authentication methods
2. Click "FIDO2 Security Key"
3. Set "Enforce attestation" to **No**
4. Click Save

### "Permission denied" or "Forbidden"
**Problem:** Authentication fails even with correct credentials.

**Solution:**
- Check the service principal has `UserAuthenticationMethod.ReadWrite.All` permission
- Verify admin consent has been granted (check in App registrations → API permissions)
- If using Managed Identity, verify it has "Key Vault Crypto Officer" role

### "Key Vault not found"
**Problem:** Cannot access Key Vault.

**Solution:**
- Verify the Key Vault name is correct (check in Azure Portal)
- Ensure your account/service principal has appropriate role assignment
- Check if you're logged into the right Azure subscription (`Get-AzContext`)

### "Failed to retrieve challenge"
**Problem:** Cannot get passkey creation challenge from Entra ID.

**Solution:**
- Verify the user exists in Entra ID
- Check your Graph token has `UserAuthenticationMethod.ReadWrite.All` permission
- Ensure you're using application permissions, not delegated permissions

### JSON file not found
**Problem:** PasskeyLogin.ps1 can't find the credential file.

**Solution:**
- Use the full path: `.\PasskeyLogin.ps1 -KeyFilePath "C:\full\path\to\file.json"`
- Make sure you're in the correct directory
- Check the filename matches exactly (case-sensitive on some systems)

---

## Security Best Practices

### ✅ DO:
- **Use Key Vault** for storing private keys (use `-UseKeyVault` parameter)
- **Use Managed Identity** when running on Azure resources
- **Use certificates** instead of client secrets for service principals
- **Enable purge protection** on Key Vault (enabled by default)
- **Store credential JSON files securely** (treat like passwords)
- **Use Premium SKU** for Key Vault in production (HSM-backed keys)
- **Rotate client secrets** before they expire (default: 12 months)
- **Test in a non-production environment first**

### ❌ DON'T:
- Store client secrets in scripts or version control
- Share credential JSON files via unsecured channels (email, Slack, etc.)
- Use local key generation for production workloads
- Disable soft delete or purge protection on Key Vault
- Give service principals more permissions than needed
- Keep expired or unused passkeys registered

### Recommended Setup for Production:
1. Use **Premium SKU** Key Vault with HSM-backed keys
2. Use **Managed Identity** or **certificate-based authentication**
3. Enable **soft delete** (90 days) and **purge protection** (default)
4. Store credential files in a **secure password manager** or encrypted storage
5. Set up **Azure Monitor alerts** for Key Vault access
6. Implement **Conditional Access policies** to enforce passkey usage
7. Regularly **audit** registered authentication methods

---

## File Structure

After running all scripts, you'll have:

```
passkeys/
├── Initialize-PasskeyKeyVault.ps1    # Setup script
├── New-KeyVaultPasskey.ps1           # Registration script
├── PasskeyLogin.ps1                  # Authentication script
├── README.md                         # This file
└── username_DisplayName_credential.json  # Generated credential file(s)
```

**Credential JSON Format:**
```json
{
  "credentialId": "base64url-encoded-id",
  "relyingParty": "login.microsoft.com",
  "url": "https://login.microsoft.com",
  "userHandle": "base64url-encoded-handle",
  "username": "user@domain.com",
  "signCount": 0,
  "keyVault": {
    "vaultName": "kv-passkey-1234",
    "keyName": "passkey-a1b2c3d4",
    "clientId": "app-id",
    "tenantId": "tenant-id",
    "clientSecret": "secret"
  }
}
```

---

## Additional Resources

### Microsoft Documentation
- [Passkeys in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-passkey-fido2)
- [FIDO2 Security Keys](https://learn.microsoft.com/entra/identity/authentication/concept-authentication-passwordless#fido2-security-keys)
- [Azure Key Vault Best Practices](https://learn.microsoft.com/azure/key-vault/general/best-practices)
- [Managed Identities](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview)

### Standards
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 CTAP2 Specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)

### Security Frameworks
- [Microsoft Security Benchmark - Identity Management](https://learn.microsoft.com/security/benchmark/azure/security-control-identity-management)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)

---

## Support and Contributions

**Author:** Nathan McNulty  
**Date:** February 6, 2026  
**Based on work by:** Fabian Bader (TokenTacticsV2), Jos Lieben (Lieben Consultancy)

For issues, questions, or contributions, please refer to the main repository.

---

## License

Please refer to the LICENSE file in the root of the repository.
