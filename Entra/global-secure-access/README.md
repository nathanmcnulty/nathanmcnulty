# Global Secure Access

These policy files should help speed up deployment of Global Secure Access. As settings become avialable in Settings Catalog or handled as part of the installer, I will try to update the policy files here.

## Windows

At the time of this writing, Global Secure Access cannot acquire QUIC, DNS over HTTPS, or DNS over TLS, so we need to disable these in our browsers. The following configuration profile disables these for Edge and Chrome. If using Firefox, you will need to add the ADMX templates to Intune and add the settings or use PowerShell scripts: 
[Browser Restrictions Configuration Profile](./windows/Global%20Secure%20Access%20-%20Browser%20Restrictions.json)

There are also several client settings that are not available in Settings Catalog yet, so I have created Remediation scripts to help you set the desired settings. This script also ensures that IPv4 is preferred over IPv6 as Global Secure Access does not support IPv6 yet.

I have added helper text in the scripts, but for reference (and future settings), the registry values come from here:
https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client#client-registry-keys

Below are the discovery and remediation scripts:

[Discovery script](./windows/gsa-settings-discovery.ps1)  
[Detection script](./windows/gsa-settings-detection.ps1)

## macOS

Global Secure Access for macOS requires macOS 13.0 or higher, the device must be registered to Entra with the Company Portal, and the Enterprise SSO plug-in must be deployed.

With those in place, deploy the following policies:
- [Approve system extensions](./macos/Global%20Secure%20Access%20-%20Extensions.json)
- [Configure Transparent Proxy](./macos/Global%20Secure%20Access%20-%20Transparent%20Proxy.xml)
- [Configure Browser Restrictions](./macos/Global%20Secure%20Access%20-%20Browser%20Restrictions.json)
- [Configure Tray Buttons](./macos/Global%20Secure%20Access%20-%20Tray%20Buttons.xml)
  - May consider adjusting these based on the docs: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-macos-client#hide-or-unhide-system-tray-menu-buttons
- Package and deploy the client using the PKG downloaded from Entra

## iOS

Global Secure Access uses the Defender for Endpoint app as a host, so we need to deploy that first, and then enable Global Secure Access.

### For Supervised devices
- Create an app configuration policy for managed devices targeting Defender for Endpoint
  - Key: `issupervised`
  - Type: String
  - Value: `{{issupervised}}`
- Create Zero-touch (Silent) Control Filter policy
  - [Mobileconfig from Microsoft](https://download.microsoft.com/download/f/8/e/f8ed3484-b665-4c3c-9ae9-272c8a04159b/Microsoft_Defender_for_Endpoint_Control_Filter_Zerotouch.mobileconfig)

### For all devices
- Create the VPN configuration profile for Global Secure Access
  - [Follow Microsoft Learn](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-ios-client#create-a-vpn-profile-and-configure-global-secure-access-for-microsoft-defender-for-endpoint)
    - Be sure to pay attention to the GSA specific key/value pairs
- Deploy the Defender for Endpoint app


## Android

No specific configurations required beyond deploying the Defender for Endpoint app with Global Secure Access enabled.

---

# TLS Inspection Automation

The [Initialize-GSATLSInspection.ps1](Initialize-GSATLSInspection.ps1) script automates the complete setup of TLS inspection for Microsoft Global Secure Access, following Microsoft Security Benchmark best practices.

## Quick Start

### Prerequisites

```powershell
# Install required modules
Install-Module Az.Accounts -Force
Install-Module Microsoft.Graph.Authentication -Force

# Connect to services
Connect-MgGraph -Scopes "NetworkAccess.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All"
Connect-AzAccount
```

### Basic Usage

```powershell
.\Initialize-GSATLSInspection.ps1 -OrganizationName "ShareMyLabs"
```

This creates:
- Azure Key Vault with Premium SKU (HSM-backed)
- Self-signed root CA certificate (10 years, RSA 4096)
- GSA intermediate certificate (5 years)
- Azure Storage account with static website for CRL hosting
- CRL Distribution Point with the root CA's revocation list
- 4 Intune policies to deploy root certificate to all platforms

### Custom CRL Hostname

```powershell
.\Initialize-GSATLSInspection.ps1 `
    -OrganizationName "ShareMyLabs" `
    -CrlHostname "crl.sharemylabs.com" `
    -Verbose
```

When `-CrlHostname` is provided:
- The CDP URL in certificates uses your custom hostname (e.g., `http://crl.sharemylabs.com/gsa-tls-root-ca.crl`)
- Script outputs CNAME instructions to map the hostname to the Azure Storage static website
- After you create the CNAME, the script validates DNS resolution (with fallback to Cloudflare 1.1.1.1 and Google 8.8.8.8)
- Registers the custom domain on the storage account for proper HTTP routing

Without `-CrlHostname`, the CDP URL uses the Azure Storage static website URL directly.

### Production Setup with Monitoring

```powershell
.\Initialize-GSATLSInspection.ps1 `
    -OrganizationName "ShareMyLabs" `
    -CrlHostname "crl.sharemylabs.com" `
    -LogAnalyticsWorkspaceId "/subscriptions/.../workspaces/security-logs" `
    -EnableDefender `
    -Verbose

# Note: Policies created but not assigned - manually assign to specific groups for testing first in the Intune portal
# For testing environments only, add: -AssignIntunePolicies
```

## Key Features

### 🔐 Security by Design

- **Private keys never leave Key Vault**: Non-exportable keys, signing via Key Vault REST API
- **Microsoft Security Benchmark compliant**: DP-8 (key repository), LT-4 (audit logging), LT-1 (threat detection)
- **HSM-backed keys**: Premium SKU uses FIPS 140-2 Level 2 compliant hardware security modules
- **RBAC authorization**: Least privilege access model
- **Soft delete + purge protection**: Accidental deletion protection

### 📜 Certificate Lifecycle

1. Creates self-signed root CA in Key Vault (10-year validity)
2. Retrieves CSR from Global Secure Access
3. Signs CSR using Key Vault signing API (hybrid approach with CertificateRequest)
4. Uploads signed intermediate certificate to GSA
5. Deploys root CA to all device platforms via Intune

### 📊 Monitoring & Compliance

- Optional Log Analytics integration (2-year retention)
- Optional Microsoft Defender for Key Vault (Recommended)
- Diagnostic logging for all key operations
- Detailed output for tracking and reporting

### � CRL Distribution Point

- **Automatic CRL generation**: Empty CRL signed by the root CA via Key Vault (30-day validity)
- **Azure Storage static website**: CRL hosted on a StorageV2 account with HTTP access (no HTTPS — per RFC 5280, CRLs are cryptographically signed so transport security is unnecessary and HTTPS would create circular dependency)
- **CDP extension**: All signed certificates include a CRL Distribution Point extension pointing to the hosted CRL
- **Custom hostname support**: Optional `-CrlHostname` parameter for branded CRL URLs
- **DNS validation with fallback**: CNAME resolution tries local DNS → Cloudflare (1.1.1.1) → Google (8.8.8.8)
- **Custom domain registration**: Automatically registers the CNAME on the storage account for proper HTTP routing

### �📱 Multi-Platform Support

Creates 4 Intune policies:
- Windows (Trusted Root Certification Authorities)
- macOS (System Keychain)
- iOS (System Trust Store)
- Android (User/System Certificate Store)

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `OrganizationName` | **Required** | Organization name for certificate |
| `KeyVaultSKU` | `Premium` | `Premium` (HSM) or `Standard` (software) |
| `ResourceGroupName` | `rg-gsa-tls` | Resource group for Key Vault |
| `Location` | `eastus` | Azure region |
| `LogAnalyticsWorkspaceId` | None | Enable audit logs (full resource ID) |
| `EnableDefender` | False | Enable Defender for Key Vault |
| `CrlHostname` | None | Custom hostname for CRL Distribution Point (e.g., `crl.contoso.com`) |
| `StorageAccountName` | Auto-derived | Azure Storage Account name for CRL hosting (3-24 chars, lowercase + numbers) |
| `AssignIntunePolicies` | False | Assign to All Devices (not recommended; manual assignment to groups preferred) |
| `Force` | False | Recreate existing resources |

## Post-Setup Steps

1. **Verify GSA Certificate**
   - Navigate to: [TLS Inspection Settings](https://entra.microsoft.com/#view/Microsoft_Azure_Network_Access/TLSInspectionPolicy.ReactView)
   - Confirm certificate status: **Enabled**

2. **Verify CRL Distribution Point**
   ```powershell
   # Check CRL is accessible (use your storage URL or custom hostname)
   Invoke-WebRequest -Uri "http://<storage-or-custom-hostname>/gsa-tls-root-ca.crl" -UseBasicParsing
   ```
   - Verify HTTP 200 with `Content-Type: application/pkix-crl`

3. **Create CNAME Record** (if using `-CrlHostname`)
   - Create a CNAME DNS record mapping your custom hostname to the storage static website URL
   - Example: `crl.contoso.com` → `sagsacrlcontoso.z13.web.core.windows.net`
   - The script will validate the CNAME and register the custom domain on the storage account

4. **Assign Intune Policies** (default - manual assignment required)
   - Intune → Devices → Configuration
   - Assign "GSA TLS Root Certificate" policies to appropriate device groups
   - **Best Practice**: Target specific pilot groups first, then expand to production
   - **Note**: Use `-AssignIntunePolicies` switch only for testing environments if you want automatic "All Devices" assignment

5. **Enable TLS Inspection**
   - Global Secure Access → Secure → TLS inspection policies
   - Create policy scoped to pilot / production users

6. **Verify Deployment**
   ```powershell
   # Windows
   Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*Global Secure Access*" }
   
   # macOS
   security find-certificate -a -c "Global Secure Access" /Library/Keychains/System.keychain
   ```

## Troubleshooting

### Common Issues

**RBAC Permissions Delay**
- Wait 2-3 minutes for role assignment propagation
- Script includes retry logic with exponential backoff

**Certificate Signing Fails**
- Verify Crypto Officer role assigned to your user
- Check Key Vault health in Azure Portal
- Script auto-retries transient errors (429/503)

**Intune Policy Creation Fails**
- Verify `DeviceManagementConfiguration.ReadWrite.All` permission
- Check Intune licensing
- Review Graph API error details in verbose output

**CNAME Not Resolving for Custom CRL Hostname**
- Verify CNAME record is created at your DNS provider
- Allow time for DNS propagation (up to 5 minutes)
- The script tries local DNS, then falls back to Cloudflare (1.1.1.1) and Google (8.8.8.8)
- You can cancel CNAME validation and create the record later — all other resources are already provisioned

**CRL HTTP 400 Error**
- The custom domain must be registered on the Azure Storage account
- The script handles this automatically after CNAME validation
- If done manually: set the custom domain on the storage account via Azure Portal → Storage account → Networking → Custom domain

**TLS Inspection Not Working**
- Allow at least 60 min for Intune certificate deployment
- Reboot device after certificate installation
- Verify GSA client in "Connected" state
- Test with: `https://example.com` (should show "Issued by: Global Secure Access TLS CA")

### Testing Between Runs

```powershell
# Clean slate for testing
Remove-AzResourceGroup -Name "rg-gsa-tls" -Force

# Or purge soft-deleted vault
Remove-AzKeyVault -VaultName "kv-name" -Location "eastus" -InRemovedState -Force
```

## Architecture

### Security Model

```
┌─────────────────────────────────────────────────┐
│          Azure Key Vault (Premium SKU)          │
│  ┌───────────────────────────────────────────┐  │
│  │  Root CA Certificate                      │  │
│  │  - CN: Global Secure Access TLS CA        │  │
│  │  - RSA 4096 (HSM-backed)                  │  │
│  │  - Validity: 10 years                     │  │
│  │  - Private Key: NON-EXPORTABLE            │  │
│  │  - Extensions: CA=true, pathLen=1         │  │
│  └───────────────────────────────────────────┘  │
│                       │                         │
│                       ▼                         │
│  ┌───────────────────────────────────────────┐  │
│  │  Key Vault Signing API                    │  │
│  │  POST /keys/{name}/sign                   │  │
│  │  - Input: SHA256 hash of CSR TBS          │  │
│  │  - Output: RSA 4096 signature             │  │
│  │  - Private key never leaves HSM           │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
              │                    │
              ▼                    ▼
┌──────────────────────────┐ ┌──────────────────────────┐
│   GSA TLS Service        │ │  Azure Storage (CRL)     │
│  ┌────────────────────┐  │ │  ┌────────────────────┐  │
│  │ Intermediate Cert   │  │ │  │ Static Website     │  │
│  │ - Signed by root   │  │ │  │ - gsa-tls-root-    │  │
│  │ - Validity: 5 yrs  │  │ │  │   ca.crl           │  │
│  │ - CA=true, pL=0    │  │ │  │ - HTTP only (5280) │  │
│  │ - EKU: serverAuth  │  │ │  │ - 30-day validity  │  │
│  │ - CDP: CRL URL     │  │ │  │ - Custom hostname  │  │
│  └────────────────────┘  │ │  │   (optional)       │  │
│           │              │ │  └────────────────────┘  │
│           ▼              │ └──────────────────────────┘
│  Issues leaf certs for   │
│  intercepted HTTPS       │
└──────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────┐
│        Microsoft Intune (4 Policies)            │
│  - Windows: Trusted Root CA                     │
│  - macOS: System Keychain                       │
│  - iOS: System Trust Store                      │
│  - Android: User/System Certificate Store       │
└─────────────────────────────────────────────────┘
```

### Certificate Signing Flow

Traditional approach (NOT used - exports private key):
```
❌ CertificateRequest → Create private key locally → Sign → Export as PFX
```

**This script's approach** (private key stays in Key Vault):
```
✅ CertificateRequest → Build TBS structure
   → Extract TBS bytes → SHA256 hash
   → Send hash to Key Vault → HSM signs hash
   → Wrap signature into X509Certificate2
   → Upload to GSA
```

This hybrid approach uses .NET `CertificateRequest` for X.509 structure building while delegating signing to Key Vault, ensuring CA private keys never exist outside the HSM.

## Compliance & Best Practices

### Microsoft Security Benchmark

✅ **DP-8: Ensure security of key and certificate repository**
- RBAC-based access control
- Soft delete and purge protection enabled
- HSM-backed keys (Premium SKU)
- Non-exportable private keys

✅ **LT-4: Enable logging for security investigation**
- Diagnostic logs sent to Log Analytics
- 730-day (2-year) retention period
- All key/secret/certificate operations audited

✅ **LT-1: Enable threat detection capabilities**
- Microsoft Defender for Key Vault (optional)
- Anomaly detection and suspicious access alerts

### Azure Key Vault Best Practices

- ✅ RBAC authorization (not legacy access policies)
- ✅ Separate Key Vaults per environment (dev/test/prod)
- ✅ Resource group isolation
- ✅ Soft delete (90-day recovery window)
- ✅ Purge protection (permanent delete disabled)
- ✅ Network restrictions (optional private endpoint support)
- ✅ Monitoring and alerting configured

## Certificate Renewal

### Root CA Renewal (at 9 years)

The root CA has a 10-year validity. Plan renewal 1 year before expiration:

1. Generate new root CA certificate in same Key Vault:
   ```powershell
   .\Initialize-GSATLSInspection.ps1 `
       -OrganizationName "ShareMyLabs" `
       -CertificateCommonName "Global Secure Access TLS CA v2" `
       -KeyVaultName "existing-vault" `
       -Force
   ```

2. Distribute new root to devices (parallel to old root)
3. Monitor device certificate deployment (Intune reports)
4. After 100% deployment, update GSA to use new intermediate
5. Remove old root certificate from devices after transition period

### Intermediate Certificate Renewal (at 4 years)

The GSA intermediate has a 5-year validity. Renew 1 year early:

1. Generate new CSR in GSA portal (or via API)
2. Re-run signing portion of script (reuse existing root CA)
3. Upload new intermediate to GSA
4. Old leaf certificates remain valid until natural expiration

GSA automatically begins issuing new leaf certificates using the updated intermediate.

### CRL Renewal (every 30 days)

The CRL has a 30-day validity (`NextUpdate`). Re-run the script to generate and upload a fresh CRL:

```powershell
.\Initialize-GSATLSInspection.ps1 -OrganizationName "ShareMyLabs"
```

The script detects existing resources and only regenerates the CRL. Consider scheduling this via Azure Automation or a pipeline.

## Additional Resources

- [Global Secure Access TLS Inspection Docs](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-transport-layer-security-settings)
- [Microsoft Security Benchmark - Key Vault Baseline](https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/key-vault-security-baseline)
- [Azure Key Vault Best Practices](https://learn.microsoft.com/en-us/azure/key-vault/general/best-practices)
- [Intune Trusted Certificate Profiles](https://learn.microsoft.com/en-us/mem/intune/protect/certificates-trusted-root)

## Example Output

```
╔════════════════════════════════════════════════════════════════════╗
║  Global Secure Access TLS Inspection - Setup Complete              ║
╚════════════════════════════════════════════════════════════════════╝

✓ Azure Key Vault
   Name:         kv-gsa-tls-abc123
   SKU:          Premium (HSM-backed)
   Location:     eastus
   RBAC:         Enabled
   Security:     Soft Delete (90d), Purge Protection
   Monitoring:   Diagnostic Logs → Log Analytics (2 year retention)
   Protection:   Microsoft Defender for Key Vault (Enabled)

✓ Root CA Certificate
   Name:         gsa-tls-root-ca
   Subject:      CN=Global Secure Access TLS CA, O=ShareMyLabs
   Thumbprint:   A1B2C3D4E5F6...
   Key:          RSA 4096 (Non-exportable)
   Validity:     2026-02-10 → 2036-02-10 (10 years)

✓ Azure Storage (CRL Hosting)
   Account:      sagsacrlsharemylabs
   Static Web:   http://sagsacrlsharemylabs.z13.web.core.windows.net
   CRL URL:      http://crl.sharemylabs.com/gsa-tls-root-ca.crl
   CRL Size:     698 bytes
   Content-Type: application/pkix-crl
   Next Update:  2026-03-12 (30-day validity)

✓ Global Secure Access
   Certificate:  Enabled
   Thumbprint:   X7Y8Z9A1B2C3...
   Validity:     2026-02-10 → 2031-02-10 (5 years)
   Portal:       https://entra.microsoft.com/#view/.../TLSInspection

✓ Intune Policies Created
   Windows:      24b9a8c7-... (Not assigned - manual assignment required)
   macOS:        35c1d9e8-... (Not assigned - manual assignment required)
   iOS:          46d2e0f9-... (Not assigned - manual assignment required)
   Android:      57e3f1g0-... (Not assigned - manual assignment required)

✓ DNS CNAME Validated
   Hostname:     crl.sharemylabs.com
   Target:       sagsacrlsharemylabs.z13.web.core.windows.net
   Resolver:     Cloudflare (1.1.1.1)
   Custom Domain: Registered
   CRL Verified:  HTTP 200, application/pkix-crl

Next Steps:
  1. Verify certificate in GSA portal (status should be "Enabled")
  2. Assign Intune policies to device groups (policies created but not assigned)
  3. Monitor Intune policy deployment (30-60 min for certificate distribution)
  4. Create TLS inspection policy in GSA → Secure
  5. Assign TLS inspection policy to pilot user group
  6. Test with pilot users, verify leaf certificates issued by GSA CA
  7. Expand to production users
  8. Set calendar reminder for certificate renewal (4 years)
```

---

For issues or questions about the automation script, please open an issue in the repository.