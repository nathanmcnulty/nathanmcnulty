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

## Private Access Enterprise Apps

The [New-EntraPrivateAccessEnterpriseApps.ps1](./New-EntraPrivateAccessEnterpriseApps.ps1) script creates Microsoft Entra Private Access enterprise apps from either a CSV containing `userPrincipalName`, `IP`, and `FQDN` columns or direct parameters.

It uses only the `Microsoft.Graph.Authentication` module and the `Invoke-MgGraphRequest` cmdlet for Graph operations.

IP values accept either a single IP address or a CIDR value such as `10.2.2.174`, `10.2.2.174/32`, or `10.2.2.0/24`. The script validates those values up front and throws a clear error before making Graph calls if a row contains another format.

Single IP addresses and host-sized CIDR inputs are both normalized to the same host-sized Graph `ipRangeCidr` segment so reruns treat them as the same destination. Wider CIDRs are normalized to their canonical network prefix and kept as `ipRangeCidr` segments.

Single ports such as `443` are also accepted on `-Ports` or `-Port` and normalized to `443-443` before calling Graph, so the script is forgiving if you forget the repeated range syntax.

```powershell
Connect-MgGraph -Scopes "Directory.ReadWrite.All","NetworkAccess.ReadWrite.All","AppRoleAssignment.ReadWrite.All" -NoWelcome

.\New-EntraPrivateAccessEnterpriseApps.ps1 `
   -CsvPath .\private-access.csv `
   -Ports "3389-3389","445-445"
```

```powershell
.\New-EntraPrivateAccessEnterpriseApps.ps1 `
   -UserPrincipalName "user1@contoso.com","user2@contoso.com" `
   -FQDN "app.contoso.internal" `
   -IP "10.0.0.10" `
   -Port "443"
```

Rows are grouped by destination so rerunning the script reuses the same app name, skips existing segments, and adds only missing user assignments.

The script assumes the connector group already exists. It does not create connectors or connector groups. If `-ConnectorGroupId` is omitted, the script queries existing connector groups and opens `Out-GridView` when more than one group exists so you can choose interactively. For unattended automation, pass `-ConnectorGroupId` explicitly.

Direct-parameter mode provisions one destination per invocation and is useful when you do not want to stage a CSV first.

Microsoft Entra Private Access also enforces overlapping IP segment checks across apps, so avoid assigning the same IP or CIDR range to multiple enterprise apps unless that overlap is intentional and supported.

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

[Initialize-GSATLSInspection.ps1](Initialize-GSATLSInspection.ps1) provisions an HSM-backed CA and stages a signed certificate for Microsoft Entra Global Secure Access TLS inspection. It supports new deployments and migration from an on-premises CA.

## Security and lifecycle design

- The root uses a non-exportable 4096-bit `RSA-HSM` key in Azure Key Vault Premium.
- The dedicated root has no EKU or path-length constraint. The GSA CA has `CA=true`, `pathLen=1`, `serverAuth`, `keyCertSign`, and `cRLSign`, allowing GSA's additional short-lived CA tier.
- Active GSA certificates are preserved until GSA enables a replacement. `-RotateGsaCertificate` uploads and enables the new certificate through the same beta Graph transition used by the portal.
- GSA reads request `Prefer: include-unknown-enum-members` so `enabled` and `disabled` are not returned as `unknownFutureValue`.
- CRLs are HSM-signed, monotonically numbered, uploaded using Microsoft Entra authorization, and verified before certificate issuance.
- Storage Shared Key and anonymous blob access are disabled.
- `-Force` can replace only a conflicting pending CSR after confirmation; it never deletes the resource group or an active certificate.
- `-WhatIf` returns before resource mutation.

## Prerequisites

- PowerShell 7+, `Az.Accounts`, and `Microsoft.Graph.Authentication`. Azure resource operations use `Invoke-AzRestMethod`; no other Az modules are required.
- Azure `Contributor` plus `User Access Administrator`, or `Owner`, when scoped RBAC assignments must be created.
- Graph delegated scopes `NetworkAccess.ReadWrite.All` and `DeviceManagementConfiguration.ReadWrite.All` for full setup. `-RenewCrlOnly` requires no Graph session.
- Appropriate Global Secure Access and Intune licensing.

```powershell
Install-Module Az.Accounts -Force
Install-Module Microsoft.Graph.Authentication -Force
Connect-AzAccount
Connect-MgGraph -Scopes 'NetworkAccess.ReadWrite.All','DeviceManagementConfiguration.ReadWrite.All'
```

## Preview and deploy

```powershell
.\Initialize-GSATLSInspection.ps1 -OrganizationName 'Contoso' -WhatIf
.\Initialize-GSATLSInspection.ps1 -OrganizationName 'Contoso' -Verbose
```

Intune profiles are unassigned unless `-AssignIntunePolicies` is supplied. Pilot-group assignment is recommended.

## Migrate from an on-premises CA

```powershell
.\Initialize-GSATLSInspection.ps1 `
    -OrganizationName 'Contoso' `
    -KeyVaultName 'kv-gsa-contoso' `
    -RootCertificateName 'gsa-tls-root-ca-v2' `
    -RotateGsaCertificate
```

The active on-premises-backed certificate remains active until GSA enables the replacement. Deploy and verify the new root before running the rotation, then retire the old root only after validation.

## Renew the CRL

`-RenewCrlOnly` is reuse-only: the resource group, Premium vault, RSA-HSM root, and storage account must exist. It does not use Graph, create a CSR, or modify Intune.

```powershell
.\Initialize-GSATLSInspection.ps1 `
    -OrganizationName 'Contoso' `
    -KeyVaultName 'kv-gsa-contoso' `
    -StorageAccountName 'sagsacrlcontoso' `
    -RootCertificateName 'gsa-tls-root-ca-v2' `
    -RenewCrlOnly
```

Schedule it before the CRL's 30-day `nextUpdate`.

## Private endpoint, CRL DNS, and Intune

A Key Vault private endpoint applies to the signing or renewal host; GSA itself does not access Key Vault. Supply `-EnablePrivateEndpoint`, a subnet resource ID, and an existing `privatelink.vaultcore.azure.net` zone resource ID. The script creates the `vault` endpoint and DNS group, verifies private resolution and data-plane access, then disables public access. It restores public access if validation fails.

With `-CrlHostname crl.contoso.com`, create the displayed CNAME to the exact static-website hostname. Certificate issuance stops unless DNS and HTTP retrieval work.

Default trusted-root profiles cover Windows, macOS, iOS/iPadOS, Android Enterprise Device Owner, Android Enterprise Work Profile, and Android AOSP Device Owner. Android Device Administrator is excluded. Existing matching profiles are updated while assignments are preserved.

## Important parameters

| Parameter | Default | Purpose |
|---|---:|---|
| `OrganizationName` | Required | Certificate organization |
| `KeyVaultName` | Generated | Existing or new Premium vault |
| `RootCertificateName` | `gsa-tls-root-ca` | Use a new name for migration |
| `StorageAccountName` | Derived | Existing or new CRL storage |
| `CrlHostname` | None | Optional custom HTTP CDP |
| `RotateGsaCertificate` | False | Upload and enable replacement; preserve active until transition |
| `RenewCrlOnly` | False | Renew CRL from existing resources |
| `EnablePrivateEndpoint` | False | Private-link hardening after validation |
| `AssignIntunePolicies` | False | Assign profiles to All Devices |
| `Force` | False | Confirm deletion of an unusable pending CSR |

## Verification and next steps

```powershell
Invoke-Pester .\tests\Initialize-GSATLSInspection.Tests.ps1 -Output Detailed
```

After deployment, verify CRL retrieval, deploy the root to a pilot group, confirm the certificate is active, and test a narrowly scoped TLS inspection security profile.

References: [GSA TLS architecture](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-transport-layer-security), [certificate tutorial](https://learn.microsoft.com/en-us/entra/global-secure-access/tutorial-internet-access-tls-inspection), [Graph update API](https://learn.microsoft.com/en-us/graph/api/networkaccess-externalcertificateauthoritycertificate-update?view=graph-rest-beta), [Key Vault private link](https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service), and [Intune trusted roots](https://learn.microsoft.com/en-us/intune/intune-service/protect/certificates-trusted-root).
