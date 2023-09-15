# Check if you have a KDS Root Key (requires Domain Admin permissions)
# See https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key
# Must run PowerShell as Administrator
Get-KdsRootKey

# If none exists, run the following as Domain Administrator, then wait 10 hours...
Add-KdsRootKey -EffectiveImmediately

# Create the Directory services account
New-ADServiceAccount -Name "MDI-Svc" -DNSHostName "MDI-Svc.domain.com" -PrincipalsAllowedToRetrieveManagedPassword "Domain Controllers" -KerberosEncryptionType AES256

### Now recommend using SYSTEM account instead of creating a dedicated gMSA for this
# Create the Manage action account
#New-ADServiceAccount -Name "MDI-Action-Svc" -DNSHostName "MDI-Action-Svc.domain.com" -PrincipalsAllowedToRetrieveManagedPassword "Domain Controllers" -KerberosEncryptionType AES256
