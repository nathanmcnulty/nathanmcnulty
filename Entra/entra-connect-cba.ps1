$admin = "admin@domain.com"

# Create cert
$params = @{
    DnsName = "sub.domain.com"
    CertStoreLocation = "Cert:\LocalMachine\My"
    KeyAlgorithm = "RSA"
    KeyLength = 2048
    HashAlgorithm = "SHA256"
    NotAfter = (Get-Date).AddYears(1)
    KeyExportPolicy = "NonExportable"
}
$cert = New-SelfSignedCertificate @params

# Add service account permissions to private key
$rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$path = "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$($rsaCert.key.UniqueName)"
$permissions = Get-Acl -Path $path
$serviceAccount = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync -Name ObjectName).ObjectName
$rule = New-Object Security.Accesscontrol.FileSystemAccessRule "$serviceAccount", "read", allow
$permissions.AddAccessRule($rule)
Set-Acl -Path $path -AclObject $permissions

# Check permissions
$permissions = Get-Acl -Path $path
$permissions.Access

# Disable sync scheduler and set up SP with CBA
Set-ADSyncScheduler -SyncCycleEnabled $false
Add-EntraApplicationRegistration –UserPrincipalName $admin -CertificateThumbprint $cert.Thumbprint
Add-ADSyncApplicationRegistration –UserPrincipalName $admin -CertificateThumbprint $cert.Thumbprint

# Verify now using SP and enable sync scheduler
Get-ADSyncEntraConnectorCredential
Set-ADSyncScheduler -SyncCycleEnabled $true


# Rollover process
Set-ADSyncScheduler -SyncCycleEnabled $false

$params = @{
    DnsName = "sub.domain.com"
    CertStoreLocation = "Cert:\LocalMachine\My"
    KeyAlgorithm = "RSA"
    KeyLength = 2048
    HashAlgorithm = "SHA256"
    NotAfter = (Get-Date).AddYears(1)
    KeyExportPolicy = "NonExportable"
}
$cert = New-SelfSignedCertificate @params

$rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$path = "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$($rsaCert.key.UniqueName)"
$permissions = Get-Acl -Path $path
$serviceAccount = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync -Name ObjectName).ObjectName
$rule = New-Object Security.Accesscontrol.FileSystemAccessRule "$serviceAccount", "read", allow
$permissions.AddAccessRule($rule)
Set-Acl -Path $path -AclObject $permissions

Invoke-ADSyncApplicationCredentialRotation –UserPrincipalName $admin -CertificateThumbprint $cert.Thumbprint