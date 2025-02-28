#Requires -Module Microsoft.Graph
[CmdletBinding()]
Param(
   [string]$user = "user@domain.com"
)
# Get user devices
$devices = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=userPrincipalName eq '$user'").value.id

# Get issuing CAs
$issuingId = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/cloudCertificationAuthority?`$filter=cloudCertificationAuthorityType eq 'issuingCertificationAuthority'").value.Id

# Revoke certificates from all issuing CAs for the user's devices
$issuingId | ForEach-Object {
    $caId = $_
    ($devices | ForEach-Object { Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/cloudCertificationAuthority/$caId/cloudCertificationAuthorityLeafCertificate?`$filter=deviceId eq '$_'" }).value.id | ForEach-Object {
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/cloudCertificationAuthority(id='$caId')/revokeLeafCertificate" -Body @{ leafCertificateId = "$_" }
    }
}