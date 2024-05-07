#Requires -Modules ActiveDirectory,Microsoft.Graph.Authentication,Microsoft.Graph.Identity.DirectoryManagement
[CmdletBinding()]
Param(
   [array]$ou = (Get-ADOrganizationalUnit -Filter * | Out-GridView -Title "Select an OU" -PassThru),
   [switch]$NotStarted,
   [switch]$Pending,
   [switch]$Completed,
   [switch]$NotEnrolled,
   [switch]$All
)

# Create arrays for reporting
[array]$NotStartedReport = @()
[array]$PendingReport = @()
[array]$CompletedReport = @()
[array]$NotEnrolledReport = @()

$ou.DistinguishedName | ForEach-Object {
    Write-Output "`nGetting a list of all devices in $_"
    $devices = Get-ADComputer -SearchBase $_ -SearchScope Subtree -Filter "Enabled -eq 'True'" -Properties userCertificate

    if ($NotStarted -or $All) {
        Write-Output "Getting a list of devices that have not read the SCP and added their certificate into AD"
        $NotStartedReport += $devices | Where-Object { [string]::IsNullOrEmpty($_.userCertificate) }
    }

    if ($Pending -or $All) {
        Write-Output "Getting a list of devices that have read SCP and pushed certificate into AD but have not completed Hybrid join"
        if (!(Get-MgContext)) { Connect-MgGraph }
        Get-MgDevice -All | Where-Object { ($_.TrustType -eq 'ServerAd') -and ($_.ProfileType -ne 'RegisteredDevice') } | ForEach-Object {
            $deviceId = $_.DeviceId
            $PendingReport += $devices | Where-Object { $_.objectGUID -eq $deviceId }
        }
    }

    if ($Completed -or $All) {
        Write-Output "Getting a list of devices that have completed Hybrid join"
        if (!(Get-MgContext)) { Connect-MgGraph }
        Get-MgDevice -All | Where-Object { ($_.TrustType -eq 'ServerAd') -and ($_.ProfileType -eq 'RegisteredDevice') } | ForEach-Object {
            $deviceId = $_.DeviceId
            $CompletedReport += $devices | Where-Object { $_.objectGUID -eq $deviceId }
        }
    }

    if ($NotEnrolled -or $All) {
        Write-Output "Getting a list of devices that have completed Hybrid join that have not completed Intune enrollment"
        if (!(Get-MgContext)) { Connect-MgGraph }
        Get-MgDevice -All | Where-Object { ($_.TrustType -eq 'ServerAd') -and ($_.ProfileType -eq 'RegisteredDevice') -and ($_.MdmAppId -ne '0000000a-0000-0000-c000-000000000000') } | ForEach-Object {
            $deviceId = $_.DeviceId
            $NotEnrolledReport += $devices | Where-Object { $_.objectGUID -eq $deviceId }
        }
    }
}

if ($NotStartedReport) {
   Write-Output "`nDevices that have not started the Hybrid join process"
   $NotStartedReport | Format-Table -AutoSize
}

if ($PendingReport) {
   Write-Output "`nDevices that are pending Hybrid join in Entra"
   $PendingReport | Format-Table -AutoSize
}

if ($CompletedReport) {
   Write-Output "`nDevices that have completed Hybrid join process"
   $CompletedReport | Format-Table -AutoSize
}

if ($NotEnrolledReport) {
   Write-Output "`nDevices that have completed Hybrid join but have not enrolled in Intune"
   $NotEnrolledReport | Format-Table -AutoSize
}
