# Get all iOS managed app protection policies that have been applied to at least one user and list the apps that are protected by these policies
$appApps = New-Object System.Collections.ArrayList
(Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections").value.id | ForEach-Object { 
    (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$_`?`$expand=apps,assignments,deploymentSummary" -OutputType PSObject).deploymentSummary.configurationDeploymentSummaryPerApp | Where-Object { $_.configurationAppliedUserCount -eq 0 } | ForEach-Object {
        $appApps.Add($_.mobileAppIdentifier.bundleId)
    }
}
Write-Output "List of iOS apps where APP has been applied:`n"
$appApps | Select-Object -Unique

# Get all Android managed app protection policies that have been applied to at least one user and list the apps that are protected by these policies
$appApps = New-Object System.Collections.ArrayList
(Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/AndroidManagedAppProtections").value.id | ForEach-Object { 
    (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/AndroidManagedAppProtections/$_`?`$expand=apps,assignments,deploymentSummary" -OutputType PSObject).deploymentSummary.configurationDeploymentSummaryPerApp | Where-Object { $_.configurationAppliedUserCount -eq 0 } | ForEach-Object {
        $appApps.Add($_.mobileAppIdentifier.packageId)
    }
}
Write-Output "`n`nList of Android apps where APP has been applied:`n"
$appApps | Select-Object -Unique