# Get all iOS managed app protection policies that have been applied to at least one user and list the apps that are protected by these policies
$iOSApps = New-Object System.Collections.ArrayList
(Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections").value.id | ForEach-Object { 
    (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections/$_`?`$expand=apps,assignments,deploymentSummary" -OutputType PSObject).deploymentSummary.configurationDeploymentSummaryPerApp | Where-Object { $_.configurationAppliedUserCount -ne 0 } | ForEach-Object {
        $iOSApps.Add($_.mobileAppIdentifier.bundleId) | Out-Null
    }
}

# Get all Android managed app protection policies that have been applied to at least one user and list the apps that are protected by these policies
$androidApps = New-Object System.Collections.ArrayList
(Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/AndroidManagedAppProtections").value.id | ForEach-Object { 
    (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/AndroidManagedAppProtections/$_`?`$expand=apps,assignments,deploymentSummary" -OutputType PSObject).deploymentSummary.configurationDeploymentSummaryPerApp | Where-Object { $_.configurationAppliedUserCount -ne 0 } | ForEach-Object {
        $androidApps.Add($_.mobileAppIdentifier.packageId) | Out-Null
    }
}

Write-Output "List of iOS apps where APP has been applied:`n"
$iOSApps | Select-Object -Unique

Write-Output "`n`nList of Android apps where APP has been applied:`n"
$androidApps | Select-Object -Unique