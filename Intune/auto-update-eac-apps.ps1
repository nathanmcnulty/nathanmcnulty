# Auto-approve Enterprise App Catalog app updates
# As of 24/12/02, this has only been tested in a lab environment

# Get list of apps with available updates
$body = @{
    select = @(
        "ApplicationId"
        "LatestRevisionId"
    )
    skip = 0
    top = 50
    orderBy = @()
    filter = "UpdateAvailable eq 'true' and IsSuperseded eq 'false'"
} | ConvertTo-Json
Invoke-MgGraphRequest -Method "POST" -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/retrieveWin32CatalogAppsUpdateReport" -Body $body -OutputFilePath .\temp.txt
$values = (Get-Content .\temp.txt | ConvertFrom-Json).Values

# Iterate through each app and update
0..($values.count-1) | ForEach-Object { 
    # Get current and latest app details
    $applicationId = $($values[$_][0])
    $latestRevisionId = $($values[$_][1])
    $currentApp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$applicationId/?`$expand=assignments,microsoft.graph.win32CatalogApp/referencedCatalogPackage,microsoft.graph.win32CatalogApp/latestUpgradeCatalogPackage" -OutputType PSObject
    $latestApp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/convertFromMobileAppCatalogPackage(mobileAppCatalogPackageId='$latestRevisionId')" -OutputType PSObject

    # Create the new app
    $body = @{
        "@odata.type" = $latestApp.'@odata.type'
        applicableArchitectures = $latestApp.applicableArchitectures
        allowAvailableUninstall = $true
        categories = @()
        description = $latestApp.description
        developer = $latestApp.developer
        displayName = $latestApp.displayName
        displayVersion = $latestApp.displayVersion
        fileName = $latestApp.fileName
        installCommandLine = $latestApp.installCommandLine
        installExperience = $latestApp.installExperience
        informationUrl = $latestApp.informationUrl
        isFeatured = $false
        roleScopeTagIds = @()
        notes = $latestApp.notes
        minimumCpuSpeedInMHz = $null
        minimumFreeDiskSpaceInMB = $null
        minimumMemoryInMB = $null
        minimumNumberOfProcessors = $null
        minimumSupportedWindowsRelease = $latestApp.minimumSupportedWindowsRelease
        msiInformation = $null
        owner = $latestApp.owner
        privacyInformationUrl = $latestApp.privacyInformationUrl
        publisher = $latestApp.publisher
        returnCodes = $latestApp.returnCodes
        rules = $latestApp.rules
        setupFilePath = $latestApp.setupFilePath
        uninstallCommandLine = $latestApp.uninstallCommandLine
        mobileAppCatalogPackageId = $latestApp.mobileAppCatalogPackageId
    } | ConvertTo-Json -Depth 4
    $newApp = Invoke-MgGraphRequest -Method "POST" -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/" -Body $body -OutputType PSObject

    # Set supercedence
    $body = @{
        relationships = @(@{
            "@odata.type" = "#microsoft.graph.mobileAppSupersedence"
            targetId = $applicationId
            supersedenceType = "update"
        })
    } | ConvertTo-Json -Depth 4
    Invoke-MgGraphRequest -Method "POST" -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.Id)/updateRelationships" -Body $body

    # Match assignment of existing app
    $currentApp.assignments | ForEach-Object { 
        [array]$assignments += @{
            "@odata.type" = "#microsoft.graph.mobileAppAssignment"
            target = $_.target
            intent = $_.intent
            settings = $_.settings
        }
    }
    $body = @{
        mobileAppAssignments = $assignments
    } | ConvertTo-Json -Depth 4
    Invoke-MgGraphRequest -Method "POST" -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($newApp.Id)/assign" -Body $body
}
Remove-Item .\temp.txt