Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All"

# Get all guest objectIds
Write-Output "Getting all guests in the tenant..."
$allGuests = @()
$uri = "/beta/users?`$filter=userType eq 'Guest'&`$select=id&`$top=999"
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $allGuests += $response.value.id
    $uri = $response.'@odata.nextLink'
} while ($uri)
Write-Output "Found $($allGuests.Count) guests in the tenant."

# Get all audit logs
# Could try to pull only specific services but concerned about missing new things they add:
# 'Entitlement Management','Access Reviews','Lifecycle Workflows' | ForEach-Object { `$filter=loggedByService eq '$_' }
Write-Output "Getting all audit logs in the tenant..."
$allAuditLogs = @()
$uri = "/beta/auditLogs/directoryAudits?`$top=999"
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $allAuditLogs += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)
Write-Output "Found $($allAuditLogs.Count) audit log events in the tenant."

# Create list of all guest objectIds that have been targeted by a licensed
Write-Output "Getting the list of all guests that have been targeted by a licensed feature..."
$licensedGuests = @()
$allAuditLogs | Where-Object { $_.additionalDetails.key -eq "GovernanceLicenseFeatureUsed" -and ('"Guest"' -in ("$(($_.targetResources.modifiedProperties | Where-Object { $_.displayname -eq "TargetUserType" }).newValue)","$(($_.targetResources.modifiedProperties | Where-Object { $_.displayname -eq "TargetUserType" }).oldValue)")) } | ForEach-Object {
    if (($_.additionaldetails | Where-Object { $_.key -eq "GovernanceLicenseFeatureUsed" }).value -eq "True") {
        $licensedGuests += ($_.targetResources | Where-Object { $_.Type -eq "User" }).Id
    }
}

$cost = ($licensedGuests | Select-Object -Unique).count * 0.75
Write-Output "You have $($licensedGuests | Select-Object -Unique) guest(s) that have used an Identity Governance licensed feature. Estimated cost will be: $cost."
