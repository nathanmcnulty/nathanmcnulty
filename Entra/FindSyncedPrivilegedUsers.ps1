# Connect with appropriate scopes for PIM
Connect-MgGraph -Scopes RoleAssignmentSchedule.Read.Directory,RoleEligibilitySchedule.Read.Directory

# Get active assignments
$active = @()
$uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignmentSchedules?`$expand=RoleDefinition,Principal,DirectoryScope"
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    $active += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

$active | ForEach-Object {
    if ($_.Principal."@odata.type" -match '.user' -and $_.Principal.onPremisesSyncEnabled -eq $true) {
        Write-Output "$($_.RoleDefinition.DisplayName),$($_.Principal.userPrincipalName)"
    }
    if ($_.Principal."@odata.type" -match '.group') {
        $roleName = $_.RoleDefinition.DisplayName
        $members = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($_.PrincipalId)/members" -OutputType PSObject).value.userPrincipalName
        if ($members.Count -ne 0) { $members | ForEach-Object { Write-Output "$roleName,$_" }}
    }
}

# Get eligible assignments
$eligible = @()
$uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleEligibilitySchedules?`$expand=RoleDefinition,Principal,DirectoryScope"
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    $eligible += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

$eligible | ForEach-Object {
    if ($_.Principal."@odata.type" -match '.user' -and $_.Principal.onPremisesSyncEnabled -eq $true) {
        Write-Output "$($_.RoleDefinition.DisplayName),$($_.Principal.userPrincipalName)"
    }
    if ($_.Principal."@odata.type" -match '.group') {
        $roleName = $_.RoleDefinition.DisplayName
        $members = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$($_.PrincipalId)/members" -OutputType PSObject).value.userPrincipalName
        if ($members.Count -ne 0) { $members | ForEach-Object { Write-Output "$roleName,$_" }}
    }
}