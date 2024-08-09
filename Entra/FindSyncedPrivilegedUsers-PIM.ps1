# Connect with appropriate scopes for PIM
Connect-MgGraph -Scopes RoleAssignmentSchedule.Read.Directory,RoleEligibilitySchedule.Read.Directory

# Get active assignments
Get-MgBetaRoleManagementDirectoryRoleAssignmentSchedule -ExpandProperty RoleDefinition,Principal,DirectoryScope -All | ForEach-Object {
    if ($_.Principal.AdditionalProperties."@odata.type" -match '.user' -and $_.Principal.AdditionalProperties.onPremisesSyncEnabled -eq $true) {
        Write-Output "$($_.RoleDefinition.DisplayName),$($_.Principal.AdditionalProperties.userPrincipalName)"
    }
    if ($_.Principal.AdditionalProperties."@odata.type" -match '.group') {
        $roleName = $_.RoleDefinition.DisplayName
        $members = (Get-MgGroupMember -GroupId $_.PrincipalId).AdditionalProperties.userPrincipalName
        if ($members.Count -ne 0) { $members | ForEach-Object { Write-Output "$roleName,$_" }}
    }
}

# Get eligible assignments
Get-MgBetaRoleManagementDirectoryRoleEligibilitySchedule -ExpandProperty RoleDefinition,Principal,DirectoryScope -All | ForEach-Object {
    if ($_.Principal.AdditionalProperties."@odata.type" -match '.user' -and $_.Principal.AdditionalProperties.onPremisesSyncEnabled -eq $true) {
        Write-Output "$($_.RoleDefinition.DisplayName),$($_.Principal.AdditionalProperties.userPrincipalName)"
    }
    if ($_.Principal.AdditionalProperties."@odata.type" -match '.group') {
        $roleName = $_.RoleDefinition.DisplayName
        $members = (Get-MgGroupMember -GroupId $_.PrincipalId).AdditionalProperties.userPrincipalName
        if ($members.Count -ne 0) { $members | ForEach-Object { Write-Output "$roleName,$_" }}
    }
}
