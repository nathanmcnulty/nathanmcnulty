$groupPrefix = "eog-adminroles-"

# Helper function to create and update groups
function ProcessGroup {
    param(
        [string]$GroupName,
        [array]$CurrentUsers
    )

    # If the group doesn't exist, create it, othewrwise get its objectId
    if ($GroupName -notin $groups) {
        $body = @{
            displayName = $GroupName
            mailEnabled = $false
            mailNickname = $GroupName
            securityEnabled = $true
            UniqueName = $GroupName
        }
        $groupId = (New-MgBetaGroup -BodyParameter $body).Id
    } else { 
        $groupId  = (Get-MgBetaGroup -Filter "UniqueName eq '$GroupName'").Id 
    }

    # Get the existing members objectIds
    [array]$existingUsers = (Get-MgBetaGroupMember -GroupId $groupId -All).Id

    # If existing members are found and users are registered for the method, compare the lists and store the differences in $add and $remove
    if ($existingUsers -and $CurrentUsers) {
        $add = Compare-Object -ReferenceObject $CurrentUsers -DifferenceObject $existingUsers -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
        $remove = Compare-Object -ReferenceObject $CurrentUsers -DifferenceObject $existingUsers -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
    # If existing members are found but no users are registered for the method, store the existing members in $remove
    } elseif ($existingUsers) {
        # Consider adding logic to prevent large scale removal:
        # if ($existing.Count -gt 50) { Write-Warning "Group has more than 50 members, consider reviewing before removing all members" }
        $remove = $existingUsers
    # If no existing members are found and users are registered for the method, add them to $add
    } else {
        $add = $CurrentUsers
    }

    # Add missing users to group
    if ($add) { 
        # Create a new array list and store the OData values for use in BodyParameter
        $values = [System.Collections.Generic.List[Object]]::new()
        $add | ForEach-Object { $values.Add("https://graph.microsoft.com/beta/directoryObjects/$_") }

        # Loop through the list of users and add them to the group in batches of 20 (limit for the API)
        while ($values.Count -ne 0) {
            Update-MgBetaGroup -GroupId $groupId -BodyParameter @{ "members@odata.bind" = $values[0..19] }
            if ($values.Count -gt 20) { $values.RemoveRange(0,20) } else { $values.RemoveRange(0,$values.Count) }
        }
    }

    # Remove users from group
    if ($remove) { $remove | ForEach-Object { Remove-MgBetaGroupMemberByRef -GroupId $groupId -DirectoryObjectId $_ }}
}

# Connect with scopes necessary to create groups amd read role assignments
Connect-MgGraph -Scopes Group.ReadWrite.All,RoleManagement.Read.Directory,EntitlementManagement.Read.All -NoWelcome

# Get latest $groupPrefix* groups
$global:groups = (Get-MgBetaGroup -Filter "startswith(UniqueName,'$groupPrefix')" -Property UniqueName).UniqueName

# Get privileged role assignments
$privileged = ((Get-MgBetaRoleManagementDirectoryRoleAssignment -ExpandProperty "roleDefinition" -Filter "roleDefinition/isPrivileged eq true" -Property PrincipalId).PrincipalId | Select-Object -Unique | ForEach-Object { Get-MgDirectoryObject -DirectoryObjectId $_ | Where-Object { $_.AdditionalProperties.servicePrincipalType -notin ('Application','ManagedIdentity') }}).Id
ProcessGroup -GroupName ($groupPrefix + "privileged") -CurrentUsers $privileged

# Get non-privileged role assignments
$nonprivileged = ((Get-MgBetaRoleManagementDirectoryRoleAssignment -ExpandProperty "roleDefinition" -Filter "roleDefinition/isPrivileged eq false" -Property PrincipalId).PrincipalId | Select-Object -Unique | ForEach-Object { Get-MgDirectoryObject -DirectoryObjectId $_ | Where-Object { $_.AdditionalProperties.servicePrincipalType -notin ('Application','ManagedIdentity') }}).Id
ProcessGroup -GroupName ($groupPrefix + "nonprivileged") -CurrentUsers $nonprivileged

# All roles
$all = $privileged + $nonprivileged | Select-Object -Unique
ProcessGroup -GroupName ($groupPrefix + "all") -CurrentUsers $all

# TO DO: Logging, error handling, batching for performance