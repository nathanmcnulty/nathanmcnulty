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
        $groupId = (Invoke-MgGraphRequest -Method POST -Uri "/beta/groups" -Body $body).value.Id
    } else { 
        $groupId  = (Invoke-MgGraphRequest -Method GET -Uri "/beta/groups?`$filter=UniqueName eq '$GroupName'").value.Id
    }

    # Get the existing members objectIds (paged for all results)
    $existingUsers = @()
    $uri = "/beta/groups/$groupId/members?`$select=id&`$top=999"
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        $existingUsers += $response.value.id
        $uri = $response.'@odata.nextLink'
    } while ($uri)

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
            Invoke-MgGraphRequest -Method PATCH -Uri "/beta/groups/$groupId" -Body @{ "members@odata.bind" = @($values[0..19]) }
            if ($values.Count -gt 20) { $values.RemoveRange(0,20) } else { $values.RemoveRange(0,$values.Count) }
        }
    }

    # Remove users from group
    if ($remove) { $remove | ForEach-Object { Invoke-MgGraphRequest -Method DELETE -Uri "/beta/groups/$groupId/members/$_/`$ref" }}
}

# Connect with scopes necessary to create groups amd read role assignments
Connect-MgGraph -Identity -NoWelcome

# Get latest $groupPrefix* groups
$global:groups = (Invoke-MgGraphRequest -Method GET -Uri "/beta/groups?`$filter=startswith(UniqueName,'$groupPrefix')&`$select=UniqueName" | Select-Object -ExpandProperty value).UniqueName

# Get privileged role assignments
$privileged = ((Invoke-MgGraphRequest -Method GET -Uri "/beta/roleManagement/directory/roleAssignments?`$expand=roleDefinition&`$filter=roleDefinition/isPrivileged eq true&`$select=principalId").value.principalId | Select-Object -Unique | ForEach-Object {
    Invoke-MgGraphRequest -Method GET -Uri "/beta/directoryObjects/$_" | Where-Object { $_.servicePrincipalType -notin ('Application','ManagedIdentity') }
}).Id
ProcessGroup -GroupName ($groupPrefix + "privileged") -CurrentUsers $privileged

# Get non-privileged role assignments
$nonprivileged = ((Invoke-MgGraphRequest -Method GET -Uri "/beta/roleManagement/directory/roleAssignments?`$expand=roleDefinition&`$filter=roleDefinition/isPrivileged eq false&`$select=principalId" | Select-Object -ExpandProperty value).principalId | Select-Object -Unique | ForEach-Object {
    Invoke-MgGraphRequest -Method GET -Uri "/beta/directoryObjects/$_" | Where-Object { $_.servicePrincipalType -notin ('Application','ManagedIdentity') }
}).Id
ProcessGroup -GroupName ($groupPrefix + "nonprivileged") -CurrentUsers $nonprivileged

# All roles
$all = $privileged + $nonprivileged | Select-Object -Unique
ProcessGroup -GroupName ($groupPrefix + "all") -CurrentUsers $all

# TO DO: Logging, error handling, batching for performance
<# Resources for potential improvements:

https://www.powershellgallery.com/packages/Generate-EntraAdminRolesReport/0.1/Content/Generate-EntraAdminRolesReport.ps1

#>