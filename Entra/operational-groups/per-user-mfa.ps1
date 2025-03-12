# TO DO: Look at batching to improve performance

# Connect with scopes necessary to create groups, update membership, and query users
Connect-MgGraph -Scopes Group.ReadWrite.All,User.Read.All

# Get latest per-user MFA state details
$report = Get-MgBetaUser -All -Property id,perUserMfaState

# If you would prefer to only create groups for states that exist, delete the states section below and uncomment the following command:
# $states = $report.additionalProperties.perUserMfaState | Select-Object -Unique

# Define states to maintain groups for, delete or comment out ones you don't want
$states = @(
    'disabled',
    'enabled',
    'enforced'
)

$states | ForEach-Object {
    # Store state in a variable for simpler use in loops and filters
    $state = $_

    # Get users in current state
    [array]$users = ($report | Where-Object { $state -in $_.additionalProperties.perUserMfaState }).Id

    # If the group doesn't exist
    if (!(Get-MgBetaGroup -Filter "mailNickName eq 'operational-pum-$state'")) {
        # Create the group and store its objectId in $groupId
        $groupId = (New-MgBetaGroup -DisplayName "operational-pum-$state" -MailEnabled:$False  -MailNickName "operational-pum-$state" -SecurityEnabled).Id

        # If a non-empty list of users, add them to $add for the logic to add users to the group
        if ($users) { [array]$add = $users }
    # If the group does exist
    } else {
        # Get the group's objectId
        $groupId  = (Get-MgBetaGroup -Filter "mailNickName eq 'operational-pum-$state'").Id

        # Get the existing members' objectIds
        [array]$members = (Get-MgBetaGroupMember -GroupId $groupId).Id

        # If existing members are found and users are in current state, compare the lists and store the differences in $add and $remove
        if ($members -and $users) {
            [array]$add = Compare-Object -ReferenceObject $users -DifferenceObject $members -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
            [array]$remove = Compare-Object -ReferenceObject $users -DifferenceObject $members -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        # If existing members are found but no users are in current state, store the existing members in $remove
        } elseif ($members) {
            # May consider adding logic to prevent large scale removal:
            # if ($members.Count -gt 20) { Write-Warning "Group has more than 20 members, consider reviewing before removing all members" }
            [array]$remove = $members
        # If no existing members are found and users are in current state, add them to $add
        } else {
            [array]$add = $users
        }
    }

    # Add missing users to group
    if ($add) {
        # Create a new array list and store the OData values for use in BodyParameter
        $values = New-Object System.Collections.ArrayList
        $add | ForEach-Object { $values.Add("https://graph.microsoft.com/beta/directoryObjects/$_") | Out-Null }

        # Loop through the list of users and add them to the group in batches of 20 (limit for the API)
        while ($values.Count -ne 0) {
            Update-MgGroup -GroupId $groupId -BodyParameter @{ "members@odata.bind" = $values[0..19] }
            if ($values.Count -gt 20) { $values.RemoveRange(0,20) } else { $values.RemoveRange(0,$values.Count) }
        }
    }

    # Remove users from group
    if ($remove) { $remove | ForEach-Object { Remove-MgBetaGroupMemberByRef -GroupId $groupId -DirectoryObjectId $_ }}

    # Remove variables to prevent carrying values into next loop
    Remove-Variable state,groupId,members,users,add,remove,values -ErrorAction SilentlyContinue
}