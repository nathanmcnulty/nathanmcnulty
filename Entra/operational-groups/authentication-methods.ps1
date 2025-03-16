# TO DO: Look at batching to improve performance

# Connect with scopes necessary to create groups, update membership, and query the Reports API
Connect-MgGraph -Scopes Group.ReadWrite.All,AuditLog.Read.All

# Get latest registration details
$report = Get-MgBetaReportAuthenticationMethodUserRegistrationDetail -All

# If you would prefer to only create groups for methods that exist, delete the methods section below and uncomment the following command:
# $methods = $report.methodsRegistered | Select-Object -Unique

# Define methods to maintain groups for, delete or comment out ones you don't want
$methods = @(
    'email',
    'mobilePhone',
    'officePhone',
    'alternateMobilePhone',
    'microsoftAuthenticatorPush',
    'softwareOneTimePasscode',
    'hardwareOneTimePasscode',
    'fido2SecurityKey',
    'windowsHelloForBusiness',
    'microsoftAuthenticatorPasswordless',
    'temporaryAccessPass',
    'macOsSecureEnclaveKey',
    'passKeyDeviceBound',
    'passKeyDeviceBoundAuthenticator',
    'passKeyDeviceBoundWindowsHello'
)

$methods | ForEach-Object {
    # Store method in a variable for simpler use in loops and filters
    $method = $_

    # Get users currently registered for the method
    [array]$users = ($report | Where-Object { $method -in $_.MethodsRegistered }).Id

    # If the group doesn't exist
    if (!(Get-MgBetaGroup -Filter "mailNickName eq 'operational-am-$method'")) {
        # Create the group and store its objectId in $groupId
        $groupId = (New-MgBetaGroup -DisplayName "operational-am-$method" -MailEnabled:$False  -MailNickName "operational-am-$method" -SecurityEnabled).Id

        # If a non-empty list of users, add them to $add for the logic to add users to the group
        if ($users) { [array]$add = $users }
    # If the group does exist
    } else {
        # Get the group's objectId
        $groupId  = (Get-MgBetaGroup -Filter "mailNickName eq 'operational-am-$method'").Id

        # Get the existing members' objectIds
        [array]$members = (Get-MgBetaGroupMember -GroupId $groupId).Id

        # If existing members are found and users are registered for the method, compare the lists and store the differences in $add and $remove
        if ($members -and $users) {
            [array]$add = Compare-Object -ReferenceObject $users -DifferenceObject $members -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
            [array]$remove = Compare-Object -ReferenceObject $users -DifferenceObject $members -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        # If existing members are found but no users are registered for the method, store the existing members in $remove
        } elseif ($members) {
            # May consider adding logic to prevent large scale removal:
            # if ($members.Count -gt 20) { Write-Warning "Group has more than 20 members, consider reviewing before removing all members" }
            [array]$remove = $members
        # If no existing members are found and users are registered for the method, add them to $add
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
            Update-MgBetaGroup -GroupId $groupId -BodyParameter @{ "members@odata.bind" = $values[0..19] }
            if ($values.Count -gt 20) { $values.RemoveRange(0,20) } else { $values.RemoveRange(0,$values.Count) }
        }
    }

    # Remove users from group
    if ($remove) { $remove | ForEach-Object { Remove-MgBetaGroupMemberByRef -GroupId $groupId -DirectoryObjectId $_ }}

    # Remove variables to prevent carrying values into next loop
    Remove-Variable method,groupId,members,users,add,remove,values -ErrorAction SilentlyContinue
}

# Define the things you want to maintain groups for when FALSE, delete or comment out ones you don't want
$IsSomethingFalse = @(
    "IsAdmin",
    "IsMfaCapable",
    "IsMfaRegistered",
    "IsPasswordlessCapable",
    "IsSsprCapable",
    "IsSsprEnabled",
    "IsSsprRegistered"
)

$IsSomethingFalse | ForEach-Object {
    # Store value in a variable for use in loops and filters
    $something = $_

    # Get users whose value is FALSE
    [array]$users = ($report | Where-Object { $_.$something -eq $false }).Id

    # If the group doesn't exist
    if (!(Get-MgBetaGroup -Filter "mailNickName eq 'operational-am-$something-false'")) {
        # Create the group and store its objectId in $groupId
        $groupId = (New-MgBetaGroup -DisplayName "operational-am-$something-false" -MailEnabled:$False  -MailNickName "operational-am-$something-false" -SecurityEnabled).Id

        # Assuming a non-empty list of users, add them to the variable for the logic to add users to the group
        if ($users) { [array]$add = $users }
    # If the group does exist
    } else {
        # Get the group's objectId and the existing members' objectIds
        $groupId  = (Get-MgBetaGroup -Filter "mailNickName eq 'operational-am-$something-false'").Id
        [array]$members = (Get-MgBetaGroupMember -GroupId $groupId).Id

        # If existing members are found, compare the list of users to the list of members and store the differences in $add and $remove
        if ($members -and $users) {
            [array]$add = Compare-Object -ReferenceObject $users -DifferenceObject $members -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
            [array]$remove = Compare-Object -ReferenceObject $users -DifferenceObject $members -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        # If existing members are found but the list of users is empty, store the existing members in $remove
        } elseif ($members) {
            # May consider adding logic to prevent large scale changes:
            # if ($members.Count -gt 20) { Write-Warning "Group has more than 20 members, consider reviewing before removing all members" }
            [array]$remove = $members
        # If no existing members are found and a non-empty list of users, add them to the variable for the logic to add users to the group
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
            Update-MgBetaGroup -GroupId $groupId -BodyParameter @{ "members@odata.bind" = $values[0..19] }
            if ($values.Count -gt 20) { $values.RemoveRange(0,20) } else { $values.RemoveRange(0,$values.Count) }
        }
    }

    # Remove users from group
    if ($remove) { $remove | ForEach-Object { Remove-MgBetaGroupMemberByRef -GroupId $groupId -DirectoryObjectId $_ }}

    # Remove variables to prevent carrying values into next loop
    Remove-Variable something,groupId,members,users,add,remove,values -ErrorAction SilentlyContinue
}

$IsSomethingTrue | ForEach-Object {
    # Store value in a variable for use in loops and filters
    $something = $_

    # Get users whose value is TRUE
    [array]$users = ($report | Where-Object { $_.$something -eq $true }).Id

    # If the group doesn't exist
    if (!(Get-MgBetaGroup -Filter "mailNickName eq 'operational-am-$something-true'")) {
        # Create the group and store its objectId in $groupId
        $groupId = (New-MgBetaGroup -DisplayName "operational-am-$something-true" -MailEnabled:$False  -MailNickName "operational-am-$something-true" -SecurityEnabled).Id

        # Assuming a non-empty list of users, add them to the variable for the logic to add users to the group
        if ($users) { [array]$add = $users }
    # If the group does exist
    } else {
        # Get the group's objectId and the existing members' objectIds
        $groupId  = (Get-MgBetaGroup -Filter "mailNickName eq 'operational-am-$something-true'").Id
        [array]$members = (Get-MgBetaGroupMember -GroupId $groupId).Id

        # If existing members are found, compare the list of users to the list of members and store the differences in $add and $remove
        if ($members -and $users) {
            [array]$add = Compare-Object -ReferenceObject $users -DifferenceObject $members -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
            [array]$remove = Compare-Object -ReferenceObject $users -DifferenceObject $members -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        # If existing members are found but the list of users is empty, store the existing members in $remove
        } elseif ($members) {
            # May consider adding logic to prevent large scale changes:
            # if ($members.Count -gt 20) { Write-Warning "Group has more than 20 members, consider reviewing before removing all members" }
            [array]$remove = $members
        # If no existing members are found and a non-empty list of users, add them to the variable for the logic to add users to the group
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
            Update-MgBetaGroup -GroupId $groupId -BodyParameter @{ "members@odata.bind" = $values[0..19] }
            if ($values.Count -gt 20) { $values.RemoveRange(0,20) } else { $values.RemoveRange(0,$values.Count) }
        }
    }

    # Remove users from group
    if ($remove) { $remove | ForEach-Object { Remove-MgBetaGroupMemberByRef -GroupId $groupId -DirectoryObjectId $_ }}

    # Remove variables to prevent carrying values into next loop
    Remove-Variable something,groupId,members,users,add,remove,values -ErrorAction SilentlyContinue
}