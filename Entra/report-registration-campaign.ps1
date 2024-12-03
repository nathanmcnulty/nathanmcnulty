# As of 2024/12/03, Registration campaign only supports Microsoft Authenticator
# https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/RegistrationCampaign/fromNav/

# Connect with required scopes
Connect-MgGraph -Scopes Policy.Read.All,AuditLog.Read.All

# Get list of users targeted by registration campaign
$campaign = (Get-MgPolicyAuthenticationMethodPolicy).RegistrationEnforcement.AuthenticationMethodsRegistrationCampaign
$users = New-Object System.Collections.ArrayList
$campaign.IncludeTargets | ForEach-Object {
    # Add users to ArrayList (remove Out-Null to see count)
    if ($_.TargetType -eq "user") {
        $users.Add($_.Id) | Out-Null
    }

    # Add group members to ArrayList (remove Out-Null to see count)
    if ($_.TargetType -eq "group") {
        (Get-MgGroupMember -GroupId $_.Id).Id | ForEach-Object { $users.Add($_) } | Out-Null
    }
}

# Remove excluded users (not in GUI)
$campaign.ExcludeTargets | ForEach-Object {
    # Remove users from ArrayList (remove Out-Null to see count)
    if ($_.TargetType -eq "user") {
        $users.Remove($_.Id) | Out-Null
    }

    # Remove group members from ArrayList (remove Out-Null to see count)
    if ($_.TargetType -eq "group") {
        (Get-MgGroupMember -GroupId $_.Id).Id | ForEach-Object { $users.Remove($_) } | Out-Null
    }
}

# Get registration details for users
$report = Get-MgReportAuthenticationMethodUserRegistrationDetail | Where-Object { $_.Id -in $users }
$report | Select-Object UserPrincipalName,IsMfaCapable,UserPreferredMethodForSecondaryAuthentication,MethodsRegistered | Sort-Object IsMfaCapable  | Format-Table -Wrap

<# Add MFA capable users to a group
$groupId = (Get-MgGroup -Filter "DisplayName eq 'Enforce MFA'").Id
$report | Where-Object { $_.IsMfaCapable -eq $true } | ForEach-Object { 
    New-MgGroupMember -GroupId $groupId -DirectoryObjectId $_.Id
}
#>

<# Registration campgain my support passkeys in the future, here's the examples for that:
$groupId = (Get-MgGroup -Filter "DisplayName eq 'Enforce passkeys'").Id
$report | Where-Object { "passKeyDeviceBoundAuthenticator" -in $_.MethodsRegistered } | ForEach-Object { 
    New-MgGroupMember -GroupId $groupId -DirectoryObjectId $_.Id
}
#>