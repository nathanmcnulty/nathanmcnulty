# Connect with required scopes
Connect-MgGraph -Scopes Policy.Read.All,AuditLog.Read.All

# Get list of users targeted by registration campaign
$users = New-Object System.Collections.ArrayList
(Get-MgPolicyAuthenticationMethodPolicy).RegistrationEnforcement.AuthenticationMethodsRegistrationCampaign.IncludeTargets | ForEach-Object {
    # Add users to ArrayList (remove Out-Null to see count)
    if ($_.TargetType -eq "user") {
        $users.Add($_.Id) | Out-Null
    }

    # Add group members to ArrayList (remove Out-Null to see count)
    if ($_.TargetType -eq "group") {
        (Get-MgGroupMember -GroupId $_.Id).Id | ForEach-Object { $users.Add($_) } | Out-Null
    }
} 

# Get registration details for users
Get-MgReportAuthenticationMethodUserRegistrationDetail | Where-Object { $_.Id -in $users } | Select-Object UserPrincipalName,UserPreferredMethodForSecondaryAuthentication,IsMfaCapable | Sort-Object IsMfaCapable