$groupPrefix = "eog-department-"

# Connect with scopes necessary to create groups, update membership, and query the Reports API
Connect-MgGraph -Scopes Group.ReadWrite.All,User.Read.All -NoWelcome

# Get department of all users in the tenant
$departments = (Get-MgBetaUser -All -Property Department | Where-Object { $null -ne $_.Department } | Select-Object Department -Unique).Department

# Get existing department groups
$groups = (Get-MgBetaGroup -Filter "startswith(UniqueName,'$groupPrefix')" -Property UniqueName).UniqueName

# Create department groups
$departments | ForEach-Object {
    $groupName = "$groupPrefix$($_ -replace '[^a-zA-Z0-9]','')"
    $groupName = $groupName.Substring(0, [Math]::Min($groupName.Length, 64))

    if ($groupName -notin $groups) {
        $body = @{
            displayName = "$groupPrefix$_"
            description = "Department Group: $_"
            mailEnabled = $false
            mailNickname = $groupName
            securityEnabled = $true
            GroupTypes = @("DynamicMembership")
            MembershipRule = "(user.department -eq `"$_`")"
            MembershipRuleProcessingState = "On"
            UniqueName = $groupName
        }
        New-MgBetaGroup -BodyParameter $body
    }
}

<#
Note: There is no ideal way to handle deleting inactive groups

If you would like to attempt this, get all groups, get membership count for each. If empty, set an extension attribute with the date unless one already exists. If not empty, clear the extension attribute. Then use the date value to determine when it is safe to delete the group.
#>
