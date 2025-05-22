$groupPrefix = "eog-department-"

# Connect with scopes necessary to create groups, update membership, and query the Reports API
Connect-MgGraph -Identity -NoWelcome

# Get department of all users in the tenant
$departments = @()
$uri = "/beta/users?`$select=department&`$top=999"
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $departments += $response.value.department | Where-Object { $null -ne $_ }
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Get existing department groups
$groups = (Invoke-MgGraphRequest -Method GET -Uri "/beta/groups?`$filter=startswith(UniqueName,'$groupPrefix')&`$select=UniqueName").value.UniqueName

# Create department groups
$departments | Select-Object -Unique | ForEach-Object {
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
        Invoke-MgGraphRequest -Method POST -Uri "/beta/groups" -Body $body
    }
}

<#
Note: There is no ideal way to handle deleting inactive groups

If you would like to attempt this, get all groups, get membership count for each. If empty, set an extension attribute with the date unless one already exists. If not empty, clear the extension attribute. Then use the date value to determine when it is safe to delete the group.
#>
