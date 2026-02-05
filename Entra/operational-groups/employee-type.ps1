$groupPrefix = "eog-employeetype-"

# Connect with scopes necessary to create groups, update membership, and query the Reports API
Connect-MgGraph -Identity -NoWelcome

# Get employeeType of all users in the tenant
$employeeTypes = @()
$uri = "/beta/users?`$select=employeeType&`$top=999"
do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $employeeTypes += $response.value.employeeType | Where-Object { $null -ne $_ }
    $uri = $response.'@odata.nextLink'
} while ($uri)

# Get existing employeeType groups
$groups = (Invoke-MgGraphRequest -Method GET -Uri "/beta/groups?`$filter=startswith(UniqueName,'$groupPrefix')&`$select=UniqueName").value.UniqueName

# Create employeeType groups
$employeeTypes | Select-Object -Unique | ForEach-Object {
    $groupName = "$groupPrefix$($_ -replace '[^a-zA-Z0-9]','')"
    $groupName = $groupName.Substring(0, [Math]::Min($groupName.Length, 64))

    if ($groupName -notin $groups) {
        $body = @{
            displayName = "$groupPrefix$_"
            description = "employeeType Group: $_"
            mailEnabled = $false
            mailNickname = $groupName
            securityEnabled = $true
            GroupTypes = @("DynamicMembership")
            MembershipRule = "(user.employeeType -eq `"$_`")"
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
