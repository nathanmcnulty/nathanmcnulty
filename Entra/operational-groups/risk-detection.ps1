$groupPrefix = "eog-riskdetection-"

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

# Connect with scopes necessary to create groups, update membership, and query the Reports API
Connect-MgGraph -Scopes Group.ReadWrite.All,IdentityRiskEvent.Read.All -NoWelcome

# Get latest risk detection details
$global:report = Get-MgBetaRiskDetection -All -Filter "Activity eq 'user'" -Property userId,riskEventType,riskState | Where-Object { $_.RiskState -in ('atRisk','confirmedCompromised') }
$global:groups = (Get-MgBetaGroup -Filter "startswith(UniqueName,'$groupPrefix')" -Property UniqueName).UniqueName

# If you would prefer to only create groups for event types that exist, delete the event types section below and uncomment the following command:
# $eventTypes = $report.RiskEventType | Select-Object -Unique

# Define event types to maintain groups for, delete or comment out ones you don't want
$eventTypes  = @(
    "adminConfirmedUserCompromised", 
    "anomalousToken",
    "anomalousUserActivity",
    "anonymizedIPAddress",
    "generic",
    "impossibleTravel",
    "investigationsThreatIntelligence",
    "suspiciousSendingPatterns",
    "leakedCredentials",
    "maliciousIPAddress",
    "malwareInfectedIPAddress",
    "mcasSuspiciousInboxManipulationRules",
    "newCountry",
    "passwordSpray",
    "riskyIPAddress",
    "suspiciousAPITraffic",
    "suspiciousBrowser",
    "suspiciousInboxForwarding",
    "suspiciousIPAddress",
    "tokenIssuerAnomaly",
    "unfamiliarFeatures",
    "unlikelyTravel"
)

$eventTypes | ForEach-Object {
    $type = $_

    # Get users currently registered for the method
    $current = ($report | Where-Object { $_.RiskEventType -eq $type }).UserId
    ProcessGroup -GroupName "$groupPrefix$type" -CurrentUsers $current
}