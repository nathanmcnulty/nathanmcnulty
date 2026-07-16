param(
    [Parameter(Mandatory = $false)]
    [string] $EmergencyAccountsGroupObjectId = $env:EMERGENCY_ACCESS_GROUP_OBJECT_ID,

    [Parameter(Mandatory = $false)]
    [object] $WebhookData,

    [Parameter(Mandatory = $false)]
    [object] $Request,

    [Parameter(Mandatory = $false)]
    [object] $TriggerMetadata
)

$ErrorActionPreference = 'Stop'

# These bindings allow the same script to run as an Automation webhook or HTTP-triggered Function.
$null = $WebhookData
$null = $Request
$null = $TriggerMetadata

$parsedGroupId = [guid]::Empty
if (-not [guid]::TryParse($EmergencyAccountsGroupObjectId, [ref]$parsedGroupId)) {
    throw 'EmergencyAccountsGroupObjectId must be a valid Microsoft Entra group object ID.'
}

Connect-MgGraph -Identity -NoWelcome

$policies = (Invoke-MgGraphRequest `
    -Method GET `
    -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies').value

$updatedPolicies = [System.Collections.Generic.List[string]]::new()
$unchangedPolicies = [System.Collections.Generic.List[string]]::new()
$failedPolicies = [System.Collections.Generic.List[object]]::new()

foreach ($policy in $policies) {
    $currentExclusions = @($policy.conditions.users.excludeGroups)
    if ($EmergencyAccountsGroupObjectId -in $currentExclusions) {
        $unchangedPolicies.Add([string]$policy.id)
        continue
    }

    $body = @{
        conditions = @{
            users = @{
                excludeGroups = @($currentExclusions + $EmergencyAccountsGroupObjectId | Select-Object -Unique)
            }
        }
    }

    try {
        Invoke-MgGraphRequest `
            -Method PATCH `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($policy.id)" `
            -Body ($body | ConvertTo-Json -Depth 8) `
            -ContentType 'application/json'
        $updatedPolicies.Add([string]$policy.id)
    }
    catch {
        $failedPolicies.Add([pscustomobject]@{
            policyId = [string]$policy.id
            error = $_.Exception.Message
        })
    }
}

$result = [ordered]@{
    policiesEvaluated = @($policies).Count
    policiesUpdated = $updatedPolicies.Count
    policiesAlreadyExcluded = $unchangedPolicies.Count
    policiesFailed = $failedPolicies.Count
    updatedPolicyIds = @($updatedPolicies)
    failed = @($failedPolicies)
}

if (Get-Command Push-OutputBinding -ErrorAction SilentlyContinue) {
    $statusCode = if ($failedPolicies.Count -eq 0) { 200 } else { 500 }
    Push-OutputBinding -Name Response -Value @{
        StatusCode = $statusCode
        Body = ($result | ConvertTo-Json -Depth 6)
        Headers = @{ 'Content-Type' = 'application/json' }
    }
}
else {
    [pscustomobject]$result
}

if ($failedPolicies.Count -gt 0) {
    throw "Failed to update $($failedPolicies.Count) Conditional Access policy or policies."
}
