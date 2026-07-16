# Emergency Access Accounts

These solutions ensure a designated Microsoft Entra security group remains excluded from Conditional Access policies. Place the emergency access accounts in that group and deploy one remediation method.

## Recommended approach

Use the Microsoft Sentinel solution when Entra audit logs are already ingested into Sentinel. It reacts to successful Conditional Access policy creation or modification and checks only the affected policy. The template deploys the complete path: NRT analytics rule, alert-triggered Logic App, and alert-created automation rule.

Use the scheduled Logic App or PowerShell solution when Sentinel is not available. Those approaches enumerate all Conditional Access policies, which is less event-specific but provides a useful periodic safety check.

## Microsoft Sentinel and Logic App

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnathanmcnulty%2Fnathanmcnulty%2Frefs%2Fheads%2Fmain%2FEntra%2Femergency-access%2Femergency-access-exclusion-sentinel.json)

Deploy [emergency-access-exclusion-sentinel.json](emergency-access-exclusion-sentinel.json) to the resource group where the Logic App should reside. Provide:

- Emergency access group object ID
- Existing Sentinel workspace name
- Resource group containing the Sentinel workspace
- Optional Logic App name

The template contains no tenant-specific identifiers. It creates this flow:

```text
Conditional Access policy audit event
    -> Log Analytics AuditLogs
    -> Sentinel NRT analytics rule
    -> alert-created Sentinel automation rule
    -> Logic App
    -> Microsoft Graph policy GET/PATCH
```

The deployed query is equivalent to the following, with the Logic App name inserted from the template parameter to prevent remediation events from retriggering the workflow:

```kql
AuditLogs
| where Result =~ "success"
| where OperationName in ("Add conditional access policy", "Update conditional access policy")
| where Identity != "emergency-access-exclusion-sentinel"
| extend CAPolicyId = tostring(todynamic(TargetResources)[0].id), ActorIdentity = Identity
| where isnotempty(CAPolicyId)
| project TimeGenerated, CAPolicyId, OperationName, ActorIdentity, CorrelationId
```

The analytics rule creates one alert per changed policy and does not create an incident. The automation rule invokes the playbook when that specific analytics rule creates an alert. This replaces the older direct analytics-rule playbook invocation path retired in March 2026.

### Post-deployment permissions

Two permissions are required after deployment:

1. Grant Microsoft Sentinel's service account **Microsoft Sentinel Automation Contributor** on the resource group containing the playbook.
2. Grant the Logic App managed identity Microsoft Graph application permissions `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess`.

Example Graph permission assignment:

```powershell
$ManagedIdentityObjectId = "<managed identity object ID from deployment output>"

Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All", "Application.Read.All"

$GraphServicePrincipal = Get-MgServicePrincipal `
    -Filter "appId eq '00000003-0000-0000-c000-000000000000'" `
    -Property Id,AppRoles

$ExistingAssignments = Get-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $ManagedIdentityObjectId `
    -All

foreach ($PermissionName in "Policy.Read.All", "Policy.ReadWrite.ConditionalAccess") {
    $AppRole = $GraphServicePrincipal.AppRoles |
        Where-Object {
            $_.Value -eq $PermissionName -and
            $_.AllowedMemberTypes -contains "Application"
        }

    if ($AppRole.Id -notin $ExistingAssignments.AppRoleId) {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $ManagedIdentityObjectId `
            -PrincipalId $ManagedIdentityObjectId `
            -ResourceId $GraphServicePrincipal.Id `
            -AppRoleId $AppRole.Id
    }
}
```

## Scheduled Logic App

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnathanmcnulty%2Fnathanmcnulty%2Frefs%2Fheads%2Fmain%2FEntra%2Femergency-access%2Femergency-access-exclusion.json)

The scheduled [emergency-access-exclusion.json](emergency-access-exclusion.json) workflow checks every Conditional Access policy and adds the configured group wherever it is absent. Grant its managed identity the same Graph permissions described above.

## Azure Automation or PowerShell Function

[emergency-access-exclusion.ps1](emergency-access-exclusion.ps1) provides the same full-policy evaluation for an Azure Automation runbook or PowerShell Function. It can run on a schedule or be invoked by a webhook. Webhook content is not trusted or used to select a policy; every invocation re-reads the authoritative policy collection from Microsoft Graph.

Configuration:

- Runbook parameter `EmergencyAccountsGroupObjectId`, or Function application setting `EMERGENCY_ACCESS_GROUP_OBJECT_ID`
- System-assigned or user-assigned managed identity
- `Microsoft.Graph.Authentication` PowerShell module
- Graph application permissions `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess`

The script validates the group ID, preserves existing exclusions, updates only noncompliant policies, and reports evaluated, changed, unchanged, and failed counts. An HTTP-triggered PowerShell Function can use the script as `run.ps1` with bindings named `Request` and `Response`.

Treat Automation webhook URLs and Function keys as secrets. Azure Automation authorizes webhook calls by possession of the URL and retains runbook input in job logs.

## Azure Monitor alternative

An Azure Monitor scheduled query alert can use the same KQL as the Sentinel rule, but Log Analytics alert evaluation is interval-based and does not provide Sentinel's alert automation model. Use this only when Azure Monitor alerts are already the preferred automation entry point.

## Verification

1. Create or update a test Conditional Access policy without the emergency access group exclusion.
2. Confirm the selected automation method adds the group to `conditions.users.excludeGroups` without changing other policy conditions.
3. For Sentinel, confirm one NRT alert and a successful automation-rule action and Logic App run.
4. Update the policy again after the exclusion exists and confirm no PATCH is required.
5. Review failures and Sentinel analytics-rule health regularly.

## References

- [Manage emergency access accounts in Microsoft Entra ID](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access)
- [Work with near-real-time analytics rules in Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/create-nrt-rules)
- [Create and use Microsoft Sentinel automation rules](https://learn.microsoft.com/azure/sentinel/create-manage-use-automation-rules)
- [Migrate alert-triggered playbooks to automation rules](https://learn.microsoft.com/azure/sentinel/automation/migrate-playbooks-to-automation-rules)
- [Start an Azure Automation runbook from a webhook](https://learn.microsoft.com/azure/automation/automation-webhooks)
- [PowerShell developer reference for Azure Functions](https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell)
