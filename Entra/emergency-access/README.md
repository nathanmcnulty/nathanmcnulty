# Emergency Access Accounts

## Excluding Emergency Access Accounts from Conditional Access

### Logic App - Scheduled
<details>
  <summary>Expand for details</summary><br>

<span style="display:block">[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnathanmcnulty%2Fnathanmcnulty%2Frefs%2Fheads%2Fmain%2FEntra%2Femergency-access%2Femergency-access-exclusion.json)</span>

This solution exlcudes a security group from all CA policies, so you will need to create a security group and place your emergency access accounts in this group. Conditional Access caches group memberships, so there is no risk that an outage between Conditional Access and Entra ID will cause issues. You will need the security group objectId during deployment of the Logic App template below.

<img width="728" height="709" alt="image" src="https://github.com/user-attachments/assets/25608f7f-00dc-4e0c-8f3c-a16af389f92f" />
</details>

### Logic App - Sentinel

<details>
  <summary>Expand for details</summary><br>

<span style="display:block">[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnathanmcnulty%2Fnathanmcnulty%2Frefs%2Fheads%2Fmain%2FEntra%2Femergency-access%2Femergency-access-exclusion-sentinel.json)</span>

This solution uses a Sentinel NRT Analytics rule to create an alert that triggers a Logic App. The Logic App only runs when an alert is created (so only when a Conditional Access change is detected), and this reduces cost by not running as often as well as limiting the number of actions because it only needs to process the one Conditional Access policy that was created or changed rather than processing all policies.<br><br>

The query below excludes the Managed Identity (to avoid loops) based on the default name of the Logic app, so if you change the name of the Logic App, you will need to change the query below to reflect the name of the Logic App. Sentinel will also need to be granted permissions on the resource group containing the Logic app.<br><br>

```kql
AuditLogs
| where OperationName in ("Add conditional access policy","Update conditional access policy")
| extend CAPolicyId = parse_json(TargetResources)[0]["id"]
| where Identity != "emergency-access-exclusion"
//| where parse_json(InitiatedBy)["app"]["appId"] == '' // Uncomment to exclude all modifications made by apps
```
</details>

### Logic App - Azure Monitor

<details>
  <summary>Expand for details</summary><br>
This solution is nearly identical to the Sentinel method above except that Azure Monitor (Log Analytics) can only run the query on an interval (1, 5, 10, or 15 minutes), and the cost to enable alerts may actually be more expensive than running Logic Apps on a schedule. The value here is if you inted to (or already do) create lots of alerts based on your Azure Monitor data.<br><br>
  
The query already excludes the Identity that is based on the default name of the Logic App. If you change the name of the Logic App, you will need to change the query below to reflect the name of the Logic App.<br><br>

```kql
AuditLogs
| where OperationName in ("Add conditional access policy","Update conditional access policy")
| extend CAPolicyId = parse_json(TargetResources)[0]["id"]
| where Identity != "emergency-access-exclusion"
//| where parse_json(InitiatedBy)["app"]["appId"] == '' // Uncomment to exclude all modifications made by apps
```
</details>

### Automation account

<details>
  <summary>Expand for details</summary><br>
This solution uses a PowerShell runbook in an Azure Automation account, and it can be configured to run on a schedule or triggered via a webhook. I plan to create an Azure Developer CLI (azd) deployment for this and a few other solutions as a showcase of how that tool works, but for now you can simply copy the code from the script here:
https://github.com/nathanmcnulty/nathanmcnulty/blob/main/Entra/emergency-access/emergency-access-exclusion.ps1
</details>

### Granting Permissions to the Managed Identity

To ensure emergency access accounts are never blocked by Conditional Access policies, we will use some form of automation to check and remediate all Conditional Access policise. For this, we will always want to use a Managed Identity, and that Managed Identity will need permissions in Entra to make the necessary changes in Conditional Access. Regardless of automation tool you choose, you will need to copy the Managed Identity from Settings - Identity, and use the following script to grant the Managed Identity permissions to modify Conditional Access policies:

```powershell
$MI = "752c2130-dd18-4804-b2a5-c04edb155335"

# Connect to Graph with scope to grant API permissions to Managed Identity
Connect-MgGraph -Scopes "AppRoleAssignment.ReadWrite.All"

# Get SP for Graph API
$GraphSP = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'").value

# Get each permission App Role ID and assign the App Role to the Managed Identity
"Policy.Read.All","Policy.ReadWrite.ConditionalAccess" | ForEach-Object {
   $permission = $_
   $AppRole = $GraphSP.AppRoles | Where-Object {$_.Value -eq $permission -and $_.AllowedMemberTypes -contains "Application"}
   $body = @{
    "principalId" = $MI
    "resourceId" = $GraphSP.Id
    "appRoleId" = $AppRole.Id
   }
   Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MI/appRoleAssignments" -Body ($body | ConvertTo-Json) -ContentType "application/json"
}
```

