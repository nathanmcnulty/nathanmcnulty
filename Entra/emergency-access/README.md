# Emergency Access Accounts

## Excluding Emergency Access Accounts from Conditional Access

### Logic App - Sliding Window

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fnathanmcnulty%2Fnathanmcnulty%2Ff54023819a4336930237e8403b2df923bf492508%2FEntra%2Femergency-access%2Femergency-access-exclusion.json)

This solution exlcudes a security group from all CA policies, so you will need to create a security group and place your emergency access accounts in this group. Conditional Access caches group memberships, so there is no risk that an outage between Conditional Access and Entra ID will cause issues. You will need the security group objectId during deployment of the Logic App template below.

<img width="728" height="709" alt="image" src="https://github.com/user-attachments/assets/25608f7f-00dc-4e0c-8f3c-a16af389f92f" />

Once the resource has been created, copy the Managed Identity from Settings - Identity, and use the following script to grant the Managed Identity permissions to modify Conditional Access policies:

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
