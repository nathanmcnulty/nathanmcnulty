# Entra Operational Groups

The goal behind this solution is to maintain groups based on various details such as registered authentication methods, MFA/passwordless, risk states, device details, sign-in logs, audit logs, and more. We can then use these for policy targeting, to build dynamic groups, or even syncing to on-prem or other cloud solutions. These can even be used to provide some of the Identity Governance features for those only licensed for Entra ID Premium P2 :)

Here's an example of resetting user passwords, but I would recommend waiting for the groups that determine users in the IsPasswordlessCapable-true group are also not in a group that shows they recently used a weaker method.

```powershell
Get-MgGroup -Filter "displayName eq 'eog-authmethods-IsPasswordlessCapable-true'" | ForEach-Object {
  Get-MgGroupMember -GroupId $_.Id | ForEach-Object {
    $passwordProfile  = @{
      forceChangePasswordNextSignIn = $false
      forceChangePasswordNextSignInWithMfa = $false
      password = "$(New-Guid)"
    }
    Update-MgUser -UserId $_ -PasswordProfile $passwordProfile -WhatIf -Verbose
  }
}
```

If you plan to use something like an Azure Automation account or Function app, you only need the **Microsoft.Graph.Authentication** module for these. This runs with better performance and reduces memory use for these environments, though it's not quite as admin friendly. Check the graph-powershell folder if you would prefer using full Graph PowerShell cmdlet based scripts.

You will also need to run this to grant the necessary permissions to a Managed Identity (update $SP_ID with the objectId of your SP/MI) ;)

```
$SP_ID = "9b2b5994-f530-4470-8e4c-832e90d9a290"
"Group.ReadWrite.All","RoleManagement.Read.Directory","EntitlementManagement.Read.All","AuditLog.Read.All","User.Read.All","IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All","Directory.Read.All" | ForEach-Object {
   $PermissionName = $_
   $GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
   $AppRole = $GraphSP.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}
   New-MgServicePrincipalAppRoleAssignment -AppRoleId $AppRole.Id -ServicePrincipalId $SP_ID -ResourceId $GraphSP.Id -PrincipalId $SP_ID
}
```
