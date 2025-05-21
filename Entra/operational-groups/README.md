# Entra Operational Groups

The goal behind this solution is to maintain groups based on auth methods registered, MFA/passwordless, risk states, device details, sign-in logs, audit logs, and more. We can then use these to build dynamic groups to help with things like automate offboarding from weaker MFA methods and scrambling passwordless user's passwords :)

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

If you plan to use something like an Azure Automation Account or Function App, you will need the following modules:

```
Microsoft.Graph.Authentication
Microsoft.Graph.Beta.Groups
Microsoft.Graph.Beta.Identity.SignIns
Microsoft.Graph.Beta.Identity.Governance
Microsoft.Graph.Beta.Reports
Microsoft.Graph.Beta.Users
```

And this will grant the necessary permissions to a Managed Identity ;)

```
$SP_ID = "9b2b5994-f530-4470-8e4c-832e90d9a290"
"Group.ReadWrite.All","RoleManagement.Read.Directory","EntitlementManagement.Read.All","AuditLog.Read.All","User.Read.All","IdentityRiskEvent.Read.All" | ForEach-Object {
   $PermissionName = $_
   $GraphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
   $AppRole = $GraphSP.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}
   New-MgServicePrincipalAppRoleAssignment -AppRoleId $AppRole.Id -ServicePrincipalId $SP_ID -ResourceId $GraphSP.Id -PrincipalId $SP_ID
}

```
