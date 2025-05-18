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
