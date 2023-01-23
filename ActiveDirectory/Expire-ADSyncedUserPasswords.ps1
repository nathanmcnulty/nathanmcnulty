[CmdletBinding()]
   Param(
      [switch] $StartAadSync,
      [switch] $RevokeAadTokens
    )

# Get list of enabled users whose passwords are expired
Get-ADUser -SearchBase "OU=Employees,DC=domain,DC=com" -Filter { Enabled -eq $True -and PasswordNeverExpires -eq $False } -Properties "SAMAccountName","DisplayName","mail","passwordlastset","msDS-UserPasswordExpiryTimeComputed","CanonicalName" | Select-Object -Property "SAMAccountName","UserPrincipalName","mail","DisplayName","passwordlastset",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}},"CanonicalName" | Where-Object { $_.ExpiryDate -lt (Get-Date) } | ForEach-Object {
   # Set change password at next logon flag
   Set-ADUser $_.SAMAccountName -ChangePasswordAtLogon $true -Verbose
   
   # Revoke Azure AD tokens
   if ($RevokeAadTokens) {
      [array]$users += $_.UserPrincipalName
   }
}

# Immediately sync changes to Azure AD
if ($StartAadSync) {
   Start-Sleep -Seconds 60
   #Start-ADSyncSyncCycle -PolicyType Delta
   #Invoke-Command -ComputerName AADConnect -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }
}

if ($users) {
   # (Optional) Move to line 1: #Requires -Module Microsoft.Graph.Authentication,Microsoft.Graph.Users,Microsoft.Graph.Users.Actions
   # Connect to Azure AD
   Connect-MgGraph -ClientID <appId> -TenantId <tenantId> -CertificateThumbprint <thumbprint> -Scopes User.ReadWrite.All
   $users | ForEach-Object { Revoke-MgUserSignInSession -UserId $_ }
}