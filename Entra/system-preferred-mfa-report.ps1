# If using PowerShell 7, add -Parallel to the ForEach-Object
# I will add batching to this later... maybe, lol

Connect-MgGraph -Scopes Policy.Read.All

$spmfa = New-Object System.Collections.ArrayList
$spmfa.Add("Id,userPrincipalName,IsSystemPreferredAuthenticationMethodEnabled,UserPreferredMethodForSecondaryAuthentication")

Get-MgUser -All | ForEach-Object {
   $value = Get-MgBetaUserAuthenticationSignInPreference -UserId $_.Id
   $spmfa.Add("$($_.Id),$($_.userPrincipalName),$($value.IsSystemPreferredAuthenticationMethodEnabled),$($value.UserPreferredMethodForSecondaryAuthentication)")
}

$spmfa | ConvertFrom-Csv
