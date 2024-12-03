# This script will find users who have not changed their password in the specified number of days
# It is important to look for users that will be locked out by enforcing a cloud password policy
# To filter noise, this report excludes accounts that have never logged in and ones that have not logged in for the same number of days

Connect-MgGraph -Scopes User.Read.All

$days = -180

Get-MgBetaUser -All -Property UserPrincipalName,LastPasswordChangeDateTime,UserType,SignInActivity | Where-Object { 
    $_.LastPasswordChangeDateTime -lt (Get-Date).AddDays($days) -and $_.SignInActivity.LastSuccessfulSignInDateTime -lt (Get-Date).AddDays($days) -and $_.SignInActivity.LastSuccessfulSignInDateTime -ne $null 
} | Select-Object UserPrincipalName,LastPasswordChangeDateTime,@{Name="LastSignInDateTime"; Expression={ $_.SignInActivity.LastSuccessfulSignInDateTime }} | Sort-Object LastPasswordChangeDateTime