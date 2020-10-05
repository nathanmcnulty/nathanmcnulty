#Requires -Module ActiveDirectory
<#
.Synopsis
    Discover servers using default admin passwords
.DESCRIPTION
    Many deploy servers from templates which have generic local admin passwords that are then changed post-deployment. Sometimes the password change may fail, or the process may not be automated. This can be scheduled to run and check for any servers still using the default password.
.NOTES
    This may not be the fastest method, but it was quick and easy to throw together. Please submit a PR if you have improvements.
#>

[string]$credentialfile = "C:\scripts\credentials\default-server.xml"
[string]$ou = "OU=Servers,DC=domain,DC=com"
[array]$list = @()

if (Test-Path -Path $credentialfile) { $creds = Import-Clixml $credentialfile } else { $creds = Get-Credential }

Get-ADComputer -Filter { enabled -eq $true } -SearchBase $ou -SearchScope Subtree  | ForEach-Object {
    if (Test-WSMan -ComputerName $_.Name -Credential $creds -Authentication Negotiate -ErrorAction SilentlyContinue) { $list += $_.Name }}
Write-Output $list