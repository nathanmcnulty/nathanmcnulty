#Requires -Module ActiveDirectory
<#
.Synopsis
    
.DESCRIPTION
    
.NOTES
    
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$OU = "OU=Desktops,DC=domain,DC=com",
    [int]$disable = 270,
    [int]$delete = 365

)

# Disable after 270 days of no use
if ($disable) { 
    Search-ADAccount -ComputersOnly -AccountInactive -DateTime (Get-Date).AddDays(-$disable) -SearchBase $OU -SearchScope Subtree | Disable-ADAccount
}
# Delete after 360 days of no use
if ($delete) { 
    Search-ADAccount -ComputersOnly -AccountInactive -DateTime (Get-Date).AddDays(-$delete) -SearchBase $OU -SearchScope Subtree |  Remove-ADObject -Recursive -Confirm:$false
}