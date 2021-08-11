#Requires -Module ActiveDirectory
<#
.Synopsis
    Remove stale computer objects from AD
.DESCRIPTION
    This script can be passed parameters, such as multiple OU's and date ranges, to automate stale computer/sever object cleanup from Active Directory
.NOTES
    21.08.11 - Added check for whenCreated to avoid catching staged accounts prior to use
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$OU = "OU=Desktops,DC=domain,DC=com",
    [int]$disable = 180,
    [int]$delete = 270

)

# Disable after $disable days of no use
if ($disable) { 
    Search-ADAccount -ComputersOnly -AccountInactive -DateTime (Get-Date).AddDays(-$disable) -SearchBase $OU -SearchScope Subtree | ForEach-Object { 
        if ((Get-ADComputer -Identity $_.distinguishedName -Properties whenCreated).whenCreated -lt (Get-Date).AddDays(-$disable)) { Get-ADComputer -Identity $_.distinguishedName | Disable-ADAccount }
    }    
}
# Delete after $delete days of no use
if ($delete) { 
    Search-ADAccount -ComputersOnly -AccountInactive -DateTime (Get-Date).AddDays(-$delete) -SearchBase $OU -SearchScope Subtree | ForEach-Object {
        if ((Get-ADComputer -Identity $_.distinguishedName -Properties whenCreated).whenCreated -lt (Get-Date).AddDays(-$delete)) { Get-ADComputer -Identity $_.distinguishedName | Remove-ADObject -Recursive -Confirm:$false }
    }
}