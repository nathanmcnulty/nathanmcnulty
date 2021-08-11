#Requires -Module ActiveDirectory
<#
.Synopsis
    Remove stale user objects from AD
.DESCRIPTION
    This script can be passed parameters, such as multiple OU's and date ranges, to automate stale user object cleanup from Active Directory
.NOTES
    21.08.11 - Added check for whenCreated to avoid catching staged accounts prior to use
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$OU = "OU=Users,OU=DOM,DC=domain,DC=com",
    [int]$disable = 90,
    [int]$delete = 180

)

# Disable after $disable days of no use
if ($disable) { 
    Search-ADAccount -UsersOnly -AccountInactive -DateTime (Get-Date).AddDays(-$disable) -SearchBase $OU -SearchScope Subtree | ForEach-Object { 
        if ((Get-ADUser -Identity $_.distinguishedName -Properties whenCreated).whenCreated -lt (Get-Date).AddDays(-$disable)) { Get-ADUser -Identity $_.distinguishedName | Disable-ADAccount }
    }
}
# Delete after $delete days of no use
if ($delete) { 
    Search-ADAccount -UsersOnly -AccountInactive -DateTime (Get-Date).AddDays(-$delete) -SearchBase $OU -SearchScope Subtree |  ForEach-Object {
        if ((Get-ADUser -Identity $_.distinguishedName -Properties whenCreated).whenCreated -lt (Get-Date).AddDays(-$delete)) { Get-ADUser -Identity $_.distinguishedName | Remove-ADObject -Recursive -Confirm:$false }
        }
}