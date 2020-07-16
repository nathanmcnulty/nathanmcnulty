#Requires -Module ActiveDirectory
<#
.Synopsis
    When authenticated users bind devices to AD using default user rights assignment, Domain Admins is the object owner. 
    But when accounts are delegated rights to bind devices, that account is given owner and other extended permissions posing a security risk.
    We want to remove ownership so they can no longer change permissions, and we want to remove those permissions to limit abuse
.DESCRIPTION
    This script allows you to replace owner and remove permissions from service accounts used for binding objects to Active Directory
.NOTES
    Test first
#>

Import-Module ActiveDirectory

# DN of Searchbase, will search subtrees
$OU = 'OU=Example,DC=domain,DC=com'

# Bind accoun to clean up
$bindAccount = 'Domain\User'

# New owner for the object, like 'Domain Admins'
$owner = New-Object System.Security.Principal.NTAccount('Domain', 'User/Group')

(Get-ADObject -SearchBase $OU -SearchScope Subtree -LDAPFilter '(objectClass=computer)').DistinguishedName | ForEach-Object {
    $ACL = Get-Acl -Path "AD:\$_"
    $ACL.SetOwner($owner)
    Set-Acl -Path "AD:\$_" -AclObject $ACL
    $ACL.access | Where-Object { $_.IdentityReference -like "*$bindAccount*" } | ForEach-Object -Process { $ACL.RemoveAccessRule($_) } -End { $ACL | Set-Acl }
}