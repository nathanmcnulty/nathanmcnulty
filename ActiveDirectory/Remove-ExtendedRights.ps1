#Requires -Module ActiveDirectory
<#
.Synopsis
    Removes the extended rights from an account, such as a bind account
.DESCRIPTION
    When you bind a computer object, there are many permissions granted to that account. This removes those permissions.
.NOTES
    Use this with Remove-ADBindPermissions.ps1
#>

Import-Module ActiveDirectory

# Specify account (like a binding account)
$account = 'Domain\User'

# Replace user with * in small orgs, bigger orgs may need to add to the filter to limit results or PS will run out of memory
$ldapfilter = "(objectClass=user)"

# Borrowed some code from ManageEngine: https://www.manageengine.com/products/ad-manager/powershell/powershell-get-ad-permissions-report.html
$schemaGUID = @{}
$ErrorActionPreference = 'SilentlyContinue'
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaGUID=*)' -Properties name, schemaGUID -ErrorAction SilentlyContinue |  ForEach-Object { $schemaGUID.add([System.GUID]$_.schemaGUID,$_.name) }
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID | ForEach-Object { $schemaGUID.add([System.GUID]$_.rightsGUID,$_.name) }
$ErrorActionPreference = 'Continue'

# Get a list of AD objects.
$AOs  = @((Get-ADDomain).DistinguishedName)
$AOs += (Get-ADOrganizationalUnit -Filter *).DistinguishedName
$AOs += (Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -SearchScope Subtree -LDAPFilter "$ldapfilter").DistinguishedName

$cleanup = $AOs | ForEach-OBject { 
    (Get-Acl -Path "AD:\$_").Access | Select-Object @{name='organizationalunit';expression={$_}}, `
    @{name='objectTypeName';expression={if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {'All'} Else {$schemaGUID.Item($_.objectType)}}}, `
    @{name='inheritedObjectTypeName';expression={$schemaGUID.Item($_.inheritedObjectType)}}, `
    *
} | Out-GridView -PassThru | Select-Object -Property 

$cleanup | ForEach-Object { 
    $ACL = Get-Acl -Path "AD:\$_"
    $ACL.SetOwner($owner)
    Set-Acl -Path "AD:\$_" -AclObject $ACL
    $ACL.access | Where-Object { $_.IdentityReference -like "*$account*" } | ForEach-Object -Process { $ACL.RemoveAccessRule($_) } -End { $ACL | Set-Acl }
}