#Requires -Module ActiveDirectory
<#
.Synopsis
    By default, Active Directory allows anyone to bind up to 10 devices to AD. It is best practice to remove this right and instead use a binding account mapped to specific OU's. This script helps set the appropriate permissions for the binding account which also includes the ability to re-bind an existing object that may have lost domain membership.
.DESCRIPTION
    Provide the OU and name of the binding account you want to delegate binding permissions to. This can be easily modified to use a group instead.
.NOTES
    Need to add more error handling and input validation
#>
[CmdletBinding()]
param (
    [string]$OU = "$((Get-ADDomain).ComputersContainer)",
    [string]$bindName = "bind-server"
)

begin {
    # Check to make sure both the OU and bind account exist first
    if (!(Test-Path -Path AD:\$OU)) { Write-Output "$OU does not exist"; Start-Sleep -Seconds 10; exit }
    if (!(Get-ADUser -Filter { samAccountName -eq $bindName})) { Write-Output "$bindName does not exist"; Start-Sleep -Seconds 10; exit } else { $bindObject = New-Object System.Security.Principal.SecurityIdentifier((Get-ADUser $bindName).SID) }
}

process {
    # Build list of extended rights and guids from AD schema
    $ADRootDSE = Get-ADRootDSE
    $GUIDs = @{}
    Get-ADObject -SearchBase ($ADRootDSE.SchemaNamingContext) -LDAPFilter "(schemaidguid=*)" -Properties LDAPDisplayName,schemaIDGUID | ForEach-Object {$GUIDs[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID}
    $ExtendedRights = @{}
    Get-ADObject -SearchBase ($ADRootDSE.ConfigurationNamingContext) -LDAPFilter "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid | ForEach-Object {$ExtendedRights[$_.displayName]=[System.GUID]$_.rightsGuid}

    # Add Create and Delete Computer Objects on object and all descendents to ACE list
    $ACEList = New-Object System.Collections.Generic.List[System.Object]
    "CreateChild"<#,"DeleteChild"#> | ForEach-Object {
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $bindObject, $_, "Allow", $GUIDs["computer"]
        $ACEList.Add($ACE)
    }

    # Add ReadProperty and WriteProperty on descendant computer objects to ACE list
    "ReadProperty","WriteProperty" | ForEach-Object {
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $bindObject, $_, "Allow", "Descendents", $GUIDs["computer"]
        $ACEList.Add($ACE)
    }

    # Add remaining extended rights
    "Reset Password","Account Restrictions","Validated write to DNS host name","Validated write to service principal name" | ForEach-Object {
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $bindObject, "ExtendedRight", "Allow", $ExtendedRights["$_"], "Descendents", $GUIDs["computer"]
        $ACEList.Add($ACE)
    }

    # Get existing ACL, add ACE's, and set ACL
    $ACL = Get-Acl -Path "AD:\$OU"
    $ACEList | ForEach-Object { $ACL.AddAccessRule($_) }
    Set-Acl -AclObject $ACL -Path "AD:\$OU"    
}

end {
    
}
