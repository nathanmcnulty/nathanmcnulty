#Requires -Module AzureADPreview
<#
.Synopsis
    Manages password administrators on administrative units based on security groups created by the prereqs script
.NOTES
    I am working on migrating this from on-premise to Azure Automation, and I may turn this into an advanced function to reduce runtime
    Consider scraping the audit logs for the trigger (AuditLogs | where OperationName == "Update group" | where TargetResources[0].displayName contains "AUPWAdmins")
    Please feel free to ask me questions on Twitter: @nathanmcnulty
#>

# $creds = Import-CliXml -Path <scrit path>\creds.xml
Connect-AzureAD #-Credential $credss

# This prefix matches the prefix you used in the prereqs script
$prefix = "AUPWAdmins"

# You can change the role if you'd like admins to have ability reset MFA or edit user properties
$role = (Get-AzureADDirectoryRole | Where-Object -Property DisplayName -EQ -Value "Password Administrator").objectId

function AddAdminToAURole {
    [CmdletBinding()]
    param ([Parameter(ValueFromPipeline=$true)]
        $userObj
    )

    $roleMember = New-Object -TypeName Microsoft.Open.AzureAD.Model.RoleMemberInfo
    $roleMember.objectId = $userObj.objectId
    Add-AzureADScopedRoleMembership -ObjectId $AUobjId -RoleObjectId $role -RoleMemberInfo $roleMember
}

function RemoveAdminFromAURole {
    [CmdletBinding()]
    param ([Parameter(ValueFromPipeline=$true)]
        $userObj
    )

    $userObjId = $userObj.objectId
    Get-AzureAdScopedRoleMembership -ObjectId $AUobjId | Where-Object { $userObj.RoleMemberInfo.ObjectId -eq $userObjId } | ForEach-Object { 
        Remove-AzureAdScopedRoleMembership -ObjectId $AUobjId -ScopedRoleMembershipId $_.id
    }
}

# Grab list of AUPWAdmin groups and evaluate membership of those against the roles on the AU's
(Get-AzureADGroup -SearchString "$prefix") | ForEach-Object {
    $AU = ($_.DisplayName).Replace("$prefix-","")
    $AUobjId = (Get-AzureADAdministrativeUnit -Filter "displayname eq '$AU'").objectId
    $existingAdmins = (Get-AzureADScopedRoleMembership -ObjectId $AUobjID).roleMemberInfo
    $currentAdmins = Get-AzureADGroupMember -ObjectID $_.objectId

    # Compare-Object won't work on null values, so if all members of a group are removed, this logic makes sure they get removed
    if ($currentAdmins -eq $null -and $existingAdmins -eq $null) { 
        Write-Output "Both groups are empty"
        break
    } elseif ($existingAdmins -eq $null -and -not $currentAdmins -eq $null) {
        $currentUsers | AddAdminToAURole $_
    } elseif ($currentAdmins -eq $null -and -not $existingAdmins -eq $null) {
        $currentUsers | RemoveAdminFromAURole $_
    } else {
        $list = Compare-Object -ReferenceObject $currentAdmins -DifferenceObject $existingAdmins -Property objectId -PassThru
        $list | Where-Object { $_.SideIndicator -eq "<=" } | ForEach-Object { AddAdminToAURole $_ }
        $list | Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { RemoveAdminFromAURole $_ }
    }
}