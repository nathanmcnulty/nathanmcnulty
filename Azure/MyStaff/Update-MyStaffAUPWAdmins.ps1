#Requires -Module AzureADPreview
<#
.Synopsis
    Manages password administrators on administrative units based on security groups created by the prereqs script
.NOTES
    I am working on migrating this from on-premise to Azure Automation, and I may turn this into an advanced function to reduce runtime
    Consider scraping the audit logs for the trigger (AuditLogs | where OperationName == "Update group" | where TargetResources[0].displayName contains "AUPWAdmins")
    Please feel free to ask me questions on Twitter: @nathanmcnulty
#>

Connect-AzureAD

# This prefix matches the prefix you used in the prereqs script
$prefix = "AUPWAdmins"

# You can change the role if you'd like admins to have ability reset MFA or edit user properties
$role = (Get-AzureADDirectoryRole | Where-Object -Property DisplayName -EQ -Value "Password Administrator").objectId

# Grab list of AUPWAdmin groups and evaluate membership of those against the roles on the AU's
(Get-AzureADGroup -SearchString "$prefix") | ForEach-Object {
    $AU = ($_.DisplayName).Replace("$prefix-","")
    $AUobjId = (Get-AzureADAdministrativeUnit -Filter "displayname eq '$AU'").objectId
    $existingAdmins = (Get-AzureADScopedRoleMembership -ObjectId $AUobjID).roleMemberInfo.objectId
    $currentAdmins = (Get-AzureADGroupMember -ObjectID $_.objectId).objectId

    # Add admins
    $currentAdmins | ForEach-Object { 
        if ($_ -notin $existingAdmins) {
            $roleMember = New-Object -TypeName Microsoft.Open.AzureAD.Model.RoleMemberInfo
            $roleMember.objectId = $_
            Add-AzureADScopedRoleMembership -ObjectId $AUobjId -RoleObjectId $role -RoleMemberInfo $roleMember
        }
    }

    # Remove admins
    $existingAdmins | ForEach-Object {
        if ($_ -notin $currentAdmins) {
            $userObjId = $_
            Get-AzureAdScopedRoleMembership -ObjectId $AUobjId | Where-Object { $_.RoleMemberInfo.ObjectId -eq $userObjId } | ForEach-Object { 
                Remove-AzureAdScopedRoleMembership -ObjectId $AUobjId -ScopedRoleMembershipId $_.id
            }
        }
    }
}