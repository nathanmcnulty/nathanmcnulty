#Requires -Module AzureADPreview
<#
.Synopsis
    This script adds members to the appropriate administrative units
.NOTES
    I am working on migrating this from on-premise to Azure Automation, and I may turn this into an advanced function to reduce runtime
    Consider where password reset admins also have permission to modify groups to give themselves access to reset more users than intended
    Please feel free to ask me questions on Twitter: @nathanmcnulty
#>

# $creds = Import-CliXml -Path <scrit path>\creds.xml
Connect-AzureAD #-Credential $creds

# This prefix matches the prefix you used in the prereqs script
$prefix = "AUPWAdmins"

# Restrict users from being added to AU's (prevent privilege escalation)
$excludedGroups = "IT-Staff","AdminGroups"
$excludedUsers = $excludedGroups | ForEach-Object { Get-AzureADGroup -SearchString $_ | Get-AzureADGroupMember -All $true }

function AddUserToAU {
    [CmdletBinding()]
    param ([Parameter(ValueFromPipeline=$true)]
        $userObj
    )

    if ($userObj.objectId -notin $excludedUsers.objectId) {
        $userObjId = $userObj.objectId
        Add-AzureADAdministrativeUnitMember -ObjectId $AUobjId -RefObjectId $userObjId
        Write-Output "Added $($userObj.displayName) to $AU"
    }
}

function RemoveUserFromAU {
    [CmdletBinding()]
    param ([Parameter(ValueFromPipeline=$true)]
        $userObj
    )

    $userObjId = $userObj.objectId
    $userDisplayname = (Get-AzureADUser -ObjectId $userObjId).displayName
    Remove-AzureADAdministrativeUnitMember -ObjectId $AUobjId -MemberId $userObjId
    Write-Output "Removed $userDisplayName from $AU"
}

# Grab list of AUPWAdmin groups and evaluate membership of those against the roles on the AU's
(Get-AzureADGroup -SearchString "$prefix") | ForEach-Object {
    $AU = ($_.DisplayName).Replace("$prefix-","")
    $AUobjId = (Get-AzureADAdministrativeUnit -Filter "displayname eq '$AU'").objectId
    $existingUsers = Get-AzureADAdministrativeUnitMember -ObjectId $AUobjId -All $true
    $currentUsers = Get-AzureADGroup -SearchString $AU | Get-AzureADGroupMember -All $true | ForEach-Object { 
        # Add support for single depth nested groups; add more if you need to
        if ($_.objectType -eq "Group") { $_ | Get-AzureADGroupMember -All $true } else { $_ }
    }
    if ($currentUsers -eq $null -and $existingUsers -eq $null) { 
        Write-Output "Both groups are empty"
        break
    } elseif ($existingUsers -eq $null -and -not $currentUsers -eq $null) {
        $currentUsers | AddUserToAU $_
    } elseif ($currentUsers -eq $null -and -not $existingUsers -eq $null) {
        $existingUsers | RemoveUsersFromAU $_
    } else {
        $list = Compare-Object -ReferenceObject $currentUsers -DifferenceObject $existingUsers -Property objectId -PassThru
        $list | Where-Object { $_.SideIndicator -eq "<=" } | ForEach-Object { AddUserToAU $_ }
        $list | Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { RemoveUserFromAU $_ }
    }
}