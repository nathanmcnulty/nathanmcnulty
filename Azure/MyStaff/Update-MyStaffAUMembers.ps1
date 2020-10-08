#Requires -Module AzureADPreview
<#
.Synopsis
    This script adds members to the appropriate administrative units
.NOTES
    I am working on migrating this from on-premise to Azure Automation, and I may turn this into an advanced function to reduce runtime
    Consider where password reset admins also have permission to modify groups to give themselves access to reset more users than intended
    Please feel free to ask me questions on Twitter: @nathanmcnulty
#>

Connect-AzureAD

# This prefix matches the prefix you used in the prereqs script
$prefix = "AUPWAdmins"

# Restrict users from being added to AU's (prevent privilege escalation)
$excludedGroups = "IT-Staff","AdminGroups"

# Grab list of AUPWAdmin groups and evaluate membership of those against the roles on the AU's
(Get-AzureADGroup -SearchString "$prefix") | ForEach-Object {
    $AU = ($_.DisplayName).Replace("$prefix-","")
    $AUobjId = (Get-AzureADAdministrativeUnit -Filter "displayname eq '$AU'").objectId
    $existingUsers = (Get-AzureADAdministrativeUnitMember -ObjectId $AUobjID -All $true).objectId
    $currentUsers = (Get-AzureADGroup -SearchString $AU | Get-AzureADGroupMember -All $true).objectId
    $excludedUsers = ($excludedGroups | ForEach-Object { Get-AzureADGroup -SearchString $_ | Get-AzureADGroupMember -All $true }).objectId

    # Add members to AU
    $currentUsers | ForEach-Object {
        if ($_ -notin $existingUsers -and $_ -notin $excludedUsers) {
            Add-AzureADAdministrativeUnitMember -ObjectId $AUobjID -RefObjectId $_
        }
    }

    # Remove members from AU
    $existingUsers | ForEach-Object {
        if ($_ -notin $currentUsers) {
            Remove-AzureADAdministrativeUnitMember -ObjectId $AUobjID -MemberId $_
        }
    }
}