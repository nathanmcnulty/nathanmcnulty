#Requires -Module AzureADPreview,ActiveDirectory
<#
.Synopsis
    Creates Administrative Units and security groups for use with MyStaff/Password Reset in Azure
.NOTES
    1) This only needs to be run when you need to add an AU/security group
    2) AU's and password admin security groups are based off EXISTING groups
    3) The prefix is used to tie everything together and must match in all scripts
    You may want to consider email enabled groups if you want to communicate to admins through this
    Please feel free to ask me questions on Twitter: @nathanmcnulty
#>

Connect-AzureAD

# The prefix must match in all scripts as it is how AU's and groups are found in the automation scripts
# Password admin security groups will be created using prefix-groupname
$prefix = "AUPWAdmins"

##### Create Administrative Units ######
# IMPORTANT: The list must reference existing security groups. AU's are created and populated based on these groups, and password administrator groups/permissions are based off them
# I have location based security groups managed by an IAM. Example format: <location>-Students
# I use these AU's for more than just MyStaff, but you may find it easier to create MyStaff specific groups/AU's to avoid conflicts with future solutions
# I used Get-ADGroup to create my list, but import CSV is probably easier for most
if (Test-Path -Path "C:\Scripts\AUNames.csv") { 
    $list = Import-Csv -Path "C:\Scripts\AUNames.csv"
} else { 
    # Also support adhoc creation
    $userInput = Read-Host "Please provide AU names separated by commas"
    $list = $userInput.Split(',')
}

# You can have multiple AU's with the same name. This code ensures that only AU's with names that do not exist yet are created.
$existingAUs = Get-AzureADAdministrativeUnit -All $true
$list | ForEach-Object { 
    if ($_ -notin $existingAUs.DisplayName) { New-AzureADAdministrativeUnit -Description $_ -DisplayName $_ }
}

##### Create admin security groups #####
# These security groups will be given password administrator of AU's, and the format will be: AUPWAadmins-<location>-Students
# I create these in AD so our IAM maintains can maintain group membership, but you can do this in Azure instead (see below)
$GroupsOU = "OU=Groups,DC=domain,DC=com"
if (!(Get-ADObject -Filter {name -eq $prefix} -SearchBase $GroupsOU)) { New-ADOrganizationalUnit -Name $prefix -Path $GroupsOU }
$list | ForEach-Object {
    if ((Get-ADGroup -Filter {name -eq $_}) -and -not (Get-ADGroup -Filter {name -eq "$prefix-$_"} )) {
        New-ADGroup -Name "$prefix-$_" -DisplayName "$prefix-$_" -GroupScope Global -GroupCategory Security -Path "OU=$prefix,$GroupsOU"
    }
}

<# To do this in Azure. For the New-AzureADGroup, you may want to mail enable too if you want to be able to email password reset admins.
$prefix = "AUPWAdmins"
$list | ForEach-Object { 
    if (!(Get-AzureADGroup -Filter "displayname eq '$prefix-$_'")) {
        New-AzureADGroup -DisplayName "$prefix-$_" -SecurityEnabled $true }
}
#>