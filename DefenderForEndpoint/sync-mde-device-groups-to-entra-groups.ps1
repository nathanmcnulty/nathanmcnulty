<#
$MI = "MI Object ID"

# Defender API permissions
$DefenderATP = Get-MgServicePrincipal -Filter "AppId eq 'fc780465-2017-40d4-a0c5-307022471b92'"
$permission = $DefenderATP.AppRoles | Where-Object { $_.Value -eq "Machine.Read.All" -and $_.AllowedMemberTypes -contains "Application" } | Select-Object -First 1
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI -AppRoleId $permission.Id -PrincipalId $MI -ResourceId $DefenderATP.Id

# Graph API permissions
$Graph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
$permission = $Graph.AppRoles | Where-Object {$_.Value -eq "Group.ReadWrite.All" -and $_.AllowedMemberTypes -contains "Application"}
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI -AppRoleId $permission.Id -PrincipalId $MI -ResourceId $Graph.Id 
#>

# Get MDE API access token
Connect-AzAccount -Identity
$token = (New-Object System.Management.Automation.PSCredential("token", (Get-AzAccessToken -ResourceUrl "https://api.securitycenter.microsoft.com/.default" -AsSecureString).token)).GetNetworkCredential().Password

## Set MDE API headers
$headers = @{
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token"
}

# Get all devices 
$AllDevices = (Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines?`$filter=aadDeviceId ne null&`$select=rbacGroupName,rbacGroupId,aadDeviceId" -Headers $headers).value | Select-Object rbacGroupName,rbacGroupId,aadDeviceId

# Connect to Graph
Connect-MgGraph -Identity

# Create groups if they don't exist or check if displayName needs to be updated
$AllDevices | Select-Object rbacgroupName,rbacGroupId -Unique | ForEach-Object {
    $group = Get-MgGroup -Filter "MailNickName eq 'mde-dg-$($_.rbacGroupId)'"
    if ($group) {
        if ($group.displayName -ne "MDE-DG-$($_.rbacGroupName)") {
            Update-MgGroup -GroupId $group.Id -DisplayName "MDE-DG-$($_.rbacGroupName)"
        }
    } else {
        New-MgBetaGroup -DisplayName "MDE-DG-$($_.rbacGroupName)" -MailEnabled:$False  -MailNickName "mde-dg-$($_.rbacGroupId)" -SecurityEnabled
    }
    Remove-Variable group
}

# Compare groups and update membership
$AllDevices | Select-Object rbacGroupId -Unique | ForEach-Object {
    $rbacGroupId = $_.rbacGroupId
    $group = Get-MgGroup -Filter "MailNickName eq 'mde-dg-$rbacGroupId'"
    $MDE = (($AllDevices | Where-Object { $_.rbacGroupId -eq $rbacGroupId }).aadDeviceId | ForEach-Object { Get-MgDevice -Filter "deviceId eq '$_'"}).Id
    $Entra = (Get-MgGroupMember -GroupId $group.Id).Id

    if ($Entra) {
        $Compare = Compare-Object -ReferenceObject $MDE -DifferenceObject $Entra

        # Remove from group
        $Compare | Where-Object { $_.sideindicator -eq '=>' } | ForEach-Object {
            Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $_.InputObject
        }

        # Add to group
        $Compare | Where-Object { $_.sideindicator -eq '<=' } | ForEach-Object {
            New-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $_.InputObject
        }
    } else {
        $MDE | ForEach-Object { New-MgGroupmember -GroupId $group.Id -DirectoryObjectId $_ }
    }
}
