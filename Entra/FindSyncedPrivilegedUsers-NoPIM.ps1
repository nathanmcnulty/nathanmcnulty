# Connect with appropriate permissions
Connect-MgGraph -Scopes RoleManagement.Read.Directory,User.Read.All

Get-MgDirectoryRole -All | ForEach-Object {
    $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id | Where-Object { 
        $_.AdditionalProperties.userPrincipalName -ne $null -and $_.AdditionalProperties.userPrincipalName -notmatch ".onmicrosoft.com" 
    }
    if ($roleMembers.Count -ne 0) {
        $roleName = $_.DisplayName
        $roleMembers | ForEach-Object { if ((Get-MgUser -UserId $_.Id -Property OnPremisesSyncEnabled).OnPremisesSyncEnabled -ne $null) { 
            [array]$members += (Get-MgUser -UserId $_.Id).UserPrincipalName
        }}
        if ($members.Count -ne 0) { $members | Foreach-Object { Write-Output "$roleName,$_" }
            Remove-Variable members
        }
    }
}
