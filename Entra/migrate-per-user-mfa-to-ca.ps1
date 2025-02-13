# Add per-user MFA enabled/enforced users to a group
$groupId = (New-MgGroup -DisplayName 'Per-User MFA Users' -MailEnabled:$False  -MailNickName 'per-user-mfa-users' -SecurityEnabled).Id
Get-MgUser -Filter "perUserMfaState eq 'enforced'" | ForEach-Object {
    New-MgGroupMember -GroupId $groupId -DirectoryObjectId $_.Id -Verbose
}
Get-MgUser -Filter "perUserMfaState eq 'enabled'" | ForEach-Object {
    New-MgGroupMember -GroupId $groupId -DirectoryObjectId $_.Id -Verbose
}

# Create CA policy targeting this security group, then run the following
# Disable per-user MFA for members of the group
Get-MgGroupMember -GroupId $groupId | ForEach-Object {
    Invoke-MgGraphRequest -Method PATCH -Uri "/users/$($_.Id)/authentication/requirements/" -Body @{ perUserMfaState = 'disabled' } -Verbose
}
