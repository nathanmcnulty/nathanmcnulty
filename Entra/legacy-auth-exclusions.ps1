# Create group for Legacy Authentication Exclusion
$group = New-MgGroup -DisplayName "Allow Legacy Authentication" -MailEnabled:$false -MailNickname 'AllowLegacyAuth' -SecurityEnabled

# Find all users who have used legacy authentication and add them to the exclusion group
("Exchange ActiveSync","IMAP","MAPI","SMTP","POP","other clients" | ForEach-Object { 
    Get-MgAuditLogSignIn -Filter "ClientAppUsed eq '$_'" -All 
}).userId | Select-Object -Unique | ForEach-Object {
        New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $_
}
