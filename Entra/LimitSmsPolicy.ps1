# Add Policy.ReadWrite.AuthenticationMethod and uncomment last commands to set SMS Authentication Method to the Group
# Connect to Graph with necessary scopes
Connect-MgGraph -Scopes Group.ReadWrite.All,AuditLog.Read.All

# Create new group to allow SMS use
$groupId = (New-MgGroup -DisplayName 'Allow SMS' -MailEnabled:$False  -MailNickName 'Allow-SMS' -SecurityEnabled).Id

# Get all users registered for SMS and add them to the security group
Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter "methodsRegistered/any(i:i eq 'mobilePhone')" | ForEach-Object {
    New-MgGroupMember -GroupId $groupId -DirectoryObjectId $_.Id
}

<# Set Authentication method policy for SMS to enabled but limited to the Allow SMS group we created 
$params = @{
    "@odata.type"= "#microsoft.graph.smsAuthenticationMethodConfiguration"
    "id" = "Sms"
    "includeTargets" = @(
        @{
            "id" = "$groupId"
            "isRegistrationRequired" = $false
            "targetType" = "group"
            "isUsableForSignIn" = $false
        }
    )
    "excludeTargets" = @(
    )
    "state" = "enabled"
}
Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration -AuthenticationMethodConfigurationId Sms -BodyParameter $params
#>
