# Set Tenant Name
$tenantName = "<YOURDOMAIN>.onmicrosoft.com"

# Connect to Microsoft Graph within Azure Automation
Connect-AzAccount -Identity
$token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
Connect-MgGraph -AccessToken $token.Token

# Get members of Advanced Auditing dynamic group
$groupId = (Get-MgGroup -Filter "DisplayName eq 'Azure Automation - Advanced Auditing'").Id
$groupMembers = (Get-MgGroupMember -GroupId $groupId | Select-Object -ExpandProperty AdditionalProperties).mail

# Connect to Exchange Online using Managed Identity
Connect-ExchangeOnline -ManagedIdentity -Organization $tenantName -Verbose

# I have absolutely no idea why the script fails without running a Get-Mailbox first...
Get-Mailbox -Identity $groupMembers[0] | Out-Null

# Enable all advanced auditing
$groupMembers | ForEach-Object {
    Write-Output $_
    Set-Mailbox -Identity $_ -AuditAdmin @{add="Create","FolderBind","SendAs","SendOnBehalf","SoftDelete","HardDelete","Update","Move","MoveToDeletedItems","UpdateFolderPermissions","ApplyRecord","RecordDelete","Send","UpdateCalendarDelegation","UpdateComplianceTag","UpdateInboxRules","MailItemsAccessed"} -AuditDelegate @{add="Create","FolderBind","SendAs","SendOnBehalf","SoftDelete","HardDelete","Update","Move","MoveToDeletedItems","UpdateFolderPermissions","ApplyRecord","MailItemsAccessed","RecordDelete","UpdateComplianceTag","UpdateInboxRules"} -AuditOwner @{add="Create","SoftDelete","HardDelete","Update","Move","MoveToDeletedItems","UpdateFolderPermissions","ApplyRecord","RecordDelete","Send","UpdateCalendarDelegation","UpdateComplianceTag","UpdateInboxRules","MailItemsAccessed","MailboxLogin","SearchQueryInitiated"}
}
