# Set Tenant Name
$tenantName = "<YOURDOMAIN>.onmicrosoft.com"

# Connect to Microsoft Graph within Azure Automation
Connect-AzAccount -Identity
$token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -AsSecureString).Token
Connect-MgGraph -AccessToken $token

# Get members of Advanced Auditing dynamic group
$groupId = (Get-MgGroup -Filter "DisplayName eq 'Azure Automation - Advanced Auditing'").Id
$groupMembers = (Get-MgGroupMember -GroupId $groupId | Select-Object -ExpandProperty AdditionalProperties).mail

# Connect to Exchange Online using Managed Identity
Connect-ExchangeOnline -ManagedIdentity -Organization $tenantName -Verbose

# I have absolutely no idea why the script fails without running a Get-Mailbox first...
#Get-Mailbox -Identity $groupMembers[0] | Out-Null

# Enable all advanced auditing
$groupMembers | ForEach-Object {
    Write-Output $_
    Set-Mailbox -Identity $_ -AuditEnabled $true -AuditLogAgeLimit 365 -AuditAdmin @{add='Update, Copy, Move, MoveToDeletedItems, SoftDelete, HardDelete, FolderBind, SendAs, SendOnBehalf, MessageBind, Create, UpdateFolderPermissions, AddFolderPermissions, ModifyFolderPermissions, RemoveFolderPermissions, UpdateInboxRules, UpdateCalendarDelegation, RecordDelete, ApplyRecord, MailItemsAccessed, UpdateComplianceTag, Send, AttachmentAccess, PriorityCleanupDelete, ApplyPriorityCleanup, PreservedMailItemProactively'} -AuditDelegate @{add='Update, Move, MoveToDeletedItems, SoftDelete, HardDelete, FolderBind, SendAs, SendOnBehalf, Create, UpdateFolderPermissions, AddFolderPermissions, ModifyFolderPermissions, RemoveFolderPermissions, UpdateInboxRules, RecordDelete, ApplyRecord, MailItemsAccessed, UpdateComplianceTag, AttachmentAccess, PriorityCleanupDelete, ApplyPriorityCleanup, PreservedMailItemProactively'} -AuditOwner @{add='Update, Move, MoveToDeletedItems, SoftDelete, HardDelete, Create, MailboxLogin, UpdateFolderPermissions, AddFolderPermissions, ModifyFolderPermissions, RemoveFolderPermissions, UpdateInboxRules, UpdateCalendarDelegation, RecordDelete, ApplyRecord, MailItemsAccessed, UpdateComplianceTag, Send, SearchQueryInitiated, AttachmentAccess, PriorityCleanupDelete, ApplyPriorityCleanup, PreservedMailItemProactively'}
}
