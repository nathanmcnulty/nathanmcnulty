#Requires -Modules ExchangeOnlineManagement

# Connect to Exchange Online
Connect-ExchangeOnline

# Enable all advanced auditing
(Get-Mailbox -ResultSize Unlimited -Filter { RecipientType -eq "UserMailbox" -and RecipientTypeDetails -ne "DiscoveryMailbox"}).PrimarySmtpAddress | ForEach-Object {
    Write-Output $_
    Set-Mailbox -Identity $_ -AuditEnabled $true -AuditLogAgeLimit 365 -AuditAdmin @{add='Update, Copy, Move, MoveToDeletedItems, SoftDelete, HardDelete, FolderBind, SendAs, SendOnBehalf, MessageBind, Create, UpdateFolderPermissions, AddFolderPermissions, ModifyFolderPermissions, RemoveFolderPermissions, UpdateInboxRules, UpdateCalendarDelegation, RecordDelete, ApplyRecord, MailItemsAccessed, UpdateComplianceTag, Send, AttachmentAccess, PriorityCleanupDelete, ApplyPriorityCleanup, PreservedMailItemProactively'} -AuditDelegate @{add='Update, Move, MoveToDeletedItems, SoftDelete, HardDelete, FolderBind, SendAs, SendOnBehalf, Create, UpdateFolderPermissions, AddFolderPermissions, ModifyFolderPermissions, RemoveFolderPermissions, UpdateInboxRules, RecordDelete, ApplyRecord, MailItemsAccessed, UpdateComplianceTag, AttachmentAccess, PriorityCleanupDelete, ApplyPriorityCleanup, PreservedMailItemProactively'} -AuditOwner @{add='Update, Move, MoveToDeletedItems, SoftDelete, HardDelete, Create, MailboxLogin, UpdateFolderPermissions, AddFolderPermissions, ModifyFolderPermissions, RemoveFolderPermissions, UpdateInboxRules, UpdateCalendarDelegation, RecordDelete, ApplyRecord, MailItemsAccessed, UpdateComplianceTag, Send, SearchQueryInitiated, AttachmentAccess, PriorityCleanupDelete, ApplyPriorityCleanup, PreservedMailItemProactively'}
}