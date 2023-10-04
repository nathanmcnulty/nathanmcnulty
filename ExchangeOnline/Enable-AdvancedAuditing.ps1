#Requires ExchangeOnlineManagement

# Connect to Exchange Online
Connect-ExchangeOnline

# Enable all advanced auditing
(Get-Mailbox -ResultSize Unlimited -Filter { RecipientType -eq "UserMailbox" -and RecipientTypeDetails -ne "DiscoveryMailbox"}).PrimarySmtpAddress | ForEach-Object {
    Write-Output $_
    Set-Mailbox -Identity $_ -AuditEnabled $true -AuditLogAgeLimit 365 -AuditAdmin @{add="Create","FolderBind","SendAs","SendOnBehalf","SoftDelete","HardDelete","Update","Move","MoveToDeletedItems","UpdateFolderPermissions","ApplyRecord","RecordDelete","Send","UpdateCalendarDelegation","UpdateComplianceTag","UpdateInboxRules","MailItemsAccessed"} -AuditDelegate @{add="Create","FolderBind","SendAs","SendOnBehalf","SoftDelete","HardDelete","Update","Move","MoveToDeletedItems","UpdateFolderPermissions","ApplyRecord","MailItemsAccessed","RecordDelete","UpdateComplianceTag","UpdateInboxRules"} -AuditOwner @{add="Create","SoftDelete","HardDelete","Update","Move","MoveToDeletedItems","UpdateFolderPermissions","ApplyRecord","RecordDelete","Send","UpdateCalendarDelegation","UpdateComplianceTag","UpdateInboxRules","MailItemsAccessed","MailboxLogin","SearchQueryInitiated"}
}