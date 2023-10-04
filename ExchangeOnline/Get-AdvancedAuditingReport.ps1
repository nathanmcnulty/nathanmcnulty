#Requires ExchangeOnlineManagement

# Connect to Exchange Online
Connect-ExchangeOnline

# Create CSV with headers
Add-Content -Path $env:USERPROFILE\EXOAudit.csv -Value "Mailbox,Type,Attribute,Value"

# Populate CSV with those missing attributes
(Get-Mailbox -ResultSize Unlimited -Filter { RecipientType -eq "UserMailbox" -and RecipientTypeDetails -ne "DiscoveryMailbox"}).PrimarySmtpAddress | ForEach-Object {
    $mailbox = Get-Mailbox -Identity $_
    if ($mailbox.AuditAdmin -notcontains 'MailItemsAccessed') { Add-Content -Path $env:USERPROFILE\EXOAudit.csv -Value "$_,$($mailbox.RecipientTypeDetails),AuditAdmin,MailItemsAccessed" }
    if ($mailbox.AuditDelegate -notcontains 'MailItemsAccessed') { Add-Content -Path $env:USERPROFILE\EXOAudit.csv -Value "$_,$($mailbox.RecipientTypeDetails),AuditDelegate,MailItemsAccessed" }
    if ($mailbox.AuditOwner -notcontains 'MailItemsAccessed') { Add-Content -Path $env:USERPROFILE\EXOAudit.csv -Value "$_,$($mailbox.RecipientTypeDetails),AuditOwner,MailItemsAccessed" }
    if ($mailbox.AuditOwner -notcontains 'SearchQueryInitiated') { Add-Content -Path $env:USERPROFILE\EXOAudit.csv -Value "$_,$($mailbox.RecipientTypeDetails),AuditOwner,SearchQueryInitiated" }
}