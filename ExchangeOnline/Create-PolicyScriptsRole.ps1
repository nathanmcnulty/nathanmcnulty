<#
.Synopsis
   Create limited role for running policy scripts within Exchange Online
.DESCRIPTION
   Creates all necessary management roles and role entries for management scripts to enforce policies such as enabling mailbox auditing, enabling litigation hold, disabling remote powershell, and setting mailbox folder permissions
.NOTES
   You will need to create a service account prior to running this script that you will use to run your policy automation. This can be a federated AD account or a cloud-only account.
#>

# Change this to the UPN of your service account
[string]$serviceaccount = "exo-policyscripts@domain.onmicrosoft.com"

#Create new management roles for policy scripts. Two roles required due to AuditEnabled only being available to Audit Logs Role.
New-ManagementRole -Name "Mail Recipient - Policy Scripts" -Parent "Mail Recipients"
New-ManagementRole -Name "Audit Logs - Policy Scripts" -Parent "Audit Logs"

# Create role group, adding both new management roles and our policy script account as a member
New-RoleGroup "Policy Script Management" -Description "Limited scope for running policy scripts against Exchange Online" -Roles "Mail Recipient - Policy Scripts","Audit Logs - Policy Scripts" -Members $serviceaccount -Confirm:$false

# Strip unnecessary role permissions (delay added because EXO died without it)
Get-ManagementRoleEntry "Mail Recipient - Policy Scripts\*" | Where-Object { $_.Name -notin "Set-User","Set-UserPhoto","Get-Mailbox","Set-Mailbox","Add-MailboxFolderPermission" } | ForEach-Object { Remove-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\$($_.Name)" -Verbose -Confirm:$false; Start-Sleep -Seconds 1 }
Get-ManagementRoleEntry "Audit Logs - Policy Scripts\*" | Where-Object { $_.Name -notin "Set-Mailbox" } | ForEach-Object { Remove-ManagementRoleEntry -Identity "Audit Logs - Policy Scripts\$($_.Name)" -Verbose -Confirm:$false; Start-Sleep -Seconds 1 }

# Add role entry for disabling remote powershell on mailboxes
Remove-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Set-User" -Confirm:$false
Add-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Set-User" -Parameters "Identity","RemotePowerShellEnabled"

# Add role entry for disabling remote powershell on mailboxes
Remove-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Set-UserPhoto" -Confirm:$false
Add-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Set-UserPhoto" -Parameters "Identity","PictureData"

# Add role entry to give permssions to find mailboxes based on search criteria
Remove-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Get-Mailbox" -Confirm:$false
Add-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Get-Mailbox" -Parameters "Identity","Filter","RecipientTypeDetails","ResultSize"

# Add role entry for enabling litigation hold on mailboxes
Remove-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Set-Mailbox" -Confirm:$false
Add-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Set-Mailbox" -Parameters "Identity","LitigationHoldEnabled","LitigationHoldDuration","LitigationHoldDate","LitigationHoldOwner","ForwardingSmtpAddress"

# Add role entry to give permssions to find mailboxes based on search criteria
Remove-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Add-MailboxFolderPermission" -Confirm:$false
Add-ManagementRoleEntry -Identity "Mail Recipient - Policy Scripts\Add-MailboxFolderPermission" -Parameters "Identity","User","AccessRights"