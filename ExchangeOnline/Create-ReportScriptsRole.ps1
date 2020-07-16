<#
.Synopsis
   Create limited role for running report scripts within Exchange Online
.DESCRIPTION
   Creates all necessary management roles and role entries for running reports such as risky inbox rules, delegated permissions, etc.
.NOTES
   You will need to create a service account prior to running this script that you will use to run your automation. This can be a federated AD account or a cloud-only account.
#>

# Change this to the UPN of your service account
[string]$serviceaccount = "exo-reportscripts@domain.onmicrosoft.com"

#Create new management roles for report scripts. Two roles required due to AuditEnabled only being available to Audit Logs Role.
New-ManagementRole -Name "Mail Recipient - Report Scripts" -Parent "Mail Recipients"

# Create role group, adding both new management roles and our report script account as a member
New-RoleGroup "Report Script Management" -Description "Limited scope for running report scripts against Exchange Online" -Roles "Mail Recipient - Report Scripts" -Members $serviceaccount -Confirm:$false

# Strip unnecessary role permissions (delay added because EXO died without it)
Get-ManagementRoleEntry "Mail Recipient - Report Scripts\*" | Where-Object { $_.Name -notin "Get-Mailbox","Get-InboxRule" } | ForEach-Object { Remove-ManagementRoleEntry -Identity "Mail Recipient - Report Scripts\$($_.Name)" -Verbose -Confirm:$false; Start-Sleep -Seconds 1 }

# Add role entry to give permssions to find mailboxes based on search criteria
Remove-ManagementRoleEntry -Identity "Mail Recipient - Report Scripts\Get-Mailbox" -Confirm:$false
Add-ManagementRoleEntry -Identity "Mail Recipient - Report Scripts\Get-Mailbox" -Parameters "Identity","ForwardTo","ForwardAsAttachmentTo","RedirectTo"

# Add role entry to give permssions to get inbox rules
Remove-ManagementRoleEntry -Identity "Mail Recipient - Report Scripts\Get-InboxRule" -Confirm:$false
Add-ManagementRoleEntry -Identity "Mail Recipient - Report Scripts\Get-InboxRule" -Parameters "Mailbox"
