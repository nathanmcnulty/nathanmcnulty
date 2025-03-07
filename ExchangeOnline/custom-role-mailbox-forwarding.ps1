#Requires -Module ExchangeOnlineManagement

# Get the objectId and appId from the app registration for the service principal or managed identity
$SP_ID = "SP objectId"
$AppId = "SP appId"

# Connect to Exchange Online
Connect-ExchangeOnline

# Create linked Service Principal in Exchange
New-ServicePrincipal -AppId $AppId -ServiceId $SP_ID -DisplayName "exo-automation"

# Create new Management role
New-ManagementRole -Name "Configure Forwarding" -Parent "User Options" -Verbose

# Remove unnecessary permissions
Get-ManagementRoleEntry "Configure Forwarding\*" | Where-Object { $_.Name -notin "Get-Mailbox" } | ForEach-Object { 
    Remove-ManagementRoleEntry -Identity "Configure Forwarding\$($_.Name)" -Verbose -Confirm:$false 
}

# Add limited Set-Mailbox permissions
Add-ManagementRoleEntry -Identity "Configure Forwarding\Set-Mailbox" -Parameters "Identity","DeliverToMailboxAndForward","ForwardingSmtpAddress","ForwardingAddress"

# Create a Role Group, add our custom Mailbox Auditing role, and add our Service Principal as a member
New-RoleGroup "Mailbox Forwarding Management" -Description "Limited scope for Azure Automation to set Mailbox Forwarding" -Roles "Configure Forwarding" -Members $SP_ID -Confirm:$false -Verbose