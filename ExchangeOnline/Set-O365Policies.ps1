#Requires -Modules ActiveDirectory
<#
.Synopsis
   Set required policies for Exchange Online
.DESCRIPTION
   Sets policies such as enabling mailbox auditing, enabling litigation hold, disabling remote powershell, and setting mailbox folder permissions
.NOTES
   You will need to run Create-PolicyScriptsRole.ps1 (and perform its prerequisite) before running this script. 
   This script needs to be run on a schedule as these settings cannot be enabled by default for new mailbox creations (that I know of)
   When changing from accounts to variables, I may have introduced bugs. Keep an eye out ;)
#>

# Location of log file and credential file (created by Get-Credential | Export-CliXml using the account used to run the scheduled task)
[string]$logfile = "C:\scripts\logs\$(Get-Date -Format yyyy.MM)-Set-O365Policies.log"
[string]$credentialfile = "C:\scripts\credentials\exo-scripts.xml"

# List of users to exclude from Remote Powershell policy
[array]$rpexclusion = "admin_account","script_account","other_account"

# Litigation Hold variables
[int]$holdduration = 2555
[string]$holdowner = "o365admin@domain.onmicrosoft.com"

# Calendar permissions variables
[string]$ADGroup = "ADSecurityGroup"
[array]$excludedusers = "exclude_user1","exclude_user2"
[string]$adminuser = "admin_user"

function TimeStampLog {
	param (
		[string] $message
	)
	process { Add-Content -Path $logfile -Value "$(Get-Date -Format G)`t$message" }
}

# Timestamp log for start of script
TimeStampLog "Office 365 - Set Policies has started"

# Create session with Exchange Powershell
try { 
    if (Test-Path -Path $credentialfile) { $creds = Import-Clixml $credentialfile } else { TimeStampLog "No credential file found. Prompting for credentials"; $creds = Get-Credential }
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://outlook.office365.com/powershell-liveid/" -Credential $creds -Authentication Basic -AllowRedirection
    Import-PSSession $Session -DisableNameChecking
} catch { TimeStampLog "Failed to connect to Exchange Online PowerShell Session" }
if ($session.State -eq "Opened") { TimeStampLog "Connected to Exchange Online PowerShell Session" } else { TimeStampLog "Failed to connect to Exchange Online PowerShell Session"; exit }

# Disable Remote Powershell for all users except admins
$rplist = Get-Mailbox -ResultSize unlimited -Filter { RemotePowerShellEnabled -eq $true} | Where-Object { $_.Name -notin $rpexclusion }
TimeStampLog "Found $($rplist.Count) mailboxes without Remote Powershell disabled"
$rplist | ForEach-Object { 
    TimeStampLog "Attempting to disable Remote Powershell for user: $($_.Identity)"
    Set-User -Identity $_.Identity -RemotePowerShellEnabled $false -Verbose
}

# Write out list of users that still do not have remote powershell disabled
Get-Mailbox -ResultSize unlimited -Filter { RemotePowerShellEnabled -eq $true} | Where-Object { $_.Name -notin $rpexclusion } | ForEach-Object { TimeStampLog "Remote Powershell not disabled for user: $($_.Identity)"}

# Enable Litigation Hold for all mailboxes
[array]$lhlist = Get-Mailbox -Filter { LitigationHoldEnabled -ne "True" } -RecipientTypeDetails UserMailbox -ResultSize Unlimited
TimeStampLog "Found $($lhlist.Count) mailboxes without litigation hold enabled"
$lhlist | ForEach-Object {
    TimeStampLog "Attempting to enable Litigation Hold for user: $($_.Identity)"
    $date = $_.WhenMailboxCreated
    Set-Mailbox -Identity $_.Identity -LitigationHoldEnabled $true -LitigationHoldDuration $holdduration -LitigationHoldDate $date -LitigationHoldOwner $holdowner -Verbose
}

# Write out list of users that still do not have Litigation Hold enabled
Get-Mailbox -Filter { LitigationHoldEnabled -ne "True"  } -RecipientTypeDetails UserMailbox -ResultSize Unlimited | ForEach-Object { TimeStampLog "Litigation Hold not enabled for user: $($_.Identity)"}

# Enable Mailbox Auditing
[array]$malist = Get-Mailbox -Filter { auditEnabled -eq $false }
$malist | ForEach-Object {
    TimeStampLog "Attempting to enable Mailbox Auditing for user: $($_.Identity)"
    Set-Mailbox -Identity $_.Identity -AuditEnabled $true -Verbose
}

# Write out list of users that still do not have Mailbox Auditing enabled
Get-Mailbox -Filter { auditEnabled -eq $false } | ForEach-Object { TimeStampLog "Mailbox Auditing not enabled for user: $($_.Identity)"}

# Get mailboxes with a ForwardingSmtpAddress and unset ForwardingSmtpAddress
[array]$fsmtplist = Get-Mailbox -Filter { ForwardingSmtpAddress -ne $null }
$fsmtplist | ForEach-Object { 
    TimeStampLog "Attempting to disable ForwardingSmtpAddress for user: $($_.Identity)"
    Set-Mailbox -Identity $_.Identity -ForwardingSmtpAddress $null -Verbose
}

# Write out list of users that still have a ForwardingSmtpAddress enabled
Get-Mailbox -Filter { ForwardingSmtpAddress -ne $null } | ForEach-Object { TimeStampLog "ForwardingSmtpAddress not disabled for user: $($_.Identity)"}

# Get list of users and ensure a user has at least Reviewer access to those user calendars
Get-ADGroupMember -Identity $ADGroup | Where-Object { $_.Name -notin $excludedusers } | ForEach-Object {
    $permissions = Get-MailboxFolderPermission -Identity "$($_.Name)`:\calendar"
    if ($permissions | Where-Object { $_.User.ADRecipient.Identity -eq $adminuser } | Where-Object { $_.AccessRights -in "None","AvailabilityOnly","LimitedDetails" }) { Set-MailboxFolderPermission -Identity "$($_.Name)`:\calendar" -User $adminuser -AccessRights Reviewer -Verbose }
    if (!($permissions | Where-Object { $_.User.ADRecipient.Identity -eq $adminuser })) { Add-MailboxFolderPermission -Identity "$($_.Name)`:\calendar" -User $adminuser -AccessRights Reviewer -Verbose }
}

# Timestamp log for end of script
TimeStampLog "Office 365 - Set Policies has ended"