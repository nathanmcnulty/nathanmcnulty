<#
.SYNOPSIS
Disables or enables email notifications for a Teams webinar.

.DESCRIPTION
This function updates the email notification settings for a Teams webinar.

.PARAMETER EventId
The webinar event ID in the format: <guid>@<tenantId>

.PARAMETER EnableNotifications
Boolean to enable or disable attendee email notifications

.EXAMPLE
Set-WebinarNotifications -EventId "{event-guid}@{tenant-id}" -EnableNotifications $false

.NOTES
Requires Microsoft Graph permission: VirtualEvent.ReadWrite
#>

[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$EventId,
	
	[Parameter(Mandatory = $false)]
	[bool]$EnableNotifications = $false
)

$body = @{
	'settings' = @{
		'@odata.type' = '#microsoft.graph.virtualEventSettings'
		'isAttendeeEmailNotificationEnabled' = $EnableNotifications
	}
}

try {
	$response = Invoke-MgGraphRequest -Method PATCH -Uri "/beta/solutions/virtualEvents/webinars/$EventId" -Body $body -ErrorAction Stop
} catch {
	$content = $_.Exception.Response.Content -as [string]
	try { $graphMsg = ($content | ConvertFrom-Json -ErrorAction Stop).error.message } catch { $graphMsg = $null }
	$message = if ($graphMsg) { $graphMsg } elseif ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
	Write-Error $message
}