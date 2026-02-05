
<#
.SYNOPSIS
Registers an attendee for a Teams webinar using Microsoft Graph API.

.DESCRIPTION
This function registers an attendee for a Teams webinar by submitting their information through Microsoft Graph API.
Requires authentication with appropriate permissions (VirtualEventRegistration-Anon.ReadWrite.All or VirtualEvent.ReadWrite).

.PARAMETER EventId
The webinar event ID in the format: <guid>@<tenantId>

.PARAMETER FirstName
The first name of the attendee

.PARAMETER LastName
The last name of the attendee

.PARAMETER Email
The email address of the attendee

.PARAMETER PreferredTimezone
The preferred timezone for the attendee

.PARAMETER PreferredLanguage
The preferred language for the attendee (e.g., en-us)

.EXAMPLE
Register-WebinarAttendee -FirstName "Nathan" -LastName "McNulty" -Email "nathan@domain.com"

.EXAMPLE
Register-WebinarAttendee -EventId "abc123@tenant.com" -FirstName "Jane" -LastName "Smith" -Email "jane@example.com" -PreferredTimezone "Eastern Standard Time"

.NOTES
References:
- https://learn.microsoft.com/en-us/graph/api/resources/virtualeventwebinar?view=graph-rest-beta
- https://learn.microsoft.com/en-us/graph/cloud-communications-virtual-events-webinar-usecases#data-sync
#>

[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string]$EventId,
	
	[Parameter(Mandatory = $true)]
	[string]$FirstName,
	
	[Parameter(Mandatory = $true)]
	[string]$LastName,
	
	[Parameter(Mandatory = $true)]
	[string]$Email,
	
	[Parameter(Mandatory = $false)]
	[string]$PreferredTimezone = "Pacific Standard Time",
	
	[Parameter(Mandatory = $false)]
	[string]$PreferredLanguage = "en-us"
)

$body = @{
	firstName = $FirstName
	lastName = $LastName
	email = $Email
	preferredTimezone = $PreferredTimezone
	preferredLanguage = $PreferredLanguage
}

try {
	$response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/solutions/virtualEvents/webinars/$EventId/registrations" -Body $body -ErrorAction Stop
} catch {
	# Output a single concise error line (prefer Graph error message when available)
	$content = $_.Exception.Response.Content -as [string]
	try { $graphMsg = ($content | ConvertFrom-Json -ErrorAction Stop).error.message } catch { $graphMsg = $null }
	$message = if ($graphMsg) { $graphMsg } elseif ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
	Write-Error $message
	return $null
}