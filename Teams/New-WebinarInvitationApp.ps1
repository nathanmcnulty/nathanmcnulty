<#
.SYNOPSIS
Creates an app registration and service principal for automated Teams webinar invitations.

.DESCRIPTION
This script creates an Azure AD app registration with the VirtualEventRegistration-Anon.ReadWrite.All permission
for automated webinar attendee registration using Microsoft Graph REST via Invoke-MgGraphRequest.

.PARAMETER AppName
The name of the app registration to create

.EXAMPLE
.\New-WebinarInvitationApp.ps1 -AppName "Webinar-Invitations"

.NOTES
Requires Microsoft Graph permissions: Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All
#>

param(
	[Parameter(Mandatory = $false)]
	[string]$AppName = "Webinar-Invitations"
)

try {
    # Connect to Graph with permissions to create an app and assign permissions
    Connect-MgGraph -Scopes Application.ReadWrite.All,AppRoleAssignment.ReadWrite.All -ErrorAction Stop
    
    # Create application
    $appPayload = @{
        displayName = $AppName
        signInAudience = "AzureADMyOrg"
        web = @{ redirectUris = @("http://localhost") }
    }
    $app = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/applications" -Body ($appPayload | ConvertTo-Json) -ErrorAction Stop
    
    # Create corresponding service principal
    $spId = (Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" -Body (@{ appId = $app.appId } | ConvertTo-Json) -ErrorAction Stop).Id
    
    # Get Microsoft Graph service principal and required app role
    $graphSP = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" -ErrorAction Stop).value
    $appRole = $graphSP.appRoles | Where-Object { $_.value -eq "VirtualEventRegistration-Anon.ReadWrite.All" -and $_.allowedMemberTypes -contains "Application" } | Select-Object -First 1
    
    # Assign the app role to the newly created service principal
    $assignmentPayload = @{ 
        principalId = $spId
        resourceId = $graphSP.id
        appRoleId = $appRole.id
    }
    $roleAssignment = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId/appRoleAssignedTo" -Body ($assignmentPayload | ConvertTo-Json) -ErrorAction Stop
    
    Write-Host "App registration created successfully: $($app.appId) (objectId: $($app.id))" -ForegroundColor Green
    Write-Host "Service principal created: $spId" -ForegroundColor Green
    
    return [pscustomobject]@{ AppId = $app.appId; AppObjectId = $app.id; ServicePrincipalId = $spId; AppRoleAssignment = $roleAssignment }
} catch {
    Write-Error "Failed to create app registration or assign role: $_"
    throw $_
}