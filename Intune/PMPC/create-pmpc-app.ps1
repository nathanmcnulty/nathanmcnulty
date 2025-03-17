# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Create the application
$app = New-MgApplication -DisplayName "Patch My PC - Intune Connector"

# Create service principal
$sp = New-MgServicePrincipal -AppId $app.AppId

# Grant permissions
$GraphSP = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
$permissions = @(
    "78145de6-330d-4800-a6ce-494ff2d33d07" # DeviceManagementApps.ReadWrite.All
    "dc377aa6-52d8-4e23-b271-2a7ae04cedf3" # DeviceManagementConfiguration.Read.All
    "2f51be20-0bb4-4fed-bf7b-db946066c75e" # DeviceManagementManagedDevices.Read.All
    "58ca0d9a-1575-47e1-a3cb-007ef2e4583b" # DeviceManagementRBAC.Read.All
    "5ac13192-7ace-4fcf-b828-1a26f28068ee" # DeviceManagementServiceConfig.ReadWrite.All
    "98830695-27a2-44f7-8c18-0c3ebc9698f6" # GroupMember.Read.All
)
$permissions | ForEach-Object { 
    New-MgServicePrincipalAppRoleAssignment -AppRoleId $_ -ServicePrincipalId $sp.Id -ResourceId $GraphSP.Id -PrincipalId $sp.Id
}