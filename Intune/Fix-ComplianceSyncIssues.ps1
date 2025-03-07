#Requires -Modules 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.DeviceManagement'

Connect-MgGraph -Identity

$azureDeviceList = Get-MgDevice -All -Property Id, DeviceId, IsCompliant -Filter 'isCompliant eq true or isCompliant eq false' | Select-Object Id, DeviceId, IsCompliant
$intuneDeviceList = Get-MgDeviceManagementManagedDevice -All -Property AzureAdDeviceId, ComplianceState -Filter "ManagedDeviceOwnerType eq 'Company'" | Select-Object @{ name = "DeviceId"; expression = { $_.AzureAdDeviceId } },@{ name = "isCompliant"; expression = { if ($_.ComplianceState -eq "compliant") { $true} else { $false } } }

Compare-Object -ReferenceObject $azureDeviceList -DifferenceObject $intuneDeviceList -Property DeviceId, IsCompliant -PassThru | Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object {
    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/devices/$($_.Id)" -Body (@{ isCompliant = $_.isCompliant } | ConvertTo-Json)
    if ((Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/devices/$($_.Id)" | ConvertFrom-Json).isCompliant -ne $_.isCompliant) { Write-Output "$($_.Id) compliance state not changed" }
}