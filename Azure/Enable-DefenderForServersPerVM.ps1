### Apply Defender for Servers to one VM ###
$vmname = "VMName"

# Set Context to subscription containing the VM
Set-AzContext -Subscription <GUID>

# Get the VM Id
$id = (Get-AzVm -Name $vmname).Id

# Create Uri using $Id (easier to read) :)
$uri = "https://management.azure.com$id/providers/Microsoft.Security/pricings/virtualMachines?api-version=2024-01-01"

# Get Access Token to talk to the API
$at = (Get-AzAccessToken).token

# Create body for API call, remove subplan line for Plan 2
$body = @{
   "properties" = @{
      "pricingTier" = "Standard"
      "subPlan" = "P1"
   }
} | ConvertTo-Json

# Invoke API call to enable Defender for Servers
Invoke-RestMethod -Method Put -Uri $uri -Headers @{Authorization = "Bearer $at"} -Body $body -ContentType "application/json"
