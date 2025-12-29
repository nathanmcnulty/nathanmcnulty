# Populate values, may need to define subscription if MI given access to multiple subs
$name = "security-copilot"
$subscriptionName = "sub-security-copilot"
$location = "eastus"
$geo = "us"
$numberOfUnits = 1

# Connect to Azure as Managed Identity
Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Identity | Out-Null
$subscriptionId = (Set-AzContext -Subscription $subscriptionName).Subscription.Id

# Ensure capacity is new
$oldCapacity = (Invoke-AzRestMethod -Uri "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$name/providers/Microsoft.SecurityCopilot/capacities/$name`?api-version=2024-11-01-preview" -ErrorAction SilentlyContinue).content | ConvertFrom-Json | Where-Object { $_.systemData.createdAt -lt (Get-Date -AsUTC).AddMinutes(-50) } 
if ($oldCapacity) {
    Write-Host "Deleting existing capacity..."
    Remove-AzResource -ResourceId $_.id -Force
    Start-Sleep -Seconds 10
}

# Base64 encode template to avoid dependencies on external storage!
$encodedTemplate = "ewogICAgIiRzY2hlbWEiOiAiaHR0cDovL3NjaGVtYS5tYW5hZ2VtZW50LmF6dXJlLmNvbS9zY2hlbWFzLzIwMTQtMDQtMDEtcHJldmlldy9kZXBsb3ltZW50VGVtcGxhdGUuanNvbiMiLAogICAgImNvbnRlbnRWZXJzaW9uIjogIjEuMC4wLjAiLAogICAgInBhcmFtZXRlcnMiOiB7CiAgICAgICAgImNhcGFjaXR5TmFtZSI6IHsKICAgICAgICAgICAgInR5cGUiOiAiU3RyaW5nIgogICAgICAgIH0sCiAgICAgICAgImxvY2F0aW9uIjogewogICAgICAgICAgICAidHlwZSI6ICJTdHJpbmciCiAgICAgICAgfSwKICAgICAgICAibnVtYmVyT2ZVbml0cyI6IHsKICAgICAgICAgICAgInR5cGUiOiAiSW50IgogICAgICAgIH0sCiAgICAgICAgImNyb3NzR2VvQ29tcHV0ZSI6IHsKICAgICAgICAgICAgInR5cGUiOiAiU3RyaW5nIgogICAgICAgIH0sCiAgICAgICAgImdlbyI6IHsKICAgICAgICAgICAgInR5cGUiOiAiU3RyaW5nIgogICAgICAgIH0KICAgIH0sCiAgICAicmVzb3VyY2VzIjogWwogICAgICAgIHsKICAgICAgICAgICAgInR5cGUiOiAiTWljcm9zb2Z0LlNlY3VyaXR5Q29waWxvdC9jYXBhY2l0aWVzIiwKICAgICAgICAgICAgImFwaVZlcnNpb24iOiAiMjAyMy0xMi0wMS1wcmV2aWV3IiwKICAgICAgICAgICAgIm5hbWUiOiAiW3BhcmFtZXRlcnMoJ2NhcGFjaXR5TmFtZScpXSIsCiAgICAgICAgICAgICJsb2NhdGlvbiI6ICJbcGFyYW1ldGVycygnbG9jYXRpb24nKV0iLAogICAgICAgICAgICAicHJvcGVydGllcyI6IHsKICAgICAgICAgICAgICAgICJudW1iZXJPZlVuaXRzIjogIltwYXJhbWV0ZXJzKCdudW1iZXJPZlVuaXRzJyldIiwKICAgICAgICAgICAgICAgICJjcm9zc0dlb0NvbXB1dGUiOiAiW3BhcmFtZXRlcnMoJ2Nyb3NzR2VvQ29tcHV0ZScpXSIsCiAgICAgICAgICAgICAgICAiZ2VvIjogIltwYXJhbWV0ZXJzKCdnZW8nKV0iCiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICBdCn0="
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedTemplate)) | Out-File .\template.json

# Create the resource
$params = @{
   Name = $name
   ResourceGroupName = $name
   TemplateFile = ".\template.json"
   CapacityName = $name
   Location = $location
   CrossGeoCompute = "Allowed"
   Geo = $geo
   NumberOfUnits = $numberOfUnits
}
New-AzResourceGroupDeployment @params
