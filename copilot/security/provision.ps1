# Populate values, may need to define subscription if MI given access to multiple subs
$name = "security-copilot"
$location = "eastus"
$geo = "us"
$numberOfUnits = 1

# Connect to Azure as Managed Identity
Disable-AzContextAutosave -Scope Process | Out-Null
$context = (Connect-AzAccount -Identity).context
Set-AzContext -SubscriptionName $context.subscription -DefaultProfile $context | Out-Null

# Ensure capacity is new
if (!(Get-AzResourceGroup -Name $name -Location $location -ErrorAction SilentlyContinue)) {
   New-AzResourceGroup -Name $name -Location $location -Force
} else {
   Remove-AzResourceGroup $name -Force -Verbose
   New-AzResourceGroup -Name $name -Location $location -Force
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
