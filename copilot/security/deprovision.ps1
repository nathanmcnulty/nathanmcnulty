# Populate values, may need to define subscription if MI given access to multiple subs
$name = "security-copilot"
$subscriptionId = "24231b54-f7ab-486d-8522-936f3dddab17"

# Connect to Azure as Managed Identity
Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount #-Identity
Set-AzContext -SubscriptionName $subscriptionId | Out-Null

# Delete resource to deprovision SCU
Remove-AzResource -ResourceId "/subscriptions/$subscriptionId/resourceGroups/$name/providers/Microsoft.SecurityCopilot/capacities/$name" -Force -ErrorAction SilentlyContinue
