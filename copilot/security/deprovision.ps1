# Populate values, may need to define subscription if MI given access to multiple subs
$name = "security-copilot"
$subscriptionName = "sub-security-copilot"

# Connect to Azure as Managed Identity
Disable-AzContextAutosave -Scope Process | Out-Null
Connect-AzAccount -Identity | Out-Null
$subscriptionId = (Set-AzContext -Subscription $subscriptionName).Subscription.Id

# Delete resource to deprovision SCU
Remove-AzResource -ResourceId "/subscriptions/$subscriptionId/resourceGroups/$name/providers/Microsoft.SecurityCopilot/capacities/$name" -Force -ErrorAction SilentlyContinue
