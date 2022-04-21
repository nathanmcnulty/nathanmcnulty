## Grant MI Management Group Contributor and User Access Administrator on the necessary management groups
# Prevent inheriting AzContext in your runbook
Disable-AzContextAutosave -Scope Process
# Connect to Azure with system-assigned managed identity
$AzureContext = (Connect-AzAccount -Identity).Context
# Set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext

# Get all subscriptions starting with Visual Studio, then move them to the management group
(Get-AzSubscription | Where-Object { $_.Name -like "Visual Studio*" }) | ForEach-Object { 
    New-AzManagementGroupSubscription -GroupId '5dbd79f8-1fd9-45d2-a9e8-f6e399306e33' -SubscriptionId $_.SubscriptionId 
}
