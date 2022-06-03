# Download blobs for Azure storage
Connect-AzAccount
$storageAccount = Get-AzStorageAccount -Name $resourceName -ResourceGroupName $resourceGroupName
$storageContainer = Get-AzStorageContainer -Name $conatinerName -Context $storageAccount.Context
Get-AzStorageBlob -Container $storageContainer.Name -Context $storageContainer.Context | ForEach-Object { 
    Get-AzStorageBlobContent -Container $storageContainer.name -Context $storageContainer.Context $_.Name 
}