# Copy Authorization header from browser
$headers = @{ "Authorization" = "$(Get-Clipboard)" }

# Logs Ingestion API headers
$scope= [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default") 
$body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials"
$token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method "Post" -Body $body -Headers @{"Content-Type"="application/x-www-form-urlencoded"}).access_token

$ApiHeaders = @{
    "Authorization" = "Bearer $token"
    "Content-Type"="application/json"
    "x-ms-client-request-id" = New-Guid
}

# Get list of devices
$devices = Get-MgDeviceManagementManagedDevice -ManagedDeviceId 537f17f9-32e4-44de-acf7-22bcfc09b607
# devices = Get-MgDeviceManagementManagedDevice -All

$devices | ForEach-Object {
    # Get properties
    $deviceId = $_.Id
    $deviceName = $_.DeviceName
    $availableIds = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceId')/deviceInventories" -Headers $headers).value.id

    # Get instances
    $body = $availableIds | ForEach-Object {
        $property = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices('$deviceId')/deviceInventories('$_')?`$expand=instances(`$expand=Microsoft.Graph.deviceInventorySimpleItem/properties)" -Headers $headers
        
        [array]$properties = $property.instances | ForEach-Object {
            [hashtable]$ht = @{}
            $_.properties | ForEach-Object { $ht.Add($_.id,$_.value.value) }
            return $ht
        }

        $json = @{
            deviceName = $deviceName
            deviceId = $deviceId
            propertyId = $property.id
            lastSyncDateTime = $property.lastSyncDateTime
            properties = $properties
        }
        return $json
    } | ConvertTo-Json -Depth 8

    # Invoke-RestMethod -Method "POST" -Uri "https://your-url.monitor.azure.com/dataCollectionRules/dcr-1234567890/streams/IntuneInventory?api-version=2023-01-01" -Body $body -Headers $ApiHeaders
}
