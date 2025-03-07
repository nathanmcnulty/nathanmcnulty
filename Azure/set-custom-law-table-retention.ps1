# Define variables
$resourceId = "/subscriptions/96e4534f-1815-4eaf-9420-4d612d2abf3f/resourcegroups/sentinel-sml-westus3/providers/microsoft.operationalinsights/workspaces/sentinel-sml-westus3"
$retentionPeriod = 180

# Get access token for Log Analytics API
try {
    $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-AzAccessToken -ResourceUrl 'https://api.loganalytics.io' -AsSecureString).Token))
    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token
        'Prefer' = 'metadata-format-v4, wait=600'
    }
} catch {
    Write-Error "Failed to retrieve access token: $_"
    exit
}

# Get tables from Log Analytics API
$tables = ((Invoke-RestMethod -Method "POST" -Uri "https://api.loganalytics.io/v1$resourceId/metadata" -Headers $headers).tables | where-Object { $_.hasData -eq $true }).Id

# Get access token for Azure Management API
try {
    $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-AzAccessToken -AsSecureString).Token))
    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = 'Bearer ' + $token
    }
} catch {
    Write-Error "Failed to retrieve access token: $_"
    exit
}

# Set retention period in body
$body = @{
    properties = @{
        totalRetentionInDays = $retentionPeriod
    }
} | ConvertTo-Json

# Update tables
$tables | ForEach-Object { 
    $response = Invoke-RestMethod "https://management.azure.com$resourceId/tables/$_`?api-version=2023-09-01" -Method 'PATCH' -Body $body -Headers $headers
    if ($response.properties.provisioningState -ne 'Succeeded') {
        Write-Error "Failed to update retention period for table $_`: $response"
    } else {
        Write-Output "Successfully updated retention period for table $_"
    }
}