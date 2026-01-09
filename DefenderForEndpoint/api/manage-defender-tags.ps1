# Microsoft Defender for Endpoint - Tag Management Script
# Automatically adds and removes tags based on device IP addresses

# Authenticate
Disable-AzContextAutosave -Scope Process
Connect-AzAccount -Identity

# Get token
$secureAccessToken = (Get-AzAccessToken -ResourceUri 'https://api.securitycenter.microsoft.com/.default' -AsSecureString).token
$ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAccessToken)
try {
    $accessToken = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
}

# Set up headers
$headers = @{'Authorization' = "Bearer $accessToken"}

# Set up mappings
$mappings = @{
    "PRE - Tag 1" = @(
        '10.0.1.'
    )
    "PRE - Tag 2" = @(
        '10.1.1.','10.1.2.','10.1.3.',
        '10.2.1.','10.2.2.',
        '10.3.1.'
    )
    "PRE - Tag 3" = @(
        '10.4.1.',
        '10.5.1.','10.5.2.'
    )
}

$mappings.GetEnumerator() | ForEach-Object {
    $correctTag = $_.Key
    $ipPrefixes = $_.Value
    
    Write-Host "`nProcessing tag: $correctTag" -ForegroundColor Cyan
    
    # Get all devices matching this IP range
    $devices = @()
    foreach ($ipPrefix in $ipPrefixes) {
        Write-Host "  Querying devices with IP prefix: $ipPrefix"
        $result = Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines?`$filter=startsWith(lastIpAddress, '$ipPrefix')" -Headers $headers -ContentType "application/json"
        $devices += $result.value
    }
    
    if ($devices.Count -eq 0) {
        Write-Host "  No devices found for this IP range: $ipPrefix*" -ForegroundColor Yellow
        continue
    }
    
    Write-Host "  Found $($devices.Count) device(s): $($devices.Id -join ', ')"
    
    # Find devices that need tag corrections
    $devicesToAddTag = @()
    $tagsToRemove = @{}  # Key = tag name, Value = array of device IDs
    
    foreach ($device in $devices) {
        # Check if device has the correct tag
        if ($device.machineTags -notcontains $correctTag) { 
            $devicesToAddTag += $device.Id 
        }
        
        # Check for incorrect TVM tags that need to be removed
        $incorrectTvmTags = $device.machineTags | Where-Object { $_ -like "TVM -*" -and $_ -ne $correctTag }
        foreach ($incorrectTag in $incorrectTvmTags) {
            if (-not $tagsToRemove.ContainsKey($incorrectTag)) { 
                $tagsToRemove[$incorrectTag] = @() 
            }
            $tagsToRemove[$incorrectTag] += $device.Id
        }
    }
    
    # Remove incorrect TVM tags
    foreach ($tagToRemove in $tagsToRemove.Keys) {
        $machineIds = $tagsToRemove[$tagToRemove]
        Write-Host "  Removing tag '$tagToRemove' from $($machineIds.Count) device(s)" -ForegroundColor Yellow
        
        $body = @{
            "Value" = $tagToRemove
            "Action" = "Remove"
            "MachineIds" = $machineIds
        } | ConvertTo-Json
        
        try {
            $response = Invoke-WebRequest -Method POST -Uri "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines" -Headers $headers -Body $body -ContentType "application/json"
            if ($response.StatusCode -eq 200) {
                Write-Host "    Successfully removed tag" -ForegroundColor Green
            } else {
                Write-Host "    Unexpected response code: $($response.StatusCode)" -ForegroundColor Yellow
            }
        } catch { 
            Write-Host "    Error removing tag: $_" -ForegroundColor Red
        }
    }
    
    # Add correct tag where missing
    if ($devicesToAddTag.Count -gt 0) {
        Write-Host "  Adding tag '$correctTag' to $($devicesToAddTag.Count) device(s)" -ForegroundColor Green
        
        $body = @{
            "Value" = $correctTag
            "Action" = "Add"
            "MachineIds" = $devicesToAddTag
        } | ConvertTo-Json
        
        try {
            $response = Invoke-WebRequest -Method POST -Uri "https://api.securitycenter.microsoft.com/api/machines/AddOrRemoveTagForMultipleMachines" -Headers $headers -Body $body -ContentType "application/json"
            if ($response.StatusCode -eq 200) {
                Write-Host "    Successfully added tag" -ForegroundColor Green
            } else {
                Write-Host "    Unexpected response code: $($response.StatusCode)" -ForegroundColor Yellow
            }
        } catch { 
            Write-Host "    Error adding tag: $_" -ForegroundColor Red
        }
    } else { 
        Write-Host "  All devices already have the correct tag" -ForegroundColor Green
    }
}

Write-Host "`nTag management complete!" -ForegroundColor Cyan
