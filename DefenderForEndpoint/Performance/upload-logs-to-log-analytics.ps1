# Auth as SP that has Microsoft.Insights/Telemetry/Write on our LAW
$tenantId = "847b5907-ca15-40d2-b171-eb18619dbfab"
$appId = "249e282e-24a9-4b94-99d1-39bd2fdc2074"
$appSecret = "9bN2Q~~jdYk4mC5~ERj2XvOBs9dusGJ4ym6wJa7E"

# DCR endpoint
$endpoint_uri = "https://dcr-mdav-perf-udsh-westus2.logs.z1.ingest.monitor.azure.com"
$dcrImmutableId = "dcr-f5b19458f1ab4452a5d1ab8d9df8409c"
$streamName = "Custom-MdavPerfData"

# Get access token to talk to DCR endpoint as SP  
$body = "client_id=$appId&scope=https%3a%2f%2fmonitor.azure.com%2f%2f.default&client_secret=$appSecret&grant_type=client_credentials";
$headers = @{"Content-Type"="application/x-www-form-urlencoded"};
$bearerToken = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method "Post" -Body $body -Headers $headers).access_token

# Get EstiamtedImpact events from Defender MPLog
$DeviceId = (dsregcmd /status | Select-String "deviceId").ToString().Split(" ")[-1]
$DeviceName = $env:COMPUTERNAME

$body = New-Object System.Collections.ArrayList
Get-Content (Get-Item -Path "$env:ProgramData\Microsoft\Windows Defender\Support\MPLog*") | Select-String -Pattern "Impact: \b([5-9][0-9])%" | Select-String "TotalTime: \d{3,5}," | ForEach-Object {
    [string]$Timestamp = "$(Get-Date -Date $_.ToString().Substring(0,23) -Format O)Z"
    [string]$ProcessImageName = $_.ToString().Substring(23).Split(',')[0].Split(' ')[-1]
    [int]$ProcessId = $_.ToString().Substring(23).Split(',')[1].Split(' ')[-1]
    [int]$TotalTime = $_.ToString().Substring(23).Split(',')[2].Split(' ')[-1]
    [int]$Count = $_.ToString().Substring(23).Split(',')[3].Split(' ')[-1]
    [int]$MaxTime = $_.ToString().Substring(23).Split(',')[4].Split(' ')[-1]
    [string]$MaxTimeFile = $_.ToString().Substring(23).Split(',')[5].Split(':')[-1].Trim(' ')
    [int]$EstimatedImpact = $_.ToString().Substring(23).Split(',')[6].Split(' ')[-1].Trim('%')

    $json = @{
        DeviceId = $DeviceId
        DeviceName = $DeviceName
        Timestamp = $Timestamp
        ProcessImageName = $ProcessImageName
        ProcessId = $ProcessId
        TotalTime = $TotalTime
        Count = $Count
        MaxTime = $MaxTime
        MaxTimeFile = $MaxTimeFile
        EstimatedImpact = $EstimatedImpact
    }
    $body.Add($json)
}

# Send data to the DCR endpoint
$headers = @{"Authorization"="Bearer $bearerToken";"Content-Type"="application/json"}
$count = [Math]::Ceiling($body.count/1000)

0..($count-1) | ForEach-Object {
    [Int]$start = $_*1000
    [Int]$end = ($_*1000)+999
    Invoke-RestMethod -Uri "$endpoint_uri/dataCollectionRules/$dcrImmutableId/streams/$($streamName)?api-version=2023-01-01" -Method "Post" -Body ($body[$start..$end] | ConvertTo-Json) -Headers $headers
}