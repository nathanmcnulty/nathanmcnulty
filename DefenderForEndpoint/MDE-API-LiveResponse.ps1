## Service Principal Info
$tenantId = '847b3907-ca15-b0f4-b171-eb18319dbfab'
$appId = '6b3b624f-99bb-4ad7-bd38-16a6b3a476a2'
$appSecret = 'wjA8Q~vTRm3XChp_IzD2odWYKWZcaoA9a4Ozldrl'

## Get Token
$resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}
$token = (Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop).access_token

# Upload script to the file library
$filePath = ".\RestoreFromQuarantine.ps1"
$fileContents = ([IO.File]::ReadAllBytes($filePath))

$params = @{
    method = POST
    uri = "https://api.security.microsoft.com/api/libraryfiles"
    headers = @{
        'Content-Type' = 'multipart/form-data'
        Authorization = "Bearer $token"
    }
    body = @{
        file = $fileContents
        ParametersDescription = "Original path of file to be restored from quarantine"
        HasParameters = "true"
        OverrideIfExists = "true"
        Description = "Restores specified file from quarantine"
    }
}
Invoke-RestMethod @params

# Function to run live response because of rate limiting
# Limits: 10 calls per minute, 25 concurrent live response sessions
function InvokeLiveResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $File,
        [Parameter(Mandatory=$true)]
        [string] $MachineId
    )
    
    $params = @{
        method = "POST"
        uri = "https://api.securitycenter.microsoft.com/api/machines/$machineId/runliveresponse"
        body = @{
            Commands = @( @{
                            type = "RunScript"
                            params = @(
                                @{ key = "ScriptName"; value = "RestoreFromQuarantine.ps1" }
                                @{ key = "Args"; value = $file }
                            )
            } )
            Comment = "Restoring $file from quarantine"
        }
    }
    Invoke-RestMethod @params

    # Get results
    Invoke -RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machineactions/$machineId/GetLiveResponseResultDownloadLink(index=0)" -Headers @{ Authorization = "Bearer $token" }
}

# Iterate through list of devices (must be machineId, can get via list devices)
$devices = Get-Clipboard # or Import-Csv or whatever

$devices | ForEach-Object -Parallel 10 {
    InvokeLiveResponse -File "C:\path\to\where\file\was\quarantined.txt" -MachineId $_
    Start-Sleep -Seconds 60
}