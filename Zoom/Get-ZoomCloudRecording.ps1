<#
.Synopsis
    Download recorded meetings from Zoom
.DESCRIPTION
    Script for automating download of recorded meetings from Zoom so we can store them or upload them somewhere else
    This does not remove recordings from Zoom. You can manually remove from the console or use my Delete-ZoomCloudRecording script.
.NOTES
    Planning on adding logging soon
#>

# Headers contain auth token
$token = "API Bearer Token" #consider storing and pulling this from a vault
$headers=@{}
$headers.Add("authorization", "Bearer $token")

# Make Invoke-WebRequest run faster
$ProgressPreference = 'SilentlyContinue'

# Set date range
$startDate = (Get-Date).AddDays(-2).ToString('yyyy-MM-dd')
$endDate = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')

# Process all pages and records
do {
    # next_page_token tells the API what page we are on and null to start seems to be OK
    $nextPageToken = $response.next_page_token
    $response = Invoke-RestMethod -Uri "https://api.zoom.us/v2/accounts/me/recordings?page_size=300&next_page_token=$nextPageToken&from=$startDate&to=$endDate" -Method 'GET' -Headers $headers
    $response.meetings | ForEach-Object { 
        # Create a folder per user
        $user = ($_.host_email).Split('@')[0]
        if (!(Test-Path -Path "C:\Zoom\$user")) { New-Item -Path "C:\Zoom\$user" -ItemType Directory }
        
        # Create filename based on date, topic, and meeting ID (and strip non-alphanumeric characters)
        $filename = "$(($_.start_time).Split('T')[0])_$($_.topic)_$($_.id)" -replace "\W"
        
        # Get list of download URL's, and if null (might mean audio only), skip download and move to the next entry
        $url = ($_.recording_files | Where-Object { $_.file_type -eq "MP4" }).download_url
        if ($url -eq $null) { continue }
        
        # Many meetings have more than one recording, so we have to iterate through all recordings
        0..($url.count -1) | ForEach-Object {
            if (!(Test-Path "C:\Zoom\$user\$filename-$_.mp4")) {
                if ($url.count -lt 2) { $uri = $url + "?access_token=$token" } else { $uri = $url[$_] + "?access_token=$token" }
                Invoke-WebRequest -Uri $uri -OutFile "C:\Zoom\$user\$filename-$_.mp4" 
            }
        }
    }
} while ($nextPageToken -ne "")