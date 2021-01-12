<#
.Synopsis
    Find meetings attended by a specific user
.DESCRIPTION
    This supports discovery of meetings attended by a user when you don't know who hosted the meeting
.NOTES
    This is terribly optimized and may not be the best way to do this (it was just the easiest)
    If this actually is the best way to do this, this could be turned into an advanced function so you can pass parameters to it
#>

# Headers contain auth token
$token = "API Bearer Token" #consider storing and pulling this from a vault
$headers=@{}
$headers.Add("authorization", "Bearer $token")

# Set date range
$startDate = (Get-Date).AddDays(-2).ToString('yyyy-MM-dd') # Can replace with just $startDate = "2021-01-11"
$endDate = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')

# Specify user by email
$email = "email@domain.com"

# If using authentication profiles, comment out email above and the if ($email... below, then uncomment the two $name lines
# Keep in mind that names are not unique, so plan for common names
# $name = "nathan mcnulty"

# Get list of all meeting ID's for the given date range
do {
    $response = Invoke-RestMethod -Uri "https://api.zoom.us/v2/metrics/meetings?page_size=300&next_page_token=$nextPageToken&from=$startDate&to=$endDate" -Method 'GET' -Headers $headers
    
    # next_page_token tells the API what page we are on and null to start seems to be OK
    $nextPageToken = $response.next_page_token

    # Check each meeting for the participant specified 
    $response.meetings.id | ForEach-Object {
        $meeting = Invoke-RestMethod -Uri "https://api.zoom.us/v2/metrics/meetings/$_/participants?page_size=300" -Method 'GET' -Headers $headers
        
        # If user attended, write out details of the meeting to the console
        if ($email -in $meeting.participants.email) { Invoke-RestMethod -Uri "https://api.zoom.us/v2/metrics/meetings/$_" -Method 'GET' -Headers $headers }
        # if ($name -in $meeting.participants.user_name) { Invoke-RestMethod -Uri "https://api.zoom.us/v2/metrics/meetings/$_" -Method 'GET' -Headers $headers }
    }
} while ($nextPageToken -ne "")