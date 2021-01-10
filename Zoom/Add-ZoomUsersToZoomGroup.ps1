<#
.Synopsis
    Add all Zoom users for a specified domain to a group in Zoom
.DESCRIPTION
    The Zoom admin console offers this capability already, and it's probably better to use it there
    You can also use SAML mappings to do this, and I believe that's a much better path
.NOTES
    You must create the group prior to this and obtain the groupID
#>

# Tenant specific variables
$domain = "domain.com"
$GroupId = "HwqtsFZuTP6nu38_aCTKsz"

# Headers contain auth key
$token = "API Token"
$headers=@{}
$headers.Add("authorization", "Bearer $token")

# Process all pages and records
do {
    # This API endpoint seems to care if a null next_page_token is passed
    if ($response.next_page_token) {
        $response = Invoke-RestMethod -Uri "https://api.zoom.us/v2/users?page_size=300&next_page_token=$nextPageToken&status=active" -Method GET -Headers $headers
    } else {
        $response = Invoke-RestMethod -Uri "https://api.zoom.us/v2/users?page_size=300&status=active" -Method GET -Headers $headers
    }
    # Add users based on matching domain
    [array]$apiusers += $response.users | Where-Object { $_.email -like "*@$domain" }

    # next_page_token tells the API what page we are on and null to start seems to be OK
    $nextPageToken = $response.next_page_token    
} while ($nextPageToken -ne "")

# Process users and add members to groups
$apiusers | ForEach-Object { if ($_.group_ids -eq $null) { Invoke-RestMethod -Uri "https://api.zoom.us/v2/groups/$groupID/members" -Method POST -Headers $headers -ContentType 'application/json' -Body "{`"members`":[{`"id`":`"$_`"}]}`"}"}}