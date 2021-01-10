#Requires -Module ActiveDirectory
<#
.Synopsis
    Get group membership from Active Directory groups and map members to a group in Zoom
.DESCRIPTION
    Groups in Zoom can be used to specify policies. While it is possible to map users to groups through SAML (which I would recommend), in some cases you may need to allow login with Google which bypasses this feature.
    While you can add all users from a domain into a group through Zoom's admin console, you can't select just 700 users from a domain and add them.
    I wrote this to quickly map a few smaller groups of a few hundred users to groups. 
.NOTES
    You must create the group prior to this and obtain the groupID. I may extend this in the future to an Out-GridView selection, but for now, this is on you ;)
    Since I just threw this together for a one off, I didn't bother automating the creation of the bearer token. You can add that if you want.
    I refactored this so it has parameters instead of hard coding everything, so there may be typos. Let me know!
#>

# Tenant specific variables
$Domain = "domain.com" # Domain portion of user's email address, not necessarily AD domain
$ADGroups = "ADGroup1,ADGroup2"
$groupID = "k2okECpLRPa9b2SttQoIqx"

# Headers contain auth key
$token = Read-Host "Enter API Token"
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
    [array]$apiusers += $response.users

    # next_page_token tells the API what page we are on and null to start seems to be OK
    $nextPageToken = $response.next_page_token
} while ($nextPageToken -ne "")

# Get email addresses of all users in specified groups
$ADUsers = $ADGroups | ForEach-Object { Get-ADGroupMember -Identity $_ | ForEach-Object { (Get-ADUser -Identity $_ -Properties mail).mail }}

$apiusers | Where-Object { $_.email -like "*@$domain" } | ForEach-Object { 
    if ($adusers -contains $_.email) { 
        Invoke-RestMethod -Uri "https://api.zoom.us/v2/groups/$groupId/members" -Method POST -Headers $headers -ContentType 'application/json' -Body "{`"members`":[{`"id`":`"$($_.id)`"}]}`"}"
    }
}