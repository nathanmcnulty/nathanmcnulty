<#
.Synopsis
    Add all Zoom users for a specified domain to a group in Zoom
.DESCRIPTION
    The Zoom admin console offers this capability already, and it's probably better to use it there
    You can also use SAML mappings to do this, and I believe that's a much better path
.NOTES
    I wrote this mostly to learn while I was playing with the API
    You must create the group prior to this and obtain the groupID
    Since I just threw this together for a one off, I didn't bother automating the creation of the bearer token. You can add that if you want.
    I refactored this so it has parameters instead of hard coding everything, so there may be typos. Let me know!
#>

$token = "API Token"
$domain = "domain.com"
$GroupId = "HwqtsFZuTP6nu38_aCTKsz"

# Headers contain key
$headers=@{}
$headers.Add("authorization", "Bearer $token")

1..170 | ForEach-Object { 
    $response = Invoke-RestMethod -Uri "https://api.zoom.us/v2/users?page_number=$_&page_size=300&status=active" -Method GET -Headers $headers
    [array]$apiusers += $response.users | Where-Object { $_.email -like "*@$domain" }
}

$apiusers | ForEach-Object { if ($_.group_ids -eq $null) { Invoke-RestMethod -Uri "https://api.zoom.us/v2/groups/$groupID/members" -Method POST -Headers $headers -ContentType 'application/json' -Body "{`"members`":[{`"id`":`"$_`"}]}`"}"}}