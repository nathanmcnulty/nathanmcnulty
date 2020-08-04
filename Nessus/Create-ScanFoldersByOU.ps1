# Set variables for base OU and URI
$ou = "OU=T1,OU=Servers,DC=domain,DC=com"
$uri = "https://nessus.domain.com:8834/folders"

# Set up authentication
if (Test-Path -Path $env:USERPROFILE\nessus.xml) {
    $key = Import-Clixml -Path $env:USERPROFILE\nessus.xml
} else {
    $key = @{
        accessKey = Read-Host "Enter access key"
        secretKey = Read-Host "Enter secret key"
    }
    $save = Read-Host "Would you like to save this for future use? (Y/N)"
    if ($save -eq "Y") { Export-Clixml -InputObject $key -Path $env:USERPROFILE\nessus.xml -Force }
}

# Set up headers for authentication
$headers=@{}
$headers.Add("X-ApiKeys", "accessKey=$($key.accessKey);secretKey=$($key.secretKey)")

# Get list of existing folders in Nessus
$existing = (Invoke-RestMethod -Uri $uri -Method Get -Headers $headers).folders.name

# Create base folders if they don't exist
(Get-ADObject -Filter { objectClass -eq "organizationalUnit" } -SearchBase $ou -SearchScope OneLevel).name | ForEach-Object { 
    if ( $_ -notin $existing ) { Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body @{name="$_"} }
}