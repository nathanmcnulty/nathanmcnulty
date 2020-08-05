# Set variables for base OU and URI
$ou = "OU=Servers,DC=domain,DC=com"
$uri = "https://nessus.domain.com:8834"
$templatename = "Advanced Scan Template"

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

# Get list of folders in Nessus
$folders = (Invoke-RestMethod -Uri "$uri/folders" -Method Get -Headers $headers).folders

# Get template scan ID
$templateid = ((Invoke-RestMethod -Uri "$uri/scans" -Method Get -Headers $headers).scans | Where-Object { $_.name -eq $templatename }).id

# Create base folders if they don't exist
$list = (Get-ADObject -Filter { objectClass -eq "organizationalUnit" } -SearchBase $ou -SearchScope OneLevel).name 
$folders | ForEach-Object { 
    # Have to store variables for ForEach-Object for sub-OU's
    $name = $_.Name
    $id = $_.id

    # If sub-OU's exist, we'll create one scan per OU, otherwise we'll create one scan for the OU
    if ( $name -in $list ) {
        $subou = Get-ADObject -Filter { objectClass -eq "organizationalUnit" } -SearchBase "OU=$name,$ou" -SearchScope OneLevel
        if ($subou) {
            $subou | ForEach-Object { Invoke-RestMethod -Uri "$uri/scans/$templateid/copy" -Method Post -Headers $headers -Body @{ folder_id="$id";name="$name - $($_.name)" }}
        } else {
            Invoke-RestMethod -Uri "$uri/scans/$templateid/copy" -Method Post -Headers $headers -Body @{ folder_id="$id";name="$name" }
        }
    }
}