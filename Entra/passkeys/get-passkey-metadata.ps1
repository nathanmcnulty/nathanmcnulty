# Get list of AAGUIDs and description from MDS
$jwt = (Invoke-RestMethod -Uri "https://mds3.fidoalliance.org/")
$split = ($jwt -split '\.')[1]
$remainder = $split.Length % 4
if ($remainder -eq 2) { $split += '==' }
if ($remainder -eq 3) { $split += '=' }
$split = $split.Replace('-', '+').Replace('_', '/')
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($split)) | ConvertFrom-Json

# Get list of allowed AAGUIDs from passkeys API
$allowed = ((Get-MgPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Fido2" }).AdditionalProperties.keyRestrictions.aaGuids
Write-Output "The list of currently allowed AAGUIDs are:"
$decoded.entries.metadataStatement | Select-Object aaguid,description | Where-Object { $_.aaguid -in $allowed }

# Get list of all AAGUIDs from Entra
$registered = ((Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter "methodsRegistered/any(i:i eq 'passKeyDeviceBound')" -All).Id | ForEach-Object { Get-MgUserAuthenticationFido2Method -UserId $_ -All }).AaGuid | Select-Object -Unique
Write-Output "The list of currently registered AAGUIDs are:"
$decoded.entries.metadataStatement | Select-Object aaguid,description | Where-Object { $_.aaguid -in $registered }



# Get list of AAGUIDs from passkeydevs
$json = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/refs/heads/main/combined_aaguid.json"

# Get list of allowed AAGUIDs from passkeys API
$allowed = ((Get-MgPolicyAuthenticationMethodPolicy).AuthenticationMethodConfigurations | Where-Object { $_.Id -eq "Fido2" }).AdditionalProperties.keyRestrictions.aaGuids
Write-Output "The list of currently allowed AAGUIDs are:"
$allowed | ForEach-Object { Write-Output "$_ $($json.$_.Name)" }

# Get list of all AAGUIDs from Entra
$registered = ((Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter "methodsRegistered/any(i:i eq 'passKeyDeviceBound')" -All).Id | ForEach-Object { Get-MgUserAuthenticationFido2Method -UserId $_ -All }).AaGuid | Select-Object -Unique
Write-Output "The list of currently registered AAGUIDs are:"
$registered | ForEach-Object { Write-Output "$_ $($json.$_.Name)" }