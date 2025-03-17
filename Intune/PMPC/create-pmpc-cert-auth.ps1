# Create a new certificate
$newCert = @{
    Subject = "CN=PatchMyPCIntuneConnector"
    CertStoreLocation = "Cert:\LocalMachine\My"
    HashAlgorithm = 'sha256'
    KeyExportPolicy = 'NonExportable'
    KeyUsage = 'DigitalSignature'
    KeyAlgorithm = 'RSA'
    KeyLength = 2048
    KeySpec = 'Signature'
    NotAfter = (Get-Date).AddYears(1)
    TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
}
$cert = New-SelfSignedCertificate @newCert

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# Add key credentials to the application
$app = Get-MgApplication -Filter "displayName eq 'Patch My PC - Intune Connector'"
$body = @{
	keyCredentials = @(
		@{
			keyId = "$(New-Guid)"
			type = "AsymmetricX509Cert"
			usage = "Verify"
			key = [System.Convert]::ToBase64String($cert.RawData)
		}
	)
}
Update-MgApplication -ApplicationId $app.Id -BodyParameter ($body | ConvertTo-Json)

<# If you create the cert on a remote server but run Graph PowerShell locally, you can use this to copy params locally

On the remote server, run:

$body = @{
	keyCredentials = @(
		@{
			keyId = "$(New-Guid)"
			type = "AsymmetricX509Cert"
			usage = "Verify"
			key = [System.Convert]::ToBase64String($cert.RawData)
		}
	)
}
$body | ConvertTo-Json | Set-Clipboard

On the client with Graph PowerShell, run:

$app = Get-MgApplication -Filter "displayName eq 'Patch My PC - Intune Connector'"

$body = @{}
$customObject = Get-Clipboard | ConvertFrom-Json
$customObject.PSObject.Properties | ForEach-Object {
    $body[$_.Name] = $_.Value
}
Update-MgApplication -ApplicationId $app.Id -BodyParameter ($body | ConvertTo-Json)

#>