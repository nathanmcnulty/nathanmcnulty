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
$params = @{
	keyCredentials = @(
		@{
			endDateTime = $cert.NotAfter
			startDateTime = $cert.NotBefore
            customKeyIdentifier = [System.Text.Encoding]::ASCII.GetBytes("$($cert.Thumbprint)")
			type = "AsymmetricX509Cert"
			usage = "Verify"
			key = $cert.PublicKey.EncodedKeyValue.RawData
			displayName = $cert.Subject
		}
	)
}
Update-MgApplication -ApplicationId $app.Id -BodyParameter $params

<# If you create the cert on a remote server but run Graph PowerShell locally, you can use this to copy params locally

On the remote server, run:

$params = @{
	keyCredentials = @(
		@{
			endDateTime = $cert.NotAfter
			startDateTime = $cert.NotBefore
            customKeyIdentifier = [System.Text.Encoding]::ASCII.GetBytes("$($cert.Thumbprint)")
			type = "AsymmetricX509Cert"
			usage = "Verify"
			key = $cert.PublicKey.EncodedKeyValue.RawData
			displayName = $cert.Subject
		}
	)
}
$params | ConvertTo-Json | Set-Clipboard

On the client with Graph PowerShell, run:

$app = Get-MgApplication -Filter "displayName eq 'Patch My PC - Intune Connector'"

$params = @{}
$customObject = Get-Clipboard | ConvertFrom-Json
$customObject.PSObject.Properties | ForEach-Object {
    $params[$_.Name] = $_.Value
}
Update-MgApplication -ApplicationId $app.Id -BodyParameter $params

#>