BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\Initialize-GSATLSInspection.ps1'
    $scriptText = [System.IO.File]::ReadAllText($scriptPath)
    $tokens = $null
    $parseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors) { throw "Target script has parse errors: $($parseErrors -join '; ')" }

    foreach ($name in @(
        'Write-Info', 'Write-Success', 'Write-StepHeader', 'ConvertTo-Base64Url', 'ConvertFrom-Base64Url',
        'Get-DerLength', 'Get-KeyVaultToken', 'Get-StorageToken', 'Invoke-AzRestMethodWithRetry',
        'Enable-KeyVaultPrivateEndpoint', 'Set-AzureStorageBlob', 'New-CrlFromKeyVault',
        'Get-GraphCollection', 'Assert-GsaCertificateRoot', 'Get-KeyVaultCertificatePem', 'Get-CrlBlob',
        'Get-VerifiedCrlInfo', 'Assert-PublishedCrl', 'New-IntuneTrustedRootCertPolicy',
        'Assert-KeyVaultRootCertificate'
    )) {
        $functionAst = $scriptAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true) | Select-Object -First 1
        if (-not $functionAst) { throw "Required function '$name' was not found." }
        $functionText = $functionAst.Extent.Text
        if ($name -eq 'Enable-KeyVaultPrivateEndpoint') {
            # The production helper uses DNS. Substitute loopback only in this AST-loaded
            # test copy so rollback coverage remains deterministic and offline.
            $functionText = $functionText.Replace(
                '[System.Net.Dns]::GetHostAddresses("$VaultName.vault.azure.net") | ForEach-Object IPAddressToString',
                '[System.Net.IPAddress]::Loopback | ForEach-Object IPAddressToString'
            )
        }
        Invoke-Expression $functionText
    }

    function New-TestRoot {
        param(
            [string]$Subject,
            [double]$ValidityDays = 365
        )

        $key = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $Subject,
            $key,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $usage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($usage, $true)
        )
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false)
        )

        [PSCustomObject]@{
            Key = $key
            Certificate = $request.CreateSelfSigned(
                [DateTimeOffset]::UtcNow.AddMinutes(-5),
                [DateTimeOffset]::UtcNow.AddDays($ValidityDays)
            )
        }
    }

    function New-TestIssuedCertificate {
        param([Parameter(Mandatory)]$Issuer)

        $key = [System.Security.Cryptography.RSA]::Create(2048)
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=GSA Test Intermediate',
            $key,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $true, 1, $true)
        )
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
                [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign,
                $true
            )
        )
        $generator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA(
            $Issuer.Key,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        try {
            $certificate = $request.Create(
                $Issuer.Certificate.SubjectName,
                $generator,
                [DateTimeOffset]::UtcNow.AddMinutes(-5),
                [DateTimeOffset]::UtcNow.AddDays(90),
                [byte[]](1..16)
            )
        } finally {
            $key.Dispose()
        }

        $base64 = [Convert]::ToBase64String($certificate.RawData, 'InsertLineBreaks') -replace "`r`n", "`n"
        [PSCustomObject]@{
            Certificate = $certificate
            Pem = "-----BEGIN CERTIFICATE-----`n$base64`n-----END CERTIFICATE-----"
        }
    }

    $mainStart = $scriptText.IndexOf('#region Main Script')
    if ($mainStart -lt 0) { throw 'Main script region was not found.' }
    $mainFlowStart = $scriptText.IndexOf('$stepNum = 1', $mainStart)
    if ($mainFlowStart -lt 0) { throw 'Main flow was not found.' }
    # Module/version checks are separate static requirements. Execute the actual
    # main flow from its first state mutation so mocked lifecycle tests stay fast.
    $script:mainScriptText = $scriptText.Substring($mainFlowStart)
    $crlSelectionStart = $scriptText.IndexOf('# Generate and upload CRL')
    $crlSelectionEnd = $scriptText.IndexOf('$storageUrl =', $crlSelectionStart)
    if ($crlSelectionStart -lt 0 -or $crlSelectionEnd -lt $crlSelectionStart) { throw 'CRL selection block was not found.' }
    $script:crlSelectionText = $scriptText.Substring($crlSelectionStart, $crlSelectionEnd - $crlSelectionStart)

    function Invoke-TestRenewalMain {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter(Mandatory)][string]$SubscriptionId,
            [AllowEmptyString()][string]$KeyVaultName,
            [AllowEmptyString()][string]$StorageAccountName,
            [string]$ResourceGroupName = 'rg-gsa-tls',
            [string]$RootCertificateName = 'gsa-tls-root-ca',
            [bool]$CrlOnlyMode = $true
        )

        $ErrorActionPreference = 'Stop'
        $KeyVaultSKU = 'Premium'
        $Location = 'eastus'
        $OrganizationName = 'Contoso'
        $CertificateCommonName = 'GSA Test Root'
        $RenewCrlOnly = $CrlOnlyMode
        $CrlStatusOnly = $false
        $RotateGsaCertificate = $false
        $EnableGsaCertificate = $false
        $AssignIntunePolicies = $false
        $EnablePrivateEndpoint = $false
        $EnableDefender = $false
        $LogAnalyticsWorkspaceId = $null
        $Force = $false
        $CrlHostname = $null
        $IntunePlatforms = @('Windows')
        $crlOnly = $RenewCrlOnly -or $CrlStatusOnly
        $readExisting = $crlOnly -or $EnableGsaCertificate

        Invoke-Expression $script:mainScriptText
    }

    function Invoke-TestCrlSelection {
        param(
            [Parameter(Mandatory)][hashtable]$RootInfo,
            [Parameter(Mandatory)][string]$StorageAccountName,
            [bool]$ReadExisting = $false
        )

        $rootCertInfo = $RootInfo
        $readExisting = $ReadExisting
        Invoke-Expression $script:crlSelectionText
        [PSCustomObject]@{
            FileName = $crlFileName
            ExistingCrl = $existingCrl
            PreviousCrlInfo = $previousCrlInfo
        }
    }
}

Describe 'Initialize-GSATLSInspection lifecycle safeguards' {
    It 'rejects a GSA certificate that chains to another root' {
        $expectedRoot = New-TestRoot -Subject 'CN=Expected Root'
        $otherRoot = New-TestRoot -Subject 'CN=Other Root'
        $gsaCertificate = New-TestIssuedCertificate -Issuer $otherRoot
        try {
            {
                Assert-GsaCertificateRoot -GsaCertificate @{ id = 'gsa-test'; certificate = $gsaCertificate.Pem } -Root $expectedRoot.Certificate
            } | Should -Throw '*does not validate to root*'
        } finally {
            $gsaCertificate.Certificate.Dispose()
            $expectedRoot.Certificate.Dispose()
            $expectedRoot.Key.Dispose()
            $otherRoot.Certificate.Dispose()
            $otherRoot.Key.Dispose()
        }
    }

    It 'keeps an existing different-root Intune profile and creates a thumbprint-scoped replacement' {
        $oldRoot = New-TestRoot -Subject 'CN=Old Root'
        $newRoot = New-TestRoot -Subject 'CN=New Root'
        $oldRootBase64 = [Convert]::ToBase64String($oldRoot.Certificate.RawData)
        $newRootBase64 = [Convert]::ToBase64String($newRoot.Certificate.RawData)
        $baseName = 'GSA TLS Root Certificate - Windows'
        $existing = [PSCustomObject]@{
            id = 'old-policy'
            displayName = $baseName
            trustedRootCertificate = $oldRootBase64
            '@odata.type' = '#microsoft.graph.windows81TrustedRootCertificate'
        }
        $script:graphUris = @()
        $script:createdPolicy = $null

        Mock Get-GraphCollection {
            param([string]$Uri)
            $script:graphUris += $Uri
            if ($Uri -match [regex]::Escape($newRoot.Certificate.Thumbprint)) { return @() }
            return @($existing)
        }
        Mock Invoke-MgGraphRequest {
            param($Method, $Uri, $Body, $ContentType)
            if ($Method -ne 'POST') { throw "Unexpected Graph write: $Method $Uri" }
            $script:createdPolicy = $Body | ConvertFrom-Json
            [PSCustomObject]@{ id = 'new-policy' }
        }

        try {
            $result = New-IntuneTrustedRootCertPolicy -Platform Windows -RootCertBase64 $newRootBase64 -AssignToAllDevices $false

            $result | Should -Be 'new-policy'
            $script:createdPolicy.displayName | Should -Be "$baseName - $($newRoot.Certificate.Thumbprint)"
            $script:createdPolicy.trustedRootCertificate | Should -Be $newRootBase64
            $existing.trustedRootCertificate | Should -Be $oldRootBase64
            Assert-MockCalled Invoke-MgGraphRequest -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' }
            Assert-MockCalled Invoke-MgGraphRequest -Times 0 -Exactly -ParameterFilter { $Method -eq 'PATCH' }
        } finally {
            $oldRoot.Certificate.Dispose()
            $oldRoot.Key.Dispose()
            $newRoot.Certificate.Dispose()
            $newRoot.Key.Dispose()
        }
    }

    It 'requires a preexisting matching Intune profile without issuing Graph writes' {
        $root = New-TestRoot -Subject 'CN=Stage Root'
        $rootBase64 = [Convert]::ToBase64String($root.Certificate.RawData)
        Mock Get-GraphCollection { @() }
        Mock Invoke-MgGraphRequest { throw 'Graph writes are forbidden in RequireExisting mode.' }

        try {
            {
                New-IntuneTrustedRootCertPolicy -Platform Windows -RootCertBase64 $rootBase64 -AssignToAllDevices $false -RequireExisting
            } | Should -Throw '*Stage and deploy*'
            Assert-MockCalled Invoke-MgGraphRequest -Times 0 -Exactly
        } finally {
            $root.Certificate.Dispose()
            $root.Key.Dispose()
        }
    }

    It 'rejects a public endpoint that returns an HTML response instead of the CRL' {
        Mock Start-Sleep {}
        Mock Invoke-WebRequest {
            [PSCustomObject]@{
                StatusCode = 200
                Headers = @{ 'Content-Type' = 'text/html; charset=utf-8' }
                RawContentStream = [System.IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes('<html>not a CRL</html>'))
            }
        }

        { Assert-PublishedCrl -Uri 'http://crl.example.test/root.crl' -ExpectedBytes ([byte[]](1, 2, 3)) } |
            Should -Throw '*exact published CRL*'
    }

    It 'rejects a public endpoint whose CRL bytes differ despite the expected content type' {
        Mock Start-Sleep {}
        Mock Invoke-WebRequest {
            [PSCustomObject]@{
                StatusCode = 200
                Headers = @{ 'Content-Type' = 'application/pkix-crl' }
                RawContentStream = [System.IO.MemoryStream]::new([byte[]](9, 8, 7))
            }
        }

        { Assert-PublishedCrl -Uri 'http://crl.example.test/root.crl' -ExpectedBytes ([byte[]](1, 2, 3)) } |
            Should -Throw '*exact published CRL*'
    }

    It 'permits a currently valid near-expiry root for CRL renewal but not certificate issuance' {
        $root = New-TestRoot -Subject 'CN=Renewal Root' -ValidityDays 30
        Mock Get-KeyVaultToken { 'test-token' }
        Mock Invoke-RestMethod { [PSCustomObject]@{ key = [PSCustomObject]@{ kty = 'RSA-HSM' } } }
        $certificateInfo = @{ Certificate = $root.Certificate; KeyId = 'https://vault.test/keys/root/version' }

        try {
            { Assert-KeyVaultRootCertificate -CertificateInfo $certificateInfo -ExpectedKeyType 'RSA-HSM' -ForCrl } | Should -Not -Throw
            { Assert-KeyVaultRootCertificate -CertificateInfo $certificateInfo -ExpectedKeyType 'RSA-HSM' } | Should -Throw '*expires too soon*'
        } finally {
            $root.Certificate.Dispose()
            $root.Key.Dispose()
        }
    }

    It 'caps CRL nextUpdate at the root expiry' {
        $root = New-TestRoot -Subject 'CN=Short CRL Root' -ValidityDays 0.02
        $script:crlSigningKey = $root.Key
        Mock Get-KeyVaultToken { 'test-token' }
        Mock Invoke-RestMethod {
            param($Uri, $Method, $Headers, $Body, $ContentType)
            $request = $Body | ConvertFrom-Json
            $hash = ConvertFrom-Base64Url $request.value
            $signature = $script:crlSigningKey.SignHash(
                $hash,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            [PSCustomObject]@{ value = ConvertTo-Base64Url $signature }
        }

        try {
            $crl = New-CrlFromKeyVault -IssuerCert $root.Certificate -KeyVaultKeyId 'https://vault.test/keys/root/version' -CrlNumber 42 -NextUpdate ([DateTimeOffset]::UtcNow.AddDays(30))
            $info = Get-VerifiedCrlInfo -Bytes $crl -IssuerCert $root.Certificate

            $info.NextUpdate | Should -BeLessOrEqual ([DateTimeOffset]::new($root.Certificate.NotAfter.ToUniversalTime()))
            $info.NextUpdate | Should -BeGreaterThan $info.ThisUpdate
        } finally {
            $root.Certificate.Dispose()
            $root.Key.Dispose()
        }
    }

    It 'uses the supplied ETag for a conditional CRL overwrite' {
        $script:storageHeaders = $null
        Mock Get-StorageToken { 'storage-token' }
        Mock Invoke-RestMethod {
            param($Uri, $Method, $Headers, $Body, $ContentType)
            $script:storageHeaders = @{} + $Headers
        }

        Set-AzureStorageBlob -StorageAccountName 'examplestorage' -ContainerName '$web' -BlobName 'root.crl' `
            -Content ([byte[]](1, 2, 3)) -ContentType 'application/pkix-crl' -ETag '"0x8DABC"'

        $script:storageHeaders['If-Match'] | Should -Be '"0x8DABC"'
        $script:storageHeaders.ContainsKey('If-None-Match') | Should -BeFalse
    }

    It 'stops after the subscription switch when the selected Azure tenant differs from Graph' {
        $script:azContextCalls = 0
        $script:resourceAccessed = $false
        Mock Get-MgContext {
            [PSCustomObject]@{
                Account = 'admin@contoso.test'
                TenantId = 'graph-tenant'
                Scopes = @('NetworkAccess.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All')
            }
        }
        Mock Get-AzContext {
            $script:azContextCalls++
            [PSCustomObject]@{
                Account = [PSCustomObject]@{ Id = 'admin@contoso.test' }
                Tenant = [PSCustomObject]@{ Id = if ($script:azContextCalls -eq 1) { 'graph-tenant' } else { 'selected-tenant' } }
                Subscription = [PSCustomObject]@{ Id = if ($script:azContextCalls -eq 1) { 'initial-subscription' } else { 'selected-subscription' }; Name = 'Test subscription' }
            }
        }
        Mock Set-AzContext {}
        Mock Invoke-AzRestMethod {
            $script:resourceAccessed = $true
            throw 'Resource access must not occur after a tenant mismatch.'
        }

        {
            Invoke-TestRenewalMain -SubscriptionId 'selected-subscription' -KeyVaultName 'kvtestroot' -StorageAccountName 'satestcrl' -CrlOnlyMode:$false
        } | Should -Throw '*does not match Azure tenant*'

        $script:azContextCalls | Should -Be 2
        $script:resourceAccessed | Should -BeFalse
    }

    It 'refuses unnamed setup in an existing resource group before any create or name-availability request' {
        $script:azureMethods = @()
        Mock Get-MgContext {
            [PSCustomObject]@{
                Account = 'admin@contoso.test'
                TenantId = 'tenant-test'
                Scopes = @('NetworkAccess.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All')
            }
        }
        Mock Get-AzContext {
            [PSCustomObject]@{
                Account = [PSCustomObject]@{ Id = 'admin@contoso.test' }
                Tenant = [PSCustomObject]@{ Id = 'tenant-test' }
                Subscription = [PSCustomObject]@{ Id = 'subscription-test'; Name = 'Test subscription' }
            }
        }
        Mock Set-AzContext {}
        Mock Invoke-AzRestMethod {
            param($Method, $Path, $Payload)
            $script:azureMethods += $Method
            if ($Method -ne 'GET') { throw "Unexpected setup mutation: $Method $Path" }
            if ($Path -match '/resourceGroups/rg-test/resources\?') {
                $resources = @{ value = @(@{ type = 'Microsoft.KeyVault/vaults'; name = 'existing-vault' }) } | ConvertTo-Json -Depth 5
                return [PSCustomObject]@{ StatusCode = 200; Content = $resources }
            }
            throw "Unexpected Azure resource access: $Path"
        }
        Mock Invoke-MgGraphRequest { throw 'The existing-resource guard must run before Graph mutation.' }

        {
            Invoke-TestRenewalMain -SubscriptionId 'subscription-test' -KeyVaultName '' -StorageAccountName '' -ResourceGroupName 'rg-test' -CrlOnlyMode:$false
        } | Should -Throw '*Supply both -KeyVaultName and -StorageAccountName*'

        $script:azureMethods | Should -HaveCount 1
        $script:azureMethods[0] | Should -Be 'GET'
        Assert-MockCalled Invoke-MgGraphRequest -Times 0 -Exactly
    }

    It 'restores disabled-deny Key Vault settings and preserves unrelated ACL fields after private validation fails' {
        $vaultName = 'localhost'
        $resolvedIp = '127.0.0.1'
        $vaultConfiguration = @{
            properties = @{
                publicNetworkAccess = 'Disabled'
                networkAcls = @{
                    defaultAction = 'Deny'
                    bypass = 'None'
                    ipRules = @(@{ value = '10.20.30.0/24'; action = 'Allow' })
                    virtualNetworkRules = @(@{ id = '/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/private'; action = 'Allow' })
                }
            }
        } | ConvertTo-Json -Depth 10
        $endpointConfiguration = @{
            properties = @{
                provisioningState = 'Succeeded'
                privateLinkServiceConnections = @(@{ properties = @{ privateLinkServiceConnectionState = @{ status = 'Approved' } } })
                customDnsConfigs = @(@{ ipAddresses = @($resolvedIp) })
            }
        } | ConvertTo-Json -Depth 10
        $script:networkPatches = @()

        Mock Start-Sleep {}
        Mock Get-KeyVaultToken { 'test-token' }
        Mock Invoke-AzRestMethod {
            param($Method, $Path, $Payload)
            if ($Path -like '*privateDnsZoneGroups*') { return [PSCustomObject]@{ StatusCode = 200; Content = '{}' } }
            if ($Path -like '*privateEndpoints*') { return [PSCustomObject]@{ StatusCode = 200; Content = $endpointConfiguration } }
            if ($Path -like '*Microsoft.KeyVault/vaults*') { return [PSCustomObject]@{ StatusCode = 200; Content = $vaultConfiguration } }
            throw "Unexpected Azure REST read: $Method $Path"
        }
        Mock Invoke-AzRestMethodWithRetry {
            param($Method, $Uri, $Payload)
            $script:networkPatches += ($Payload | ConvertFrom-Json)
            [PSCustomObject]@{ StatusCode = 200; Content = '{}' }
        }
        Mock Invoke-RestMethod { throw 'Private data-plane access was deliberately rejected.' }

        {
            Enable-KeyVaultPrivateEndpoint -SubscriptionId 'test' -ResourceGroupName 'rg' -Location 'eastus' -VaultName $vaultName `
                -SubnetId '/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/private' `
                -PrivateDnsZoneId '/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net'
        } | Should -Throw '*original network settings were restored*'

        $script:networkPatches | Should -HaveCount 2
        $rollback = $script:networkPatches[1]
        $rollback.properties.publicNetworkAccess | Should -Be 'Disabled'
        $rollback.properties.networkAcls.defaultAction | Should -Be 'Deny'
        $rollback.properties.networkAcls.bypass | Should -Be 'None'
        $rollback.properties.networkAcls.ipRules[0].value | Should -Be '10.20.30.0/24'
        $rollback.properties.networkAcls.virtualNetworkRules[0].id | Should -Match '/subnets/private$'
    }

    It 'selects a root-scoped CRL path instead of a legacy CRL signed by another root' {
        $legacyRoot = New-TestRoot -Subject 'CN=Legacy Root'
        $newRoot = New-TestRoot -Subject 'CN=Replacement Root'
        $script:crlSigningKey = $legacyRoot.Key
        Mock Get-KeyVaultToken { 'test-token' }
        Mock Invoke-RestMethod {
            param($Uri, $Method, $Headers, $Body, $ContentType)
            $hash = ConvertFrom-Base64Url (($Body | ConvertFrom-Json).value)
            $signature = $script:crlSigningKey.SignHash(
                $hash,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            [PSCustomObject]@{ value = ConvertTo-Base64Url $signature }
        }

        try {
            $legacyCrl = New-CrlFromKeyVault -IssuerCert $legacyRoot.Certificate -KeyVaultKeyId 'https://vault.test/keys/legacy/version' -CrlNumber 1 -NextUpdate ([DateTimeOffset]::UtcNow.AddDays(30))
            $newRootInfo = @{
                Certificate = $newRoot.Certificate
                Thumbprint = $newRoot.Certificate.Thumbprint
            }
            Mock Get-CrlBlob {
                param($StorageAccountName, $BlobName)
                if ($BlobName -eq 'gsa-tls-root-ca.crl') { return @{ Bytes = $legacyCrl; ETag = '"legacy-etag"' } }
                return $null
            }
            Mock Set-AzureStorageBlob { throw 'The CRL selection block must not overwrite storage.' }

            $selection = Invoke-TestCrlSelection -RootInfo $newRootInfo -StorageAccountName 'satestcrl'

            $selection.FileName | Should -Be "gsa-tls-root-ca-$($newRoot.Certificate.Thumbprint.ToLowerInvariant()).crl"
            $selection.ExistingCrl | Should -BeNullOrEmpty
            Assert-MockCalled Get-CrlBlob -Times 2 -Exactly
            Assert-MockCalled Set-AzureStorageBlob -Times 0 -Exactly
        } finally {
            $legacyRoot.Certificate.Dispose()
            $legacyRoot.Key.Dispose()
            $newRoot.Certificate.Dispose()
            $newRoot.Key.Dispose()
        }
    }

    It 'renews a verified legacy CRL without infrastructure, RBAC, or Graph writes' {
        $root = New-TestRoot -Subject 'CN=Legacy Renewal Root' -ValidityDays 3650
        $rootBase64 = [Convert]::ToBase64String($root.Certificate.RawData)
        $rootInfo = @{
            Certificate = $root.Certificate
            Pem = "-----BEGIN CERTIFICATE-----`n$rootBase64`n-----END CERTIFICATE-----"
            Thumbprint = $root.Certificate.Thumbprint
            Expiration = $root.Certificate.NotAfter
            KeyId = 'https://vault.test/keys/root/version'
        }
        $script:crlSigningKey = $root.Key
        Mock Get-KeyVaultToken { 'test-token' }
        Mock Invoke-RestMethod {
            param($Uri, $Method, $Headers, $Body, $ContentType)
            if ($Method -eq 'Get' -and $Uri -like '*certificates/gsa-tls-root-ca?api-version=7.5') {
                return [PSCustomObject]@{ x5t = $root.Certificate.Thumbprint }
            }
            if ($Method -ne 'POST') { throw "Unexpected REST operation: $Method $Uri" }
            $hash = ConvertFrom-Base64Url (($Body | ConvertFrom-Json).value)
            $signature = $script:crlSigningKey.SignHash(
                $hash,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            [PSCustomObject]@{ value = ConvertTo-Base64Url $signature }
        }

        try {
            $legacyCrl = New-CrlFromKeyVault -IssuerCert $root.Certificate -KeyVaultKeyId $rootInfo.KeyId -CrlNumber 7 -NextUpdate ([DateTimeOffset]::UtcNow.AddDays(30))
            $rgContent = @{ location = 'eastus' } | ConvertTo-Json
            $kvContent = @{ properties = @{ sku = @{ name = 'premium' }; enableRbacAuthorization = $true; enablePurgeProtection = $true; softDeleteRetentionInDays = 90; vaultUri = 'https://vault.test/' } } | ConvertTo-Json -Depth 8
            $saContent = @{ properties = @{ allowSharedKeyAccess = $false; allowBlobPublicAccess = $false; minimumTlsVersion = 'TLS1_2'; supportsHttpsTrafficOnly = $false; primaryEndpoints = @{ web = 'https://legacy.z1.web.core.windows.net/' }; customDomain = @{ name = $null } } } | ConvertTo-Json -Depth 8
            $script:azureMethods = @()
            $script:publishedBlob = $null
            $script:publishedETag = $null
            $script:publicationChecks = @()

            Mock Start-Sleep {}
            Mock Get-AzContext {
                [PSCustomObject]@{
                    Account = [PSCustomObject]@{ Id = 'admin@contoso.test' }
                    Tenant = [PSCustomObject]@{ Id = 'tenant-test' }
                    Subscription = [PSCustomObject]@{ Id = 'subscription-test'; Name = 'Test subscription' }
                }
            }
            Mock Set-AzContext {}
            Mock Invoke-AzRestMethod {
                param($Method, $Path, $Payload)
                $script:azureMethods += $Method
                if ($Method -ne 'GET') { throw "Renewal attempted infrastructure write: $Method $Path" }
                if ($Path -match '/Microsoft\.KeyVault/vaults/kvtestroot\?') { return [PSCustomObject]@{ StatusCode = 200; Content = $kvContent } }
                if ($Path -match '/Microsoft\.Storage/storageAccounts/satestcrl\?') { return [PSCustomObject]@{ StatusCode = 200; Content = $saContent } }
                if ($Path -match '/resourceGroups/rg-test\?') { return [PSCustomObject]@{ StatusCode = 200; Content = $rgContent } }
                throw "Unexpected Azure REST read: $Path"
            }
            Mock Get-KeyVaultCertificatePem { $rootInfo }
            Mock Assert-KeyVaultRootCertificate {}
            Mock Get-CrlBlob {
                param($StorageAccountName, $BlobName)
                if ($BlobName -eq 'gsa-tls-root-ca.crl') { return @{ Bytes = $legacyCrl; ETag = '"legacy-etag"' } }
                return $null
            }
            Mock Set-AzureStorageBlob {
                param($StorageAccountName, $ContainerName, $BlobName, $Content, $ContentType, $ETag)
                $script:publishedBlob = $BlobName
                $script:publishedETag = $ETag
            }
            Mock Assert-PublishedCrl {
                param($Uri, $ExpectedBytes)
                $script:publicationChecks += $Uri
            }
            Mock Invoke-MgGraphRequest { throw 'Renewal must not contact Graph.' }

            $result = Invoke-TestRenewalMain -SubscriptionId 'subscription-test' -KeyVaultName 'kvtestroot' -StorageAccountName 'satestcrl' -ResourceGroupName 'rg-test'

            $result.Operation | Should -Be 'RenewCrlOnly'
            $result.NextUpdate | Should -BeGreaterThan ([DateTimeOffset]::UtcNow.AddYears(5).AddMinutes(-1))
            $result.NextUpdate | Should -BeLessOrEqual ([DateTimeOffset]::UtcNow.AddYears(5))
            $script:azureMethods | Should -Not -Contain 'PUT'
            $script:azureMethods | Should -Not -Contain 'PATCH'
            $script:publishedBlob | Should -Be 'gsa-tls-root-ca.crl'
            $script:publishedETag | Should -Be '"legacy-etag"'
            $script:publicationChecks | Should -Contain 'http://legacy.z1.web.core.windows.net/gsa-tls-root-ca.crl'
            Assert-MockCalled Invoke-MgGraphRequest -Times 0 -Exactly
        } finally {
            $root.Certificate.Dispose()
            $root.Key.Dispose()
        }
    }
}
