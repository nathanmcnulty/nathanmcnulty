BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\Initialize-GSATLSInspection.ps1'
    $scriptText = [System.IO.File]::ReadAllText($scriptPath)
    $tokens = $null
    $parseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)

    foreach ($name in 'Write-Info', 'Write-Success', 'ConvertTo-Base64Url', 'ConvertFrom-Base64Url', 'Get-DerLength', 'New-SignedCertificateFromCSR', 'New-CrlFromKeyVault', 'Get-VerifiedCrlInfo') {
        $functionAst = $scriptAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true) | Select-Object -First 1
        Invoke-Expression $functionAst.Extent.Text
    }

    function Write-Info { param([string]$Message) }
    function Write-Success { param([string]$Message) }
    function Get-KeyVaultToken { 'offline-test-token' }
}

Describe 'Initialize-GSATLSInspection static safety contract' {
    It 'parses without errors' {
        $parseErrors | Should -HaveCount 0
    }

    It 'requires only the intended modules' {
        $scriptText | Should -Match '#Requires -Modules Microsoft\.Graph\.Authentication, Az\.Accounts'
        $scriptText | Should -Not -Match 'Az\.Resources|Az\.KeyVault|Get-AzADUser|Get-AzADServicePrincipal|Remove-AzResourceGroup'
    }

    It 'enforces an HSM-backed root and disables Storage Shared Key' {
        $scriptText | Should -Match 'kty = "RSA-HSM"'
        $scriptText | Should -Match 'allowSharedKeyAccess = \$false'
        $scriptText | Should -Not -Match 'listKeys\?api-version|SharedKey \$\{StorageAccountName\}'
    }

    It 'uses the least constrained compatible CA hierarchy' {
        $scriptText | Should -Match 'basic_constraints = @\{ ca = \$true \}'
        $scriptText | Should -Match '\$true,\s+# hasPathLengthConstraint\s+1,\s+# one non-self-issued intermediate CA may follow'
    }

    It 'enables the uploaded GSA certificate without deleting an active certificate' {
        $scriptText | Should -Match "status\s*=\s*'enabled'"
        $scriptText | Should -Match "Enable GSA TLS certificate"
        $scriptText | Should -Match 'include-unknown-enum-members'
        $scriptText | Should -Not -Match 'Delete existing active GSA certificate'
        $scriptText | Should -Match 'Delete pending GSA certificate'
    }

    It 'targets modern Intune platforms and excludes Android Device Administrator' {
        $scriptText | Should -Match '#microsoft\.graph\.androidDeviceOwnerTrustedRootCertificate'
        $scriptText | Should -Match '#microsoft\.graph\.androidWorkProfileTrustedRootCertificate'
        $scriptText | Should -Match '#microsoft\.graph\.aospDeviceOwnerTrustedRootCertificate'
        $scriptText | Should -Not -Match '#microsoft\.graph\.androidTrustedRootCertificate'
    }

    It 'publishes and verifies the CRL before creating a GSA CSR' {
        $scriptText.IndexOf('# Generate and upload CRL') | Should -BeLessThan $scriptText.IndexOf('Global Secure Access Certificate')
        $scriptText | Should -Match 'Refusing to continue with a certificate containing this CDP'
    }

    It 'returns before mutation when WhatIf is requested' {
        $scriptText.IndexOf('WhatIf deployment plan') | Should -BeLessThan $scriptText.IndexOf('Step $($stepNum): Resource Group')
    }

    It 'configures static website through Blob REST with Microsoft Entra authorization' {
        $scriptText | Should -Match 'restype=service&comp=properties'
        $scriptText | Should -Match 'Authorization = "Bearer \$storageToken"'
        $scriptText | Should -Not -Match 'properties = @\{ staticWebsite'
    }

    It 'avoids unsupported combined Azure RBAC filters' {
        $scriptText | Should -Not -Match '\$filter=principalId eq .* and roleDefinitionId eq'
    }

    It 'preserves the Graph transitional unknownFutureValue state' {
        $scriptText | Should -Match "'unknownFutureValue'"
        $scriptText | Should -Match '\$pending\.status -eq ''unknownFutureValue'''
        $scriptText | Should -Match '-not \$pending\.certificateSigningRequest'
    }
}

Describe 'Offline Key Vault signing reconstruction' {
    BeforeEach {
        $script:issuerKey = [System.Security.Cryptography.RSA]::Create(4096)
        function Invoke-RestMethod {
            param($Uri, $Method, $Headers, $Body, $ContentType)
            $request = $Body | ConvertFrom-Json
            $hash = ConvertFrom-Base64Url $request.value
            $signature = $script:issuerKey.SignHash(
                $hash,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            [PSCustomObject]@{ value = ConvertTo-Base64Url $signature }
        }

        $rootRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Offline Test Root',
            $script:issuerKey,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $rootRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
        )
        $rootUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature
        $rootRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($rootUsage, $true)
        )
        $rootRequest.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($rootRequest.PublicKey, $false)
        )
        $script:rootCertificate = $rootRequest.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddDays(-1),
            [DateTimeOffset]::UtcNow.AddYears(10)
        )
        $script:childKey = [System.Security.Cryptography.RSA]::Create(2048)
    }

    AfterEach {
        $script:childKey.Dispose()
        $script:rootCertificate.Dispose()
        $script:issuerKey.Dispose()
    }

    It 'builds a verifiable GSA CA with pathLen 1, serverAuth, and a CDP' {
        $childRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=GSA Offline Test,O=Contoso',
            $script:childKey,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $issued = New-SignedCertificateFromCSR `
            -CsrPem $childRequest.CreateSigningRequestPem() `
            -IssuerCert $script:rootCertificate `
            -KeyVaultKeyId 'https://offline.test/keys/root/version' `
            -CrlDistributionPointUrl 'http://crl.example.test/gsa.crl' `
            -NotAfter ([DateTimeOffset]::UtcNow.AddYears(5))

        $basic = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension](
            $issued.Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' }
        )
        $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension](
            $issued.Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
        )

        $basic.CertificateAuthority | Should -BeTrue
        $basic.HasPathLengthConstraint | Should -BeTrue
        $basic.PathLengthConstraint | Should -Be 1
        @($eku.EnhancedKeyUsages.Value) | Should -Contain '1.3.6.1.5.5.7.3.1'
        @($issued.Certificate.Extensions.Oid.Value) | Should -Contain '2.5.29.31'
    }

    It 'builds a signed CRL with a large monotonic CRL number' {
        $crl = New-CrlFromKeyVault `
            -IssuerCert $script:rootCertificate `
            -KeyVaultKeyId 'https://offline.test/keys/root/version' `
            -CrlNumber ([System.Numerics.BigInteger]::new(1234567890123)) `
            -NextUpdate ([DateTimeOffset]::UtcNow.AddDays(30))

        $crl.Length | Should -BeGreaterThan 500
        $crl[0] | Should -Be 0x30
    }

    It 'gives the intermediate and CRL the same five-year expiry' {
        $childRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=GSA Lifetime Test', $script:childKey,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        $rootCertInfo = @{ Certificate = $script:rootCertificate }
        $crlOnly = $false
        $start = $scriptText.IndexOf('# Generate and upload CRL')
        $end = $scriptText.IndexOf('# Resolve the existing publication', $start)
        . ([scriptblock]::Create($scriptText.Substring($start, $end - $start)))
        $expiry = $certificateNotAfter
        $issued = New-SignedCertificateFromCSR -CsrPem $childRequest.CreateSigningRequestPem() `
            -IssuerCert $script:rootCertificate -KeyVaultKeyId 'https://offline.test/keys/root/version' -NotAfter $expiry
        try {
            $crl = New-CrlFromKeyVault -IssuerCert $script:rootCertificate `
                -KeyVaultKeyId 'https://offline.test/keys/root/version' -CrlNumber 2 -NextUpdate $expiry
            $info = Get-VerifiedCrlInfo -Bytes $crl -IssuerCert $script:rootCertificate
            $info.NextUpdate | Should -Be ([DateTimeOffset]::new($issued.Certificate.NotAfter.ToUniversalTime()))
            ($expiry - $info.NextUpdate).TotalSeconds | Should -BeLessThan 1
            $info.DaysRemaining | Should -BeGreaterThan 1824
        } finally { $issued.Certificate.Dispose() }
    }
}
