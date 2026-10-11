BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    . "$root/Export-PasskeyToGitHubSecret.ps1"
    $key = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7'))
    $fixture = @{ credentialId = 'AQIDBA'; userHandle = 'BQYHCA'; userName = 'fixture@example.invalid'; privateKey = $key.ExportPkcs8PrivateKeyPem() }
    $key.Dispose()
    $registration = "$root/Register-GitHubPasskeyViaTAP.ps1"
}
Describe 'GitHub secret validation and atomicity boundaries' {
    BeforeEach {
        Mock Invoke-GitHubPasskeyCli {}
        $c = $fixture.Clone()
    }
    It 'maps exactly four established names with the private key last' {
        $result = Export-PasskeyToGitHubSecret -Credential $c -Repository 'test-owner/test-repo' -ConsumersPaused -Confirm:$false
        $result.Success | Should -BeTrue
        $result.Atomic | Should -BeFalse
        $result.SecretNames -join ',' | Should -Be 'PASSKEY_PRIVATE_CREDENTIAL_ID,PASSKEY_PRIVATE_USER_HANDLE,PASSKEY_PRIVATE_USER_PRINCIPAL_NAME,PASSKEY_PRIVATE_KEY'
        Should -Invoke Invoke-GitHubPasskeyCli -Times 6 -Exactly
        Should -Invoke Invoke-GitHubPasskeyCli -Times 1 -Exactly -ParameterFilter { $Arguments[0] -eq 'secret' -and $Arguments[2] -eq 'PASSKEY_PRIVATE_KEY' -and $InputText -ceq $fixture.privateKey -and $Arguments -notcontains $fixture.privateKey }
    }
    It 'accepts the registration PSCustomObject schema' {
        $result = Export-PasskeyToGitHubSecret -Credential ([pscustomobject]$c) -Repository 'test-owner/repo' -ConsumersPaused -Confirm:$false
        $result.Success | Should -BeTrue
    }
    It 'does nothing under WhatIf including preflight' {
        Export-PasskeyToGitHubSecret -Credential $c -Repository 'test-owner/repo' -ConsumersPaused -WhatIf
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
    }
    It 'requires explicit consumers-paused acknowledgement' {
        { Export-PasskeyToGitHubSecret -Credential $c -Repository 'test-owner/repo' -Confirm:$false } | Should -Throw '*Pause*'
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
    }
    It 'rejects malformed repository before any operation' -ForEach @('https://github.com/owner/repo','owner/repo/extra','owner/repo --evil','/repo','owner/..','owner/repo?x=1') {
        { Export-PasskeyToGitHubSecret -Credential $c -Repository $_ -ConsumersPaused -Confirm:$false } | Should -Throw
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
    }
    It 'validates every field before first operation' -ForEach @('credentialId','userHandle','userName','privateKey') {
        $c[$_] = ''
        { Export-PasskeyToGitHubSecret -Credential $c -Repository 'owner/repo' -ConsumersPaused -Confirm:$false } | Should -Throw
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly
    }
    It 'rejects wrong field types' {
        $c.userName = @('fixture@example.invalid')
        { Get-GitHubPasskeySecretValues $c } | Should -Throw '*string*'
    }
    It 'rejects noncanonical base64url' -ForEach @('A','AB','AA==','a b','a+b','AA/') {
        $c.userHandle = $_
        { Get-GitHubPasskeySecretValues $c } | Should -Throw
    }
    It 'rejects oversized values' {
        $c.userName = ('x' * 49153)
        { Get-GitHubPasskeySecretValues $c } | Should -Throw '*size*'
    }
    It 'rejects a public key and wrong curve' {
        $k = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve]::CreateFromValue('1.3.132.0.34'))
        try {
            $c.privateKey = $k.ExportPkcs8PrivateKeyPem()
            { Get-GitHubPasskeySecretValues $c } | Should -Throw '*P-256*'
            $c.privateKey = $k.ExportSubjectPublicKeyInfoPem()
            { Get-GitHubPasskeySecretValues $c } | Should -Throw '*P-256*'
        } finally { $k.Dispose() }
    }
    It 'stops after each failing write, reports names only, and never rolls back' -ForEach @(0,1,2,3) {
        $script:failAt = $_
        $script:writeCount = 0
        Mock Invoke-GitHubPasskeyCli {
            if ($Arguments[0] -eq 'secret') {
                if ($script:writeCount++ -eq $script:failAt) { throw 'DO_NOT_LEAK_RAW_PROCESS_ERROR' }
            }
        }
        $caught = $null
        try { Export-PasskeyToGitHubSecret -Credential $c -Repository 'owner/repo' -ConsumersPaused -Confirm:$false } catch { $caught = $_ }
        $caught | Should -Not -BeNullOrEmpty
        $caught.Exception.Message | Should -Match 'Failed or unknown'
        $caught.Exception.Message | Should -Not -Match 'DO_NOT_LEAK|BEGIN PRIVATE|fixture@'
        $script:writeCount | Should -Be ($script:failAt + 1)
        Should -Invoke Invoke-GitHubPasskeyCli -Times 0 -Exactly -ParameterFilter { $Arguments -contains 'delete' }
    }
    It 'does not expose credential contents in successful results' {
        $result = Export-PasskeyToGitHubSecret -Credential $c -Repository 'owner/repo' -ConsumersPaused -Confirm:$false | ConvertTo-Json -Depth 10
        $result | Should -Not -Match 'BEGIN PRIVATE|fixture@|AQIDBA|BQYHCA'
    }
}
Describe 'Registration dry-run and trust boundaries' {
    BeforeAll {
        $text = Get-Content $registration -Raw
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
        $f = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-RegistrationUri' }, $true)
        . ([scriptblock]::Create($f.Extent.Text))
        $verifyFunction = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-RegistrationVerified' }, $true)
        . ([scriptblock]::Create($verifyFunction.Extent.Text))
    }
    It 'rejects untrusted endpoint origins' -ForEach @('http://login.microsoftonline.com/x','https://login.microsoftonline.com.evil.invalid/x','https://login.microsoftonline.com:444/x','https://user@login.microsoftonline.com/x','https://evil.invalid/x') {
        { Assert-RegistrationUri $_ } | Should -Throw
    }
    It 'accepts the three pinned HTTPS origins' -ForEach @('https://login.microsoftonline.com/common/login','https://login.microsoft.com/tenant/fido/create','https://mysignins.microsoft.com/api/session/authorize') {
        { Assert-RegistrationUri $_ } | Should -Not -Throw
    }
    It 'has no plaintext credential-file write or inherited console dumps' {
        $text | Should -Not -Match 'Set-Content|Out-File|Write-Host|OutputPath'
    }
    It 'WhatIf returns before gh, HTTP and key generation' {
        # Executed in a child scope. Invalid gh PATH is intentionally irrelevant for preview.
        $output = & $registration -TAP (ConvertTo-SecureString 'synthetic-test-only' -AsPlainText -Force) -UserPrincipalName 'fixture@example.invalid' -TenantId '11111111-1111-1111-1111-111111111111' -Repository 'owner/repo' -ConsumersPaused -AllowLegacySoftwareAttestation -WhatIf
        $output | Should -BeNullOrEmpty
    }
    It 'requires legacy-attestation opt-in even for preview' {
        { & $registration -TAP (ConvertTo-SecureString 'synthetic-test-only' -AsPlainText -Force) -UserPrincipalName 'fixture@example.invalid' -TenantId '11111111-1111-1111-1111-111111111111' -Repository 'owner/repo' -ConsumersPaused -WhatIf } | Should -Throw '*AllowLegacySoftwareAttestation*'
    }
}

Describe 'Registration success must bind the new credential' {
    BeforeAll {
        $text = Get-Content $registration -Raw
        $tokens = $null; $errors = $null
        $ast = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
        $f = $ast.Find({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-RegistrationVerified' }, $true)
        . ([scriptblock]::Create($f.Extent.Text))
    }
    BeforeEach { $response = @{ VerificationState = 2; ErrorCode = 0; DataUpdates = @{ FidoDevices = @{ CredentialId = 'AQIDBA' } } } }
    It 'accepts successful bound verification' { { Assert-RegistrationVerified 200 $response 'AQIDBA' } | Should -Not -Throw }
    It 'rejects HTTP errors even with success body' { { Assert-RegistrationVerified 400 $response 'AQIDBA' } | Should -Throw }
    It 'rejects nonzero protocol error even with success state' { $response.ErrorCode = 1; { Assert-RegistrationVerified 200 $response 'AQIDBA' } | Should -Throw }
    It 'rejects mismatched credential' { { Assert-RegistrationVerified 200 $response 'BQYHCA' } | Should -Throw }
    It 'rejects missing credential binding' { $response.DataUpdates = @{}; { Assert-RegistrationVerified 200 $response 'AQIDBA' } | Should -Throw }
    It 'rejects ambiguous multi-credential binding' { $response.DataUpdates.FidoDevices = @(@{CredentialId='AQIDBA'},@{CredentialId='BQYHCA'}); { Assert-RegistrationVerified 200 $response 'AQIDBA' } | Should -Throw }
    It 'rejects pending verification' { $response.VerificationState=1; { Assert-RegistrationVerified 200 $response 'AQIDBA' } | Should -Throw }
}
