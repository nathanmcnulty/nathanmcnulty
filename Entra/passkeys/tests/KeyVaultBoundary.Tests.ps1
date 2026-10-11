BeforeAll {
    $scriptText = Get-Content "$PSScriptRoot/../PasskeyLogin.ps1" -Raw
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($scriptText, [ref]$tokens, [ref]$errors)
    foreach ($function in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]}, $false)) {
        . ([scriptblock]::Create($function.Extent.Text))
    }
    $version = '0123456789abcdef0123456789abcdef'
    $keyId = "https://testvault.vault.azure.net/keys/test-key/$version"
}
Describe 'Key Vault target boundary' {
    It 'retains the registered version and matching metadata' {
        $r = Resolve-KeyVaultReference testvault test-key $keyId
        $r.keyId | Should -BeExactly $keyId
    }
    It 'supports existing manual name and URL-in-keyName inputs' {
        (Resolve-KeyVaultReference testvault test-key).keyId | Should -Be 'https://testvault.vault.azure.net/keys/test-key'
        (Resolve-KeyVaultReference testvault $keyId).keyId | Should -BeExactly $keyId
    }
    It 'rejects untrusted or ambiguous references: <Bad>' -ForEach @(
        @{ Bad='https://attacker.invalid/keys/test-key' },
        @{ Bad='http://testvault.vault.azure.net/keys/test-key' },
        @{ Bad='https://testvault.vault.azure.net.attacker.invalid/keys/test-key' },
        @{ Bad='https://testvault.vault.azure.net:444/keys/test-key' },
        @{ Bad='https://user@testvault.vault.azure.net/keys/test-key' },
        @{ Bad='https://testvault.vault.azure.net/keys/test-key?redirect=evil' },
        @{ Bad='https://testvault.vault.azure.net/keys/test-key#fragment' },
        @{ Bad='https://testvault.vault.azure.net/secrets/test-key' },
        @{ Bad='https://testvault.vault.azure.net/keys/../test-key' },
        @{ Bad='https://testvault.vault.azure.net/keys/%2e%2e/test-key' },
        @{ Bad='https://testvault.vault.azure.net/keys/test-key/' },
        @{ Bad='https://testvault.vault.azure.net/keys/test-key/not-a-version' },
        @{ Bad='https://testvault.vault.azure.net\keys\test-key' }
    ) {
        { Resolve-KeyVaultReference testvault test-key $Bad } | Should -Throw
    }
    It 'rejects conflicting vault or key metadata' {
        { Resolve-KeyVaultReference othervault test-key $keyId } | Should -Throw '*conflicts*'
        { Resolve-KeyVaultReference testvault other-key $keyId } | Should -Throw '*conflicts*'
    }
    It 'rejects invalid manual identifiers' {
        { Resolve-KeyVaultReference 'testvault.attacker.invalid/' test-key } | Should -Throw
        { Resolve-KeyVaultReference testvault '../test-key' } | Should -Throw
    }
    It 'signs only the stored version, does not follow redirects, and never signs latest' {
        Mock Invoke-RestMethod { @{value = ConvertTo-Base64Url ([byte[]]::new(64))} }
        $null = New-FidoSignature -Challenge dummy -Origin https://login.microsoft.com -AuthDataBytes ([byte[]]::new(37)) -KeyVaultInfo @{vaultName='testvault';keyName='test-key';keyId=$keyId} -KeyVaultToken 'offline-test-token'
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter {
            $Uri -ceq 'https://testvault.vault.azure.net/keys/test-key/0123456789abcdef0123456789abcdef/sign?api-version=7.4' -and $MaximumRedirection -eq 0
        }
    }
    It 'rejects a malicious helper input before HTTP' {
        Mock Invoke-RestMethod { throw 'Unexpected network' }
        { New-FidoSignature -Challenge dummy -Origin https://login.microsoft.com -AuthDataBytes ([byte[]]::new(37)) -KeyVaultInfo @{vaultName='testvault';keyName='test-key';keyId='https://attacker.invalid/keys/key'} -KeyVaultToken 'offline-test-token' } | Should -Throw '*Invalid Key Vault*'
        Should -Invoke Invoke-RestMethod -Times 0
    }
}
Describe 'Credential and token handling' {
    It 'accepts schema aliases and uint32 counters' {
        { Assert-CredentialData @{userPrincipalName='user@example.com'; credentialId='aWQ';userHandle='aGFuZGxl';keyValue='dummy';rpId='login.microsoft.com';counter=[long]4294967295} } | Should -Not -Throw
    }
    It 'rejects null, array, malformed fields, and invalid keyVault objects' {
        foreach ($invalid in @($null, @(), 'credential', @{credentialId=17}, @{userHandle=$null}, @{keyVault=$null}, @{keyVault=@{}}, @{keyVault=@{vaultName=@('testvault');keyName='key'}}, @{counter=-1}, @{counter='0'}, @{counter=1.5}, @{counter=[long]4294967296})) {
            { Assert-CredentialData $invalid } | Should -Throw
        }
    }
    It 'handles modern SecureString Az tokens without platform-dependent conversion' {
        function Get-AzAccessToken { param($ResourceUrl) }
        Mock Get-AzAccessToken { @{Token = ConvertTo-SecureString 'offline-token-abc' -AsPlainText -Force} }
        Get-KeyVaultToken | Should -BeExactly 'offline-token-abc'
        $scriptText | Should -Not -Match 'PtrToStringAuto'
        $scriptText | Should -Match 'ZeroFreeBSTR'
    }
    It 'does not expose exception or service body data in signing error logs' {
        $record = [Management.Automation.ErrorRecord]::new([Exception]::new('SECRET_PREFIX'), 'test', 'NotSpecified', $null)
        $record.ErrorDetails = [Management.Automation.ErrorDetails]::new('TOKEN_BODY')
        $message = Get-HttpErrorMessage $record
        $message | Should -Not -Match 'SECRET_PREFIX|TOKEN_BODY'
    }
    It 'rejects invalid credential files before token acquisition or HTTP' {
        $file = Join-Path $TestDrive invalid.json
        '{"username":"user@example.com","credentialId":"aWQ","userHandle":"aGFuZGxl","keyVault":{"vaultName":"testvault","keyName":"test-key","keyId":"https://attacker.invalid/keys/key"}}' | Set-Content $file
        Mock Invoke-RestMethod {throw 'Unexpected HTTP'}
        Mock Invoke-WebRequest {throw 'Unexpected HTTP'}
        { & "$PSScriptRoot/../PasskeyLogin.ps1" -KeyFilePath $file -KeyVaultAccessToken offline-token } | Should -Throw '*Invalid credential file*'
        Should -Invoke Invoke-RestMethod -Times 0
        Should -Invoke Invoke-WebRequest -Times 0
    }
}
Describe 'Cookie selection' {
    It 'ignores foreign domains, expired, insecure, and empty cookies' {
        $good = [Net.Cookie]::new('ESTSAUTHPERSISTENT','good','/','.login.microsoftonline.com'); $good.Secure=$true
        $foreign = [Net.Cookie]::new('ESTSAUTH','bad','/','attacker.invalid');$foreign.Secure=$true
        $expired = [Net.Cookie]::new('ESTSAUTH','expired','/','login.microsoftonline.com');$expired.Secure=$true;$expired.Expires=[datetime]::Now.AddDays(-1)
        $insecure = [Net.Cookie]::new('ESTSAUTH','insecure','/','login.microsoftonline.com')
        (Select-PreferredEstsCookie @($foreign,$expired,$insecure,$good)).Value | Should -BeExactly good
        Select-PreferredEstsCookie @($foreign,$expired,$insecure) | Should -BeNullOrEmpty
        Select-PreferredEstsCookie @() | Should -BeNullOrEmpty
    }
}
Describe 'Interrupt loop state' {
    It 'bounds repeated ConvergedSignIn through the complete function' {
        $context=@{Session=[Microsoft.PowerShell.Commands.WebRequestSession]::new();PageState=@{pgid='ConvergedSignIn';urlLogin='/common/login';sessionId='fixture'}}
        Mock Invoke-WebRequest { @{StatusCode=200;Content='{"pgid":"ConvergedSignIn","urlLogin":"/common/login","sessionId":"fixture"}'} }
        {Resolve-EntraLoginInterrupts -Context $context} | Should -Throw '*interrupt loop*'
        Should -Invoke Invoke-WebRequest -Times 10 -Exactly
    }
}
Describe 'AuthUrl validation before token acquisition' {
    It 'rejects off-origin URLs without any HTTP: <BadAuth>' -ForEach @(
        @{BadAuth='https://login.microsoftonlineXcom/common/oauth2/authorize?client_id=x&response_type=code&redirect_uri=x'},
        @{BadAuth='http://login.microsoftonline.com/common/oauth2/authorize?client_id=x&response_type=code&redirect_uri=x'},
        @{BadAuth='https://login.microsoftonline.com:444/common/oauth2/authorize?client_id=x&response_type=code&redirect_uri=x'},
        @{BadAuth='https://user@login.microsoftonline.com/common/oauth2/authorize?client_id=x&response_type=code&redirect_uri=x'}
    ) {
        Mock Invoke-RestMethod { throw 'Unexpected HTTP' }
        Mock Invoke-WebRequest { throw 'Unexpected HTTP' }
        { & "$PSScriptRoot/../PasskeyLogin.ps1" -UserName user@example.com -UserHandle aGFuZGxl -CredentialId aWQ -KeyVaultName testvault -KeyVaultKeyName key -KeyVaultAccessToken offline-token -AuthUrl $BadAuth -ErrorAction Continue 2>$null } | Should -Throw '*Invalid auth URL*'
        Should -Invoke Invoke-RestMethod -Times 0
        Should -Invoke Invoke-WebRequest -Times 0
    }
}
Describe 'Result output contract' {
    BeforeEach {
        $context=@{Session=[Microsoft.PowerShell.Commands.WebRequestSession]::new();UserPrincipalName='user@example.com';AuthUrl='https://login.microsoftonline.com/'}
        Mock Invoke-WebRequest { @{StatusCode=200;Content='{}'} }
    }
    It 'returns Success false without any cookie, including after retries' {
        $result=Complete-EntraPasskeyLogin -Context $context
        $result.Success | Should -BeFalse
        $result.AuthenticationCookieValue | Should -BeNullOrEmpty
        Should -Invoke Invoke-WebRequest -Times 3 -Exactly
    }
    It 'does not declare success for a foreign ESTSAUTH cookie' {
        $cookie=[Net.Cookie]::new('ESTSAUTH','foreign','/','attacker.invalid');$cookie.Secure=$true
        $context.Session.Cookies.Add($cookie)
        (Complete-EntraPasskeyLogin -Context $context).Success | Should -BeFalse
    }
    It 'returns metadata without bearer material by default and exports only when requested' {
        $cookie=[Net.Cookie]::new('ESTSAUTH','offline-cookie','/','login.microsoftonline.com');$cookie.Secure=$true
        $context.Session.Cookies.Add($cookie)
        $result=Complete-EntraPasskeyLogin -Context $context
        $result.Success | Should -BeTrue
        $result.AuthenticationCookieValue | Should -BeNullOrEmpty
        $result.SessionPersistedToGlobalScope | Should -BeFalse
        (Complete-EntraPasskeyLogin -Context $context -IncludeAuthenticationCookie).AuthenticationCookieValue | Should -BeExactly 'offline-cookie'
        $result.UserPresenceVerified | Should -BeFalse
        $result.UserVerificationVerified | Should -BeFalse
    }
}
Describe 'Compatibility normalization and interrupt destination' {
    It 'normalizes existing base64 and UUID credential identifiers, rejects malformed values' {
        Confirm-Base64Url 'YWJjZA==' | Should -BeExactly 'YWJjZA'
        Confirm-Base64Url 'YWJjZA' | Should -BeExactly 'YWJjZA'
        (ConvertFrom-UuidToBase64Url '01234567-89ab-cdef-0123-456789abcdef').Length | Should -Be 22
        {Confirm-Base64Url '@malformed'} | Should -Throw
        {Confirm-Base64Url 'a'} | Should -Throw
        {Confirm-Base64Url 'abc=def'} | Should -Throw
    }
    It 'pins ConvergedSignIn origin and safely handles absent arrSessions' {
        $context=@{Session=[Microsoft.PowerShell.Commands.WebRequestSession]::new();PageState=@{pgid='ConvergedSignIn';urlLogin='/common/login';sessionId='x&other=value'}}
        Mock Invoke-WebRequest { @{StatusCode=200;Content='{}'} }
        Resolve-EntraLoginInterrupts -Context $context
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter {$Uri -ceq 'https://login.microsoftonline.com/common/login?sessionid=x%26other%3Dvalue'}
        foreach ($url in @('https://attacker.invalid/login','http://login.microsoftonline.com/login','https://login.microsoftonline.com:444/login','https://user@login.microsoftonline.com/login')) {
            $context.PageState=@{pgid='ConvergedSignIn';urlLogin=$url;sessionId='dummy'}
            {Resolve-EntraLoginInterrupts -Context $context} | Should -Throw '*Untrusted*'
        }
    }
}
