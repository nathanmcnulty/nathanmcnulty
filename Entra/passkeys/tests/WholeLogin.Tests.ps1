# Synthetic transcripts only. Every HTTP/signing boundary is mocked.
BeforeDiscovery {
    $cases=@(@{Mode='standalone'})
    $canonicalRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
    if (Test-Path (Join-Path $canonicalRoot 'build/targets.psd1')) { $cases+=@(@{Mode='source'},@{Mode='module'}) }
}
Describe 'Whole login distribution: <Mode>' -ForEach $cases {
    BeforeAll {
        $global:PSPasskeyFixtureGroup=@{}
        $script:mode=$Mode
        $script:artifact=Join-Path $PSScriptRoot '../PasskeyLogin.ps1'
        $script:canonicalRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
        if ($Mode -eq 'module') { Import-Module (Join-Path $canonicalRoot 'powershell/modules/Passkey/Passkey.psd1') -Force }
        if ($Mode -eq 'source') {
            $targets=Import-PowerShellDataFile (Join-Path $canonicalRoot 'build/targets.psd1')
            $loginTarget=$targets.Scripts | Where-Object Path -eq 'github/action-passkey-login/PasskeyLogin.ps1'
            foreach ($source in $loginTarget.Sources) { . (Join-Path $canonicalRoot $source) }
        }
        $global:PSPasskeyFixtureGroup.key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
        $global:PSPasskeyFixtureGroup.pem=$global:PSPasskeyFixtureGroup.key.ExportPkcs8PrivateKeyPem()
        function Read-FixtureBytes([string]$Text) {
            $b=$Text.Replace('-','+').Replace('_','/');return ,[Convert]::FromBase64String($b.PadRight($b.Length+(4-$b.Length%4)%4,'='))
        }
        function Write-FixtureBytes([byte[]]$Bytes) { return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
        function Invoke-FixtureLogin([hashtable]$Additional=@{}) {
            $arguments=@{UserPrincipalName='fixture@example.invalid';UserHandle='aGFuZGxl';CredentialId='aWQ';PrivateKey=$global:PSPasskeyFixtureGroup.pem;PassThru=$true}
            foreach ($item in $Additional.GetEnumerator()) { $arguments[$item.Key]=$item.Value }
            if ($mode -eq 'module') { return Passkey\Invoke-EntraPasskeyLogin @arguments }
            if ($mode -eq 'source') { return Invoke-EntraPasskeyLogin @arguments }
            return & $artifact @arguments
        }
        function Invoke-FixtureWeb($Uri,$Method,$Body,$WebSession) {
            $global:PSPasskeyFixtureGroup.requests.Add([pscustomobject]@{Uri=[string]$Uri;Body=$Body;Method=$Method})
            if ($Uri -match '/oauth2/v2.0/authorize') {
                if ($global:PSPasskeyFixtureGroup.invalidConfig) { return @{StatusCode=200;Content='$Config={broken};'} }
                return @{StatusCode=200;Content='$Config={"oGetCredTypeResult":{"Credentials":{"HasFido":true,"FidoParams":{"AllowList":[]}},"FlowToken":"fixture-flow"},"sFidoChallenge":"fixture-challenge","sFT":"fixture-token","sCtx":"fixture-context","canary":"fixture-canary"};'}
            }
            if ($Uri -match '/fido/get') { return @{StatusCode=200;Content='{"sCrossDomainCanary":"fixture-cross","sessionId":"fixture-session","sCtx":"fixture-context","canary":"fixture-canary","sFT":"fixture-token"}'} }
            if ($Body.assertion) {
                $global:PSPasskeyFixtureGroup.assertion=$Body.assertion | ConvertFrom-Json
                if ($global:PSPasskeyFixtureGroup.issueCookie) {
                    $cookie=[Net.Cookie]::new('ESTSAUTH','SYNTHETIC-COOKIE','/',$global:PSPasskeyFixtureGroup.cookieDomain);$cookie.Secure=$true;$WebSession.Cookies.Add($cookie)
                }
                return @{StatusCode=200;Content=(@{pgid=$global:PSPasskeyFixtureGroup.page;urlLogin='/common/login';sessionId='fixture-session';canary='fixture-canary';sFT='fixture-token';sCtx='fixture-context';correlationId='fixture-correlation'} | ConvertTo-Json -Compress)}
            }
            if ($Uri -match '/appverify$|/kmsi$') { return @{StatusCode=200;Content='{}'} }
            if ($Uri -match '/common/login\?sessionid=') { return @{StatusCode=200;Content='{"pgid":"ConvergedSignIn","urlLogin":"/common/login","sessionId":"fixture-session"}'} }
            throw 'Unexpected fixture request.'
        }
        function Invoke-FixtureSign($Uri,$Body) {
            $global:PSPasskeyFixtureGroup.signRequests.Add([pscustomobject]@{Uri=[string]$Uri;Body=$Body})
            if ($global:PSPasskeyFixtureGroup.failSigner) { throw 'SYNTHETIC-SECRET-SERVICE-ERROR' }
            $digest=Read-FixtureBytes (($Body | ConvertFrom-Json).value)
            $digest.Length | Should -Be 32
            $signature=$global:PSPasskeyFixtureGroup.key.SignHash($digest,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)
            return @{value=(Write-FixtureBytes $signature)}
        }
    }
    AfterAll { $global:PSPasskeyFixtureGroup.key.Dispose();Remove-Variable PSPasskeyFixtureGroup -Scope Global;if ($mode -eq 'module') {Remove-Module Passkey -ErrorAction SilentlyContinue} }
    BeforeEach {
        $global:PSPasskeyFixtureGroup.requests=[Collections.Generic.List[object]]::new();$global:PSPasskeyFixtureGroup.signRequests=[Collections.Generic.List[object]]::new()
        $global:PSPasskeyFixtureGroup.assertion=$null;$global:PSPasskeyFixtureGroup.issueCookie=$true;$global:PSPasskeyFixtureGroup.cookieDomain='login.microsoftonline.com';$global:PSPasskeyFixtureGroup.page='';$global:PSPasskeyFixtureGroup.invalidConfig=$false;$global:PSPasskeyFixtureGroup.failSigner=$false
        Mock Invoke-WebRequest {Invoke-FixtureWeb $Uri $Method $Body $WebSession}
        Mock Invoke-RestMethod {Invoke-FixtureSign $Uri $Body}
        Mock Start-Sleep {}
        if ($mode -eq 'module') {
            Mock Invoke-WebRequest {Invoke-FixtureWeb $Uri $Method $Body $WebSession} -ModuleName Passkey
            Mock Invoke-RestMethod {Invoke-FixtureSign $Uri $Body} -ModuleName Passkey
            Mock Start-Sleep {} -ModuleName Passkey
        }
    }
    It 'signs a complete software assertion and explicitly disclaims verified UP/UV' {
        $result=Invoke-FixtureLogin
        @($result).Count | Should -Be 1
        $result.Success | Should -BeTrue
        $result.AuthenticationCookieValue | Should -BeNullOrEmpty
        $result.UserPresenceVerified | Should -BeFalse
        $result.UserVerificationVerified | Should -BeFalse
        $auth=Read-FixtureBytes $global:PSPasskeyFixtureGroup.assertion.authenticatorData;$client=Read-FixtureBytes $global:PSPasskeyFixtureGroup.assertion.clientDataJSON
        $auth[32] | Should -Be 5
        $hash=[Security.Cryptography.SHA256]::HashData([byte[]]($auth+[Security.Cryptography.SHA256]::HashData($client)))
        $global:PSPasskeyFixtureGroup.key.VerifyHash($hash,(Read-FixtureBytes $global:PSPasskeyFixtureGroup.assertion.signature),[Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence) | Should -BeTrue
        $global:PSPasskeyFixtureGroup.signRequests.Count | Should -Be 0
    }
    It 'executes versioned KV signing with the same cryptographic boundary' {
        $file=Join-Path $TestDrive credential.json
        @{username='fixture@example.invalid';credentialId='aWQ';userHandle='aGFuZGxl';keyVault=@{vaultName='fixturevault';keyName='fixture-key';keyId='https://fixturevault.vault.azure.net/keys/fixture-key/0123456789abcdef0123456789abcdef'}} | ConvertTo-Json | Set-Content $file
        $result=Invoke-FixtureLogin @{KeyFilePath=$file;KeyVaultAccessToken='SYNTHETIC-TOKEN';PrivateKey=$null}
        $result.Success | Should -BeTrue
        $global:PSPasskeyFixtureGroup.signRequests.Count | Should -Be 1
        $global:PSPasskeyFixtureGroup.signRequests[0].Uri | Should -BeExactly 'https://fixturevault.vault.azure.net/keys/fixture-key/0123456789abcdef0123456789abcdef/sign?api-version=7.4'
        $auth=Read-FixtureBytes $global:PSPasskeyFixtureGroup.assertion.authenticatorData;$client=Read-FixtureBytes $global:PSPasskeyFixtureGroup.assertion.clientDataJSON
        $hash=[Security.Cryptography.SHA256]::HashData([byte[]]($auth+[Security.Cryptography.SHA256]::HashData($client)))
        $global:PSPasskeyFixtureGroup.key.VerifyHash($hash,(Read-FixtureBytes $global:PSPasskeyFixtureGroup.assertion.signature),[Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence) | Should -BeTrue
    }
    It 'never falls back from selected KV failure to a provided local key' {
        $global:PSPasskeyFixtureGroup.failSigner=$true
        {Invoke-FixtureLogin @{KeyVaultName='fixturevault';KeyVaultKeyName='fixture-key';KeyVaultAccessToken='SYNTHETIC-TOKEN'}} | Should -Throw '*assertion generation failed*'
        $global:PSPasskeyFixtureGroup.signRequests.Count | Should -Be 3
        $global:PSPasskeyFixtureGroup.assertion | Should -BeNullOrEmpty
    }
    It 'returns cookie only by explicit request' { (Invoke-FixtureLogin @{IncludeAuthenticationCookie=$true}).AuthenticationCookieValue | Should -BeExactly 'SYNTHETIC-COOKIE' }
    It 'does not accept foreign-domain or absent cookies' {
        $global:PSPasskeyFixtureGroup.cookieDomain='attacker.invalid';(Invoke-FixtureLogin).Success | Should -BeFalse
        $global:PSPasskeyFixtureGroup.issueCookie=$false;(Invoke-FixtureLogin).Success | Should -BeFalse
    }
    It 'rejects application/consent/policy interactions before success' -ForEach @('CmsiInterrupt','ConvergedConsent','TenantRestrictions') {
        $global:PSPasskeyFixtureGroup.page=$_
        {Invoke-FixtureLogin} | Should -Throw
        @($global:PSPasskeyFixtureGroup.requests | Where-Object Uri -match '/appverify').Count | Should -Be 0
    }
    It 'allows only the specifically client-bound application confirmation and retains all fields' {
        $global:PSPasskeyFixtureGroup.page='CmsiInterrupt'
        (Invoke-FixtureLogin @{ConfirmApplication=$true}).Success | Should -BeTrue
        $post=@($global:PSPasskeyFixtureGroup.requests | Where-Object Uri -match '/appverify')[0]
        $post.Body.ContinueAuth | Should -BeExactly 'true'
        $post.Body.canary | Should -BeExactly 'fixture-canary'
        $post.Body.ctx | Should -BeExactly 'fixture-context'
        $post.Body.i19 | Should -BeGreaterOrEqual 1000
        $post.Body.i19 | Should -BeLessThan 9999
    }
    It 'bounds a repeated interaction' {
        $global:PSPasskeyFixtureGroup.page='ConvergedSignIn'
        {Invoke-FixtureLogin} | Should -Throw '*interrupt loop*'
        @($global:PSPasskeyFixtureGroup.requests | Where-Object Uri -match 'sessionid=').Count | Should -Be 10
    }
    It 'fails malformed server configuration without signing' {
        $global:PSPasskeyFixtureGroup.invalidConfig=$true
        {Invoke-FixtureLogin} | Should -Throw '*malformed*'
        $global:PSPasskeyFixtureGroup.assertion | Should -BeNullOrEmpty
        $global:PSPasskeyFixtureGroup.signRequests.Count | Should -Be 0
    }
    It 'preserves caller globals and default parameter values' {
        $defaults=$PSDefaultParameterValues
        $prior=Get-Variable ESTSCookie -Scope Global -ErrorAction SilentlyContinue
        try {
            $global:ESTSCookie='caller-sentinel'
            $null=Invoke-FixtureLogin
            $global:ESTSCookie | Should -BeExactly 'caller-sentinel'
            [object]::ReferenceEquals($defaults,$PSDefaultParameterValues) | Should -BeTrue
        } finally {
            if ($prior) {$global:ESTSCookie=$prior.Value} else {Remove-Variable ESTSCookie -Scope Global}
        }
    }
}
