BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    $global:PasskeyOfflineFixture = @{}
    $registration = "$root/Register-GitHubPasskeyViaTAP.ps1"
    $fakeGh = Join-Path $TestDrive 'gh'
    $ghCalls = Join-Path $TestDrive 'gh-calls.txt'
    # Fixture subprocess discards stdin, records public arguments only; never contacts GitHub.
    @'
#!/bin/sh
cat >/dev/null
printf '%s\n' "$*" >> "$PASSKEY_TEST_CALLS"
'@ | Set-Content $fakeGh -NoNewline
    & chmod +x $fakeGh
    $oldCalls = $env:PASSKEY_TEST_CALLS
    $env:PASSKEY_TEST_CALLS = $ghCalls
}
AfterAll { $env:PASSKEY_TEST_CALLS = $oldCalls; Remove-Variable PasskeyOfflineFixture -Scope Global }
Describe 'Fully mocked TAP registration transcript' {
    BeforeEach {
        Remove-Item $ghCalls -ErrorAction SilentlyContinue
        $global:PasskeyOfflineFixture.State = $null
        $global:PasskeyOfflineFixture.Mode = 'success'
        $global:PasskeyOfflineFixture.TokenRequests = 0
        Mock Get-Command { [pscustomobject]@{Source=$fakeGh} } -ParameterFilter { $Name -eq 'gh' }
        Mock Invoke-RestMethod {
            if ($Uri -match 'GetCredentialType') { return @{ FlowToken='fixture-flow' } }
            if ($Uri -match '/token$') { $global:PasskeyOfflineFixture.TokenRequests++; return @{access_token='SYNTHETIC-ACCESS-TOKEN';refresh_token='SYNTHETIC-REFRESH-TOKEN'} }
            if ($Uri -match '/session/authorize$') { return @{isAuthorized=$true;sessionCtxV2='SYNTHETIC-SESSION';requireNgcMfaForSecurityInfo=$false} }
            throw 'Unexpected mocked REST request.'
        }
        Mock Invoke-WebRequest {
            if ($Uri -match '/authorize\?') {
                $global:PasskeyOfflineFixture.State = [Web.HttpUtility]::ParseQueryString(([uri]$Uri).Query)['state']
                return @{StatusCode=200;Content='$Config={"pgid":"ConvergedSignIn","sFT":"fixture-flow","sCtx":"fixture-context","canary":"fixture-canary","apiCanary":"fixture-api","sessionId":"fixture-session","urlPost":"/common/login"};'}
            }
            if ($Uri -match '/common/login$') {
                if ($global:PasskeyOfflineFixture.Mode -eq 'consent') { return @{StatusCode=200;Content='$Config={"pgid":"Consent"};<form action="https://login.microsoftonline.com/consent"><input name="accept" value="yes"></form>'} }
                $response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::Found)
                $state = if ($global:PasskeyOfflineFixture.Mode -eq 'badstate') { 'wrong-state' } else { $global:PasskeyOfflineFixture.State }
                $response.Headers.Location = [uri]"https://mysignins.microsoft.com/#code=SYNTHETIC-CODE&state=$state"
                throw [Microsoft.PowerShell.Commands.HttpResponseException]::new('Synthetic redirect', $response)
            }
            if ($Uri -match '/authenticationmethods/new$') {
                $data = @{ requestData=@{ canary='fixture-canary';serverChallenge='AQIDBA';userId='BQYHCA';postBackUrl='https://mysignins.microsoft.com/api/post/newfido' };provisionUrl='https://login.microsoft.com/tenant/fido/create' } | ConvertTo-Json -Depth 5 -Compress
                return @{StatusCode=200;Content=(@{ErrorCode=0;Data=$data} | ConvertTo-Json -Compress)}
            }
            if ($Uri -match '/fido/create\?') { return @{StatusCode=200;Content='fixture-created'} }
            if ($Uri -match '/post/newfido\?') { return @{StatusCode=200;Content='fixture-newfido'} }
            if ($Uri -match '/session/authorize$') { return @{StatusCode=200;Content='{"sessionCtxV2":"SYNTHETIC-SESSION"}'} }
            if ($Uri -match '/authenticationmethods/verify$') {
                $id = (($Body | ConvertFrom-Json).VerificationData | ConvertFrom-Json).CredentialId
                if ($global:PasskeyOfflineFixture.Mode -eq 'mismatch') { $id='wrong-credential' }
                $errorCode = if ($global:PasskeyOfflineFixture.Mode -eq 'protocolerror') { 1 } else { 0 }
                $status = if ($global:PasskeyOfflineFixture.Mode -eq 'httperror') { 400 } else { 200 }
                return @{StatusCode=$status;Content=(@{VerificationState=2;ErrorCode=$errorCode;DataUpdates=@{FidoDevices=@{CredentialId=$id}}} | ConvertTo-Json -Depth 6 -Compress)}
            }
            throw 'Unexpected mocked web request.'
        }
        $params = @{ TAP=(ConvertTo-SecureString 'SYNTHETIC-TAP' -AsPlainText -Force);UserPrincipalName='fixture@example.invalid';TenantId='11111111-1111-1111-1111-111111111111';Repository='fixture-owner/fixture-repo';ConsumersPaused=$true;AllowLegacySoftwareAttestation=$true;Confirm=$false }
    }
    It 'registers with synthetic responses and writes exactly four names without emitting credentials' {
        $result = & $registration @params
        $result.Success | Should -BeTrue
        $result | ConvertTo-Json -Depth 5 | Should -Not -Match 'SYNTHETIC|BEGIN PRIVATE|fixture@'
        $calls = Get-Content $ghCalls
        @($calls | Where-Object { $_ -match '^secret set ' }).Count | Should -Be 4
        $calls[-1] | Should -Be 'secret set PASSKEY_PRIVATE_KEY --repo github.com/fixture-owner/fixture-repo --app actions'
        $calls -join ' ' | Should -Not -Match 'SYNTHETIC|BEGIN PRIVATE|fixture@'
        $global:PasskeyOfflineFixture.TokenRequests | Should -Be 1
    }
    It 'rejects invalid response without any secret write' -ForEach @('badstate','consent','mismatch','protocolerror','httperror') {
        $global:PasskeyOfflineFixture.Mode = $_
        { & $registration @params } | Should -Throw
        @((Get-Content $ghCalls) | Where-Object { $_ -match '^secret set ' }).Count | Should -Be 0
        if ($_ -in @('badstate','consent')) { $global:PasskeyOfflineFixture.TokenRequests | Should -Be 0 }
    }
}
