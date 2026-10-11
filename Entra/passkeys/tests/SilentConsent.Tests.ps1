BeforeAll {
    $scriptText=Get-Content "$PSScriptRoot/../PasskeyLogin.ps1" -Raw
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($scriptText,[ref]$tokens,[ref]$errors)
    foreach($function in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)) {
        . ([scriptblock]::Create($function.Extent.Text))
    }
    $defaultUrl='https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46'
}
Describe 'Unattended login boundaries' {
    It 'parses without errors' { $errors.Count | Should -Be 0 }
    It 'stops an application-confirmation interrupt before HTTP' {
        $context=@{PageState=@{pgid='CmsiInterrupt'}}
        Mock Invoke-WebRequest { throw 'Unexpected network' }
        {Resolve-EntraLoginInterrupts -Context $context} | Should -Throw '*will not submit approval*'
        Should -Invoke Invoke-WebRequest -Times 0
    }
    It 'omits credential and identity-payload diagnostics' {
        $scriptText | Should -Not -Match 'credentialId.Substring|userHandle.Substring|Write-Verbose.*(?:fidoPayload|respVerify.Content|respFinalize.Content|Exception.Message)'
    }
    It 'rejects another client before acquiring a provider token' {
        Mock Invoke-RestMethod { throw 'Unexpected network' }
        Mock Invoke-WebRequest { throw 'Unexpected network' }
        { & "$PSScriptRoot/../PasskeyLogin.ps1" -UserName 'fixture@example.invalid' -UserHandle aGFuZGxl -CredentialId aWQ -PrivateKey fixture -ConfirmApplication -AuthUrl ($defaultUrl.Replace('04b07795-8ddb-461a-bbee-02f9e1bf7b46','11111111-1111-1111-1111-111111111111')) } | Should -Throw '*expected client*'
        Should -Invoke Invoke-WebRequest -Times 0
        Should -Invoke Invoke-RestMethod -Times 0
    }
    It 'rejects any unsupported pending consent/policy interaction' -ForEach @('Consent','ConvergedConsent','TenantRestrictions','UnknownInteraction') {
        $context=@{PageState=@{pgid=$_}}
        Mock Invoke-WebRequest {throw 'Unexpected network'}
        {Resolve-EntraLoginInterrupts -Context $context} | Should -Throw '*pending interaction*'
        Should -Invoke Invoke-WebRequest -Times 0
    }
    It 'rejects duplicate decoded client keys: <Extra>' -ForEach @(
        @{Extra='client_id=11111111-1111-1111-1111-111111111111'},
        @{Extra='client%5Fid=11111111-1111-1111-1111-111111111111'},
        @{Extra='CLIENT_ID=11111111-1111-1111-1111-111111111111'},
        @{Extra='client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46'}
    ) {
        Mock Invoke-WebRequest {throw 'Unexpected network'}
        { & "$PSScriptRoot/../PasskeyLogin.ps1" -UserName 'fixture@example.invalid' -UserHandle aGFuZGxl -CredentialId aWQ -PrivateKey fixture -ConfirmApplication -AuthUrl ($defaultUrl+'&'+$Extra) } | Should -Throw '*ambiguous client_id*'
        Should -Invoke Invoke-WebRequest -Times 0
    }
}
