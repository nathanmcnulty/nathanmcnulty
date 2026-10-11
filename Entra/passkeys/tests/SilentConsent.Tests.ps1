BeforeAll {
 $scriptText=Get-Content "$PSScriptRoot/../PasskeyLogin.ps1" -Raw
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseInput($scriptText,[ref]$tokens,[ref]$errors)
}
Describe 'Unattended login boundaries' {
 It 'parses without errors' {$errors.Count|Should -Be 0}
 It 'stops an application-confirmation interrupt before submitting an HTTP request' {
  $loop=$ast.Find({param($node)$node -is [Management.Automation.Language.WhileStatementAst] -and $node.Condition.Extent.Text -match 'CmsiInterrupt'},$true)
  $loop|Should -Not -BeNullOrEmpty
  $Debug=@{pgid='CmsiInterrupt'};$InterruptHandlers=@{};$ConfirmApplication=$false
  Mock Invoke-WebRequest {throw 'Unexpected network call'}
  {& ([scriptblock]::Create($loop.Extent.Text))}|Should -Throw '*will not submit approval*'
  Should -Invoke Invoke-WebRequest -Times 0
 }
 It 'omits shortened credential and identity-payload output' {
  $scriptText|Should -Not -Match 'credentialId.Substring|userHandle.Substring|Write-Verbose.*(?:fidoPayload|respVerify.Content|respFinalize.Content|Exception.Message)'
 }
 It 'rejects confirmation for a different authorization client before login' {
  $guard=$null
  # IfStatementAst exposes Conditions through Clauses.
  if(-not $guard){$guard=$ast.Find({param($node)$node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text -match '^if \(\$ConfirmApplication\)'} ,$true)}
  $ConfirmApplication=$true;$ExpectedClientId=[guid]'04b07795-8ddb-461a-bbee-02f9e1bf7b46'
  $AuthUrl='https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=11111111-1111-1111-1111-111111111111'
  {& ([scriptblock]::Create($guard.Extent.Text))}|Should -Throw '*expected client*'
  $AuthUrl='https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46'
  {& ([scriptblock]::Create($guard.Extent.Text))}|Should -Not -Throw
 }

}
Describe 'Application confirmation query ambiguity' {
 It 'rejects duplicate decoded client keys: <Extra>' -ForEach @(
  @{Extra='client_id=11111111-1111-1111-1111-111111111111'},
  @{Extra='client%5Fid=11111111-1111-1111-1111-111111111111'},
  @{Extra='CLIENT_ID=11111111-1111-1111-1111-111111111111'},
  @{Extra='client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46'}
 ) {
  $guard=$ast.Find({param($node)$node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text -match '^if \(\$ConfirmApplication\)'},$true)
  $ConfirmApplication=$true;$ExpectedClientId=[guid]'04b07795-8ddb-461a-bbee-02f9e1bf7b46'
  $AuthUrl='https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&'+$Extra
  {& ([scriptblock]::Create($guard.Extent.Text))}|Should -Throw '*expected client*'
 }
}
