BeforeAll {
    $root = Join-Path $PSScriptRoot '../PasskeyLogin.ps1'
    $kv = Join-Path $PSScriptRoot '../keyvault/PasskeyLogin.ps1'
}
Describe 'Personal login compatibility' {
    It 'preserves named parameters, aliases and original positional arguments: <Kind>' -ForEach @(
        @{Kind='root';Relative='../PasskeyLogin.ps1';Names=@('KeyFilePath','UserPrincipalName','UserHandle','CredentialId','PrivateKey','RelyingParty','AuthUrl','UserAgent','Proxy')},
        @{Kind='kv';Relative='../keyvault/PasskeyLogin.ps1';Names=@('CredentialFromPipeline','KeyFilePath','UserPrincipalName','UserHandle','CredentialId','PrivateKey','RelyingParty','AuthUrl','UserAgent','Proxy','KeyVaultName','KeyVaultKeyName','KeyVaultAccessToken','KeyVaultClientId','KeyVaultClientSecret','KeyVaultTenantId','PassThru')}
    ) {
        $command = Get-Command (Join-Path $PSScriptRoot $Relative)
        for ($i=0;$i -lt $Names.Count;$i++) {
            $command.Parameters[$Names[$i]] | Should -Not -BeNullOrEmpty
            $attribute = $command.Parameters[$Names[$i]].Attributes | Where-Object {$_ -is [Management.Automation.ParameterAttribute]}
            $attribute.Position | Should -Be $i
        }
        $command.Parameters.UserPrincipalName.Aliases | Should -Contain UserName
        $command.Parameters.CredentialId.Aliases | Should -Contain CredentialIdentifier
    }
    It 'preserves pipeline binding and accepts SecureString/local inputs' {
        $command=Get-Command $kv
        ($command.Parameters.CredentialFromPipeline.Attributes | Where-Object {$_ -is [Management.Automation.ParameterAttribute]}).ValueFromPipeline | Should -BeTrue
        $text = Get-Content $kv -Raw
        $text | Should -Match 'ConvertTo-PlainTextValue -Value \$PrivateKey'
    }
    It 'both personal login copies use identical helper functions' {
        $baseline=Get-Content $root -Raw
        $helpers=$baseline.Substring($baseline.IndexOf('#region Helper Functions'),$baseline.IndexOf('#endregion')-$baseline.IndexOf('#region Helper Functions'))
        foreach ($path in @($root,$kv)) {
            $text=Get-Content $path -Raw
            $actual=$text.Substring($text.IndexOf('#region Helper Functions'),$text.IndexOf('#endregion')-$text.IndexOf('#region Helper Functions'))
            $actual | Should -BeExactly $helpers
        }
    }
    It 'keeps the legacy ESTSAUTH alias exclusively inside explicit global opt-in' {
        foreach ($path in @($root,$kv)) {
            $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
            $errors.Count | Should -Be 0
            $assignments=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$global:ESTSAUTH'},$true))
            $assignments.Count | Should -Be 1
            $node=$assignments[0]
            while($node -and $node -isnot [Management.Automation.Language.IfStatementAst]) {$node=$node.Parent}
            $node.Clauses[0].Item1.Extent.Text | Should -Be '$PersistSessionToGlobalScope'
        }
    }
}
