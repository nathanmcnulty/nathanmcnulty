BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Export-PasskeyToGitHubSecret.ps1')
    $fakeGh = Join-Path $TestDrive 'gh'
}
Describe 'Bounded stdin-only subprocess transport (Unix fixture)' -Skip:($IsWindows) {
    BeforeEach { Mock Get-Command { [pscustomobject]@{Source=$fakeGh} } -ParameterFilter { $Name -eq 'gh' } }
    It 'suppresses successful child stdout/stderr and sends exact stdin' {
        @'
#!/bin/sh
v=$(cat)
[ "$v" = 'SYNTHETIC-INPUT' ] || exit 7
printf 'SYNTHETIC-STDOUT'
printf 'SYNTHETIC-STDERR' >&2
'@ | Set-Content $fakeGh -NoNewline
        & chmod +x $fakeGh
        $result = Invoke-GitHubPasskeyCli -Arguments @('secret','set','FIXTURE') -InputText 'SYNTHETIC-INPUT'
        $result | Should -BeNullOrEmpty
    }
    It 'suppresses failed process output in errors' {
        @'
#!/bin/sh
cat >/dev/null
printf 'SYNTHETIC-STDERR' >&2
exit 9
'@ | Set-Content $fakeGh -NoNewline
        & chmod +x $fakeGh
        $errorText = $null
        try { Invoke-GitHubPasskeyCli -Arguments @('fixture') -InputText 'SYNTHETIC-INPUT' } catch { $errorText = $_ | Out-String }
        $errorText | Should -Match 'failed or timed out'
        $errorText | Should -Not -Match 'SYNTHETIC'
    }
    It 'bounds process wait and stdin even if child never reads' {
        @'
#!/bin/sh
sleep 6
'@ | Set-Content $fakeGh -NoNewline
        & chmod +x $fakeGh
        $clock = [Diagnostics.Stopwatch]::StartNew()
        { Invoke-GitHubPasskeyCli -Arguments @('fixture') -InputText ('x' * 49152) -TimeoutSeconds 1 } | Should -Throw '*timed out*'
        $clock.Elapsed.TotalSeconds | Should -BeLessThan 3
    }
    It 'bounds inherited output-pipe drains after the parent exits' {
        @'
#!/bin/sh
cat >/dev/null
sleep 6 &
exit 0
'@ | Set-Content $fakeGh -NoNewline
        & chmod +x $fakeGh
        $clock = [Diagnostics.Stopwatch]::StartNew()
        { Invoke-GitHubPasskeyCli -Arguments @('fixture') -InputText 'synthetic' -TimeoutSeconds 1 } | Should -Throw '*timed out*'
        $clock.Elapsed.TotalSeconds | Should -BeLessThan 3
    }
}
