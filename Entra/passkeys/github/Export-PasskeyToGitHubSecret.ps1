#Requires -Version 7.0
# Dot-source this file. No credentials are read or written merely by loading it.

function Assert-GitHubPasskeyRepository {
    param([Parameter(Mandatory)][string]$Repository)
    if ($Repository -cnotmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}$' -or
        $Repository.Split('/')[1] -in @('.', '..')) {
        throw 'Repository must be an explicit github.com owner/repo name, without a URL.'
    }
}

function Get-GitHubPasskeySecretValues {
    param([Parameter(Mandatory)][object]$Credential)
    $values = [ordered]@{}
    $mapping = [ordered]@{
        PASSKEY_PRIVATE_CREDENTIAL_ID = 'credentialId'
        PASSKEY_PRIVATE_USER_HANDLE = 'userHandle'
        PASSKEY_PRIVATE_USER_PRINCIPAL_NAME = 'userName'
        PASSKEY_PRIVATE_KEY = 'privateKey'
    }
    foreach ($name in $mapping.Keys) {
        $property = $mapping[$name]
        $value = $null
        if ($Credential -is [System.Collections.IDictionary]) {
            $value = $Credential[$property]
        } else {
            $p = $Credential.PSObject.Properties[$property]
            if ($null -ne $p) { $value = $p.Value }
        }
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
            throw "Credential field $property must be a nonempty string."
        }
        if ([Text.Encoding]::UTF8.GetByteCount($value) -gt 49152 -or $value.Contains([char]0)) {
            throw "Credential field $property exceeds the secret size limit or contains NUL."
        }
        $values[$name] = $value
    }
    foreach ($name in @('PASSKEY_PRIVATE_CREDENTIAL_ID','PASSKEY_PRIVATE_USER_HANDLE')) {
        $s = $values[$name]
        if ($s -cnotmatch '^[A-Za-z0-9_-]+$' -or ($s.Length % 4) -eq 1) {
            throw 'Credential ID and user handle must be unpadded base64url.'
        }
        try { $bytes = [Convert]::FromBase64String($s.Replace('-','+').Replace('_','/') + ('=' * ((4 - $s.Length % 4) % 4))) }
        catch { throw 'Credential ID or user handle is not valid base64url.' }
        if ([Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_') -cne $s) {
            throw 'Credential ID or user handle is not canonical base64url.'
        }
    }
    if ($values.PASSKEY_PRIVATE_USER_PRINCIPAL_NAME -notmatch '^[^\s@]+@[^\s@]+$') {
        throw 'Credential userName must be a UPN without whitespace.'
    }
    $parameters = $null
    $key = [Security.Cryptography.ECDsa]::Create()
    try {
        $key.ImportFromPem($values.PASSKEY_PRIVATE_KEY)
        $parameters = $key.ExportParameters($true)
        if ($key.KeySize -ne 256 -or $parameters.Curve.Oid.Value -ne '1.2.840.10045.3.1.7' -or $parameters.D.Length -ne 32) {
            throw 'Wrong key type.'
        }
    } catch { throw 'Credential privateKey must contain a valid unencrypted ECDSA P-256 private PEM key.' }
    finally { $key.Dispose(); if ($null -ne $parameters -and $null -ne $parameters.D) { [Array]::Clear($parameters.D, 0, $parameters.D.Length) } }
    return $values
}

function Invoke-GitHubPasskeyCli {
    # Child output is drained and discarded. Never forward gh stderr or exception details.
    param([Parameter(Mandatory)][string[]]$Arguments, [AllowNull()][string]$InputText,
          [ValidateRange(1,300)][int]$TimeoutSeconds = 60)
    $command = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { throw 'GitHub CLI (gh) is required; install it from its official source.' }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $command.Source
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    $psi.Environment['GH_HOST'] = 'github.com'
    $psi.Environment['GH_PROMPT_DISABLED'] = '1'
    foreach ($arg in $Arguments) { $psi.ArgumentList.Add($arg) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $deadlineMs = $TimeoutSeconds * 1000
    function Wait-CliTask([Threading.Tasks.Task]$Task) {
        $remaining = [int][Math]::Max(0, $deadlineMs - $clock.ElapsedMilliseconds)
        if ($remaining -le 0 -or -not $Task.Wait($remaining)) { throw 'CLI deadline exceeded.' }
    }
    try {
        $null = $process.Start()
        # Copy to Stream.Null: never accumulate arbitrary child stdout/stderr in memory.
        $stdout = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
        $stderr = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        if ($null -ne $InputText) { Wait-CliTask ($process.StandardInput.WriteAsync($InputText)) }
        Wait-CliTask ($process.StandardInput.FlushAsync())
        $process.StandardInput.Close()
        $remaining = [int][Math]::Max(0, $deadlineMs - $clock.ElapsedMilliseconds)
        if ($remaining -le 0 -or -not $process.WaitForExit($remaining)) { throw 'CLI deadline exceeded.' }
        Wait-CliTask $stdout
        Wait-CliTask $stderr
        if ($process.ExitCode -ne 0) { throw 'CLI operation failed.' }
    } catch {
        try { if (-not $process.HasExited) { $process.Kill($true) } } catch {}
        throw 'GitHub CLI operation failed or timed out; raw output was suppressed and the current write may be uncertain.'
    }
    finally { $process.Dispose() }

}

function Test-GitHubPasskeyDestination {
    param([Parameter(Mandatory)][string]$Repository)
    Assert-GitHubPasskeyRepository $Repository
    Invoke-GitHubPasskeyCli -Arguments @('auth','status','--hostname','github.com')
    # A read-only preflight checks visibility, not a guarantee of later write permission.
    Invoke-GitHubPasskeyCli -Arguments @('api', '--hostname', 'github.com', "repos/$Repository/actions/secrets?per_page=1")
}

function Export-PasskeyToGitHubSecret {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory)][object]$Credential,
        [Parameter(Mandatory)][string]$Repository,
        [switch]$ConsumersPaused
    )
    Assert-GitHubPasskeyRepository $Repository
    $values = Get-GitHubPasskeySecretValues $Credential
    if (-not $ConsumersPaused) { throw 'Pause all workflows/consumers and supply -ConsumersPaused. Four secret writes are not atomic.' }
    if (-not $PSCmdlet.ShouldProcess("github.com/$Repository", 'Replace four Actions secrets (metadata first, private key last; no rollback)')) { return }
    Test-GitHubPasskeyDestination $Repository
    $written = [Collections.Generic.List[string]]::new()
    foreach ($name in $values.Keys) {
        try {
            Invoke-GitHubPasskeyCli -Arguments @('secret','set',$name,'--repo',"github.com/$Repository",'--app','actions') -InputText $values[$name]
            $written.Add($name)
        } catch {
            $completed = if ($written.Count) { $written -join ', ' } else { '(none)' }
            throw "GitHub export incomplete. Confirmed writes: $completed. Failed or unknown: $name. Keep consumers paused. No rollback was attempted; GitHub cannot return previous secret values. Re-export the same complete credential if it remains available, or remove the orphaned Entra method and re-enroll."
        }
    }
    [pscustomobject]@{ Repository = $Repository; Success = $true; SecretNames = @($written); Atomic = $false }
}
