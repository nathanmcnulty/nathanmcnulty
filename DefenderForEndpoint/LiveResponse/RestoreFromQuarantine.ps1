function RestoreFromQuarantine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Path
    )

    Start-Process -FilePath "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList "-Restore -FilePath $Path"
}