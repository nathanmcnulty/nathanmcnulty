Get-MgBetaAuditLogSignIn -Filter "signInEventTypes/any(t: t eq 'servicePrincipal') and servicePrincipalId eq '00000000-0000-0000-0000-000000000000'" | Out-GridView -PassThru | ForEach-Object {
    New-MgBetaServicePrincipal -AppId $_.appId
    Add-Content -Path .\changes.txt Value "Registered $($_.appId). To undo, run Remove-MgBetaServicePrincipal -AppId $($_.appId)"
}