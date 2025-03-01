#Requires -Module Microsoft.Graph

Connect-MgGraph -Scopes Directory.AccessAsUser.All

Get-MgDevice -Filter "TrustType eq 'ServerAd'" -All | ForEach-Object {
    Get-MgDevice -Filter "DisplayName eq '$($_.DisplayName)' and TrustType eq 'Workplace'" | 
    Select-Object Id,DisplayName |
    Out-GridView -PassThru | 
    ForEach-Object { Remove-MgDevice -DeviceId $_.Id }
}
