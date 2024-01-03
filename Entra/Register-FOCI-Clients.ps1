# Connect to Microsoft Graphp
Connect-MgGraph

# Get list of FOCI clients and register them with Entra ID
(Invoke-WebRequest -Method GET -Uri 'https://raw.githubusercontent.com/secureworks/family-of-client-ids-research/main/known-foci-clients.csv' | ConvertFrom-Csv).client_id | ForEach-Object {
        $sp = Get-MgServicePrincipal -Filter "appId eq '$_'"
        if (-not $sp) {
            New-MgServicePrincipal -AppId $_
        }
}

# Now we need to assign custom security attributes to these apps