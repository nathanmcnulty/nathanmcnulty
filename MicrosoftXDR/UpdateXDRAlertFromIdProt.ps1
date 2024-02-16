# Connect to Graph with appropriate scopes
Connect-MgGraph -Scope SecurityAlert.ReadWrite.All, AuditLog.Read.All, Directory.Read.All

# Get all Identity Protection events that have been resolved in the last week
$events = Get-MgAuditLogDirectoryAudit -Filter "LoggedByService eq 'Identity Protection' and ActivityDisplayName eq 'ConfirmSafe' and ActivityDateTime gt $((Get-Date).AddDays(-7).ToString('yyyy-MM-dd'))"
$events | ForEach-Object {
    # Get values from the event to use for looking up and updating alert
    $actor = $_.InitiatedBy.User.UserPrincipalName
    $target = $_.TargetResources.id

    # Check to see if we've already updated the alert
    $alert = (Get-MgSecurityAlertV2 -Filter "ServiceSource eq 'azureAdIdentityProtection' and Status eq 'resolved'") | Where-Object { $_.evidence.AdditionalProperties.userAccount.azureAdUserId -eq $target }
    if (!($alert.Comments | Where-Object { $_.CreatedByDisplayName -eq 'API Action' -and $_.Comment -contains "Login confirmed safe by $actor" })) {
        $params = @{
            "@odata.type" = "microsoft.graph.security.alertComment"
            comment = "Login confirmed safe by $actor"
        }
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2/$($alert.id)/comments" -Body $params
    }
}