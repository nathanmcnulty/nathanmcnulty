$EmergencyAccountsGroupObjectID = "b4c021b8-d833-4375-bc94-c590f743cd54"

Connect-MgGraph -Identity

(Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies").value | Where-Object { $EmergencyAccountsGroupObjectID -notin $_.conditions.users.excludeGroups } | ForEach-Object {
    if ($null -eq $_) { return }

    $body = @{
        "conditions" = @{
            "users" = @{
                "excludeGroups" = @( $_.conditions.users.excludeGroups + $EmergencyAccountsGroupObjectID )
            }
        }
    }

    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($_.id)" -Body $body
        Write-Output "Successfully updated policy $($_.id)"
    } catch {
        Write-Error "Failed to update policy $($_.id)"
    }

}
