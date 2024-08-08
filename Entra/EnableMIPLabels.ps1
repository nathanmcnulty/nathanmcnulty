# Get Group.Unified settings
$grpUnifiedSetting = Get-MgBetaDirectorySetting | Where-Object { $_.DisplayName -eq "Group.Unified" }

# If doesn't exist, create it, else update it
if ($null -eq $grpUnifiedSetting) {
    # Create the Group.Unified directory setting   
    Write-Output "The Group.Unified directory setting does not exist yet - creating it now"
    $template = Get-MgBetaDirectorySettingTemplate | Where-Object { $_.DisplayName -eq "Group.Unified" }
    $params = @{
        templateId = "$($template.Id)"
        values = @(
            @{
                name = "EnableMIPLabels"
                value = "True"
            }
        )
    }
    New-MgBetaDirectorySetting -BodyParameter $params
} else {
    # Check the Group.Unified directory setting and update if necessary
    if (($grpUnifiedSetting.Values | Where-Object { $_.Name -eq "EnableMIPLabels" }).Value -eq $true) {
        Write-Output "The Group.Unified directory setting already exists and is set to true"
    } else {
        Write-Output "The Group.Unified directory setting already exists but is not set to true - updating it now"    
        $params = @{
            Values = @(
                @{
                    Name = "EnableMIPLabels"
                    Value = "True"
                }
            )
        }
        Update-MgBetaDirectorySetting -DirectorySettingId $grpUnifiedSetting.Id -BodyParameter $params
    }
}   

# Sleep for 5 seconds, then display new updated value
Start-Sleep -Seconds 5
Write-Output "The latest Group.Unified directory setting value for EnableMIPLabels should show True below"
(Get-MgBetaDirectorySetting | Where-Object { $_.DisplayName -eq "Group.Unified" }).Values
