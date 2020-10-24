[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    $Server,
    [Parameter(Mandatory = $true)]
    $GroupName
)

Invoke-Command -ComputerName $Server -ScriptBlock {
    # Get current members
    $members = Get-CimInstance -ClassName Win32_GroupUser -Filter "GroupComponent=""Win32_Group.Domain='$env:COMPUTERNAME',Name='Administrators'"""| ForEach-Object { $_.PartComponent.ToString().Split(",")[0].Split('"')[1] }
    
    if ($GroupName -notin $members) {
        ([ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group").Invoke('Add', "WinNT://$env:USERDOMAIN/$GroupName")
    } else { 
        Write-Output "The group is already in the administrators group"
    }
}