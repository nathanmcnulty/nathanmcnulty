Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" | ForEach-Object { 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\$($_.PSChildName)" -Name NetbiosOptions -Value 2 -Verbose 
}