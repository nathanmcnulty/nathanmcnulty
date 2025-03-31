# Disable LSO Offload for VMware VMs
# https://learn.microsoft.com/en-us/defender-for-identity/troubleshooting-known-issues#vmware-virtual-machine-sensor-issue
Get-ADGroupMember -Identity "Domain Controllers" | ForEach-Object { 
   Invoke-Command -ComputerName $_.Name -ScriptBlock { Get-NetAdapterAdvancedProperty | Where-Object DisplayName -Match "^Large*" | Disable-NetAdapterLso }
}
