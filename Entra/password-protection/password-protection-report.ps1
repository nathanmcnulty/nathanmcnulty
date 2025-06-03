# Define event IDs and their descriptions based on the Microsoft documentation
$eventIds = @(10014, 10015, 30002, 30003, 30004, 30005, 30007, 30008, 30009, 30010, 30021, 30022, 30023, 30024, 30026, 30027, 30028, 30029)

$eventInfo = @{
    10014 = "Pass - Password Change"
    10015 = "Pass - Password Set"
    30002 = "Fail - Password Change (Failure Reason: Customer Policy)"
    30003 = "Fail - Password Set (Failure Reason: Customer Policy)"
    30004 = "Fail - Password Change (Failure Reason: Microsoft Policy)"
    30005 = "Fail - Password Set (Failure Reason: Microsoft Policy)"
    30007 = "Audit-only Pass - Password Set (Failure Reason: Customer Policy)"
    30008 = "Audit-only Pass - Password Change (Failure Reason: Customer Policy)"
    30009 = "Audit-only Pass - Password Set (Failure Reason: Microsoft Policy)"
    30010 = "Audit-only Pass - Password Change (Failure Reason: Microsoft Policy)"
    30021 = "Fail - Password Change (Failure Reason: User Name)"
    30022 = "Fail - Password Set (Failure Reason: User Name)"
    30023 = "Audit-only Pass - Password Set (Failure Reason: User Name)"
    30024 = "Audit-only Pass - Password Change (Failure Reason: User Name)"
    30026 = "Fail - Password Change (Failure Reason: Combined Policy)"
    30027 = "Fail - Password Set (Failure Reason: Combined Policy)"
    30028 = "Audit-only Pass - Password Change (Failure Reason: Combined Policy)"
    30029 = "Audit-only Pass - Password Set (Failure Reason: Combined Policy)"
}

# Initialize array to store results
$allEvents = @()

# Get events from each DC
(Get-ADGroupMember -Identity "Domain Controllers" | Get-ADComputer).DnsHostName | ForEach-Object {
    Write-Host "Collecting events from $($_.Name)..."
    try {
        Get-WinEvent -ComputerName $_ -FilterHashtable @{LogName = 'Microsoft-AzureADPasswordProtection-DCAgent/Admin'; ID = $eventIds} -ErrorAction Stop | ForEach-Object {
            $_
            $allEvents += [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                UserName = $_.Properties[0].Value
                FullName = $_.Properties[1].Value
                EventID = $_.Id
                Description = $eventInfo[$_.Id]
                DC = $_.MachineName
                Message = $_.Message
            }
        }
    }
    catch {
        Write-Warning "Failed to collect events from $($_.Name): $_"
    }
}

# Output the results
$allEvents | Sort-Object TimeCreated | Format-Table -AutoSize