#Requires -Modules ActiveDirectory
<#
.Synopsis
    Set staff photos in Office 365
.DESCRIPTION
    Takes staff photos using employeeid.jpg and pushes them into the user in Office 365
.NOTES
    Read the synopsis... or the description
#>

# Location of log file and credential file (created by Get-Credential | Export-CliXml using the account used to run the scheduled task)
[string]$logfile = "C:\scripts\logs\$(Get-Date -Format yyyy.MM)-Set-StaffPhotos.log"
[string]$credentialfile = "C:\scripts\credentials\exo-scripts.xml"

# Picture variables
[string]$ADGroup = "All Company"
[string]$path = "C:\Pictures"
[string]$pictures = (Get-ChildItem -Path $path).BaseName

# Email variables
[string]$To = "user@domain.com"
[string]$From = "user@domain.com"
[string]$smtpServer = "mail.domain.com"

function TimeStampLog {
	param (
		[string] $message
	)
	process { Add-Content -Path $logfile -Value "$(Get-Date -Format G)`t$message" }
}

$starttime = Get-Date
TimeStampLog "Started Staff Photo Upload script"
Import-Module ActiveDirectory

try { 
    if (Test-Path -Path $credentialfile) { $creds = Import-Clixml $credentialfile } else { TimeStampLog "No credential file found. Prompting for credentials"; $creds = Get-Credential }
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/?proxyMethod=RPS -Credential $creds -Authentication Basic -AllowRedirection
    Import-PSSession $Session -DisableNameChecking
} catch { TimeStampLog "Failed to connect to Exchange Online PowerShell Session" }
if ($session.State -eq "Opened") { TimeStampLog "Connected to Exchange Online PowerShell Session" } else { TimeStampLog "Failed to connect to Exchange Online PowerShell Session"; exit }

(Get-ADGroup -Identity $ADGroup -Properties Member).Member | Get-ADUser -Properties employeeID | Select-Object employeeID,name | ForEach-Object { 
    if ($_.employeeID -in $pictures) {
        $userpic = ([Byte[]] $(Get-Content -Path "$path\$($_.employeeID).jpg" -Encoding Byte -ReadCount 0))
        while ((Get-Job -State Running).Count -gt 15) { Start-Sleep -Seconds 5 }
        Start-Job -Name $_.employeeID -ScriptBlock { Set-UserPhoto -Identity "$($_.Name)@domain.com" -PictureData $userpic -Confirm:$false -Verbose }
    } else { TimeStampLog "No photo for $($_.Name)" }
}

$endtime = Get-Date
TimeStampLog "Completed Staff Photo Upload script"
Send-MailMessage -To $To -From $From -Subject "Staff Photo Job Complete" -SmtpServer $smtpServer -Body "Started at $starttime. Ended at $endtime."