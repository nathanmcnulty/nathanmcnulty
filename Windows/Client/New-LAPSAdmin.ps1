if (!(Get-LocalUser -Name "LAPSAdmin" -ErrorAction SilentlyContinue)) {
   [securestring]$password = ConvertTo-SecureString -String (New-Guid) -AsPlainText -Force
   New-LocalUser "LAPSAdmin" -Password $password
   Add-LocalGroupMember -Group "Administrators" -Member "LAPSAdmin"
}
