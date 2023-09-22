$lapsAdmin = "LAPSAdmin"
if (!(Get-LocalUser -Name $lapsAdmin -ErrorAction SilentlyContinue)) {
   [securestring]$password = ConvertTo-SecureString -String (New-Guid) -AsPlainText -Force
   New-LocalUser $lapsAdmin -Password $password
   Add-LocalGroupMember -Group "Administrators" -Member $lapsAdmin
}
