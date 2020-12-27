# Abort if user is a local administrator
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { break }

# Get sytem paths
(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path.Split(";") | ForEach-Object {
    # Test creating a file
    Try {
        if ([io.file]::OpenWrite("$_\test").close()) { $paths += $_ }
    } catch {}
}

# Write ACL of discovered vulnerable paths
if ($paths)  { $paths | Get-Acl | Format-List }