# 0 - Nonprivileged users on the device can disable and enable the client.
# 1 - Nonprivileged users on the device are restricted from disabling and enabling the client.
$restrictNonPrivilegedUsers = 0

# 0 - Show the Sign out action, useful for scenarios where a user needs to sign in to the client with a different Entra user than the one signed in to Windows.
# 1 - Hide the Sign out action.
$HideSignOutButton = 1

# 0 - Show the Disable Private Access action.
# 1 - Hide the Disable Private Access action.
$HideDisablePrivateAccessButton = 1

# 0 - Show the Disable action. When visible, the user can disable the Global Secure Access client.
# 1 - Hide the Disable action.
$HideDisableButton = 0

try {
    # Check agent settings
    "RestrictNonPrivilegedUsers","HideSignOutButton","HideDisablePrivateAccessButton","HideDisableButton" | ForEach-Object {
        # Check values
        if ((Get-ItemProperty -Path "HKLM:\Software\Microsoft\Global Secure Access Client" -Name $_ -ErrorAction SilentlyContinue).$_ -ne (Get-Variable $_).value) {
            Write-Output "Registry value for $_ is incorrect"
            exit 1
        } 
    }

    # Check Prefer IPv4 over IPv6
    if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents -ne 32) {
        Write-Output "Registry value for DisabledComponents is incorrect"
        exit 1
    }
    
    Write-Output "Registry values are correct"
    exit 0
} catch {
    Write-Warning "Failed to read values"
    exit 1
}