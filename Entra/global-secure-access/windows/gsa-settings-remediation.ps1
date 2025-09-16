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
    # Set agent settings
    "RestrictNonPrivilegedUsers","HideSignOutButton","HideDisablePrivateAccessButton","HideDisableButton" | ForEach-Object {
        # If key doesn't exist, create it
        if (-not (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Global Secure Access Client" -Name $_ -ErrorAction SilentlyContinue)) {
            # Create the value
            New-ItemProperty -Path "HKLM:\Software\Microsoft\Global Secure Access Client" -Name $_ -Value (Get-Variable $_).value -Type DWord -Force | Out-Null
        } else {
            # Set the value
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Global Secure Access Client" -Name $_ -Value (Get-Variable $_).value -Type DWord -Force
        }
    }

    # Set Prefer IPv4 over IPv6
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 32 -Type DWord -Force

    Write-Output "Registry values set successfully"
    exit 0
} catch {
    Write-Warning "Failed to set values"
    exit 1
}