(Get-ChildItem -Path C:\Users).FullName | Where-Object { $_ -ne "C:\Users\Public" } | ForEach-Object {
    $FolderPath = "$_\AppData\Local\AnyDesk"
    # Create folder and set permissions
    try {
        # Create the folder if it doesn't exist
        if (-not (Test-Path -Path $FolderPath)) { New-Item -Path $FolderPath -ItemType Directory -ErrorAction Stop | Out-Null }

        # Get the current ACL
        $acl = Get-Acl -Path $FolderPath

        # Create a new access rule to deny read access to Users group
        $usersGroup = New-Object System.Security.Principal.NTAccount("Users")
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $usersGroup,
            "FullControl",  # Deny read permissions
            "ContainerInherit,ObjectInherit",  # Apply to folder and sub-objects
            "None",  # No propagation flags
            "Deny"   # Deny rule
        )

        # Add the deny rule to the ACL
        $acl.SetAccessRule($accessRule)

        # Apply the modified ACL to the folder
        Set-Acl -Path $FolderPath -AclObject $acl -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to create folder or set permissions. Error: $_"
    }
}