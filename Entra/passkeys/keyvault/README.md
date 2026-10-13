# Key Vault-backed passkey commands

Use PowerShell 7.6. These are standalone generated scripts from research-passkeys,
source package 0.1.0; the [parent guide](../README.md) explains ownership and limitations.

- Initialize-PasskeyKeyVault.ps1: explicit Azure/Graph provisioning; use -WhatIf first
- New-KeyVaultPasskey.ps1: Graph application-permission software registration, optionally -UseKeyVault
- Register-KeyVaultPasskeyViaTAP.ps1 / ViaESTSAuth.ps1: native Key Vault registration
- PasskeyLogin.ps1: local/software or Key Vault login

Initialization can grant permissions and create persistent client credentials; read the
confirmation/help before running. Secret creation requires -PassThru before provisioning,
or use -SkipSecret/-SkipServicePrincipal. Default -WhatIf still previews without I/O.
Secrets are not printed. Registration forwards ClientSecret as SecureString for the supported pipeline.
Software credential output requires a new file, with mode 0600 on Unix; on Windows use
a private directory. Key Vault record OutputPath retains its explicit overwrite behavior.
A confirmed-enrollment/write failure reports partial completion without rollback.

Key Vault key references retain their registered version and reject conflicting hosts,
metadata and redirects. Manual unversioned key names are not rotation-safe. Premium vault
capability does not mean keys created as EC are HSM-backed. Key Vault protects signing key
material but does not prove user presence or verification. Entra policy may reject software
assertions; no OAuth consent is automated. Offline tests do not establish live acceptance.

Use Get-Help on the downloaded script for its named inputs and examples. Get the Passkey
module and maintained source from the coordinated research change, not this distribution folder.
