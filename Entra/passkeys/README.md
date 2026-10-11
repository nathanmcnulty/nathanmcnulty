# Standalone passkey commands

These public script URLs are preserved as generated, self-contained files from
[research-passkeys](https://github.com/nathanmcnulty/research-passkeys). Use PowerShell 7.6.
Maintained source functions build into both these scripts and the Passkey module.
Source package version: 0.1.0. Do not edit generated scripts.

Review the coordinated source change in [research draft #33](https://github.com/nathanmcnulty/research-passkeys/pull/33),
including its `powershell/BUILD.md` usage/build/distribution guide. Downstream PRs record
the exact reviewed source commit. The module and source belong in research.
Unit tests and named-parameter/alias compatibility checks are maintained in research;
this repository contains samples and generated standalone scripts, with no passkey test exports.

`PasskeyLogin.ps1` and `keyvault/PasskeyLogin.ps1` have identical bytes. Both local/software
and Key Vault signing are available; use named arguments, including CredentialId and
UserName aliases, rather than relying on the former differing positional signatures.
Legacy software UP/UV bits are synthesized claims, not proof of fresh user presence or
verification. Policies may reject them. The cookie is returned only when explicitly asked.

TAP/ESTS registrations use explicit commands and verified registration before persistence.
Native software registration uses packed attestation with a synthetic self-signed batch
certificate; Key Vault registration uses none. These unattended implementations are not
FIDO-certified authenticators and do not perform authenticator presence or verification.
One limitations warning accompanies each actual login/registration; no acceptance switch is required.
Genuine authentication failure diagnostics retain warning severity.
GitHub is separate secret transport, not a signer.

`Get-ESTSAuthCookieViaTAP.ps1` requires a secure TAP, UPN and tenant ID, with no embedded
credentials. Its default cookie result is SecureString; `-AsPlainText` returns the raw string.
Metadata output is informational and unverified. Read each script's Get-Help before running.

The original DOCX and unrelated public content remain unchanged. Notifications retain
existing source alignment; no deployment, enrollment or live authentication was performed.
