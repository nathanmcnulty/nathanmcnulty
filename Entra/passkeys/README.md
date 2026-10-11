# Preserved public passkey entry points

The original `nathanmcnulty/Entra/passkeys` URLs remain available. [research-passkeys](https://github.com/nathanmcnulty/research-passkeys) is now the source of truth; this folder is maintained there and exported to the personal repository. See its [exact ownership and migration map](https://github.com/nathanmcnulty/research-passkeys/blob/main/docs/migration/personal-passkeys-map.md).

## Updated and generated files

- `PasskeyLogin.ps1` and `keyvault/PasskeyLogin.ps1` are generated from the maintained legacy action implementation. Their original positional signatures differ, so the generated variants preserve each signature, the credential-ID alias, and the explicitly opted-in `ESTSAUTH` session alias. The generation starts from one implementation; do not edit generated copies. See [LOGIN-MIGRATION.md](LOGIN-MIGRATION.md) for already-reviewed behavioral changes.
- `keyvault/Initialize-PasskeyKeyVault.ps1` and `keyvault/New-KeyVaultPasskey.ps1` are generated from the current research reference counterparts, adapting only renamed script references in help/examples/output. The registration script gains the existing research SecureString conversion fixes. No runtime module dependency was added; both references are standalone.
- `notifications/` is exported from research `samples/notifications`. Its updated template/query covers synced passkeys and Windows Hello and deduplicates companion events. The PowerShell deployment helper and template parameters are unchanged. This is source alignment only, not a deployment.

## Preserved historical experiments

The root TAP/ESTS registrations, TAP-cookie helper, metadata script, and Key Vault TAP/ESTS registrations are imported historical compatibility sources. Their public paths and script behavior are preserved; this is an ownership change, not a claim they have been upgraded to the guarded research implementation.

**Warning:** historical registration scripts synthesize software attestation/presence/verification claims. They are not hardware authenticators and are not newly security-certified. Do not run their old examples as validation. The maintained GitHub adapter has a separate explicit legacy-flow opt-in. Real authentication, credential creation, upload, permissions, and deployment require their own review.

The guarded research reference paths intentionally deny unsupported software assertions and retain none attestation where synthetic attestation was removed. Those protections are not replaced by these compatibility sources.

`Register for Authenticator App Passkey.docx` remains an unchanged historical guide at its existing personal-repository URL. It is explicitly excluded from script synchronization. The GitHub adapters added only in the draft have moved to [research github/adapters](https://github.com/nathanmcnulty/research-passkeys/tree/main/github/adapters); no previously published legacy script is removed.
