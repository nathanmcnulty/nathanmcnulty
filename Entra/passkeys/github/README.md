# GitHub-backed software-passkey adapters

These PowerShell 7 adapters preserve the existing `action-passkey-login` private-key input contract. They are intended for an explicitly authorized development account and trusted workflows. They do not bypass tenant policy, user-verification requirements, or OAuth consent.

**Experimental legacy flow:** registration relies on the baseline's unsupported endpoint flow and synthetic software attestation/presence/verification claims. It does not provide hardware-backed assurance or prove fresh human presence/verification. No live enrollment, upload, or login was validated for this package. The registration adapter requires the explicit `-AllowLegacySoftwareAttestation` opt-in; do not treat that switch as proof of security properties or service support.

## Files and compatibility

- `Register-GitHubPasskeyViaTAP.ps1`: registration adapter with GitHub secret storage, without a plaintext credential JSON file.
- `Export-PasskeyToGitHubSecret.ps1`: dot-source this file to load `Export-PasskeyToGitHubSecret`, which accepts an in-memory credential and an explicit `Repository` in `OWNER/REPO` form.
- `examples/passkey-login.yml.example`: inert example; it is not an installed or enabled workflow.

The paired action source is in [nathanmcnulty/action-passkey-login](https://github.com/nathanmcnulty/action-passkey-login). Its hardened baseline comes from `nathanmcnulty/action-passkey-login`, branch `fix/silent-consent-and-output`. Keep its URL validation, application-client binding, consent-denial behavior, and secret-output cleanup. The separate `research-passkeys` implementation deliberately refuses software-backed assertions when it cannot establish fresh presence/verification; these adapters do not remove that guard.

## Existing secret names

| In-memory field | Repository Actions secret | Action input | Action step environment |
| --- | --- | --- | --- |
| `credentialId` | `PASSKEY_PRIVATE_CREDENTIAL_ID` | `credential-id` | `CREDENTIAL_ID` |
| `userHandle` | `PASSKEY_PRIVATE_USER_HANDLE` | `user-handle` | `USER_HANDLE` |
| `userName` | `PASSKEY_PRIVATE_USER_PRINCIPAL_NAME` | `user-principal-name` | `USER_PRINCIPAL_NAME` |
| `privateKey` | `PASSKEY_PRIVATE_KEY` | `private-key` | `PRIVATE_KEY` |

Keep all four values from the same registration. In particular, do not reuse metadata from a Key Vault-backed passkey with a different software private key. Metadata format checks alone cannot prove that the key belongs to the enrolled credential.

The existing action accepts a base64url credential ID or supported UUID form, a base64url user handle, a UPN, and a private key. This exporter intentionally accepts canonical unpadded base64url IDs only, matching this registration adapter; legacy UUID input must be converted and verified separately. Preserve the registration writer's PKCS#8 PEM representation for export. These are secrets, not committed repository files or ordinary Actions variables.

## Read this before running

Building and testing these files with fixtures does not enroll a credential or upload a key. Actual registration creates persistent authentication access and requires explicit approval. The real private-key upload must be performed by the user in their trusted execution environment; do not paste the key, TAP, or resulting session cookie into chat.

Use a current, already authenticated GitHub CLI and PowerShell 7 in a trusted environment. The exporter targets GitHub.com explicitly and does not create an account, request extra token scopes, or configure credentials for you. Its caller must have permission to set Actions secrets in the exact selected repository.

Do not run with PowerShell transcription, shell command tracing, HTTP/CLI debugging, or a process-monitoring arrangement that records stdin or sensitive process memory. Do not pass a private key or TAP as a shell command-line literal. Keep recovery material only in an approved secure store, never a temporary plaintext file.

## Upload and partial-failure behavior

The exporter validates the whole record before writes, then sends each value to `gh secret set` through redirected stdin, with explicit repository and Actions scope. Values must remain within the script's size limit and GitHub's 48 KB per-secret limit. Secret values must not be put into `--body`, process arguments, logs, or dotenv files.

**The four writes are not atomic.** Before an actual upload, pause every consuming workflow and ensure no run can start until all four writes have succeeded. `-ConsumersPaused` is your acknowledgement of this prerequisite; it does not pause workflows for you. An existing run may already hold an earlier snapshot. Repository secrets are read when a run is queued, so avoid queuing runs during a rotation.

Metadata is written first and the private key last. This ordering is not a transaction or a commit protocol. If any operation fails, stop; only secret names and status should appear in the error. GitHub might have accepted a write whose acknowledgement was lost. No automatic rollback is possible because the API does not reveal the previous plaintext values. Do not restart consumers after a partial/uncertain result. Repair all four values from the same securely retained registration record. Do not blindly register another passkey or delete a working registration.

If the no-file registration adapter exits after an export failure, it does not retain the generated private key for a later retry. Keep consumers paused, inspect and remove only the newly orphaned Entra method after confirming its identity, then perform a fresh authorized registration. Do not delete any older working method blindly.

Use `-WhatIf` to inspect an export plan without secret writes. Use `Get-Help` on the scripts for their exact parameter sets. Do not infer that a failed upload undid a successful Entra enrollment.

The registration parameters are `-TAP` (a `SecureString`), `-UserPrincipalName`, `-TenantId` (GUID), `-Repository`, optional `-DisplayName` (default `Software Passkey`), `-ConsumersPaused`, and `-AllowLegacySoftwareAttestation`. It uses high-impact confirmation; `-WhatIf` validates local inputs without network access or key generation. There is no credential `OutputPath` or credential `PassThru` option. Read a TAP through a secure prompt in your own terminal, not as a command-line literal. SecureString protects the input surface but cannot prevent the authenticated registration implementation from using the TAP in memory.

### User-run secure prompt for the selected repository

After reviewing this package, confirming tenant policy, and actually pausing all consumers, run the following yourself in a trusted PowerShell terminal from this folder. It prompts for the TAP securely and for the tenant GUID; no TAP literal is placed in command history. The final confirmation covers persistent enrollment and replacing the four existing repository secrets. This does not promise that the undocumented enrollment flow will work against the current service.

```powershell
./Register-GitHubPasskeyViaTAP.ps1 -TAP (Read-Host 'Temporary Access Pass' -AsSecureString) -UserPrincipalName (Read-Host 'Development account UPN') -TenantId (Read-Host 'Entra tenant GUID') -Repository (Read-Host 'GitHub OWNER/REPO') -ConsumersPaused -AllowLegacySoftwareAttestation
```

Append `-WhatIf` for a no-network preview. Never run with transcription or HTTP debugging enabled. The TAP is used in process memory only; `SecureString` is not a guarantee against a compromised terminal or process-memory inspection.

For an existing in-memory record, the export interface is:

```powershell
. ./Export-PasskeyToGitHubSecret.ps1
Export-PasskeyToGitHubSecret -Credential $credential -Repository 'OWNER/REPO' -ConsumersPaused -WhatIf
```

Here `$credential` is an already authorized, securely supplied in-memory record, not an instruction to recover a secret from GitHub. A dry run does not authorize or perform the real upload.

## Consuming the secrets

GitHub Actions injects the secrets into the action inputs shown above. `gh secret list` and the REST secret endpoints expose names and timestamps, **not the plaintext values**. There is no supported local `gh secret get` path. A local interactive login therefore needs values provided separately through an authorized secure channel; storing them in GitHub does not make local retrieval possible.

The action obtains an ESTS authenticated session. It does not by itself promise Microsoft Graph/Azure access tokens or that an application grants the intended permissions. The example disables authentication-cookie export. If later steps require it, review that use separately and keep the cookie out of logs, outputs intended for publication, artifacts, and caches.

## Workflow trust boundary

- Use only reviewed code, allowlisted repositories and refs, and immutable action commit SHAs.
- Do not expose passkey secrets to pull-request code, fork code, untrusted `workflow_run` artifacts, or `pull_request_target` checkouts.
- Manual dispatch is useful but is not itself an authorization boundary: repository writers can change code that uses repository secrets.
- Restrict who can write workflows and dispatch trusted runs. Prefer isolated ephemeral runners over shared persistent runners.
- For stronger review gating, deliberately configure protected **environment secrets** and required reviewers. Merely adding `environment:` to a job does not protect repository secrets or create the required controls. This exporter targets repository secrets.
- Scope secrets to the consuming step. Mask derived sensitive values if they could reach logs; automatic redaction is not a security boundary. Do not enable debug logging to investigate authentication failures with live credentials.
- Retain the hardened action's explicit client validation and refusal to grant OAuth permission consent. Never rewrite denied consent into success.

## Offline verification

Tests must use fixtures and mocked processes/network calls only. They should check the four exact names, target validation, stdin transport, no secret values in argv/errors, invalid/oversized input rejection before writes, and failure at each of the four write positions. Verify timeout and uncertain acknowledgement reporting without automatic rollback/deletion. Run the hardened action's existing negative URL/client/consent tests separately.

No live enrollment, real key upload, or real authentication is implied by an offline test pass.

## References

- [GitHub CLI secret set: stdin, app and repository selection](https://cli.github.com/manual/gh_secret_set)
- [GitHub secret limits, names and read timing](https://docs.github.com/en/actions/reference/security/secrets)
- [GitHub secret API: metadata-only retrieval](https://docs.github.com/en/rest/actions/secrets#get-a-repository-secret)
- [GitHub workflow security and log masking](https://docs.github.com/en/actions/reference/security/secure-use)

