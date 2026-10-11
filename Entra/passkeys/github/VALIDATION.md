# Offline validation report

2026-10-11, PowerShell 7.6.6, Pester 6.2.0, Linux.

- PowerShell parser: all 5 implementation/test `.ps1` files passed.
- `GitHubPasskey.Tests.ps1`: 46 passed; exact schema and names, key validation, all-inputs-before-write, canonical base64url, oversize/type rejection, WhatIf and acknowledgement boundaries, every partial-write position, controlled error output, registration-origin and final-response binding checks.
- `RegistrationFlow.Tests.ps1`: 6 passed; entire registration adapter with synthetic HTTP responses and a local fake gh process. Success writes exactly four established names, private key last; mismatched OAuth state, consent form, mismatched credential, HTTP error and protocol error all stop before secret writes. The success result and fake process arguments contain no synthetic TAP/token/private-key values.
- `GitHubCli.Tests.ps1`: 4 passed; exact synthetic stdin, child stdout/stderr discarded, controlled process failures, bounded no-stdin-reader timeout and bounded descendant-held output pipes. These shell subprocess fixtures are Unix-only; Windows transport was not executed.
- Total: **56 passed, 0 failed, 0 skipped** in the final local run.

Command from this repository root, with PowerShell/Pester already installed:

```powershell
Invoke-Pester -Path ./Entra/passkeys/github/tests -Output Detailed
```

An independent reviewer additionally reran the earlier 52-test suite and independently reproduced the corrected descendant-pipe deadline with a 1-second setting (about 1.15 seconds observed). Four subprocess tests were then added to the maintained suite.

## Changes made after review

- Enrollment export requires a successful 2xx verification response, successful state, no nonzero protocol error, and exactly one credential ID matching the generated credential.
- Authorization callback checks exact trusted origin/path, one code and one state, and exact state matching. Unknown/consent form pages fail closed; only named KMSI continuations can submit a form.
- gh has a single deadline spanning asynchronous stdin, flushing, process wait, and stdout/stderr drains. Streams are discarded rather than buffered and never included in errors.
- Credential inputs are validated without PowerShell's single-element array unwrapping accidentally accepting an array as a string.

## Limits

No actual TAP, enrollment, Microsoft authentication, GitHub secret write, workflow dispatch, or token acquisition occurred. No generated test key or temporary fake-gh trace is part of this deliverable.

Live compatibility is unknown. The registration adapter is a separate experimental legacy path using undocumented endpoints and synthetic attestation/UP/UV claims; explicit opt-in does not establish real user presence or verification. Research's fail-closed software-assertion guard remains unchanged. Exact-origin/redirect restrictions intentionally prefer failure over forwarding credentials to unexpected destinations.

Four secret writes are non-atomic. The real uploader must be run by the user in their trusted environment. No-file enrollment failure recovery may require inspecting and removing a newly orphaned method before authorized re-enrollment; no automatic credential retention or rollback is provided.
