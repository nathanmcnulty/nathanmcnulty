# Login compatibility migration

## Canonical ownership

The maintained source is now `research-passkeys/github/action-passkey-login`. Both public personal login paths are deterministic generated compatibility variants, with unchanged bytes relative to personal draft head `956075f678e25fcbbf5e72b5b42141da9ed33554`. Edit the action implementation first, render and test the personal variants, then export using the explicit manifest. The guarded research reference login remains separate and unchanged.

## Original hardening baselines and scope

- Action baseline: `fix/silent-consent-and-output`, commit `d443b0d18fe3a9cf162811bd67a67b9dec77a7e7` (main plus its six-file overlay).
- Personal baseline: `main`, commit `1c0a52f339915b70e637d727edbaa0a9dd81fe17`.
- Research baseline: `7810619034d73b7061920ecfe17458cf112ad694`, read only. Its intentionally unsupported assertion paths and trusted-user-presence requirement remain untouched.
- The original hardening shared the action login implementation by selective copy into both personal standalone login scripts; the canonical layout now generates those variants deterministically. This draft promotes the reviewed changes onto the pinned personal baseline; no live enrollment, authentication, deployment, or secret upload was performed.

## Changes retained

1. Reject arbitrary Key Vault bearer-token destinations before token acquisition. Public Azure vault hostname, HTTPS, standard port, no userinfo/query/fragment, and `/keys/name[/32-hex-version]` are required. Validate the raw URL so URI normalization cannot conceal escaped/dot segments. Reject inconsistent vault/key metadata rather than silently overriding it. Validate again at signing and prohibit signing redirects.
2. Sign the exact stored key version. Existing unversioned manual names/URLs remain accepted for compatibility; those still select the current key version and are not rotation-safe. Preserve a versioned `keyId` from registration whenever available.
3. Reject null/non-object JSON and malformed known property types before network activity. Support `username`/`userName`/`userPrincipalName`, `relyingParty`/`rpId`, `privateKey`/`keyValue`, and `signCount`/`counter`; keep unrelated registration metadata. Accept string/SecureString manual private keys. Counters cover the uint32 range. Partial files may still use manual fallbacks; resolved required values are checked before login.
4. Use BSTR-specific SecureString conversion and free the unmanaged buffer. Avoid server/error-body and identifier/cookie-prefix logging. This does not make ordinary PowerShell strings zeroizable; do not log or persist exported cookies/private keys.
5. Select nonempty, secure, unexpired ESTS cookies only for the exact trusted login domains. No matching cookie returns `Success = false`; foreign ESTS-named cookies cannot claim success.
6. Initialize invocation and interrupt state. Allow bounded repeated ConvergedSignIn (10 total iterations), preserve application-confirmation denial by default, and pin its returned login URL to the Microsoft login origin. Handle absent `arrSessions` and encode its session identifier.
7. Retain the action fix branch's explicit client-bound application confirmation and exact AuthUrl origin validation. Validate AuthUrl before acquiring a Key Vault token. This is not OAuth permission-consent automation.

## Personal-script compatibility and intentional changes

Both personal paths preserve all prior named parameters, `UserName`, and original positional argument positions. `CredentialId` remains the personal canonical name; `CredentialIdentifier` is also accepted. The nested script preserves `CredentialFromPipeline` binding and registration-file handoff. PrivateKey accepts its former string (root) and SecureString (nested) inputs. Existing JSON aliases remain readable.

Security-related changes requiring caller review:

- Cookies and web sessions no longer populate globals by default. This is an intentional breaking behavior for callers relying on implicit `$global:ESTSAUTH` / `$global:webSession`. Opt in with `-PersistSessionToGlobalScope`; the personal copies then set both the legacy `ESTSAUTH` alias and `ESTSCookie`. Personal `TokenVariable` metadata remains `ESTSAUTH` when opted in. Action output names are unchanged.
- `-PassThru` returns metadata; `-IncludeAuthenticationCookie` additionally returns the cookie value. Do not send the resulting object to logs or artifacts.
- The default callback changes from the unsigned-app custom URI to Microsoft's HTTPS native-client callback, matching the action fix baseline. Client ID, scopes, RP, user-agent defaults and input purpose are retained.
- Application confirmation requires `-ConfirmApplication` and a matching `-ExpectedClientId`; unattended confirmation is denied by default.
- Invalid/null credential properties, ambiguous/mismatched KV metadata, non-public-Azure vault endpoints, nonstandard ports, and malformed versions now fail closed. Do not strip a stored key version to bypass these errors.
- Original root parameter-set metadata is consolidated into runtime validation. Named/positional calls are retained, but code inspecting exact parameter-set names must migrate.

Prefer explicit result handling:

```powershell
$result = .\PasskeyLogin.ps1 -KeyFilePath .\passkey.json -PassThru -IncludeAuthenticationCookie
if (-not $result.Success) { throw 'No verified ESTS session cookie' }
# Pass $result.AuthenticationCookieValue only to its intended ESTS-cookie consumer.
```

Temporary compatibility for old in-process consumers:

```powershell
.\PasskeyLogin.ps1 -KeyFilePath .\passkey.json -PersistSessionToGlobalScope
# Legacy $global:ESTSAUTH and $global:webSession are now explicitly requested.
```

These results are ESTS session cookies, not OAuth access tokens. They do not log Azure CLI or Microsoft Graph PowerShell in, redeem authorization codes, or populate CLI token caches.

## Intentional unresolved security/protocol differences

The personal/action software-signing path remains a legacy automation implementation. Its authenticator flags still claim UP/UV without fresh authenticator-bound evidence; Key Vault protects the signing key but does not establish user presence or user verification. This update does not convert it into a compliant authenticator, remove a Conditional Access requirement, or prove Microsoft server acceptance. The research repository's stricter assertion denial stays intact. Registration attestation and broker/token redesign were not mixed into this login patch.

No live Entra or Key Vault operation was run. Offline tests prove client-side validation/control flow only. Existing response/redirect behavior beyond the targeted Key Vault, AuthUrl and ConvergedSignIn boundaries was not comprehensively redesigned or live-certified. Sovereign Azure clouds are intentionally unsupported by this public-Azure audience/host policy.

## Offline verification

PowerShell 7.6.6 and Pester 6.2.0, with HTTP/token calls mocked. No real credentials or real TAP test account was used. From the personal repository root, run its 48 standalone login/compatibility cases:

```powershell
$r = Invoke-Pester -Path ./Entra/passkeys/tests -Output Detailed -PassThru
if ($r.FailedCount) { exit 1 }
```

The 56 GitHub adapter cases now live only in research-passkeys. From the research repository root, run:

```powershell
$r = Invoke-Pester -Path ./github/adapters/tests -Output Detailed -PassThru
if ($r.FailedCount) { exit 1 }
```

The personal focused suite includes consent/output tests, hostile URL variations, exact-version signing and no redirect forwarding, malformed credential data, SecureString conversion, cookie trust/expiry, no-cookie false results, bounded interrupt processing, and personal alias/position/pipeline compatibility. The former combined personal layout had 104 cases; after relocation, 48 remain in personal and 56 are maintained under research `github/adapters/tests`. Tests are evidence for local review only; live authentication requires separate approval.

## Draft promotion ledger

- Original hardening baseline: personal `main` at `1c0a52f339915b70e637d727edbaa0a9dd81fe17`.
- Canonical reorganization inputs: personal draft `956075f678e25fcbbf5e72b5b42141da9ed33554`, Action draft `2688294bb0f0fcb230df071eb226f2549ec82280`, research draft `ab7672dc891d4fd7c314c59a7d3f56120d61e4ad`.
- Personal branch: `codex/passkey-github-and-login-hardening-20261011`.
- Hypothesis: retain the existing public standalone paths while maintaining shared login runtime and GitHub adapters in research, with deterministic compatibility generation and explicit byte/hash export.
- Decision: keep for draft review. Independent mapping/enforcement review passed. The relocated personal suite passed 48/48 and the research adapter suite passed 56/56 on 2026-10-11 (PowerShell 7.6.6, Pester 6.2.0, Linux). Both generated personal login files match the pre-reorganization draft bytes.
- Proof: the separate commands above exercise the current repository layouts. Adapter Unix subprocess fixtures were executed; Windows subprocess transport was not.
- Hosted/live proof: not performed for this source alignment. No real registration, login, Key Vault token acquisition, repository-secret upload, or workflow dispatch was performed. Offline results cannot establish live server acceptance.
- Scope: GitHub adapters have moved to research; personal legacy root/Key Vault registration paths remain. Compatible initializer/software registration is generated from current research references; incompatible historical registrations are preserved and labeled. See [README.md](README.md) for imported-versus-updated scope and notification source alignment.
