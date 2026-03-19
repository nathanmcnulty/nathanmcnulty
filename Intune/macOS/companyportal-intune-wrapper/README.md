# Company Portal AX Installer

This bundle automates installs through the real macOS Company Portal UI.
It does not install apps outside Company Portal.

## Files

- `companyportal-install.sh`: main entrypoint
- `companyportal-install.swift`: AX installer used by the shell wrapper
- `apps.txt`: template for batch installs

## Requirements

- Company Portal must already be installed and signed in.
- The process running the script must have macOS Accessibility permission.
- Fully hidden execution is not supported. The wrapper minimizes disruption by restoring focus after opening or clicking in Company Portal.

## How It Works

1. Opens Company Portal or deep-links to the target app.
2. Uses Accessibility to find the app details view and press the real `Install` button.
3. Watches Company Portal logs to verify the backend install request for GUID-based installs.
4. Optionally waits for `CombinedStatus = Installed`.
5. For batch runs, processes each app in sequence.

## Single App Usage

By GUID and name:

```bash
/bin/zsh ./companyportal-install.sh \
  --app-guid a926d272-e04d-45b9-af37-78b9482ce23f \
  --app-name "Global Secure Access" \
  --verbose
```

By name only:

```bash
/bin/zsh ./companyportal-install.sh --app-name "Global Secure Access"
```

## Batch Usage

With repeated `--app` arguments:

```bash
/bin/zsh ./companyportal-install.sh \
  --app "a926d272-e04d-45b9-af37-78b9482ce23f|Global Secure Access" \
  --app "b37ce405-53a7-430b-84ee-d8c4b7f87fca|Escrow Buddy" \
  --continue-on-error \
  --output json
```

From `apps.txt`:

```bash
/bin/zsh ./companyportal-install.sh \
  --apps-file ./apps.txt \
  --continue-on-error \
  --settle-delay 2 \
  --output intune
```

## Useful Flags

- `--wait-for-installed`: wait until logs show `Installed` for each GUID-based app
- `--continue-on-error`: continue the batch if one app fails
- `--settle-delay <sec>`: pause briefly between apps
- `--no-return-focus`: leave Company Portal frontmost
- `--output text|json|intune`: choose output format
- `--verbose`: print progress messages

## Output

- `text`: human-readable summary
- `json`: machine-readable result, including per-app items for batch runs
- `intune`: flat key=value output suitable for collection

## Recommended Pattern

- Use GUIDs whenever possible.
- Run several apps in one batch rather than separate invocations.
- Use `--continue-on-error` for best-effort batches.
- Use `--wait-for-installed` only when you have enough timeout budget.
