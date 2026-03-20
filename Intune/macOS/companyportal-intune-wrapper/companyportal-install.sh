#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
SWIFT_SCRIPT="$SCRIPT_DIR/companyportal-install.swift"
LOG_FILE="${TMPDIR:-/tmp}/companyportal-install-wrapper.log"

usage() {
  cat <<'EOF'
Usage:
  companyportal-install.sh --app-guid <guid> [--app-name <name>] [--wait-for-installed] [--output json] [--verbose]
  companyportal-install.sh --app-name <name> [--output json] [--verbose]
  companyportal-install.sh --app <spec> [--app <spec> ...] [--continue-on-error]
  companyportal-install.sh --apps-file <path> [--continue-on-error]

Batch app format:
  --app <guid>
  --app "Display Name"
  --app "<guid>|Display Name"

Notes:
  - This wrapper launches the Swift AX installer and writes a deployment log to:
      ${TMPDIR:-/tmp}/companyportal-install-wrapper.log
  - Company Portal must already be signed in.
  - The executing process must have macOS Accessibility permission.
  - By default the wrapper restores focus back to the prior frontmost app after opening or clicking in Company Portal.
EOF
}

if [[ $# -eq 0 ]]; then
  usage
  exit 2
fi

if [[ ! -f "$SWIFT_SCRIPT" ]]; then
  echo "error: Missing Swift installer at $SWIFT_SCRIPT" >&2
  exit 1
fi

if ! command -v swift >/dev/null 2>&1; then
  echo "error: swift is not available on this Mac." >&2
  exit 1
fi

timestamp() {
  /bin/date '+%Y-%m-%d %H:%M:%S'
}

echo "[$(timestamp)] Starting Company Portal install wrapper" >> "$LOG_FILE"
echo "[$(timestamp)] Arguments: $*" >> "$LOG_FILE"

set +e
/usr/bin/env swift "$SWIFT_SCRIPT" "$@" 2>&1 | tee -a "$LOG_FILE"
status=${pipestatus[1]}
set -e

echo "[$(timestamp)] Wrapper exit code: $status" >> "$LOG_FILE"
exit "$status"
