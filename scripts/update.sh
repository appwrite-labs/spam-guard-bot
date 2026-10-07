#!/usr/bin/env bash
# Updates the bot to the latest code, then reruns the installer, which
# updates dependencies and restarts the service. Keeps your .env.
#
# Usage, as root: /opt/spam-guard-bot/scripts/update.sh

set -euo pipefail

# Everything runs inside main so bash has read the whole script before
# git pull replaces this file.
main() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Error: run this script as root, for example: sudo $0" >&2
    exit 1
  fi

  cd "$(dirname "${BASH_SOURCE[0]}")/.."
  printf '==> Fetching the latest code\n'
  git pull --ff-only
  exec ./scripts/install.sh
}

main "$@"
