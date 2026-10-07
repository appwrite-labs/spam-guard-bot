#!/usr/bin/env bash
# Installs the bot as a systemd service, or reapplies the install after an
# update. Safe to run again at any time: it skips what is already done and
# keeps your .env.
#
# Usage, as root: /opt/spam-guard-bot/scripts/install.sh
#
# Installs Node.js 22 with apt (Ubuntu or Debian) if Node.js 20 or later is
# missing, and pnpm with npm if it is missing.

set -euo pipefail

SERVICE_NAME="spam-guard-bot"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
NODE_MAJOR=22
MIN_NODE_MAJOR=20

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nError: %s\n' "$*" >&2; exit 1; }

check_memory() {
  local memory_mb
  memory_mb="$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo 2>/dev/null || echo 0)"
  if [ "$memory_mb" -gt 0 ] && [ "$memory_mb" -lt 3500 ]; then
    echo "Warning: this server has ${memory_mb} MB of RAM. Reading images can use"
    echo "about 2.3 GB, so 4 GB is recommended."
  else
    echo "OK (${memory_mb} MB)."
  fi
}

install_node() {
  if command -v node >/dev/null 2>&1 &&
    [ "$(node -p 'process.versions.node.split(".")[0]')" -ge "$MIN_NODE_MAJOR" ]; then
    echo "Node.js $(node -v) is already installed."
    return
  fi

  command -v apt-get >/dev/null 2>&1 ||
    fail "Node.js ${NODE_MAJOR} is required. Install it, then run this script again."

  apt-get update
  apt-get install -y ca-certificates curl
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
  apt-get install -y nodejs
  echo "Installed Node.js $(node -v)."
}

install_pnpm() {
  if command -v pnpm >/dev/null 2>&1; then
    echo "pnpm is already installed."
    return
  fi

  npm install -g pnpm@10
}

configure_env() {
  if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example."
  fi
  chmod 600 .env

  if grep -Eq '^DISCORD_TOKEN=[^[:space:]]+' .env; then
    echo "DISCORD_TOKEN is set."
    return
  fi

  [ -t 0 ] || fail "Set DISCORD_TOKEN in ${BOT_DIR}/.env, then run this script again."

  local token
  read -r -s -p "Paste the bot token (it stays hidden), then press Enter: " token
  echo
  [[ "$token" =~ ^[A-Za-z0-9._-]+$ ]] || fail "That does not look like a bot token."

  # Pass the token through the environment, not the command line, so it does
  # not show up in the process list.
  (
    umask 077
    TOKEN="$token" awk '
      /^DISCORD_TOKEN=/ { print "DISCORD_TOKEN=" ENVIRON["TOKEN"]; found = 1; next }
      { print }
      END { if (!found) print "DISCORD_TOKEN=" ENVIRON["TOKEN"] }
    ' .env > .env.tmp
  )
  mv .env.tmp .env
  chmod 600 .env
  echo "Saved the token to .env."
}

install_service() {
  local node_path
  node_path="$(command -v node)"

  sed -e "s|@BOT_DIR@|${BOT_DIR}|g" -e "s|@NODE@|${node_path}|g" \
    deploy/spam-guard-bot.service > "$SERVICE_FILE"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  # Clear systemd's restart limit in case an earlier start failed repeatedly.
  systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
  systemctl restart "$SERVICE_NAME"
  echo "Installed ${SERVICE_FILE} and started the bot."
}

show_status() {
  sleep 10
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "The bot is running. Recent logs:"
  else
    echo "The bot is not running. Check the logs below, fix the problem, and run"
    echo "this script again."
  fi
  journalctl -u "$SERVICE_NAME" -n 15 --no-pager || true
}

main() {
  [ "$(id -u)" -eq 0 ] || fail "Run this script as root, for example: sudo $0"
  command -v systemctl >/dev/null 2>&1 || fail "This script needs systemd."

  BOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  cd "$BOT_DIR"

  step "Checking memory"
  check_memory
  step "Checking Node.js"
  install_node
  step "Checking pnpm"
  install_pnpm
  step "Installing dependencies"
  pnpm install --prod --frozen-lockfile
  step "Fingerprinting known scam images"
  pnpm build:visual-references
  step "Checking settings (.env)"
  configure_env
  step "Installing the ${SERVICE_NAME} service"
  install_service
  step "Checking the bot"
  show_status

  cat <<EOF

Done. Useful commands:
  systemctl status ${SERVICE_NAME}      Is the bot running?
  journalctl -u ${SERVICE_NAME} -f      Watch the logs (Ctrl+C to stop watching)
  ${BOT_DIR}/scripts/update.sh          Update to the latest version

Settings are in ${BOT_DIR}/.env. After changing them, run:
  systemctl restart ${SERVICE_NAME}
EOF
}

main "$@"
