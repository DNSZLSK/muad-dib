#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/muaddib"
LOG_FILE="/var/log/muaddib-update.log"
BRANCH="master"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

cd "$INSTALL_DIR"

git fetch origin "$BRANCH" 2>/dev/null

LOCAL_SHA=$(git rev-parse HEAD)
REMOTE_SHA=$(git rev-parse "origin/$BRANCH")

if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
  log "No update available (SHA: ${LOCAL_SHA:0:8})"
  exit 0
fi

log "Update found: ${LOCAL_SHA:0:8} -> ${REMOTE_SHA:0:8}"

git pull origin "$BRANCH" >> "$LOG_FILE" 2>&1
npm ci --production >> "$LOG_FILE" 2>&1
systemctl restart muaddib-monitor

log "Update complete — muaddib-monitor restarted"
