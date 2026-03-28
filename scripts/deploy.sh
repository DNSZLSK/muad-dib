#!/bin/bash
# MUAD'DIB — Deploy script for VPS
# Usage: bash scripts/deploy.sh
#
# Configurable via environment:
#   MUADDIB_DIR       Base directory (default: /opt/muaddib)
#   MUADDIB_SERVICE   Systemd service name (default: muaddib-monitor)
#   DEPLOY_USER       Owner user (default: ubuntu)

set -euo pipefail

MUADDIB_DIR="${MUADDIB_DIR:-/opt/muaddib}"
SERVICE="${MUADDIB_SERVICE:-muaddib-monitor}"
OWNER="${DEPLOY_USER:-ubuntu}"

cd "$MUADDIB_DIR"

echo "[deploy] Deploying MUAD'DIB from $(pwd)"

# Record pre-pull HEAD for accurate diff
PRE_PULL_HEAD=$(git rev-parse HEAD)

# Pull as owning user (NOT sudo — avoids permission clobber)
git pull

POST_PULL_HEAD=$(git rev-parse HEAD)

if [ "$PRE_PULL_HEAD" = "$POST_PULL_HEAD" ]; then
  echo "[deploy] Already up to date."
  exit 0
fi

COMMITS=$(git log --oneline "$PRE_PULL_HEAD".."$POST_PULL_HEAD" | wc -l)
echo "[deploy] Pulled ${COMMITS} commit(s)"

# Fix data/logs permissions (in case of prior root damage)
if [ -f scripts/fix-permissions.sh ]; then
  bash scripts/fix-permissions.sh
fi

# Rebuild sandbox only if docker/ files changed since pre-pull
if git diff "$PRE_PULL_HEAD" --name-only | grep -q "^docker/"; then
  echo "[deploy] Sandbox files changed, rebuilding..."
  sudo docker build -t muaddib-sandbox docker/
fi

# Install deps if package-lock changed
if git diff "$PRE_PULL_HEAD" --name-only | grep -q "^package-lock.json$"; then
  echo "[deploy] package-lock.json changed, installing deps..."
  npm ci --production
fi

# Restart monitor
sudo systemctl restart "$SERVICE"

VERSION=$(node -e "console.log(require('./package.json').version)")
echo "[deploy] Deployed v${VERSION}"

# Verify the service started
sleep 2
if sudo systemctl is-active --quiet "$SERVICE"; then
  echo "[deploy] Monitor running OK"
else
  echo "[deploy] WARNING: Monitor not active — check: journalctl -u $SERVICE --since '30 sec ago'"
  exit 1
fi
