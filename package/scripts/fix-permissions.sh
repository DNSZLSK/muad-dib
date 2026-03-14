#!/bin/bash
# Fix EROFS/EACCES on /opt/muaddib/logs/ directories
# Run on VPS: sudo bash scripts/fix-permissions.sh

set -e

MUADDIB_DIR="${MUADDIB_DIR:-/opt/muaddib}"
LOG_DIR="$MUADDIB_DIR/logs"
OWNER="${SUDO_USER:-ubuntu}"

echo "[fix-permissions] Fixing log directory permissions..."

sudo mkdir -p "$LOG_DIR/alerts"
sudo mkdir -p "$LOG_DIR/daily-reports"
sudo chown -R "$OWNER:$OWNER" "$LOG_DIR"
sudo chmod -R 755 "$LOG_DIR"

echo "[fix-permissions] Done. Verifying..."
ls -la "$LOG_DIR/"
echo "[fix-permissions] Owner: $(stat -c '%U:%G' "$LOG_DIR")"

# Verify writability
PROBE="$LOG_DIR/alerts/.write-test"
touch "$PROBE" && rm "$PROBE" && echo "[fix-permissions] Write test OK" || echo "[fix-permissions] ERROR: Still not writable!"
