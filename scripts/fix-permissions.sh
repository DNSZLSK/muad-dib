#!/bin/bash
# Fix EROFS/EACCES on /opt/muaddib/data/ and /opt/muaddib/logs/ directories
# Run on VPS: sudo bash scripts/fix-permissions.sh

set -e

MUADDIB_DIR="${MUADDIB_DIR:-/opt/muaddib}"
DATA_DIR="$MUADDIB_DIR/data"
LOG_DIR="$MUADDIB_DIR/logs"
OWNER="${DEPLOY_USER:-muaddib}"

echo "[fix-permissions] Fixing data + log directory permissions for $OWNER..."

# Data directory (monitor state, ML training, scan memory, daily stats)
sudo mkdir -p "$DATA_DIR/daily-stats"
sudo chown -R "$OWNER:$OWNER" "$DATA_DIR"
sudo chmod -R 755 "$DATA_DIR"

# Log directory (alerts, daily reports)
sudo mkdir -p "$LOG_DIR/alerts"
sudo mkdir -p "$LOG_DIR/daily-reports"
sudo chown -R "$OWNER:$OWNER" "$LOG_DIR"
sudo chmod -R 755 "$LOG_DIR"

echo "[fix-permissions] Done. Verifying..."
ls -la "$DATA_DIR/"
ls -la "$LOG_DIR/"

# Verify writability
for DIR in "$DATA_DIR" "$LOG_DIR/alerts"; do
  PROBE="$DIR/.write-test"
  touch "$PROBE" && rm "$PROBE" && echo "[fix-permissions] $DIR: write OK" || echo "[fix-permissions] ERROR: $DIR not writable!"
done
