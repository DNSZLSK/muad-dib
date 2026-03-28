#!/bin/bash
# MUAD'DIB — Automated backup of monitor data files
# Run on VPS: bash scripts/backup.sh
# Cron: 04:00 UTC daily (see docs/DEPLOYMENT.md for systemd timer template)
#
# Configurable via environment:
#   MUADDIB_DIR     Base directory (default: /opt/muaddib)
#   BACKUP_DIR      Where to store backups (default: $MUADDIB_DIR/backups)
#   BACKUP_RETAIN   Number of daily backups to keep (default: 7)

set -euo pipefail

MUADDIB_DIR="${MUADDIB_DIR:-/opt/muaddib}"
BACKUP_DIR="${BACKUP_DIR:-$MUADDIB_DIR/backups}"
BACKUP_RETAIN="${BACKUP_RETAIN:-7}"

DATE=$(date -u +%Y-%m-%d)
ARCHIVE="muaddib-backup-${DATE}.tar.gz"

echo "[backup] Starting backup — ${DATE}"
echo "[backup] Source: ${MUADDIB_DIR}"
echo "[backup] Destination: ${BACKUP_DIR}/${ARCHIVE}"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Build list of files to include (skip missing files silently)
FILES_TO_BACKUP=()

add_if_exists() {
  local rel="$1"
  if [ -e "$MUADDIB_DIR/$rel" ]; then
    FILES_TO_BACKUP+=("$rel")
  else
    echo "[backup] Skipping (not found): $rel"
  fi
}

# Monitor state
add_if_exists "data/monitor-state.json"
add_if_exists "data/scan-memory.json"

# ML training data
add_if_exists "data/ml-training.jsonl"

# Daily stats history
if [ -d "$MUADDIB_DIR/data/daily-stats" ]; then
  FILES_TO_BACKUP+=("data/daily-stats")
else
  echo "[backup] Skipping (not found): data/daily-stats/"
fi

# Evaluation metrics
if [ -d "$MUADDIB_DIR/metrics" ]; then
  FILES_TO_BACKUP+=("metrics")
else
  echo "[backup] Skipping (not found): metrics/"
fi

# Abort if nothing to back up
if [ ${#FILES_TO_BACKUP[@]} -eq 0 ]; then
  echo "[backup] No files found to back up. Exiting."
  exit 0
fi

echo "[backup] Archiving ${#FILES_TO_BACKUP[@]} item(s)..."

# Create the archive from the base directory
# Use a temp file so a failed tar doesn't clobber the final archive
TEMP_ARCHIVE="${BACKUP_DIR}/.${ARCHIVE}.tmp"

tar -czf "$TEMP_ARCHIVE" -C "$MUADDIB_DIR" "${FILES_TO_BACKUP[@]}"

# Only move into place if tar succeeded
mv "$TEMP_ARCHIVE" "$BACKUP_DIR/$ARCHIVE"

echo "[backup] Archive created: $(du -h "$BACKUP_DIR/$ARCHIVE" | cut -f1)"

# Purge old backups beyond retention period
DELETED=0
while IFS= read -r old_backup; do
  rm -f "$old_backup"
  DELETED=$((DELETED + 1))
done < <(ls -1t "$BACKUP_DIR"/muaddib-backup-*.tar.gz 2>/dev/null | tail -n +$((BACKUP_RETAIN + 1)))

if [ "$DELETED" -gt 0 ]; then
  echo "[backup] Purged ${DELETED} old backup(s) (retaining ${BACKUP_RETAIN})"
fi

echo "[backup] Done. Current backups:"
ls -lh "$BACKUP_DIR"/muaddib-backup-*.tar.gz 2>/dev/null || echo "  (none)"
