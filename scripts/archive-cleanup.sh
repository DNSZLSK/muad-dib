#!/bin/bash
# Supprime les archives de plus de 30 jours
ARCHIVE_DIR="/opt/muaddib/archive"
find "$ARCHIVE_DIR" -type d -name "20*" -mtime +30 -exec rm -rf {} + 2>/dev/null
# Log
TOTAL=$(du -sh "$ARCHIVE_DIR" 2>/dev/null | cut -f1)
echo "[Archive Cleanup] $(date -Iseconds) — Total size: $TOTAL"
