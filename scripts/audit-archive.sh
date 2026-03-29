#!/bin/bash
# Usage: ./audit-archive.sh [YYYY-MM-DD] [priority]
# Exemples:
#   ./audit-archive.sh                    → résumé de toutes les dates
#   ./audit-archive.sh 2026-03-29         → liste les packages archivés ce jour
#   ./audit-archive.sh 2026-03-29 P1      → filtre par priorité

ARCHIVE_DIR="/opt/muaddib/archive"
DATE=$1
PRIORITY=$2

if [ -z "$DATE" ]; then
  echo "=== Archive Summary ==="
  for dir in "$ARCHIVE_DIR"/20*; do
    [ -d "$dir" ] || continue
    day=$(basename "$dir")
    count=$(ls "$dir"/*.tgz 2>/dev/null | wc -l)
    size=$(du -sh "$dir" 2>/dev/null | cut -f1)
    echo "$day : $count packages ($size)"
  done
  echo "---"
  echo "Total: $(du -sh "$ARCHIVE_DIR" 2>/dev/null | cut -f1)"
  exit 0
fi

DIR="$ARCHIVE_DIR/$DATE"
if [ ! -d "$DIR" ]; then
  echo "No archive for $DATE"
  exit 1
fi

for json in "$DIR"/*.json; do
  [ -f "$json" ] || continue
  pkg=$(jq -r '.package' "$json")
  ver=$(jq -r '.version' "$json")
  prio=$(jq -r '.priority' "$json")
  score=$(jq -r '.score' "$json")
  llm=$(jq -r '.llm_verdict // "none"' "$json")

  if [ -n "$PRIORITY" ] && [ "$prio" != "$PRIORITY" ]; then
    continue
  fi

  printf "%-40s %-8s score=%-4s llm=%s\n" "$pkg@$ver" "$prio" "$score" "$llm"
done
