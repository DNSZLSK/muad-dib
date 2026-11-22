#!/usr/bin/env bash
# Bound the gVisor trace logs (runsc --debug-log=<dir>/%ID%/). runsc writes them as root
# (directories 0755, files 0644), so the monitor can read them but not delete them; this
# runs as root from muaddib-runsc-cleanup.timer.
#
#   runsc-log-cleanup.sh [dir] [max_age_minutes] [max_total_mb]
#
# 1. removes every per-container directory older than max_age_minutes (default 30; the
#    host reads a container's trace right after the run);
# 2. then, while the directory is above max_total_mb (default 2048), removes the oldest
#    remaining entries (a burst of runs cannot fill the disk between two timer ticks).
# Only direct children of <dir> are removed. Exit 0, or 2 when <dir> is not a directory.
set -uo pipefail

DIR="${1:-${MUADDIB_GVISOR_LOG_DIR:-/var/log/runsc}}"
MAX_AGE_MIN="${2:-${MUADDIB_GVISOR_LOG_MAX_AGE_MIN:-30}}"
MAX_TOTAL_MB="${3:-${MUADDIB_GVISOR_LOG_MAX_MB:-2048}}"

[ -d "$DIR" ] || { echo "runsc-log-cleanup: not a directory: $DIR" >&2; exit 2; }
case "$MAX_AGE_MIN$MAX_TOTAL_MB" in *[!0-9]*) echo "runsc-log-cleanup: numeric limits expected" >&2; exit 2 ;; esac

removed_age=0
while IFS= read -r -d '' entry; do
  rm -rf -- "$entry" && removed_age=$((removed_age + 1))
done < <(find "$DIR" -mindepth 1 -maxdepth 1 -mmin +"$MAX_AGE_MIN" -print0)

removed_size=0
total_kb() { du -sk -- "$DIR" 2>/dev/null | awk '{print $1}'; }
limit_kb=$((MAX_TOTAL_MB * 1024))
while [ "$(total_kb)" -gt "$limit_kb" ]; do
  # Oldest direct child first (mtime, seconds since epoch).
  oldest=$(find "$DIR" -mindepth 1 -maxdepth 1 -printf '%T@ %p\n' | sort -n | head -1 | cut -d' ' -f2-)
  [ -n "$oldest" ] || break
  rm -rf -- "$oldest" && removed_size=$((removed_size + 1))
done

echo "runsc-log-cleanup: $DIR removed ${removed_age} older than ${MAX_AGE_MIN} min, ${removed_size} over ${MAX_TOTAL_MB} MB, now $(total_kb) KB"
exit 0
