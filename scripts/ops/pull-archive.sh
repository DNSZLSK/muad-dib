#!/usr/bin/env bash
#
# pull-archive.sh — pull the MUAD'DIB suspect-tarball archive from the VPS to
# this workstation, verify integrity, then let the VPS reclaim the space.
#
# This is OPS glue, not MUAD'DIB code. It implements the safe-delete contract of
# src/monitor/tarball-archive.js from the PC side:
#
#   1. rsync-pull the whole archive (resumable; a mid-transfer crash loses nothing).
#   2. Verify every .tgz on the LOCAL copy against the tarball_sha256 in its
#      sidecar .json. A day-dir passes only if ALL its tarballs verify.
#   3. For each verified PAST day-dir (never today's — it is still being written),
#      drop a `.pulled` sentinel back on the VPS. The monitor's cleanupOldArchives
#      treats `.pulled` aged dirs as safe to purge; un-pulled ones are KEPT.
#   4. If PURGE_AFTER_PULL=1 (default — the VPS has little disk), delete the
#      verified past day-dirs on the VPS now, for immediate reclaim.
#
# NEVER deletes a day-dir that did not fully verify, and never deletes today's.
# The malware npm has since unpublished is irreplaceable: we only free the VPS
# once this machine holds a hash-verified copy.
#
# Usage:
#   VPS_HOST=ubuntu@your.vps  ./pull-archive.sh
#
# Env:
#   VPS_HOST            (required) ssh target, e.g. ubuntu@1.2.3.4
#   VPS_ARCHIVE         VPS archive root         (default /opt/muaddib/archive)
#   LOCAL_ARCHIVE       local corpus root        (default ~/muaddib-archive)
#   BACKUP_DIR          optional 2nd local copy made before any VPS deletion
#   PURGE_AFTER_PULL    1=delete verified past days on the VPS now (default 1)
#   SSH_OPTS            extra ssh options (e.g. "-i ~/.ssh/muaddib -p 22")
#
set -euo pipefail

VPS_HOST="${VPS_HOST:?set VPS_HOST=user@host}"
VPS_ARCHIVE="${VPS_ARCHIVE:-/opt/muaddib/archive}"
LOCAL_ARCHIVE="${LOCAL_ARCHIVE:-$HOME/muaddib-archive}"
BACKUP_DIR="${BACKUP_DIR:-}"
PURGE_AFTER_PULL="${PURGE_AFTER_PULL:-1}"
SSH_OPTS="${SSH_OPTS:-}"

log() { printf '[pull-archive] %s\n' "$*"; }

sha256_of() { # $1=file -> hex digest (portable: sha256sum or shasum)
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$LOCAL_ARCHIVE"
TODAY="$(date -u +%F)"

# 1. Pull (resumable, keep source — deletion is gated on verification below).
log "pulling ${VPS_HOST}:${VPS_ARCHIVE}/ -> ${LOCAL_ARCHIVE}/"
rsync -az --partial ${SSH_OPTS:+-e "ssh $SSH_OPTS"} \
  "${VPS_HOST}:${VPS_ARCHIVE}/" "${LOCAL_ARCHIVE}/"

# Optional redundant local copy BEFORE we authorise any VPS deletion. The PC is
# a single point of failure otherwise.
if [ -n "$BACKUP_DIR" ]; then
  log "mirroring to backup ${BACKUP_DIR}/"
  mkdir -p "$BACKUP_DIR"
  rsync -a "${LOCAL_ARCHIVE}/" "${BACKUP_DIR}/"
fi

verified_days=()

# 2. Verify each PAST day-dir locally.
for daydir in "${LOCAL_ARCHIVE}"/*/; do
  [ -d "$daydir" ] || continue
  day="$(basename "$daydir")"
  # Only YYYY-MM-DD dirs, and never today's (still being written on the VPS).
  case "$day" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) : ;;
    *) continue ;;
  esac
  [ "$day" = "$TODAY" ] && { log "skip $day (today — still open)"; continue; }

  ok=1
  shopt -s nullglob
  for tgz in "$daydir"*.tgz; do
    json="${tgz%.tgz}.json"
    if [ ! -f "$json" ]; then log "  $day: no sidecar for $(basename "$tgz") — cannot verify"; ok=0; break; fi
    want="$(grep -o '"tarball_sha256"[^"]*"[0-9a-f]*"' "$json" | grep -o '[0-9a-f]\{64\}' || true)"
    if [ -z "$want" ]; then log "  $day: sidecar has no sha256 for $(basename "$tgz")"; ok=0; break; fi
    got="$(sha256_of "$tgz")"
    if [ "$want" != "$got" ]; then log "  $day: HASH MISMATCH on $(basename "$tgz") — keeping on VPS"; ok=0; break; fi
  done
  shopt -u nullglob

  if [ "$ok" -eq 1 ]; then verified_days+=("$day"); fi
done

if [ "${#verified_days[@]}" -eq 0 ]; then
  log "no fully-verified past day-dirs — nothing to release on the VPS."
  exit 0
fi
log "verified ${#verified_days[@]} past day-dir(s): ${verified_days[*]}"

# 3. Mark verified days .pulled on the VPS (monitor-safe reclaim), then 4. purge.
for day in "${verified_days[@]}"; do
  ssh $SSH_OPTS "$VPS_HOST" "touch '${VPS_ARCHIVE}/${day}/.pulled'" \
    && log "marked ${day}/.pulled on VPS" || log "WARN: could not mark ${day}/.pulled"
done

if [ "$PURGE_AFTER_PULL" = "1" ]; then
  for day in "${verified_days[@]}"; do
    # Defensive: refuse a path that isn't a plain YYYY-MM-DD under the archive.
    ssh $SSH_OPTS "$VPS_HOST" "rm -rf -- '${VPS_ARCHIVE}/${day}'" \
      && log "purged ${day} on VPS (verified copy held locally)" \
      || log "WARN: could not purge ${day} on VPS"
  done
else
  log "PURGE_AFTER_PULL=0 — left .pulled markers; the monitor will reclaim on its schedule."
fi

log "done."
