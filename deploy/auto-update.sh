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

# INTEGRITY (E1): apply only fast-forward updates. A non-fast-forward origin means the branch
# history was rewritten / force-pushed — a repo/account-compromise signal. Refuse.
if ! git merge-base --is-ancestor "$LOCAL_SHA" "$REMOTE_SHA"; then
  log "REFUSED: origin/$BRANCH is not a fast-forward of HEAD (possible history rewrite)"
  exit 1
fi

# INTEGRITY (E1, opt-in): require a valid trusted signature on the target commit. Requires
# GPG/SSH commit signing + the trusted key in muaddib's keyring; left OFF by default so updates
# don't break where signing isn't configured yet. Enable with MUADDIB_VERIFY_SIGNATURE=1.
if [ "${MUADDIB_VERIFY_SIGNATURE:-0}" = "1" ] && ! git verify-commit "$REMOTE_SHA" >>"$LOG_FILE" 2>&1; then
  log "REFUSED: $REMOTE_SHA has no valid trusted signature"
  exit 1
fi

log "Update found: ${LOCAL_SHA:0:8} -> ${REMOTE_SHA:0:8}"

# Fast-forward only (the fetch already ran above); never create a merge commit on the prod checkout.
git merge --ff-only "origin/$BRANCH" >> "$LOG_FILE" 2>&1
# --ignore-scripts: NEVER run dependency lifecycle scripts (pre/postinstall) as root during an
# unattended update — the core E1 RCE vector. This project vendors its native asset (tree-sitter
# WASM) so no dep needs a build step; re-verify on the VPS if the dependency set changes.
npm ci --production --ignore-scripts >> "$LOG_FILE" 2>&1

# Fix ownership: git pull + npm ci run as root, monitor runs as muaddib
chown -R muaddib:muaddib "$INSTALL_DIR" >> "$LOG_FILE" 2>&1

systemctl restart muaddib-monitor

log "Update complete — muaddib-monitor restarted"
