#!/usr/bin/env bash
# Rebuild the Docker sandbox image when docker/ (Dockerfile, runner, preload, mock network)
# differs from what the current image was built from.
#
#   refresh-sandbox-image.sh <install_dir> [log_file]
#
# The image is labelled with the git tree hash of docker/ (muaddib.docker-tree). When the
# checkout's docker/ tree differs from the image label (or the image has no label, or does
# not exist), the image is rebuilt under a temporary tag; only a successful build replaces
# it, and the replaced image is kept as muaddib-sandbox:previous for rollback. A failed
# build leaves the current image untouched. Exit code: 0 up to date or rebuilt, 1 build
# failed, 2 usage / not a checkout. DOCKER overrides the docker command (tests).
set -uo pipefail

INSTALL_DIR="${1:-}"
LOG_FILE="${2:-/dev/stderr}"
DOCKER="${DOCKER:-docker}"
IMAGE="muaddib-sandbox"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [sandbox-image] $1" >> "$LOG_FILE"; }

if [ -z "$INSTALL_DIR" ] || [ ! -d "$INSTALL_DIR/docker" ]; then
  log "usage: refresh-sandbox-image.sh <install_dir> [log_file] (no docker/ directory in '${INSTALL_DIR}')"
  exit 2
fi

TREE=$(git -C "$INSTALL_DIR" rev-parse HEAD:docker 2>/dev/null) || { log "not a git checkout: $INSTALL_DIR"; exit 2; }
CURRENT=$("$DOCKER" image inspect --format '{{ index .Config.Labels "muaddib.docker-tree" }}' "$IMAGE" 2>/dev/null || true)

if [ "$CURRENT" = "$TREE" ]; then
  log "up to date (docker/ tree ${TREE:0:12})"
  exit 0
fi

log "out of date (image: ${CURRENT:-no label or no image}, checkout docker/ tree: ${TREE:0:12}) - rebuilding"
if ! "$DOCKER" build -q --label "muaddib.docker-tree=$TREE" -t "$IMAGE:candidate" "$INSTALL_DIR/docker" >> "$LOG_FILE" 2>&1; then
  log "WARNING: build FAILED - keeping the current image"
  exit 1
fi
if "$DOCKER" image inspect "$IMAGE" > /dev/null 2>&1; then
  "$DOCKER" tag "$IMAGE" "$IMAGE:previous" >> "$LOG_FILE" 2>&1
fi
"$DOCKER" tag "$IMAGE:candidate" "$IMAGE" >> "$LOG_FILE" 2>&1
log "rebuilt (docker/ tree ${TREE:0:12}; previous image kept as $IMAGE:previous)"
exit 0
