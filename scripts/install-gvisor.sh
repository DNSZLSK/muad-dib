#!/bin/bash
# ══════════════════════════════════════════════════════════════
# MUAD'DIB — gVisor (runsc) installer
#
# Installs gVisor's runsc runtime and configures Docker to use it.
# gVisor provides kernel-level syscall tracing (--strace) and
# network packet logging (--log-packets) without needing strace
# or tcpdump inside the container.
#
# Usage: sudo bash scripts/install-gvisor.sh
# After install: set MUADDIB_SANDBOX_RUNTIME=gvisor in .env
# ══════════════════════════════════════════════════════════════
set -e

# ── Pre-flight checks ──
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must be run as root (sudo)." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed." >&2
  exit 1
fi

# ── Download runsc ──
ARCH=$(uname -m)
URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"

echo "[gVisor] Downloading runsc for ${ARCH}..."
wget -q "${URL}/runsc" -O /usr/local/bin/runsc
wget -q "${URL}/runsc.sha512" -O /tmp/runsc.sha512

echo "[gVisor] Verifying SHA-512 checksum..."
cd /usr/local/bin && sha512sum -c /tmp/runsc.sha512
chmod +x /usr/local/bin/runsc
rm -f /tmp/runsc.sha512

echo "[gVisor] runsc version: $(runsc --version 2>&1 | head -1)"

# ── Create log directory ──
GVISOR_LOG_DIR="${MUADDIB_GVISOR_LOG_DIR:-/tmp/runsc}"
mkdir -p "$GVISOR_LOG_DIR"
chmod 1777 "$GVISOR_LOG_DIR"
echo "[gVisor] Log directory: ${GVISOR_LOG_DIR}"

# ── Configure Docker runtime ──
# runsc install adds the runtime to /etc/docker/daemon.json with
# --strace (syscall tracing) and --debug-log (log output path).
# --log-packets captures network traffic at the gVisor kernel level,
# replacing tcpdump which requires AF_PACKET (unsupported in gVisor).
echo "[gVisor] Configuring Docker runtime..."
runsc install -- \
  --strace \
  --debug-log="${GVISOR_LOG_DIR}/%ID%/" \
  --log-packets

echo "[gVisor] Reloading Docker daemon..."
systemctl reload docker

# ── Verify installation ──
echo "[gVisor] Verifying with test container..."
if docker run --rm --runtime=runsc alpine echo "gVisor OK" 2>/dev/null; then
  echo "[gVisor] Installation successful."
else
  echo "WARNING: Test container failed. Check Docker logs." >&2
  echo "  Try: journalctl -u docker --since '5 minutes ago'" >&2
  exit 1
fi

echo ""
echo "gVisor installed and configured."
echo "To activate for MUAD'DIB sandbox:"
echo "  export MUADDIB_SANDBOX_RUNTIME=gvisor"
echo ""
echo "Log directory: ${GVISOR_LOG_DIR}"
echo "Runtime flags: --strace --log-packets --debug-log=${GVISOR_LOG_DIR}/%ID%/"
