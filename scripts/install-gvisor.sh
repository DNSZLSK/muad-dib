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
# After install: set MUADDIB_SANDBOX_RUNTIME=gvisor in .env to enable gVisor.
# Optionally set MUADDIB_REQUIRE_GVISOR=1 to FAIL CLOSED: the sandbox then refuses to run
# (returns INCONCLUSIVE) rather than silently downgrading to runc when runsc is missing.
# Default (var unset): fall back to runc but log a visible WARNING. No mandatory mode by default.
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
# Not under /tmp: the monitor service runs with PrivateTmp=true and would never see a host
# /tmp/runsc. Must match the host reader (src/sandbox/gvisor-parser.js DEFAULT_GVISOR_LOG_DIR,
# or MUADDIB_GVISOR_LOG_DIR set the same way for the monitor).
GVISOR_LOG_DIR="${MUADDIB_GVISOR_LOG_DIR:-/var/log/runsc}"
mkdir -p "$GVISOR_LOG_DIR"
# runsc creates <dir>/<id>/ as root 0755 with files 0644. 0750 root:<monitor group> keeps
# every other local user out of the traces (they hold the honeytokens and the sandboxed
# package's activity); the monitor reads through its group. Deletion is root's job (timer).
MONITOR_GROUP="${MUADDIB_MONITOR_GROUP:-muaddib}"
if getent group "$MONITOR_GROUP" >/dev/null 2>&1; then
  chown root:"$MONITOR_GROUP" "$GVISOR_LOG_DIR"
else
  echo "WARNING: group '$MONITOR_GROUP' not found - the monitor will not be able to read ${GVISOR_LOG_DIR}" >&2
fi
chmod 0750 "$GVISOR_LOG_DIR"
echo "[gVisor] Log directory: ${GVISOR_LOG_DIR} ($(stat -c '%U:%G %a' "$GVISOR_LOG_DIR"))"

# Bounded retention: unfiltered traces once filled the disk. A root timer removes traces
# older than 30 min every 10 min and caps the directory at 2048 MB (deploy/runsc-log-cleanup.sh).
INSTALL_DIR="${MUADDIB_INSTALL_DIR:-/opt/muaddib}"
if [ -f "$INSTALL_DIR/deploy/muaddib-runsc-cleanup.timer" ]; then
  install -m 0755 "$INSTALL_DIR/deploy/runsc-log-cleanup.sh" /usr/local/sbin/muaddib-runsc-log-cleanup.sh
  cp "$INSTALL_DIR/deploy/muaddib-runsc-cleanup.service" "$INSTALL_DIR/deploy/muaddib-runsc-cleanup.timer" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now muaddib-runsc-cleanup.timer
  echo "[gVisor] Retention: muaddib-runsc-cleanup.timer (30 min, 2048 MB, every 10 min)"
else
  echo "WARNING: $INSTALL_DIR/deploy/muaddib-runsc-cleanup.timer not found - traces are NOT bounded" >&2
fi

# ── Configure Docker runtime ──
# runsc install adds the runtime to /etc/docker/daemon.json. Keep the trace flags next to the
# performance ones: without --strace / --debug-log / --log-packets the runtime writes no
# trace and every sandbox report lacks process, file and network data (reported INCONCLUSIVE
# by the host). --strace-syscalls limits the trace to what gvisor-parser.js reads.
#   --directfs, --overlay2=all:memory: performance (gVisor >= 2023-06-01)
#   --log-packets: network at the gVisor kernel level (tcpdump needs AF_PACKET, unsupported)
echo "[gVisor] Configuring Docker runtime..."
runsc install -- \
  --directfs \
  --overlay2=all:memory \
  --strace \
  --strace-syscalls=openat,open,connect,execve,execveat \
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
echo "  export MUADDIB_SANDBOX_RUNTIME=gvisor      # use gVisor (runsc) when available"
echo ""
echo "Optional — refuse to run on weaker runc if gVisor is missing (fail closed):"
echo "  export MUADDIB_REQUIRE_GVISOR=1            # default: unset = fall back to runc with a WARNING"
echo ""
echo "Log directory: ${GVISOR_LOG_DIR}"
echo "Runtime flags: --directfs --overlay2=all:memory --strace --strace-syscalls=openat,open,connect,execve,execveat --log-packets --debug-log=${GVISOR_LOG_DIR}/%ID%/"
