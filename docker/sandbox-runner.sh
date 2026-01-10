#!/bin/sh
PACKAGE=$1

echo "[SANDBOX] Installing $PACKAGE..."

# Capturer les connexions réseau en background
tcpdump -i any -w /tmp/network.pcap 2>/dev/null &
TCPDUMP_PID=$!

# Installer le package avec strace pour capturer les appels système
strace -f -e trace=network,process,file -o /tmp/strace.log npm install "$PACKAGE" --ignore-scripts=false 2>&1

# Arrêter tcpdump
kill $TCPDUMP_PID 2>/dev/null

# Analyser les résultats
echo "[SANDBOX] === NETWORK CONNECTIONS ==="
grep -E "connect|sendto" /tmp/strace.log | head -20

echo "[SANDBOX] === PROCESS SPAWNS ==="
grep -E "execve|clone" /tmp/strace.log | head -20

echo "[SANDBOX] === FILE ACCESS ==="
grep -E "openat.*npmrc|openat.*ssh|openat.*aws" /tmp/strace.log | head -20

echo "[SANDBOX] Done."