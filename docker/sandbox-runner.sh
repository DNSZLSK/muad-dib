#!/bin/sh
PACKAGE="$1"

if [ -z "$PACKAGE" ]; then
  echo "Usage: sandbox-runner.sh <package-name>" >&2
  exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_MS=$(date +%s%3N 2>/dev/null || echo 0)

# ── 1. Filesystem snapshot BEFORE install ──
echo "[SANDBOX] Snapshot filesystem before install..." >&2
find / -type f 2>/dev/null | sort > /tmp/fs-before.txt

# ── 2. tcpdump in background (DNS + HTTP + HTTPS) ──
echo "[SANDBOX] Starting network capture..." >&2
tcpdump -i any -nn 'port 53 or port 80 or port 443' -l > /tmp/network.log 2>/dev/null &
TCPDUMP_PID=$!
sleep 1

# ── 3. npm install with strace ──
echo "[SANDBOX] Installing $PACKAGE..." >&2
strace -f -e trace=network,process,open,openat,connect,execve,sendto,recvfrom \
  -o /tmp/strace.log \
  npm install "$PACKAGE" --ignore-scripts=false > /tmp/install.log 2>&1
EXIT_CODE=$?

# ── 4. Filesystem snapshot AFTER install ──
echo "[SANDBOX] Snapshot filesystem after install..." >&2
find / -type f 2>/dev/null | sort > /tmp/fs-after.txt

# Stop tcpdump
kill "$TCPDUMP_PID" 2>/dev/null
wait "$TCPDUMP_PID" 2>/dev/null

END_MS=$(date +%s%3N 2>/dev/null || echo 0)
DURATION_MS=$((END_MS - START_MS))
[ "$DURATION_MS" -lt 0 ] 2>/dev/null && DURATION_MS=0

# ── 5. Filesystem diff (exclude /sandbox/node_modules/) ──
echo "[SANDBOX] Analyzing filesystem changes..." >&2
comm -13 /tmp/fs-before.txt /tmp/fs-after.txt | grep -v '^/sandbox/node_modules/' | grep -v '^/tmp/fs-\|^/tmp/install.log\|^/tmp/network.log\|^/tmp/strace.log\|^/tmp/sensitive-\|^/tmp/suspicious-cmds\|^/tmp/connections.txt\|^/tmp/dns-queries\|^/tmp/fs-created\|^/tmp/fs-deleted' > /tmp/fs-created.txt
comm -23 /tmp/fs-before.txt /tmp/fs-after.txt | grep -v '^/sandbox/node_modules/' > /tmp/fs-deleted.txt

# ── 6. Parse strace ──
echo "[SANDBOX] Parsing strace..." >&2

SENSITIVE='\.npmrc|\.ssh/|\.aws/|\.env|/etc/passwd|/etc/shadow|\.gitconfig|\.bash_history'

# 6a. Sensitive file access (read)
grep -E 'openat\(' /tmp/strace.log 2>/dev/null | \
  grep -E "$SENSITIVE" | \
  grep 'O_RDONLY' | \
  sed 's/.*openat([^,]*, "\([^"]*\)".*/\1/' | \
  sort -u > /tmp/sensitive-read.txt

# 6b. Sensitive file access (write)
grep -E 'openat\(' /tmp/strace.log 2>/dev/null | \
  grep -E "$SENSITIVE" | \
  grep -E 'O_WRONLY|O_RDWR|O_CREAT' | \
  sed 's/.*openat([^,]*, "\([^"]*\)".*/\1/' | \
  sort -u > /tmp/sensitive-written.txt

# 6c. Suspicious execve (exclude node, npm, npx, sh, git)
grep 'execve(' /tmp/strace.log 2>/dev/null | \
  grep '= 0' | \
  grep -vE 'execve\("[^"]*/(node|npm|npx|sh|git)"' | \
  sed -n 's/.*\[pid \([0-9]*\)\].*execve("\([^"]*\)".*/\1\t\2/p' > /tmp/suspicious-cmds.txt

grep 'execve(' /tmp/strace.log 2>/dev/null | \
  grep '= 0' | \
  grep -vE 'execve\("[^"]*/(node|npm|npx|sh|git)"' | \
  grep -v '\[pid' | \
  sed -n 's/.*execve("\([^"]*\)".*/0\t\1/p' >> /tmp/suspicious-cmds.txt

# 6d. Outgoing connections (AF_INET, successful)
grep 'connect(' /tmp/strace.log 2>/dev/null | \
  grep 'AF_INET' | grep -v 'AF_INET6' | \
  grep '= 0' | \
  sed -n 's/.*sin_port=htons(\([0-9]*\)).*sin_addr=inet_addr("\([^"]*\)").*/\2\t\1/p' | \
  grep -v '	65535$' | \
  grep -v '^127\.' | \
  sort -u > /tmp/connections.txt

# ── 7. Parse tcpdump ──
echo "[SANDBOX] Parsing network capture..." >&2

grep -oE '(A|AAAA)\? [^ ]+' /tmp/network.log 2>/dev/null | \
  awk '{print $2}' | \
  sed 's/\.$//' | \
  sort -u > /tmp/dns-queries.txt

# ── 8. Build JSON with jq ──
echo "[SANDBOX] Building report..." >&2

# Ensure all temp files exist
touch /tmp/fs-created.txt /tmp/fs-deleted.txt /tmp/dns-queries.txt \
  /tmp/sensitive-read.txt /tmp/sensitive-written.txt \
  /tmp/connections.txt /tmp/suspicious-cmds.txt /tmp/install.log

INSTALL_OUTPUT=$(head -c 5000 /tmp/install.log)

FS_CREATED=$(jq -R -s 'split("\n") | map(select(length > 0))' < /tmp/fs-created.txt)
FS_DELETED=$(jq -R -s 'split("\n") | map(select(length > 0))' < /tmp/fs-deleted.txt)
DNS=$(jq -R -s 'split("\n") | map(select(length > 0))' < /tmp/dns-queries.txt)
SENS_READ=$(jq -R -s 'split("\n") | map(select(length > 0))' < /tmp/sensitive-read.txt)
SENS_WRITTEN=$(jq -R -s 'split("\n") | map(select(length > 0))' < /tmp/sensitive-written.txt)

CONNS=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
  split("\t") | {host: .[0], port: (.[1] | tonumber), protocol: "TCP"}
)' < /tmp/connections.txt)

PROCS=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
  split("\t") | {command: .[1], pid: (.[0] | tonumber)}
)' < /tmp/suspicious-cmds.txt)

# ── Final JSON (ONLY output on stdout) ──
jq -n \
  --arg package "$PACKAGE" \
  --arg timestamp "$TIMESTAMP" \
  --argjson duration "${DURATION_MS:-0}" \
  --argjson fs_created "$FS_CREATED" \
  --argjson fs_deleted "$FS_DELETED" \
  --argjson dns "$DNS" \
  --argjson connections "$CONNS" \
  --argjson processes "$PROCS" \
  --argjson sensitive_read "$SENS_READ" \
  --argjson sensitive_written "$SENS_WRITTEN" \
  --arg install_output "$INSTALL_OUTPUT" \
  --argjson exit_code "${EXIT_CODE:-1}" \
  '{
    package: $package,
    timestamp: $timestamp,
    duration_ms: $duration,
    filesystem: {
      created: $fs_created,
      deleted: $fs_deleted,
      modified: []
    },
    network: {
      dns_queries: $dns,
      http_connections: $connections
    },
    processes: {
      spawned: $processes
    },
    sensitive_files: {
      read: $sensitive_read,
      written: $sensitive_written
    },
    install_output: $install_output,
    exit_code: $exit_code
  }'
