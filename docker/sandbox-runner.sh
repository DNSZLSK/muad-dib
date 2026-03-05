#!/bin/sh
PACKAGE="$1"
MODE="${2:-permissive}"

if [ -z "$PACKAGE" ]; then
  echo "Usage: sandbox-runner.sh <package-name> [permissive|strict]" >&2
  exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_MS=$(date +%s%3N 2>/dev/null || echo 0)

# ══════════════════════════════════════════════════════════════
# PHASE 1: Root-privileged setup (iptables, tcpdump, filesystem snapshot)
# Runs as root to access raw sockets and kernel netfilter.
# ══════════════════════════════════════════════════════════════

# ── 0. Strict mode: iptables rules (requires root + NET_ADMIN) ──
if [ "$MODE" = "strict" ]; then
  echo "[SANDBOX] STRICT MODE — blocking non-essential network..." >&2
  # Allow loopback
  iptables -A OUTPUT -o lo -j ACCEPT
  # Allow DNS (UDP 53)
  iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
  # Allow registry.npmjs.org (resolve + allow)
  REGISTRY_IPS=$(nslookup registry.npmjs.org 2>/dev/null | grep -E '^Address:' | tail -n+2 | awk '{print $2}')
  for ip in $REGISTRY_IPS; do
    iptables -A OUTPUT -d "$ip" -p tcp --dport 443 -j ACCEPT
  done
  # Log + reject everything else
  iptables -A OUTPUT -j LOG --log-prefix "BLOCKED: "
  iptables -A OUTPUT -j REJECT
  echo "[SANDBOX] iptables rules applied." >&2
fi

# ── 1. Filesystem snapshot BEFORE install ──
echo "[SANDBOX] Snapshot filesystem before install..." >&2
cp /opt/fs-baseline.txt /tmp/fs-before.txt

# ── 2. tcpdump: separate captures for DNS, HTTP, TLS (requires root + NET_RAW) ──
echo "[SANDBOX] Starting network capture..." >&2
tcpdump -i any -nn 'port 53' -l > /tmp/dns.log 2>/dev/null &
DNS_PID=$!
tcpdump -i any -nn -A 'tcp port 80' -l > /tmp/http.log 2>/dev/null &
HTTP_PID=$!
tcpdump -i any -nn 'tcp port 443' -l > /tmp/tls.log 2>/dev/null &
TLS_PID=$!
tcpdump -i any -nn 'not port 53 and not port 80 and not port 443' -l > /tmp/other.log 2>/dev/null &
OTHER_PID=$!
sleep 1

# ══════════════════════════════════════════════════════════════
# PHASE 2: Unprivileged install (su sandboxuser)
# npm install runs as sandboxuser with strace for syscall tracing.
# strace can trace child processes without SYS_PTRACE (parent→child).
# ══════════════════════════════════════════════════════════════

# ── 2b. CI environment simulation ──
# Simulate CI to trigger CI-aware malware that checks for these env vars
echo "[SANDBOX] Simulating CI environment..." >&2
export CI=true
export GITHUB_ACTIONS=true
export GITLAB_CI=true
export TRAVIS=true
export CIRCLECI=true
export JENKINS_URL=http://localhost:8080

# ── 2c. Canary tokens (honeypots) ──
# Use Docker-injected dynamic tokens if available, otherwise static fallbacks.
# If exfiltrated via network/DNS/files, sandbox.js detects the theft.
export GITHUB_TOKEN="${GITHUB_TOKEN:-MUADDIB_CANARY_GITHUB_f8k3t0k3n}"
export NPM_TOKEN="${NPM_TOKEN:-MUADDIB_CANARY_NPM_s3cr3tt0k3n}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-MUADDIB_CANARY_AKIAIOSFODNN7EXAMPLE}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-MUADDIB_CANARY_wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY}"
export SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-https://hooks.slack.com/MUADDIB_CANARY_SLACK}"
export DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-https://discord.com/api/webhooks/MUADDIB_CANARY_DISCORD}"

# ── 2d. Preload injection — deferred to entry point (phase 3b) ──
# NODE_OPTIONS='--require /opt/preload.js' monkey-patches http/https/net/dns.
# Enabling it during npm install causes timeouts (hundreds of wrapped network calls).
# tcpdump already captures install-phase network; preload targets runtime behavior.

# ── 3. npm install with strace — as sandboxuser ──
echo "[SANDBOX] Installing $PACKAGE as sandboxuser..." >&2
cd /sandbox/install
# Ensure sandboxuser owns the install directory
chown sandboxuser:sandboxuser /sandbox/install
# Run npm install as sandboxuser via su, wrapped in strace for syscall tracing
if [ "$MODE" = "strict" ]; then
  su sandboxuser -s /bin/sh -c "
    strace -f -e trace=network,process,open,openat,connect,execve,sendto,recvfrom \
      -o /tmp/strace.log \
      npm install \"$PACKAGE\" --ignore-scripts=false --fetch-timeout=120000 > /tmp/install.log 2>&1
  "
else
  touch /tmp/strace.log
  su sandboxuser -s /bin/sh -c "
    npm install \"$PACKAGE\" --ignore-scripts=false --fetch-timeout=120000 > /tmp/install.log 2>&1
  "
fi
EXIT_CODE=$?

# ── 3b. Entry point execution — trigger runtime malware ──
# Malware that puts code in index.js without lifecycle scripts is only
# caught when the entry point is actually required. strace + tcpdump
# are already running, so any network/filesystem activity is captured.
# Preload enabled here (not during install) to avoid npm timeout.
export NODE_OPTIONS="${NODE_OPTIONS:---require /opt/preload.js}"
echo "[SANDBOX] Executing package entry point..." >&2

if echo "$PACKAGE" | grep -q '^/'; then
  # Local mode: $PACKAGE is already a path (e.g. /sandbox/local-pkg)
  REQUIRE_PATH="$PACKAGE"
else
  # Remote mode: package installed in node_modules
  REQUIRE_PATH="/sandbox/install/node_modules/$PACKAGE"
fi

su sandboxuser -s /bin/sh -c "
  strace -f -e trace=network,process,open,openat,connect,execve,sendto,recvfrom \
    -o /tmp/strace-entrypoint.log \
    timeout 10 node -e \"try { require('$REQUIRE_PATH') } catch(e) {}\" > /tmp/entrypoint.log 2>&1
" || true

# Merge entrypoint strace into main strace log for unified analysis
cat /tmp/strace-entrypoint.log >> /tmp/strace.log 2>/dev/null

# ══════════════════════════════════════════════════════════════
# PHASE 3: Post-install analysis (back as root for full access)
# ══════════════════════════════════════════════════════════════

# ── 4. Filesystem snapshot AFTER install ──
echo "[SANDBOX] Snapshot filesystem after install..." >&2
find / -type f 2>/dev/null | sort > /tmp/fs-after.txt

# Stop tcpdump
kill "$DNS_PID" "$HTTP_PID" "$TLS_PID" "$OTHER_PID" 2>/dev/null
wait "$DNS_PID" "$HTTP_PID" "$TLS_PID" "$OTHER_PID" 2>/dev/null

END_MS=$(date +%s%3N 2>/dev/null || echo 0)
DURATION_MS=$((END_MS - START_MS))
[ "$DURATION_MS" -lt 0 ] 2>/dev/null && DURATION_MS=0

# ── 5. Filesystem diff ──
echo "[SANDBOX] Analyzing filesystem changes..." >&2
comm -13 /tmp/fs-before.txt /tmp/fs-after.txt | grep -v '^/sandbox/install/' | grep -v '^/sandbox/local-pkg/' | grep -v '^/tmp/' > /tmp/fs-created.txt
comm -23 /tmp/fs-before.txt /tmp/fs-after.txt | grep -v '^/sandbox/install/' | grep -v '^/sandbox/local-pkg/' > /tmp/fs-deleted.txt

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

# 6c. Suspicious execve
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

# ── 7. Parse DNS resolutions (query → answer pairs) ──
echo "[SANDBOX] Parsing DNS resolutions..." >&2

# Extract DNS queries and answers from dns.log
# Format: "domain query_type answer_ip"
awk '
/A\?/ { domain=$0; sub(/.*A\? /,"",domain); sub(/ .*$/,"",domain); gsub(/\.$/,"",domain); pending=domain }
/A [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ && pending {
  ip=$0; sub(/.*A /,"",ip); sub(/ .*$/,"",ip);
  print pending "\t" ip;
  pending=""
}
' /tmp/dns.log 2>/dev/null | sort -u > /tmp/dns-resolutions.txt

# Plain DNS query list (for backward compat)
grep -oE '(A|AAAA)\? [^ ]+' /tmp/dns.log 2>/dev/null | \
  awk '{print $2}' | sed 's/\.$//' | sort -u > /tmp/dns-queries.txt

# ── 8. Parse HTTP requests ──
echo "[SANDBOX] Parsing HTTP requests..." >&2

# Extract HTTP method, host, path from http.log
awk '
/^[0-9].*length [0-9]/ { next }
/(GET|POST|PUT|DELETE|PATCH) \// {
  method=$0; sub(/.*((GET|POST|PUT|DELETE|PATCH)) /,"",method);
  path=method; sub(/ .*$/,"",path);
  meth=$0; match(meth,/(GET|POST|PUT|DELETE|PATCH)/); meth=substr(meth,RSTART,RLENGTH);
  pending_method=meth; pending_path=path; pending_host=""; pending_body=""
}
/^Host:/ && pending_method { pending_host=$2; gsub(/\r/,"",pending_host) }
/^\r?$/ && pending_method && pending_host {
  print pending_method "\t" pending_host "\t" pending_path;
  pending_method=""; pending_host=""; pending_path=""
}
' /tmp/http.log 2>/dev/null > /tmp/http-requests.txt

# Extract HTTP body snippets for exfiltration detection
awk '
/^(POST|PUT|PATCH) / { capturing=1; body="" }
capturing && /^[^\t]/ && !/^(GET|POST|PUT|DELETE|PATCH|HTTP|Host:|Content|Accept|User-Agent|Connection)/ {
  if (length(body) < 500) body = body $0
}
/^\r?$/ && capturing { if (length(body)>0) print body; capturing=0; body="" }
' /tmp/http.log 2>/dev/null > /tmp/http-bodies.txt

# ── 9. Parse TLS connections (SNI via IP correlation) ──
echo "[SANDBOX] Parsing TLS connections..." >&2

# Map IPs to domains from DNS resolutions, then correlate with TLS IPs
awk '{print $1}' /tmp/connections.txt 2>/dev/null | sort -u > /tmp/tls-ips.txt

# Build domain→IP map, then find TLS connections
awk -F'\t' '
NR==FNR { ip_domain[$2]=$1; next }
{ if ($1 in ip_domain) print ip_domain[$1] "\t" $1 "\t" $2 }
' /tmp/dns-resolutions.txt /tmp/connections.txt 2>/dev/null | \
  grep '	443$' | sort -u > /tmp/tls-connections.txt

# ── 10. Blocked connections (strict mode — requires root for dmesg) ──
if [ "$MODE" = "strict" ]; then
  dmesg 2>/dev/null | grep 'BLOCKED:' | \
    sed -n 's/.*DST=\([^ ]*\).*DPT=\([^ ]*\).*/\1\t\2/p' | \
    sort -u > /tmp/blocked.txt
else
  touch /tmp/blocked.txt
fi

# ── 11. Build JSON with jq ──
echo "[SANDBOX] Building report..." >&2

# Ensure all temp files exist
touch /tmp/fs-created.txt /tmp/fs-deleted.txt /tmp/dns-queries.txt \
  /tmp/sensitive-read.txt /tmp/sensitive-written.txt \
  /tmp/connections.txt /tmp/suspicious-cmds.txt /tmp/install.log \
  /tmp/dns-resolutions.txt /tmp/http-requests.txt /tmp/http-bodies.txt \
  /tmp/tls-connections.txt /tmp/blocked.txt /tmp/entrypoint.log \
  /tmp/preload.log

INSTALL_OUTPUT=$(head -c 5000 /tmp/install.log)
ENTRYPOINT_OUTPUT=$(head -c 5000 /tmp/entrypoint.log 2>/dev/null || echo "")
PRELOAD_LOG=$(head -c 50000 /tmp/preload.log 2>/dev/null || echo "")

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

DNS_RESOLUTIONS=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
  split("\t") | {domain: .[0], ip: .[1]}
)' < /tmp/dns-resolutions.txt)

HTTP_REQUESTS=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
  split("\t") | {method: .[0], host: .[1], path: .[2]}
)' < /tmp/http-requests.txt)

HTTP_BODIES=$(jq -R -s 'split("\n") | map(select(length > 0))' < /tmp/http-bodies.txt)

TLS_CONNS=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
  split("\t") | {domain: .[0], ip: .[1], port: (.[2] | tonumber)}
)' < /tmp/tls-connections.txt)

BLOCKED=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
  split("\t") | {ip: .[0], port: (.[1] | tonumber)}
)' < /tmp/blocked.txt)

# ── Final JSON (prefixed with delimiter for reliable parsing) ──
echo "---MUADDIB-REPORT-START---"
jq -n \
  --arg package "$PACKAGE" \
  --arg timestamp "$TIMESTAMP" \
  --arg mode "$MODE" \
  --argjson duration "${DURATION_MS:-0}" \
  --argjson fs_created "$FS_CREATED" \
  --argjson fs_deleted "$FS_DELETED" \
  --argjson dns "$DNS" \
  --argjson connections "$CONNS" \
  --argjson processes "$PROCS" \
  --argjson sensitive_read "$SENS_READ" \
  --argjson sensitive_written "$SENS_WRITTEN" \
  --argjson dns_resolutions "$DNS_RESOLUTIONS" \
  --argjson http_requests "$HTTP_REQUESTS" \
  --argjson http_bodies "$HTTP_BODIES" \
  --argjson tls_connections "$TLS_CONNS" \
  --argjson blocked_connections "$BLOCKED" \
  --arg install_output "$INSTALL_OUTPUT" \
  --arg entrypoint_output "$ENTRYPOINT_OUTPUT" \
  --arg preload_log "$PRELOAD_LOG" \
  --argjson exit_code "${EXIT_CODE:-1}" \
  '{
    package: $package,
    timestamp: $timestamp,
    mode: $mode,
    duration_ms: $duration,
    filesystem: {
      created: $fs_created,
      deleted: $fs_deleted,
      modified: []
    },
    network: {
      dns_queries: $dns,
      dns_resolutions: $dns_resolutions,
      http_connections: $connections,
      http_requests: $http_requests,
      http_bodies: $http_bodies,
      tls_connections: $tls_connections,
      blocked_connections: $blocked_connections
    },
    processes: {
      spawned: $processes
    },
    sensitive_files: {
      read: $sensitive_read,
      written: $sensitive_written
    },
    install_output: $install_output,
    entrypoint_output: $entrypoint_output,
    preload_log: $preload_log,
    exit_code: $exit_code
  }'
