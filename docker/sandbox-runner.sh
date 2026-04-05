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
# PHASE 0.5: Docker camouflage — anti-sandbox evasion (T1497.001)
# Modern malware detects Docker before executing (/.dockerenv,
# /proc/1/cgroup, hex hostname, low uptime, empty home).
# If detected → stays dormant → sandbox score 0 → false negative.
# ══════════════════════════════════════════════════════════════

# ── 0.5a. Remove Docker fingerprint files ──
rm -f /.dockerenv

# ── 0.5b. Realistic bash_history (credible developer activity) ──
cat > /home/sandboxuser/.bash_history << 'HIST'
cd ~/projects/my-app
git pull origin main
npm install
npm test
code .
git status
git add -A && git commit -m "fix: update deps"
npm run build
ls -la
cat package.json
HIST
chown sandboxuser:sandboxuser /home/sandboxuser/.bash_history

# ── 0.5c. Fake project directory (developer workstation illusion) ──
mkdir -p /home/sandboxuser/projects/my-app
cat > /home/sandboxuser/projects/my-app/package.json << 'EOF'
{"name":"my-app","version":"2.1.0","main":"index.js","scripts":{"start":"node index.js","test":"jest"}}
EOF
chown -R sandboxuser:sandboxuser /home/sandboxuser/projects

# ── 0.5d. Realistic home directory structure ──
# An empty home is a strong sandbox signal. Real dev machines have these dirs.
mkdir -p /home/sandboxuser/.config /home/sandboxuser/.local/share \
  /home/sandboxuser/Downloads /home/sandboxuser/Documents \
  /home/sandboxuser/.vscode
chown -R sandboxuser:sandboxuser /home/sandboxuser/.config \
  /home/sandboxuser/.local /home/sandboxuser/Downloads \
  /home/sandboxuser/Documents /home/sandboxuser/.vscode

# ══════════════════════════════════════════════════════════════
# PHASE 0.6: Libfaketime setup (cross-process time acceleration)
# Accelerates C-level timers (nanosleep, clock_gettime, gettimeofday)
# for ALL child processes (Python, bash, etc.) — complements preload.js
# which only patches JS-level timers in Node.js.
# ══════════════════════════════════════════════════════════════

LIBFAKETIME_PATH="/usr/lib/faketime/libfaketime.so.1"
[ ! -f "$LIBFAKETIME_PATH" ] && LIBFAKETIME_PATH="/usr/local/lib/faketime/libfaketime.so.1"
[ ! -f "$LIBFAKETIME_PATH" ] && LIBFAKETIME_PATH=""

if [ -n "$MUADDIB_FAKETIME" ] && [ -n "$LIBFAKETIME_PATH" ]; then
  export LD_PRELOAD="$LIBFAKETIME_PATH"
  export FAKETIME="$MUADDIB_FAKETIME"
  export DONT_FAKE_MONOTONIC=1
  export FAKETIME_NO_CACHE=1
  echo "[SANDBOX] libfaketime active: FAKETIME=$FAKETIME" >&2
fi
# Clean up internal vars (don't expose sandbox internals to the package)
unset MUADDIB_FAKETIME MUADDIB_FAKETIME_ACTIVE

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

# ── 0b. Mock network: DNS proxy + HTTP/HTTPS honeypot (T1071/T1041 behavioral capture) ──
# Runs in all modes (permissive + strict, gVisor + runc).
# Safe domains (npm, GitHub, CDNs) are forwarded to the real upstream DNS.
# Non-safe domains resolve to 127.0.0.2 where HTTP/HTTPS honeypots capture requests.
# This allows the sandbox to observe network INTENT without real outbound traffic.
UPSTREAM_DNS=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | head -1 | awk '{print $2}')
[ -z "$UPSTREAM_DNS" ] && UPSTREAM_DNS="8.8.8.8"

# Generate per-session mock CA for HTTPS interception (unique each run).
# The CA is added to the system SSL bundle so curl/wget/python trust it.
# Node.js gets it via NODE_EXTRA_CA_CERTS.
echo "[SANDBOX] Generating mock TLS CA..." >&2
# OpenSSL 3.x outputs info messages to STDOUT (not stderr) — must suppress both
# to prevent pollution of the container stdout that carries the JSON report.
openssl genrsa -out /tmp/mock-ca-key.pem 2048 >/dev/null 2>&1
openssl req -new -x509 -key /tmp/mock-ca-key.pem -out /tmp/mock-ca.pem \
  -days 1 -subj "/O=Internet Security Research Group/CN=ISRG Root X2" >/dev/null 2>&1
openssl genrsa -out /tmp/mock-server-key.pem 2048 >/dev/null 2>&1
# Default cert for TLS connections without SNI header
# Note: first openssl stdout is piped (CSR), second needs >/dev/null for info messages
openssl req -new -key /tmp/mock-server-key.pem -subj "/CN=localhost" 2>/dev/null | \
  openssl x509 -req -CA /tmp/mock-ca.pem -CAkey /tmp/mock-ca-key.pem \
    -CAcreateserial -days 1 -out /tmp/mock-cert-default.pem >/dev/null 2>&1
# Trust the CA system-wide: append to SSL bundle (read-only FS → copy to /tmp)
cat /etc/ssl/certs/ca-certificates.crt /tmp/mock-ca.pem > /tmp/mock-ca-bundle.pem 2>/dev/null
export SSL_CERT_FILE=/tmp/mock-ca-bundle.pem
export NODE_EXTRA_CA_CERTS=/tmp/mock-ca.pem

echo "[SANDBOX] Starting mock network (upstream DNS: $UPSTREAM_DNS)..." >&2
MUADDIB_UPSTREAM_DNS=$UPSTREAM_DNS node /opt/mock-network.js >/dev/null 2>&1 &
MOCK_NET_PID=$!
# Wait for mock servers to be ready (DNS + HTTP + HTTPS)
# 10 iterations × 0.5s = 5s max (gVisor I/O overhead can delay Node.js cold start)
for _i in 1 2 3 4 5 6 7 8 9 10; do
  [ -f /tmp/mock-network-ready ] && break
  sleep 0.5
done
if [ -f /tmp/mock-network-ready ]; then
  echo "nameserver 127.0.0.1" > /etc/resolv.conf
  echo "[SANDBOX] Mock network active — DNS redirected to 127.0.0.1." >&2
else
  echo "[SANDBOX] Mock network failed to start — using real DNS." >&2
  # Log why it failed (cert files missing? node crash?)
  [ ! -f /tmp/mock-ca.pem ] && echo "[SANDBOX] DIAG: mock-ca.pem missing (openssl failed)" >&2
  [ ! -f /tmp/mock-server-key.pem ] && echo "[SANDBOX] DIAG: mock-server-key.pem missing" >&2
  [ ! -f /tmp/mock-cert-default.pem ] && echo "[SANDBOX] DIAG: mock-cert-default.pem missing" >&2
  kill "$MOCK_NET_PID" 2>/dev/null
  MOCK_NET_PID=""
fi

# ── 1. Filesystem snapshot BEFORE install ──
echo "[SANDBOX] Snapshot filesystem before install..." >&2
cp /opt/fs-baseline.txt /tmp/fs-before.txt

# ── 2. tcpdump: separate captures for DNS, HTTP, TLS (requires root + NET_RAW) ──
# gVisor mode: skip tcpdump — gVisor captures network at kernel level via --log-packets.
# tcpdump requires AF_PACKET which gVisor does not fully support.
if [ -z "$MUADDIB_GVISOR" ]; then
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
else
  echo "[SANDBOX] gVisor mode — network captured at kernel level (--log-packets)." >&2
fi

# ══════════════════════════════════════════════════════════════
# PHASE 2: Unprivileged install (su sandboxuser)
# npm install runs as sandboxuser with strace for syscall tracing.
# strace can trace child processes without SYS_PTRACE (parent→child).
# ══════════════════════════════════════════════════════════════

# ── 2b. CI environment simulation — random profile per run ──
# Simulate CI to trigger CI-aware malware. Only one CI provider per run
# (setting all simultaneously is detectable — no real CI does that).
echo "[SANDBOX] Simulating CI environment..." >&2
CI_PROFILE=$((RANDOM % 4))
export CI=true
case $CI_PROFILE in
  0) export GITHUB_ACTIONS=true ;;
  1) export GITLAB_CI=true ;;
  2) export TRAVIS=true ;;
  3) export CIRCLECI=true ;;
esac

# ── 2c. Canary tokens (honeypots) ──
# Use Docker-injected dynamic tokens if available, otherwise static fallbacks.
# If exfiltrated via network/DNS/files, sandbox.js detects the theft.
export GITHUB_TOKEN="${GITHUB_TOKEN:-ghp_R8kLmN2pQ4vW7xY9aB3cD5eF6gH8jK0mN2pQ4vW}"
export NPM_TOKEN="${NPM_TOKEN:-npm_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-AKIAIOSFODNN7EXAMPLE}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY}"
export SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-https://hooks.example.com/services/TCANARY/BCANARY/canary-slack-token}"
export DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-https://discord.com/api/webhooks/000000000000000000/abcdefghijklmnopqrstuvwxyz}"

# ── 2d. Honey environment — write canary files to sandboxuser home ──
# Realistic credential files trap malware that reads sensitive paths.
# Content is injected via Docker -e from canary-tokens.js (dynamic per session).
HONEY_HOME="/home/sandboxuser"
if [ -n "$CANARY_ENV_CONTENT" ]; then
  printf '%b' "$CANARY_ENV_CONTENT" > "$HONEY_HOME/.env"
  chown sandboxuser:sandboxuser "$HONEY_HOME/.env"
fi
if [ -n "$CANARY_NPMRC_CONTENT" ]; then
  printf '%b' "$CANARY_NPMRC_CONTENT" > "$HONEY_HOME/.npmrc"
  chown sandboxuser:sandboxuser "$HONEY_HOME/.npmrc"
fi
if [ -n "$CANARY_AWS_CONTENT" ]; then
  mkdir -p "$HONEY_HOME/.aws"
  printf '%b' "$CANARY_AWS_CONTENT" > "$HONEY_HOME/.aws/credentials"
  chown -R sandboxuser:sandboxuser "$HONEY_HOME/.aws"
fi
if [ -n "$CANARY_SSH_KEY" ]; then
  mkdir -p "$HONEY_HOME/.ssh"
  printf '%b' "$CANARY_SSH_KEY" > "$HONEY_HOME/.ssh/id_rsa"
  chmod 600 "$HONEY_HOME/.ssh/id_rsa"
  chown -R sandboxuser:sandboxuser "$HONEY_HOME/.ssh"
fi
if [ -n "$CANARY_GITCONFIG" ]; then
  printf '%b' "$CANARY_GITCONFIG" > "$HONEY_HOME/.gitconfig"
  chown sandboxuser:sandboxuser "$HONEY_HOME/.gitconfig"
fi
# Clean up canary content env vars (don't leak them to the package process)
unset CANARY_ENV_CONTENT CANARY_NPMRC_CONTENT CANARY_AWS_CONTENT CANARY_SSH_KEY CANARY_GITCONFIG
echo "[SANDBOX] Honey environment deployed." >&2

# ── 2e. Preload injection — deferred to entry point (phase 3b) ──
# NODE_OPTIONS='--require /opt/preload.js' monkey-patches http/https/net/dns.
# Enabling it during npm install causes timeouts (hundreds of wrapped network calls).
# tcpdump already captures install-phase network; preload targets runtime behavior.

# ── 3. npm install with strace — as sandboxuser ──
echo "[SANDBOX] Installing $PACKAGE as sandboxuser..." >&2
cd /sandbox/install
# Ensure sandboxuser owns the install directory
chown sandboxuser:sandboxuser /sandbox/install
# Run npm install as sandboxuser via su, wrapped in strace for syscall tracing.
# gVisor mode: no strace wrapper — gVisor traces all syscalls at the kernel level.
if [ -n "$MUADDIB_GVISOR" ]; then
  touch /tmp/strace.log
  su sandboxuser -s /bin/sh -c "
    npm install \"$PACKAGE\" --ignore-scripts=false --fetch-timeout=120000 > /tmp/install.log 2>&1
  "
elif [ "$MODE" = "strict" ]; then
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
export NODE_OPTIONS="${NODE_OPTIONS:---require /opt/node_setup.js}"
echo "[SANDBOX] Executing package entry point..." >&2

if echo "$PACKAGE" | grep -q '^/'; then
  # Local mode: $PACKAGE is already a path (e.g. /sandbox/local-pkg)
  REQUIRE_PATH="$PACKAGE"
else
  # Remote mode: package installed in node_modules
  REQUIRE_PATH="/sandbox/install/node_modules/$PACKAGE"
fi

# gVisor mode: no strace wrapper — gVisor traces at kernel level.
if [ -n "$MUADDIB_GVISOR" ]; then
  su sandboxuser -s /bin/sh -c "
    timeout 30 node -e \"try { require('$REQUIRE_PATH') } catch(e) { console.error('[ENTRY_ERROR] ' + (e.code || 'UNKNOWN') + ': ' + e.message); process.exitCode = 42; }\" > /tmp/entrypoint.log 2>&1
  " || true
else
  su sandboxuser -s /bin/sh -c "
    strace -f -e trace=network,process,open,openat,connect,execve,sendto,recvfrom \
      -o /tmp/strace-entrypoint.log \
      timeout 30 node -e \"try { require('$REQUIRE_PATH') } catch(e) { console.error('[ENTRY_ERROR] ' + (e.code || 'UNKNOWN') + ': ' + e.message); process.exitCode = 42; }\" > /tmp/entrypoint.log 2>&1
  " || true

  # Merge entrypoint strace into main strace log for unified analysis
  cat /tmp/strace-entrypoint.log >> /tmp/strace.log 2>/dev/null
fi

# ══════════════════════════════════════════════════════════════
# PHASE 3: Post-install analysis (back as root for full access)
# ══════════════════════════════════════════════════════════════

# ── 4. Filesystem snapshot AFTER install ──
echo "[SANDBOX] Snapshot filesystem after install..." >&2
find / -type f 2>/dev/null | sort > /tmp/fs-after.txt

# Stop tcpdump (only if started — skipped in gVisor mode)
if [ -z "$MUADDIB_GVISOR" ]; then
  kill "$DNS_PID" "$HTTP_PID" "$TLS_PID" "$OTHER_PID" 2>/dev/null
  wait "$DNS_PID" "$HTTP_PID" "$TLS_PID" "$OTHER_PID" 2>/dev/null
fi

# Stop mock network server
if [ -n "$MOCK_NET_PID" ]; then
  kill "$MOCK_NET_PID" 2>/dev/null
  wait "$MOCK_NET_PID" 2>/dev/null
fi

END_MS=$(date +%s%3N 2>/dev/null || echo 0)
DURATION_MS=$((END_MS - START_MS))
[ "$DURATION_MS" -lt 0 ] 2>/dev/null && DURATION_MS=0

# ── 5. Filesystem diff ──
echo "[SANDBOX] Analyzing filesystem changes..." >&2
comm -13 /tmp/fs-before.txt /tmp/fs-after.txt | grep -v '^/sandbox/install/' | grep -v '^/sandbox/local-pkg/' | grep -v '^/tmp/' > /tmp/fs-created.txt
comm -23 /tmp/fs-before.txt /tmp/fs-after.txt | grep -v '^/sandbox/install/' | grep -v '^/sandbox/local-pkg/' > /tmp/fs-deleted.txt

# ── 6. Parse strace ──
# gVisor mode: strace parsing happens on the host via gvisor-parser.js.
# Create empty files so the JSON report generation below works with empty arrays.
if [ -n "$MUADDIB_GVISOR" ]; then
  echo "[SANDBOX] gVisor mode — strace parsed on host." >&2
  touch /tmp/sensitive-read.txt /tmp/sensitive-written.txt \
    /tmp/connections.txt /tmp/suspicious-cmds.txt \
    /tmp/dns-queries.txt /tmp/dns-resolutions.txt \
    /tmp/http-requests.txt /tmp/http-bodies.txt \
    /tmp/tls-connections.txt /tmp/blocked.txt
else
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

fi  # end of non-gVisor strace/network parsing block

# ── 10b. Parse mock network logs (works in both gVisor and runc) ──
# Mock DNS: non-safe domain queries → append to dns-queries.txt and dns-resolutions.txt
# Mock HTTP: captured requests → append to http-requests.txt and http-bodies.txt
# Also parse preload.js MOCK entries from preload.log
if [ -f /tmp/mock-dns.log ]; then
  echo "[SANDBOX] Parsing mock DNS log..." >&2
  jq -r 'select(.safe == false) | .domain' /tmp/mock-dns.log 2>/dev/null | sort -u >> /tmp/dns-queries.txt
  jq -r 'select(.safe == false and .mock_ip != null) | "\(.domain)\t\(.mock_ip)"' /tmp/mock-dns.log 2>/dev/null >> /tmp/dns-resolutions.txt
fi
if [ -f /tmp/mock-http.log ]; then
  echo "[SANDBOX] Parsing mock HTTP log..." >&2
  jq -r 'select(.method != null) | "\(.method)\t\(.host)\t\(.path)"' /tmp/mock-http.log 2>/dev/null >> /tmp/http-requests.txt
  jq -r 'select(.body != null and (.body | length) > 0) | .body' /tmp/mock-http.log 2>/dev/null >> /tmp/http-bodies.txt
fi
# Parse preload.js mock entries: MOCK_FETCH body data and MOCK_HTTP_BODY entries
if [ -f /tmp/preload.log ]; then
  grep '\[PRELOAD\] MOCK_HTTP_BODY:' /tmp/preload.log 2>/dev/null | \
    sed 's/.*MOCK_HTTP_BODY: OUT [^ ]* [^ ]* //' | sed 's/ (t+.*$//' >> /tmp/http-bodies.txt 2>/dev/null
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
