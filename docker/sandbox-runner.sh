#!/bin/sh
PACKAGE="$1"
MODE="${2:-permissive}"

if [ -z "$PACKAGE" ]; then
  echo "Usage: sandbox-runner.sh <package-name> [permissive|strict]" >&2
  exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_MS=$(date +%s%3N 2>/dev/null || echo 0)

# ── 0. Strict mode: iptables rules (block all except DNS + registry) ──
if [ "$MODE" = "strict" ]; then
  echo "[SANDBOX] STRICT MODE: blocking outgoing connections..." >&2
  # Allow loopback
  iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
  # Allow DNS (port 53)
  iptables -A OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null
  iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null
  # Allow registry.npmjs.org (resolve and allow)
  REGISTRY_IPS=$(getent hosts registry.npmjs.org 2>/dev/null | awk '{print $1}')
  for ip in $REGISTRY_IPS; do
    iptables -A OUTPUT -d "$ip" -j ACCEPT 2>/dev/null
  done
  # Allow established connections (for DNS responses)
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
  # Log and reject everything else
  iptables -A OUTPUT -j LOG --log-prefix "MUADDIB_BLOCKED: " 2>/dev/null
  iptables -A OUTPUT -j REJECT 2>/dev/null
  echo "[SANDBOX] Outgoing traffic restricted to DNS + npmjs.org" >&2
fi

# ── 1. Filesystem snapshot BEFORE install ──
echo "[SANDBOX] Snapshot filesystem before install..." >&2
find / -type f 2>/dev/null | sort > /tmp/fs-before.txt

# ── 2. Network capture: DNS details, HTTP content, TLS SNI ──
echo "[SANDBOX] Starting network capture..." >&2

# 2a. DNS capture (query + answer with IPs)
tcpdump -i any -nn port 53 -l 2>/dev/null > /tmp/dns-raw.log &
DNS_PID=$!

# 2b. HTTP capture (headers + body preview, port 80 only)
tcpdump -i any -nn -A -s 2048 'tcp port 80' -l 2>/dev/null > /tmp/http-raw.log &
HTTP_PID=$!

# 2c. TLS SNI capture (port 443, extract Client Hello SNI)
tcpdump -i any -nn -s 512 'tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)' -l -x 2>/dev/null > /tmp/tls-raw.log &
TLS_PID=$!

# 2d. General network log (legacy, all ports)
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

# Stop all captures
kill "$DNS_PID" "$HTTP_PID" "$TLS_PID" "$TCPDUMP_PID" 2>/dev/null
wait "$DNS_PID" "$HTTP_PID" "$TLS_PID" "$TCPDUMP_PID" 2>/dev/null

END_MS=$(date +%s%3N 2>/dev/null || echo 0)
DURATION_MS=$((END_MS - START_MS))
[ "$DURATION_MS" -lt 0 ] 2>/dev/null && DURATION_MS=0

# ── 5. Filesystem diff (exclude /sandbox/node_modules/) ──
echo "[SANDBOX] Analyzing filesystem changes..." >&2
comm -13 /tmp/fs-before.txt /tmp/fs-after.txt | grep -v '^/sandbox/node_modules/' | grep -v '^/tmp/fs-\|^/tmp/install.log\|^/tmp/network.log\|^/tmp/strace.log\|^/tmp/sensitive-\|^/tmp/suspicious-cmds\|^/tmp/connections.txt\|^/tmp/dns-queries\|^/tmp/fs-created\|^/tmp/fs-deleted\|^/tmp/dns-raw\|^/tmp/http-raw\|^/tmp/tls-raw\|^/tmp/http-requests\|^/tmp/dns-resolutions\|^/tmp/tls-connections\|^/tmp/blocked' > /tmp/fs-created.txt
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

# ── 7. Parse DNS resolutions (query + answer IP) ──
echo "[SANDBOX] Parsing DNS resolutions..." >&2

# Extract DNS query-answer pairs: "domain<TAB>ip"
# tcpdump DNS format: "IP x.x.x.x.53 > ...: ... A? domain. ..." for query
#                     "IP x.x.x.x.53 > ...: ... A domain. x.x.x.x" for answer
awk '
/A\?/ {
  # DNS query line: extract queried domain
  for (i=1; i<=NF; i++) {
    if ($i == "A?" || $i == "AAAA?") {
      domain = $(i+1)
      gsub(/\.$/, "", domain)
    }
  }
}
/ A / && !/A\?/ {
  # DNS answer line: extract domain and resolved IP
  for (i=1; i<=NF; i++) {
    if ($i == "A") {
      d = $(i-1)
      gsub(/\.$/, "", d)
      ip = $(i+1)
      if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        print d "\t" ip
      }
    }
  }
}
' /tmp/dns-raw.log 2>/dev/null | sort -u > /tmp/dns-resolutions.txt

# Also keep simple domain list (legacy)
grep -oE '(A|AAAA)\? [^ ]+' /tmp/network.log 2>/dev/null | \
  awk '{print $2}' | \
  sed 's/\.$//' | \
  sort -u > /tmp/dns-queries.txt

# ── 8. Parse HTTP requests (method, URL, headers, body preview) ──
echo "[SANDBOX] Parsing HTTP requests..." >&2

# Extract HTTP requests from tcpdump -A output
# Lines like: GET /path HTTP/1.1, POST /path HTTP/1.1, Host: domain, body content
awk '
BEGIN { method=""; url=""; host=""; headers=""; body=""; in_body=0; in_request=0 }
/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) / {
  # Flush previous request
  if (method != "") {
    printf "%s\t%s\t%s\t%s\t%s\n", method, host, url, headers, substr(body, 1, 500)
  }
  method = $1
  url = $2
  host = ""
  headers = ""
  body = ""
  in_body = 0
  in_request = 1
}
in_request && /^Host: / {
  host = $2
  gsub(/\r/, "", host)
}
in_request && /^Content-Type: |^Authorization: |^Cookie: |^User-Agent: / {
  h = $0
  gsub(/\r/, "", h)
  headers = headers (headers ? "; " : "") h
}
in_request && /^\r?$/ && !in_body {
  in_body = 1
  next
}
in_request && in_body && length($0) > 0 {
  body = body $0
}
END {
  if (method != "") {
    printf "%s\t%s\t%s\t%s\t%s\n", method, host, url, headers, substr(body, 1, 500)
  }
}
' /tmp/http-raw.log 2>/dev/null > /tmp/http-requests.txt

# ── 9. Parse TLS connections (SNI extraction) ──
echo "[SANDBOX] Parsing TLS connections..." >&2

# Extract SNI from TLS Client Hello packets
# The SNI is in the hex dump after the Client Hello handshake type (0x01)
# We use a simpler approach: look for readable domain names in the hex output
# and correlate with destination IPs from the packet header
awk '
/^[0-9]/ && / > / {
  # Packet header line with IP addresses
  split($0, parts, " > ")
  dst = parts[2]
  # Extract destination IP (before the port)
  gsub(/\.[0-9]+:.*/, "", dst)
  gsub(/.*IP /, "", parts[1])
  src_ip = parts[1]
  gsub(/\.[0-9]+$/, "", src_ip)
  current_dst = dst
}
/0x[0-9a-f]+:/ {
  hex_line = $0
}
' /tmp/tls-raw.log 2>/dev/null > /dev/null

# Simpler SNI extraction: look for domain-like strings in TLS traffic
# tcpdump -A would show SNI as ASCII in Client Hello
# Use strace connections + DNS to correlate IP->domain for port 443
awk -F'\t' '
{
  ip = $1; port = $2
  if (port == "443") print ip
}
' /tmp/connections.txt 2>/dev/null | sort -u > /tmp/tls-ips.txt

# Build TLS connections by correlating IPs with DNS resolutions
# Format: sni<TAB>ip<TAB>port
while IFS= read -r tls_ip; do
  # Look up the domain for this IP from DNS resolutions
  sni=$(awk -F'\t' -v ip="$tls_ip" '$2 == ip {print $1; exit}' /tmp/dns-resolutions.txt 2>/dev/null)
  if [ -n "$sni" ]; then
    printf '%s\t%s\t443\n' "$sni" "$tls_ip"
  else
    printf '%s\t%s\t443\n' "unknown" "$tls_ip"
  fi
done < /tmp/tls-ips.txt > /tmp/tls-connections.txt 2>/dev/null

# ── 10. Blocked connections (strict mode) ──
BLOCKED_CONNS="[]"
if [ "$MODE" = "strict" ]; then
  # Parse kernel log for blocked connections
  dmesg 2>/dev/null | grep 'MUADDIB_BLOCKED' | \
    sed -n 's/.*DST=\([^ ]*\).*DPT=\([^ ]*\).*/\1\t\2/p' | \
    sort -u > /tmp/blocked-conns.txt
  touch /tmp/blocked-conns.txt
  BLOCKED_CONNS=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
    split("\t") | {host: .[0], port: (.[1] | tonumber)}
  )' < /tmp/blocked-conns.txt)
fi

# ── 11. Build JSON with jq ──
echo "[SANDBOX] Building report..." >&2

# Ensure all temp files exist
touch /tmp/fs-created.txt /tmp/fs-deleted.txt /tmp/dns-queries.txt \
  /tmp/sensitive-read.txt /tmp/sensitive-written.txt \
  /tmp/connections.txt /tmp/suspicious-cmds.txt /tmp/install.log \
  /tmp/dns-resolutions.txt /tmp/http-requests.txt /tmp/tls-connections.txt

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

DNS_RESOLUTIONS=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
  split("\t") | {query: .[0], answer: .[1]}
)' < /tmp/dns-resolutions.txt)

HTTP_REQUESTS=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
  split("\t") | {method: .[0], host: .[1], path: .[2], headers: .[3], body_preview: .[4]}
)' < /tmp/http-requests.txt)

TLS_CONNS=$(jq -R -s 'split("\n") | map(select(length > 0)) | map(
  split("\t") | {sni: .[0], ip: .[1], port: (.[2] | tonumber)}
)' < /tmp/tls-connections.txt)

# ── Final JSON (ONLY output on stdout) ──
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
  --argjson tls_connections "$TLS_CONNS" \
  --argjson blocked_connections "$BLOCKED_CONNS" \
  --arg install_output "$INSTALL_OUTPUT" \
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
    exit_code: $exit_code
  }'
