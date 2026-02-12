const { execSync, spawn } = require('child_process');
const path = require('path');

const DOCKER_IMAGE = 'muaddib-sandbox';
const CONTAINER_TIMEOUT = 120000; // 120 seconds
const NPM_PACKAGE_REGEX = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

// Domains excluded from network findings (false positives)
const SAFE_DOMAINS = [
  'registry.npmjs.org',
  'github.com',
  'objects.githubusercontent.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'codeload.github.com',
  'npmjs.com',
  'npmjs.org',
  'yarnpkg.com',
  'googleapis.com',
  'cloudflare.com'
];

// IPs/ports excluded from connection findings (false positives)
const SAFE_IPS = ['127.0.0.1'];
const PROBE_PORTS = [65535]; // Node.js internal connectivity checks

// Commands that are always suspicious in a sandbox
const DANGEROUS_CMDS = ['curl', 'wget', 'nc', 'netcat', 'python', 'python3', 'bash', 'sh'];

// Patterns indicating data exfiltration in HTTP bodies
const EXFIL_PATTERNS = [
  { pattern: /\bNPM_TOKEN\b/i, label: 'npm token', severity: 'CRITICAL' },
  { pattern: /\bGITHUB_TOKEN\b/i, label: 'GitHub token', severity: 'CRITICAL' },
  { pattern: /\bAWS_SECRET/i, label: 'AWS credentials', severity: 'CRITICAL' },
  { pattern: /npmrc/i, label: '.npmrc content', severity: 'CRITICAL' },
  { pattern: /\bssh-rsa\b|\bssh-ed25519\b/i, label: 'SSH key', severity: 'CRITICAL' },
  { pattern: /BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY/, label: 'private key', severity: 'CRITICAL' },
  { pattern: /\bpassword\b/i, label: 'password', severity: 'CRITICAL' },
  { pattern: /\btoken\b/i, label: 'token', severity: 'CRITICAL' },
  { pattern: /\/etc\/passwd/, label: 'passwd file', severity: 'HIGH' },
  { pattern: /\.env\b/, label: '.env content', severity: 'HIGH' }
];

// ── Docker availability checks ──

function isDockerAvailable() {
  try {
    execSync('docker info', { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

function imageExists() {
  try {
    execSync(`docker image inspect ${DOCKER_IMAGE}`, { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

// ── Build image (with cache) ──

async function buildSandboxImage() {
  if (!isDockerAvailable()) {
    console.log('[SANDBOX] Docker is not installed or not running. Skipping sandbox analysis.');
    return false;
  }

  if (imageExists()) {
    console.log('[SANDBOX] Using cached Docker image.');
    return true;
  }

  console.log('[SANDBOX] Building Docker image...');

  return new Promise((resolve) => {
    const dockerfilePath = path.join(__dirname, '..', 'docker');
    const proc = spawn('docker', ['build', '-t', DOCKER_IMAGE, dockerfilePath], {
      stdio: 'inherit'
    });

    proc.on('close', (code) => {
      if (code === 0) {
        console.log('[SANDBOX] Image built successfully.');
        resolve(true);
      } else {
        console.log('[SANDBOX] Docker build failed.');
        resolve(false);
      }
    });

    proc.on('error', () => {
      console.log('[SANDBOX] Docker error during build.');
      resolve(false);
    });
  });
}

// ── Run sandbox analysis ──

async function runSandbox(packageName, options = {}) {
  const cleanResult = { score: 0, severity: 'CLEAN', findings: [], raw_report: null, suspicious: false };

  if (!isDockerAvailable()) {
    console.log('[SANDBOX] Docker is not installed or not running. Skipping.');
    return cleanResult;
  }

  const strict = options.strict || false;
  const mode = strict ? 'strict' : 'permissive';

  // Validate package name before passing to container
  if (!NPM_PACKAGE_REGEX.test(packageName)) {
    console.log('[SANDBOX] Invalid package name: ' + packageName);
    return cleanResult;
  }

  console.log(`[SANDBOX] Analyzing "${packageName}" in isolated container (mode: ${mode})...`);

  return new Promise((resolve) => {
    let stdout = '';
    let timedOut = false;
    const containerName = `muaddib-sandbox-${Date.now()}`;

    const dockerArgs = [
      'run',
      '--rm',
      `--name=${containerName}`,
      '--network=bridge',
      '--memory=512m',
      '--cpus=1',
      '--pids-limit=100',
      '--cap-drop=ALL'
    ];

    // Strict mode needs strace (SYS_PTRACE), packet capture (NET_RAW), and iptables (NET_ADMIN)
    if (strict) {
      dockerArgs.push('--cap-add=SYS_PTRACE');
      dockerArgs.push('--cap-add=NET_RAW');
      dockerArgs.push('--cap-add=NET_ADMIN');
    }

    dockerArgs.push('--read-only');

    dockerArgs.push('--security-opt', 'no-new-privileges');
    dockerArgs.push(DOCKER_IMAGE);
    dockerArgs.push(packageName);
    dockerArgs.push(mode);

    const proc = spawn('docker', dockerArgs);

    // Timeout: kill container after 120s
    const timer = setTimeout(() => {
      timedOut = true;
      console.log('[SANDBOX] Timeout (120s). Killing container...');
      try {
        execSync(`docker kill ${containerName}`, { stdio: 'pipe', timeout: 5000 });
      } catch {
        proc.kill('SIGKILL');
      }
    }, CONTAINER_TIMEOUT);

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      // Forward sandbox progress logs (sanitize ANSI escape sequences)
      const text = data.toString().replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
      for (const line of text.split('\n')) {
        if (line.includes('[SANDBOX]')) {
          console.log(line.trim());
        }
      }
    });

    proc.on('close', () => {
      clearTimeout(timer);

      if (timedOut) {
        const result = {
          score: 100,
          severity: 'CRITICAL',
          findings: [{
            type: 'timeout',
            severity: 'CRITICAL',
            detail: 'Container exceeded 120s timeout',
            evidence: `Killed after ${CONTAINER_TIMEOUT}ms`
          }],
          raw_report: null,
          suspicious: true
        };
        displayResults(result);
        resolve(result);
        return;
      }

      // Parse JSON from container stdout
      let report;
      try {
        report = JSON.parse(stdout);
      } catch {
        console.log('[SANDBOX] Failed to parse container output.');
        resolve(cleanResult);
        return;
      }

      const { score, findings } = scoreFindings(report);
      const severity = getSeverity(score);
      const result = { score, severity, findings, raw_report: report, suspicious: score > 0 };

      displayResults(result);
      resolve(result);
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      if (err.code === 'ENOENT') {
        console.log('[SANDBOX] Docker not found. Please install Docker.');
      } else {
        console.log(`[SANDBOX] Error: ${err.message}`);
      }
      resolve(cleanResult);
    });
  });
}

// ── Scoring engine ──

function scoreFindings(report) {
  let score = 0;
  const findings = [];

  // 1. Sensitive file reads
  for (const file of (report.sensitive_files?.read || [])) {
    if (/\.npmrc/.test(file) || /\.ssh/.test(file) || /\.aws/.test(file)) {
      score += 40;
      findings.push({ type: 'sensitive_file_read', severity: 'CRITICAL', detail: `Read credential file: ${file}`, evidence: file });
    } else if (/\/etc\/passwd/.test(file) || /\/etc\/shadow/.test(file)) {
      score += 25;
      findings.push({ type: 'sensitive_file_read', severity: 'HIGH', detail: `Read system file: ${file}`, evidence: file });
    } else if (/\.env/.test(file) || /\.gitconfig/.test(file) || /\.bash_history/.test(file)) {
      score += 15;
      findings.push({ type: 'sensitive_file_read', severity: 'MEDIUM', detail: `Read config file: ${file}`, evidence: file });
    }
  }

  // 2. Sensitive file writes (from strace)
  for (const file of (report.sensitive_files?.written || [])) {
    if (/\.npmrc/.test(file) || /\.ssh/.test(file) || /\.aws/.test(file)) {
      score += 40;
      findings.push({ type: 'sensitive_file_write', severity: 'CRITICAL', detail: `Write to credential file: ${file}`, evidence: file });
    } else if (/\/etc\/passwd/.test(file) || /\/etc\/shadow/.test(file)) {
      score += 25;
      findings.push({ type: 'sensitive_file_write', severity: 'HIGH', detail: `Write to system file: ${file}`, evidence: file });
    } else {
      score += 15;
      findings.push({ type: 'sensitive_file_write', severity: 'MEDIUM', detail: `Write to sensitive file: ${file}`, evidence: file });
    }
  }

  // 3. Filesystem changes — files created in suspicious locations
  for (const file of (report.filesystem?.created || [])) {
    if (/^\/usr\/bin\//.test(file) || /crontab/.test(file) || /\/cron\.d\//.test(file)) {
      score += 50;
      findings.push({ type: 'suspicious_filesystem', severity: 'CRITICAL', detail: `File created in system path: ${file}`, evidence: file });
    } else if (/^\/tmp\//.test(file)) {
      score += 30;
      findings.push({ type: 'suspicious_filesystem', severity: 'HIGH', detail: `File created in /tmp: ${file}`, evidence: file });
    }
  }

  // 4a. DNS queries (exclude safe domains)
  for (const domain of (report.network?.dns_queries || [])) {
    if (isSafeDomain(domain)) continue;
    score += 20;
    findings.push({ type: 'suspicious_dns', severity: 'HIGH', detail: `DNS query to non-registry domain: ${domain}`, evidence: domain });
  }

  // 4b. DNS resolutions — extra detail
  for (const res of (report.network?.dns_resolutions || [])) {
    if (isSafeDomain(res.domain)) continue;
    // Already scored in 4a via dns_queries, but flag the resolution for reporting
    findings.push({ type: 'dns_resolution', severity: 'INFO', detail: `${res.domain} → ${res.ip}`, evidence: `${res.domain}:${res.ip}` });
  }

  // 5a. TCP connections (exclude safe hosts, probe ports, localhost)
  for (const conn of (report.network?.http_connections || [])) {
    if (isSafeHost(conn.host)) continue;
    if (SAFE_IPS.includes(conn.host)) continue;
    if (PROBE_PORTS.includes(conn.port)) continue;
    score += 25;
    findings.push({ type: 'suspicious_connection', severity: 'HIGH', detail: `TCP connection to ${conn.host}:${conn.port}`, evidence: `${conn.host}:${conn.port}` });
  }

  // 5b. TLS connections — non-safe domains
  for (const tls of (report.network?.tls_connections || [])) {
    if (isSafeDomain(tls.domain)) continue;
    score += 20;
    findings.push({ type: 'suspicious_tls', severity: 'HIGH', detail: `TLS connection to ${tls.domain} (${tls.ip}:${tls.port})`, evidence: tls.domain });
  }

  // 5c. HTTP exfiltration detection — scan body snippets for sensitive data
  for (const body of (report.network?.http_bodies || [])) {
    for (const pat of EXFIL_PATTERNS) {
      if (pat.pattern.test(body)) {
        score += 50;
        findings.push({
          type: 'data_exfiltration',
          severity: pat.severity,
          detail: `HTTP body contains ${pat.label}`,
          evidence: body.substring(0, 200)
        });
        break; // One match per body is enough
      }
    }
  }

  // 5d. HTTP requests to non-safe hosts
  for (const req of (report.network?.http_requests || [])) {
    if (isSafeDomain(req.host)) continue;
    score += 20;
    findings.push({ type: 'suspicious_http_request', severity: 'HIGH', detail: `${req.method} ${req.host}${req.path}`, evidence: `${req.method} ${req.host}${req.path}` });
  }

  // 5e. Blocked connections (strict mode)
  for (const blocked of (report.network?.blocked_connections || [])) {
    score += 30;
    findings.push({ type: 'blocked_connection', severity: 'HIGH', detail: `Blocked outbound to ${blocked.ip}:${blocked.port}`, evidence: `${blocked.ip}:${blocked.port}` });
  }

  // 6. Suspicious processes
  for (const p of (report.processes?.spawned || [])) {
    const cmd = p.command || '';
    const basename = cmd.split('/').pop();
    if (DANGEROUS_CMDS.some(d => basename === d)) {
      score += 40;
      findings.push({ type: 'suspicious_process', severity: 'CRITICAL', detail: `Dangerous command spawned: ${cmd}`, evidence: cmd });
    } else if (cmd) {
      score += 15;
      findings.push({ type: 'unknown_process', severity: 'MEDIUM', detail: `Unknown process spawned: ${cmd}`, evidence: cmd });
    }
  }

  score = Math.min(100, score);
  return { score, findings };
}

// ── Network report (detailed, colored) ──

function generateNetworkReport(report) {
  const lines = [];
  const RED = '\x1b[31m';
  const YELLOW = '\x1b[33m';
  const GREEN = '\x1b[32m';
  const CYAN = '\x1b[36m';
  const MAGENTA = '\x1b[35m';
  const BOLD = '\x1b[1m';
  const DIM = '\x1b[2m';
  const RESET = '\x1b[0m';

  lines.push('');
  lines.push(`${BOLD}${MAGENTA}╔══════════════════════════════════════════════════╗${RESET}`);
  lines.push(`${BOLD}${MAGENTA}║   MUAD'DIB — Sandbox Network Report              ║${RESET}`);
  lines.push(`${BOLD}${MAGENTA}╚══════════════════════════════════════════════════╝${RESET}`);
  lines.push('');
  lines.push(`  Package: ${BOLD}${report.package}${RESET}`);
  lines.push(`  Mode:    ${report.mode === 'strict' ? RED + 'STRICT' : GREEN + 'permissive'}${RESET}`);
  lines.push(`  Time:    ${report.timestamp}`);
  lines.push(`  Duration: ${report.duration_ms}ms`);

  // DNS Resolutions
  const dnsRes = report.network?.dns_resolutions || [];
  lines.push('');
  lines.push(`${BOLD}${CYAN}── DNS Resolutions (${dnsRes.length}) ──${RESET}`);
  if (dnsRes.length === 0) {
    lines.push(`  ${DIM}No DNS resolutions captured${RESET}`);
  } else {
    for (const r of dnsRes) {
      const safe = isSafeDomain(r.domain);
      const icon = safe ? GREEN + '[OK]' : YELLOW + '[!!]';
      lines.push(`  ${icon}${RESET} ${r.domain} → ${r.ip}`);
    }
  }

  // HTTP Requests
  const httpReqs = report.network?.http_requests || [];
  lines.push('');
  lines.push(`${BOLD}${CYAN}── HTTP Requests (${httpReqs.length}) ──${RESET}`);
  if (httpReqs.length === 0) {
    lines.push(`  ${DIM}No HTTP requests captured${RESET}`);
  } else {
    for (const req of httpReqs) {
      const safe = isSafeDomain(req.host);
      const icon = safe ? GREEN + '[OK]' : RED + '[!!]';
      lines.push(`  ${icon}${RESET} ${req.method} ${req.host}${req.path}`);
    }
  }

  // TLS Connections
  const tlsConns = report.network?.tls_connections || [];
  lines.push('');
  lines.push(`${BOLD}${CYAN}── TLS Connections (${tlsConns.length}) ──${RESET}`);
  if (tlsConns.length === 0) {
    lines.push(`  ${DIM}No TLS connections captured${RESET}`);
  } else {
    for (const tls of tlsConns) {
      const safe = isSafeDomain(tls.domain);
      const icon = safe ? GREEN + '[OK]' : YELLOW + '[!!]';
      lines.push(`  ${icon}${RESET} ${tls.domain} (${tls.ip}:${tls.port})`);
    }
  }

  // Blocked Connections (strict mode)
  const blocked = report.network?.blocked_connections || [];
  if (blocked.length > 0) {
    lines.push('');
    lines.push(`${BOLD}${RED}── Blocked Connections (${blocked.length}) ──${RESET}`);
    for (const b of blocked) {
      lines.push(`  ${RED}[BLOCKED]${RESET} ${b.ip}:${b.port}`);
    }
  }

  // Data Exfiltration Alerts
  const bodies = report.network?.http_bodies || [];
  const exfilAlerts = [];
  for (const body of bodies) {
    for (const pat of EXFIL_PATTERNS) {
      if (pat.pattern.test(body)) {
        exfilAlerts.push({ label: pat.label, severity: pat.severity, snippet: body.substring(0, 100) });
        break;
      }
    }
  }
  if (exfilAlerts.length > 0) {
    lines.push('');
    lines.push(`${BOLD}${RED}── Data Exfiltration Alerts (${exfilAlerts.length}) ──${RESET}`);
    for (const alert of exfilAlerts) {
      lines.push(`  ${RED}[${alert.severity}]${RESET} ${alert.label} detected in HTTP body`);
      lines.push(`    ${DIM}${alert.snippet}...${RESET}`);
    }
  }

  // Raw TCP connections
  const conns = report.network?.http_connections || [];
  if (conns.length > 0) {
    lines.push('');
    lines.push(`${BOLD}${CYAN}── Raw TCP Connections (${conns.length}) ──${RESET}`);
    for (const c of conns) {
      const safe = isSafeHost(c.host);
      const icon = safe ? GREEN + '[OK]' : YELLOW + '[!!]';
      lines.push(`  ${icon}${RESET} ${c.host}:${c.port} (${c.protocol})`);
    }
  }

  lines.push('');
  return lines.join('\n');
}

// ── Helpers ──

function isSafeDomain(domain) {
  return SAFE_DOMAINS.some(safe => domain === safe || domain.endsWith('.' + safe));
}

function isSafeHost(host) {
  return SAFE_DOMAINS.some(safe => host === safe || host.endsWith('.' + safe));
}

function getSeverity(score) {
  if (score === 0) return 'CLEAN';
  if (score <= 20) return 'LOW';
  if (score <= 50) return 'MEDIUM';
  if (score <= 80) return 'HIGH';
  return 'CRITICAL';
}

function displayResults(result) {
  console.log(`\n[SANDBOX] Score: ${result.score}/100 — ${result.severity}`);
  if (result.findings.length === 0) {
    console.log('[SANDBOX] No suspicious behavior detected.');
  } else {
    const actionable = result.findings.filter(f => f.severity !== 'INFO');
    console.log(`[SANDBOX] ${actionable.length} finding(s):`);
    for (const f of actionable) {
      console.log(`  [${f.severity}] ${f.type}: ${f.detail}`);
    }
  }
}

module.exports = { buildSandboxImage, runSandbox, scoreFindings, generateNetworkReport, EXFIL_PATTERNS, SAFE_DOMAINS, getSeverity, displayResults, isDockerAvailable, imageExists };
