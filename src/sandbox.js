const { execSync, spawn } = require('child_process');
const path = require('path');

const DOCKER_IMAGE = 'muaddib-sandbox';
const CONTAINER_TIMEOUT = 120000; // 120 seconds

// Domains excluded from network findings (false positives)
const SAFE_DOMAINS = [
  'registry.npmjs.org',
  'github.com',
  'objects.githubusercontent.com'
];

// IPs/ports excluded from connection findings (false positives)
const SAFE_IPS = ['127.0.0.1', '0.0.0.0'];
const PROBE_PORTS = [65535]; // Node.js internal connectivity checks

// Commands that are always suspicious in a sandbox
const DANGEROUS_CMDS = ['curl', 'wget', 'nc', 'netcat', 'python', 'python3', 'bash', 'sh'];

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

async function runSandbox(packageName) {
  const cleanResult = { score: 0, severity: 'CLEAN', findings: [], raw_report: null, suspicious: false };

  if (!isDockerAvailable()) {
    console.log('[SANDBOX] Docker is not installed or not running. Skipping.');
    return cleanResult;
  }

  console.log(`[SANDBOX] Analyzing "${packageName}" in isolated container...`);

  return new Promise((resolve) => {
    let stdout = '';
    let timedOut = false;
    const containerName = `muaddib-sandbox-${Date.now()}`;

    const proc = spawn('docker', [
      'run',
      '--rm',
      `--name=${containerName}`,
      '--network=bridge',
      '--memory=512m',
      '--cpus=1',
      '--pids-limit=100',
      '--cap-drop=ALL',
      '--cap-add=SYS_PTRACE',
      '--security-opt', 'no-new-privileges',
      DOCKER_IMAGE,
      packageName
    ]);

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
      // Forward sandbox progress logs
      const text = data.toString();
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

  // 4. DNS queries (exclude safe domains)
  for (const domain of (report.network?.dns_queries || [])) {
    if (isSafeDomain(domain)) continue;
    score += 20;
    findings.push({ type: 'suspicious_dns', severity: 'HIGH', detail: `DNS query to non-registry domain: ${domain}`, evidence: domain });
  }

  // 5. TCP connections (exclude safe hosts, probe ports, localhost)
  for (const conn of (report.network?.http_connections || [])) {
    if (isSafeHost(conn.host)) continue;
    if (SAFE_IPS.includes(conn.host)) continue;
    if (PROBE_PORTS.includes(conn.port)) continue;
    score += 25;
    findings.push({ type: 'suspicious_connection', severity: 'HIGH', detail: `TCP connection to ${conn.host}:${conn.port}`, evidence: `${conn.host}:${conn.port}` });
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
    console.log(`[SANDBOX] ${result.findings.length} finding(s):`);
    for (const f of result.findings) {
      console.log(`  [${f.severity}] ${f.type}: ${f.detail}`);
    }
  }
}

module.exports = { buildSandboxImage, runSandbox };
