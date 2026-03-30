const { execSync, execFileSync, spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  generateCanaryTokens,
  createCanaryEnvFile,
  createCanaryNpmrc,
  createCanaryAwsCredentials,
  createCanarySshKey,
  createCanaryGitconfig,
  detectCanaryExfiltration,
  detectCanaryInOutput
} = require('../canary-tokens.js');

const { NPM_PACKAGE_REGEX } = require('../shared/constants.js');
const { analyzePreloadLog } = require('./analyzer.js');
const { classifyDomain } = require('./network-allowlist.js');
const { parseGvisorLogs, cleanupGvisorLogs } = require('./gvisor-parser.js');

const DOCKER_IMAGE = 'muaddib-sandbox';
const CONTAINER_TIMEOUT = 120000; // 120 seconds
const SINGLE_RUN_TIMEOUT = 60000; // 60 seconds per run in multi-run mode

// ── Sandbox concurrency limiter ──
// Prevents Docker container saturation under load (16 workers × 3 runs = 48 containers).
// Pattern: same semaphore as src/shared/http-limiter.js.
const SANDBOX_CONCURRENCY_MAX = Math.max(1, parseInt(process.env.MUADDIB_SANDBOX_CONCURRENCY, 10) || 3);

const _sandboxSemaphore = { active: 0, queue: [] };

function acquireSandboxSlot() {
  if (_sandboxSemaphore.active < SANDBOX_CONCURRENCY_MAX) {
    _sandboxSemaphore.active++;
    return Promise.resolve();
  }
  return new Promise(resolve => {
    _sandboxSemaphore.queue.push(resolve);
  });
}

function releaseSandboxSlot() {
  if (_sandboxSemaphore.queue.length > 0) {
    const next = _sandboxSemaphore.queue.shift();
    next(); // Transfers slot to next waiter (active count stays the same)
  } else {
    _sandboxSemaphore.active--;
  }
}

function resetSandboxLimiter() {
  _sandboxSemaphore.active = 0;
  _sandboxSemaphore.queue.length = 0;
}

function getSandboxSemaphore() {
  return _sandboxSemaphore;
}

// Time offsets for multi-run sandbox execution (ms)
const TIME_OFFSETS = [
  { offset: 0, label: 'immediate' },
  { offset: 259200000, label: '72h offset' },   // 72 hours
  { offset: 604800000, label: '7d offset' }      // 7 days
];

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

// Commands that are sandbox infrastructure — not spawned by the package
const SAFE_SANDBOX_CMDS = new Set(['timeout', 'node', 'npm', 'npx', 'su', 'env']);

// Static canary tokens injected by sandbox-runner.sh (fallback honeypots).
// These are searched in the sandbox report as a complement to the dynamic
// tokens from canary-tokens.js (which use random values per session).
// Format-valid: match real service token formats to resist format-based detection.
const STATIC_CANARY_TOKENS = {
  GITHUB_TOKEN: 'ghp_R8kLmN2pQ4vW7xY9aB3cD5eF6gH8jK0mN2pQ4vW',
  NPM_TOKEN: 'npm_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8',
  AWS_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
  AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  SLACK_WEBHOOK_URL: 'https://hooks.example.com/services/TCANARY/BCANARY/canary-slack-token',
  DISCORD_WEBHOOK_URL: 'https://discord.com/api/webhooks/000000000000000000/abcdefghijklmnopqrstuvwxyz'
};

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
    execFileSync('docker', ['image', 'inspect', DOCKER_IMAGE], { stdio: 'pipe', timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

// ── gVisor availability check ──

function isGvisorAvailable() {
  try {
    const info = execSync('docker info', { encoding: 'utf8', stdio: 'pipe', timeout: 10000 });
    return /\brunsc\b/.test(info);
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
    const dockerfilePath = path.join(__dirname, '..', '..', 'docker').replace(/\\/g, '/');
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

// ── Run single sandbox execution ──

async function runSingleSandbox(packageName, options = {}) {
  const cleanResult = { score: 0, severity: 'CLEAN', findings: [], raw_report: null, suspicious: false };

  const strict = options.strict || false;
  const canaryTokens = options.canaryTokens || null;
  const local = options.local || false;
  const localAbsPath = options.localAbsPath || null;
  const displayName = options.displayName || packageName;
  const mode = strict ? 'strict' : 'permissive';
  const timeOffset = options.timeOffset || 0;
  const runTimeout = options.runTimeout || CONTAINER_TIMEOUT;
  const gvisorMode = options.gvisor || false;

  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const containerName = `npm-audit-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    // Realistic hostname to evade sandbox detection (T1497.001)
    // Default Docker hostname is a 12-char hex hash — easily fingerprinted.
    const fakeHostname = `dev-laptop-${crypto.randomBytes(2).toString('hex')}`;

    const dockerArgs = [
      'run',
      '--rm',
      `--name=${containerName}`,
      `--hostname=${fakeHostname}`,
      '--network=bridge',
      '--memory=512m',
      '--cpus=1',
      '--pids-limit=100',
      '--cap-drop=ALL'
    ];

    // gVisor runtime: use runsc instead of default runc
    if (gvisorMode) {
      dockerArgs.push('--runtime=runsc');
      dockerArgs.push('-e', 'MUADDIB_GVISOR=1');
    }

    // Inject canary tokens as environment variables
    if (canaryTokens) {
      for (const [key, value] of Object.entries(canaryTokens)) {
        dockerArgs.push('-e', `${key}=${value}`);
      }
      // Also inject canary file contents as env vars for the entrypoint to write
      dockerArgs.push('-e', `CANARY_ENV_CONTENT=${createCanaryEnvFile(canaryTokens).replace(/\r?\n/g, '\\n')}`);
      dockerArgs.push('-e', `CANARY_NPMRC_CONTENT=${createCanaryNpmrc(canaryTokens).replace(/\r?\n/g, '\\n')}`);
      dockerArgs.push('-e', `CANARY_AWS_CONTENT=${createCanaryAwsCredentials(canaryTokens).replace(/\r?\n/g, '\\n')}`);
      dockerArgs.push('-e', `CANARY_SSH_KEY=${createCanarySshKey().replace(/\r?\n/g, '\\n')}`);
      dockerArgs.push('-e', `CANARY_GITCONFIG=${createCanaryGitconfig().replace(/\r?\n/g, '\\n')}`);
    }

    // Inject time offset — libfaketime-aware (v2.10.7)
    // Run 1 (offset=0): no libfaketime, preload.js handles JS-level only
    // Runs 2+ (offset>0): libfaketime handles C-level time shift for ALL processes
    //   (Node, Python, bash), preload.js TIME_OFFSET=0 to avoid double acceleration
    const useFaketime = timeOffset > 0;
    dockerArgs.push('-e', `NODE_TIMING_OFFSET=${useFaketime ? 0 : timeOffset}`);

    if (useFaketime) {
      const hours = Math.floor(timeOffset / 3600000);
      const faketimeStr = hours >= 24
        ? `+${Math.floor(hours / 24)}d x1000`
        : `+${hours}h x1000`;
      dockerArgs.push('-e', `MUADDIB_FAKETIME=${faketimeStr}`);
      dockerArgs.push('-e', 'MUADDIB_FAKETIME_ACTIVE=1');
    }

    // Both modes need NET_RAW for tcpdump (runs as root in entrypoint).
    // gVisor mode: no tcpdump needed — gVisor captures via --strace/--log-packets.
    // Strict mode also needs NET_ADMIN for iptables network blocking.
    // SYS_PTRACE is not needed: strace traces its own child (npm install via su).
    // SETUID + SETGID required for su (privilege drop to sandboxuser).
    // CHOWN required for chown in sandbox-runner.sh.
    if (!gvisorMode) {
      dockerArgs.push('--cap-add=NET_RAW');
    }
    dockerArgs.push('--cap-add=SETUID');
    dockerArgs.push('--cap-add=SETGID');
    dockerArgs.push('--cap-add=CHOWN');
    if (strict) {
      dockerArgs.push('--cap-add=NET_ADMIN');
    }

    dockerArgs.push('--tmpfs', '/tmp:rw,nosuid,size=64m');
    dockerArgs.push('--tmpfs', '/sandbox/install:rw,nosuid,size=256m');
    dockerArgs.push('--tmpfs', '/home/sandboxuser:rw,noexec,nosuid,size=16m');
    dockerArgs.push('--read-only');

    // /proc/uptime evasion (T1497.003) handled by preload.js monkey-patching
    // (process.uptime, Date.now, performance.now, process.hrtime)

    dockerArgs.push('--security-opt', 'no-new-privileges');

    if (local && localAbsPath) {
      dockerArgs.push('-v', `${localAbsPath}:/sandbox/local-pkg:ro`);
    }

    dockerArgs.push(DOCKER_IMAGE);
    dockerArgs.push(local ? '/sandbox/local-pkg' : packageName);
    dockerArgs.push(mode);

    const proc = spawn('docker', dockerArgs);
    let gvisorContainerId = null;

    // Timeout: kill container
    const timer = setTimeout(() => {
      timedOut = true;
      console.log(`[SANDBOX] Timeout (${runTimeout / 1000}s). Killing container ${containerName}...`);
      try {
        execFileSync('docker', ['kill', containerName], { stdio: 'pipe', timeout: 5000 });
      } catch {
        // docker kill failed (container in intermediate state) — force remove
        try {
          execFileSync('docker', ['rm', '-f', containerName], { stdio: 'pipe', timeout: 5000 });
        } catch {
          // Last resort: kill the docker client process (container may survive as orphan)
          proc.kill('SIGKILL');
        }
      }
    }, runTimeout);

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();

      // Capture container ID for gVisor log retrieval (once, while container is running)
      if (gvisorMode && !gvisorContainerId) {
        try {
          gvisorContainerId = execFileSync('docker', ['inspect', '--format={{.Id}}', containerName], {
            encoding: 'utf8', stdio: 'pipe', timeout: 5000
          }).trim();
        } catch { /* container not yet ready, will retry on next data event */ }
      }

      // Forward sandbox progress logs (sanitize ANSI escape sequences)
      const text = data.toString().replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '');
      for (const line of text.split(/\r?\n/)) {
        if (line.includes('[SANDBOX]')) {
          console.log(line.trim());
        }
      }
    });

    proc.on('close', (code) => {
      clearTimeout(timer);

      // TIMEOUT FIRST: docker kill causes non-zero exit (code 137/SIGKILL),
      // must check before Docker error handler to avoid returning CLEAN on timeout
      if (timedOut) {
        const result = {
          score: -1,
          severity: 'INCONCLUSIVE',
          findings: [{
            type: 'timeout',
            severity: 'MEDIUM',
            detail: `Container exceeded ${runTimeout / 1000}s timeout — package too large or slow install`,
            evidence: `Killed after ${runTimeout}ms`
          }],
          raw_report: null,
          suspicious: false,
          inconclusive: true
        };
        resolve(result);
        return;
      }

      // Docker-level failure (non-timeout): log error and return clean result
      if (code !== 0 && !stdout.includes('---MUADDIB-REPORT-START---')) {
        const errLines = stderr.split(/\r?\n/).filter(l => l && !l.includes('[SANDBOX]'));
        if (errLines.length > 0) {
          console.log(`[SANDBOX] Docker error (exit ${code}): ${errLines[0]}`);
        } else {
          console.log(`[SANDBOX] Container exited with code ${code} (no output)`);
        }
        resolve(cleanResult);
        return;
      }

      // Parse JSON from container stdout using delimiter
      let report;
      try {
        const REPORT_DELIMITER = '---MUADDIB-REPORT-START---';
        const delimIdx = stdout.lastIndexOf(REPORT_DELIMITER);
        let jsonStr;
        if (delimIdx !== -1) {
          // Reliable: use delimiter to skip any package output before the report
          jsonStr = stdout.substring(delimIdx + REPORT_DELIMITER.length).trim();
        } else {
          // Fallback: find first '{' (backward compat with older images)
          const jsonStart = stdout.indexOf('{');
          const jsonEnd = stdout.lastIndexOf('}');
          if (jsonStart === -1 || jsonEnd === -1) {
            throw new Error('No JSON found in output');
          }
          jsonStr = stdout.substring(jsonStart, jsonEnd + 1);
        }
        report = JSON.parse(jsonStr);
        if (local && report) {
          report.package = displayName;
        }
      } catch (e) {
        console.log('[SANDBOX] Failed to parse container output:', e.message);
        resolve(cleanResult);
        return;
      }

      // In gVisor mode, merge kernel-level strace data from gVisor debug logs.
      // sandbox-runner.sh skips strace/tcpdump in gVisor mode, so file access,
      // connections, and process data come from gVisor's kernel-level tracing.
      if (gvisorMode && gvisorContainerId) {
        const gvisorLogDir = process.env.MUADDIB_GVISOR_LOG_DIR || '/tmp/runsc';
        const gvisorData = parseGvisorLogs(gvisorContainerId, gvisorLogDir);

        // Merge gVisor findings into report without duplicating
        if (!report.sensitive_files) report.sensitive_files = { read: [], written: [] };
        if (!report.network) report.network = {};
        if (!report.processes) report.processes = { spawned: [] };

        const existingReads = new Set(report.sensitive_files.read || []);
        for (const f of gvisorData.sensitive_files.read) {
          if (!existingReads.has(f)) report.sensitive_files.read.push(f);
        }

        const existingWrites = new Set(report.sensitive_files.written || []);
        for (const f of gvisorData.sensitive_files.written) {
          if (!existingWrites.has(f)) report.sensitive_files.written.push(f);
        }

        const existingConns = new Set((report.network.http_connections || []).map(c => `${c.host}:${c.port}`));
        if (!report.network.http_connections) report.network.http_connections = [];
        for (const c of gvisorData.network.http_connections) {
          if (!existingConns.has(`${c.host}:${c.port}`)) report.network.http_connections.push(c);
        }

        const existingProcs = new Set((report.processes.spawned || []).map(p => p.command));
        for (const p of gvisorData.processes.spawned) {
          if (!existingProcs.has(p.command)) report.processes.spawned.push(p);
        }

        // Cleanup gVisor logs to prevent disk fill
        cleanupGvisorLogs(gvisorContainerId, gvisorLogDir);
      }

      const { score, findings } = scoreFindings(report);

      // Analyze preload log for behavioral findings
      if (report.preload_log) {
        const preloadResult = analyzePreloadLog(report.preload_log);
        for (const finding of preloadResult.findings) {
          findings.push(finding);
        }
        // Add preload score (capped at 100 with the rest)
        const combinedScore = Math.min(100, score + preloadResult.score);
        // We'll use combinedScore below instead of score
        report._preloadScore = preloadResult.score;
      }

      // Canary token exfiltration detection (dynamic tokens)
      if (canaryTokens) {
        const networkExfil = detectCanaryExfiltration(report.network || {}, canaryTokens);
        const outputExfil = detectCanaryInOutput(stdout, stderr, canaryTokens);

        for (const exfil of [...networkExfil.exfiltrations, ...outputExfil.exfiltrations]) {
          findings.push({
            type: 'canary_exfiltration',
            severity: 'CRITICAL',
            detail: `Package attempted to exfiltrate ${exfil.token} (${exfil.foundIn})`,
            evidence: exfil.value
          });
        }
      }

      // Static canary token detection (fallback for shell-injected tokens)
      const staticExfil = detectStaticCanaryExfiltration(report);
      for (const { token, value } of staticExfil) {
        const alreadyDetected = findings.some(f =>
          f.type === 'canary_exfiltration' && f.detail && f.detail.includes(token)
        );
        if (!alreadyDetected) {
          findings.push({
            type: 'canary_exfiltration',
            severity: 'CRITICAL',
            detail: `Canary token exfiltration detected: ${token}`,
            evidence: value
          });
        }
      }

      const preloadScore = report._preloadScore || 0;
      const finalScore = Math.min(100, findings.reduce((s, f) => {
        if (f.type === 'canary_exfiltration') return s + 50;
        return s;
      }, score + preloadScore));
      const severity = getSeverity(finalScore);
      const result = { score: finalScore, severity, findings, raw_report: report, suspicious: finalScore > 0 };

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

// ── Multi-run sandbox orchestrator ──

async function runSandbox(packageName, options = {}) {
  const cleanResult = { score: 0, severity: 'CLEAN', findings: [], raw_report: null, suspicious: false };

  const strict = options.strict || false;
  const canaryEnabled = options.canary !== false; // enabled by default
  const local = options.local || false;

  // Validate inputs before checking Docker availability
  let localAbsPath = null;
  let displayName = packageName;

  if (local) {
    localAbsPath = path.resolve(packageName);
    if (!fs.existsSync(localAbsPath)) {
      console.log('[SANDBOX] Local path does not exist: ' + localAbsPath);
      return cleanResult;
    }
    // Read package name for display
    const pkgJsonPath = path.join(localAbsPath, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
        displayName = pkg.name || path.basename(localAbsPath);
      } catch { displayName = path.basename(localAbsPath); }
    } else {
      displayName = path.basename(localAbsPath);
    }
  } else {
    if (!NPM_PACKAGE_REGEX.test(packageName)) {
      console.log('[SANDBOX] Invalid package name: ' + packageName);
      return cleanResult;
    }
  }

  if (!isDockerAvailable()) {
    console.log('[SANDBOX] Docker is not installed or not running. Skipping.');
    return cleanResult;
  }

  // Detect sandbox runtime (gVisor or default Docker/runc)
  let useGvisor = process.env.MUADDIB_SANDBOX_RUNTIME === 'gvisor';
  if (useGvisor) {
    if (isGvisorAvailable()) {
      console.log('[SANDBOX] Runtime: gvisor (runsc)');
    } else {
      console.log('[SANDBOX] Runtime: gvisor requested but runsc not configured in Docker. Falling back to Docker standard.');
      useGvisor = false;
    }
  }

  // Generate canary tokens for this sandbox session
  let canaryTokens = null;
  if (canaryEnabled) {
    const canary = generateCanaryTokens();
    canaryTokens = canary.tokens;
  }

  const mode = strict ? 'strict' : 'permissive';

  // Acquire sandbox slot — blocks if SANDBOX_CONCURRENCY_MAX containers already running
  const queueLen = _sandboxSemaphore.queue.length;
  if (queueLen > 0) {
    console.log(`[SANDBOX] Waiting for sandbox slot (${_sandboxSemaphore.active}/${SANDBOX_CONCURRENCY_MAX} active, ${queueLen} queued)...`);
  }
  await acquireSandboxSlot();

  try {
    const runtimeLabel = useGvisor ? 'gvisor' : 'docker';
    console.log(`[SANDBOX] Analyzing "${displayName}" in isolated container (mode: ${mode}, runtime: ${runtimeLabel}${canaryEnabled ? ', canary: on' : ''}${local ? ', local' : ''}, runs: ${TIME_OFFSETS.length}, slots: ${_sandboxSemaphore.active}/${SANDBOX_CONCURRENCY_MAX})...`);

    const allRuns = [];
    let bestResult = cleanResult;

    for (let i = 0; i < TIME_OFFSETS.length; i++) {
      const { offset, label } = TIME_OFFSETS[i];
      console.log(`[SANDBOX] Run ${i + 1}/${TIME_OFFSETS.length} (${label})...`);

      const runResult = await runSingleSandbox(packageName, {
        strict,
        canaryTokens,
        local,
        localAbsPath,
        displayName,
        timeOffset: offset,
        runTimeout: SINGLE_RUN_TIMEOUT,
        gvisor: useGvisor
      });

      allRuns.push({
        run: i + 1,
        label,
        timeOffset: offset,
        score: runResult.score,
        severity: runResult.severity,
        findingCount: runResult.findings.length
      });

      // Keep the result with the highest score
      if (runResult.score > bestResult.score) {
        bestResult = runResult;
      }

      // Early exit: CRITICAL found, skip remaining runs
      if (runResult.score >= 80) {
        console.log(`[SANDBOX] Critical score (${runResult.score}) detected in run ${i + 1}. Skipping remaining runs.`);
        break;
      }
    }

    // If all runs were inconclusive (timeout), propagate inconclusive status
    // instead of returning CLEAN (which would cause false FP relabeling)
    if (bestResult.score === 0 && allRuns.length > 0 && allRuns.every(r => r.score === -1)) {
      bestResult = {
        score: -1,
        severity: 'INCONCLUSIVE',
        findings: [{
          type: 'timeout',
          severity: 'MEDIUM',
          detail: `All ${allRuns.length} runs exceeded timeout — package too large or slow install`,
          evidence: `All ${allRuns.length} runs timed out`
        }],
        raw_report: null,
        suspicious: false,
        inconclusive: true
      };
    }

    // Attach multi-run metadata
    bestResult.all_runs = allRuns;

    displayResults(bestResult);
    return bestResult;
  } finally {
    releaseSandboxSlot();
  }
}

// ── Static canary detection ──

/**
 * Detect static canary token exfiltration in a sandbox report.
 * Searches HTTP bodies, DNS queries, HTTP request URLs, TLS domains,
 * filesystem changes, process commands, and install output.
 * @param {object} report - Parsed sandbox report JSON
 * @returns {Array<{token: string, value: string}>} Exfiltrated tokens
 */
function detectStaticCanaryExfiltration(report) {
  const exfiltrated = [];
  if (!report) return exfiltrated;

  const searchable = [];

  // Network data
  for (const body of (report.network?.http_bodies || [])) if (body) searchable.push(body);
  for (const domain of (report.network?.dns_queries || [])) if (domain) searchable.push(domain);
  for (const req of (report.network?.http_requests || [])) {
    searchable.push(`${req.method || ''} ${req.host || ''}${req.path || ''}`);
  }
  for (const tls of (report.network?.tls_connections || [])) if (tls.domain) searchable.push(tls.domain);

  // Filesystem + processes
  for (const file of (report.filesystem?.created || [])) if (file) searchable.push(file);
  for (const proc of (report.processes?.spawned || [])) if (proc.command) searchable.push(proc.command);

  // Install + entrypoint output
  if (report.install_output) searchable.push(report.install_output);
  if (report.entrypoint_output) searchable.push(report.entrypoint_output);

  const allOutput = searchable.join('\n');

  for (const [tokenName, tokenValue] of Object.entries(STATIC_CANARY_TOKENS)) {
    if (allOutput.includes(tokenValue)) {
      exfiltrated.push({ token: tokenName, value: tokenValue });
    }
  }

  return exfiltrated;
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

  // 4a. DNS queries — classify via network allowlist
  for (const domain of (report.network?.dns_queries || [])) {
    const cls = classifyDomain(domain);
    if (cls === 'safe') continue;
    if (cls === 'blacklisted') {
      score += 50;
      findings.push({ type: 'sandbox_known_exfil_domain', severity: 'CRITICAL', detail: `DNS query to known exfiltration domain: ${domain}`, evidence: domain });
    } else if (cls === 'tunnel') {
      score += 30;
      findings.push({ type: 'sandbox_network_outlier', severity: 'HIGH', detail: `DNS query to tunnel/proxy domain: ${domain}`, evidence: domain });
    } else {
      score += 20;
      findings.push({ type: 'sandbox_network_outlier', severity: 'HIGH', detail: `DNS query to non-registry domain: ${domain}`, evidence: domain });
    }
  }

  // 4b. DNS resolutions — extra detail
  for (const res of (report.network?.dns_resolutions || [])) {
    const cls = classifyDomain(res.domain);
    if (cls === 'safe') continue;
    // Already scored in 4a via dns_queries, but flag the resolution for reporting
    findings.push({ type: 'dns_resolution', severity: 'INFO', detail: `${res.domain} → ${res.ip}`, evidence: `${res.domain}:${res.ip}` });
  }

  // 5a. TCP connections — classify via network allowlist
  for (const conn of (report.network?.http_connections || [])) {
    if (SAFE_IPS.includes(conn.host)) continue;
    if (PROBE_PORTS.includes(conn.port)) continue;
    const cls = classifyDomain(conn.host);
    if (cls === 'safe') continue;
    if (cls === 'blacklisted') {
      score += 50;
      findings.push({ type: 'sandbox_known_exfil_domain', severity: 'CRITICAL', detail: `TCP connection to known exfiltration host: ${conn.host}:${conn.port}`, evidence: `${conn.host}:${conn.port}` });
    } else {
      score += 25;
      findings.push({ type: 'suspicious_connection', severity: 'HIGH', detail: `TCP connection to ${conn.host}:${conn.port}`, evidence: `${conn.host}:${conn.port}` });
    }
  }

  // 5b. TLS connections — classify via network allowlist
  for (const tls of (report.network?.tls_connections || [])) {
    const cls = classifyDomain(tls.domain);
    if (cls === 'safe') continue;
    if (cls === 'blacklisted') {
      score += 50;
      findings.push({ type: 'sandbox_known_exfil_domain', severity: 'CRITICAL', detail: `TLS to known exfiltration domain: ${tls.domain} (${tls.ip}:${tls.port})`, evidence: tls.domain });
    } else {
      score += 20;
      findings.push({ type: 'suspicious_tls', severity: 'HIGH', detail: `TLS connection to ${tls.domain} (${tls.ip}:${tls.port})`, evidence: tls.domain });
    }
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

  // 5d. HTTP requests — classify via network allowlist
  for (const req of (report.network?.http_requests || [])) {
    const cls = classifyDomain(req.host);
    if (cls === 'safe') continue;
    if (cls === 'blacklisted') {
      score += 50;
      findings.push({ type: 'sandbox_known_exfil_domain', severity: 'CRITICAL', detail: `HTTP request to known exfiltration host: ${req.method} ${req.host}${req.path}`, evidence: `${req.method} ${req.host}${req.path}` });
    } else {
      score += 20;
      findings.push({ type: 'suspicious_http_request', severity: 'HIGH', detail: `${req.method} ${req.host}${req.path}`, evidence: `${req.method} ${req.host}${req.path}` });
    }
  }

  // 5e. Blocked connections (strict mode)
  for (const blocked of (report.network?.blocked_connections || [])) {
    score += 30;
    findings.push({ type: 'blocked_connection', severity: 'HIGH', detail: `Blocked outbound to ${blocked.ip}:${blocked.port}`, evidence: `${blocked.ip}:${blocked.port}` });
  }

  // 6. Suspicious processes
  for (const p of (report.processes?.spawned || [])) {
    const cmd = p.command || '';
    const basename = path.basename(cmd);
    if (SAFE_SANDBOX_CMDS.has(basename)) continue; // Skip sandbox infrastructure
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

module.exports = { buildSandboxImage, runSandbox, runSingleSandbox, scoreFindings, generateNetworkReport, EXFIL_PATTERNS, SAFE_DOMAINS, getSeverity, displayResults, isDockerAvailable, imageExists, isGvisorAvailable, STATIC_CANARY_TOKENS, detectStaticCanaryExfiltration, analyzePreloadLog, TIME_OFFSETS, SAFE_SANDBOX_CMDS, SANDBOX_CONCURRENCY_MAX, acquireSandboxSlot, releaseSandboxSlot, resetSandboxLimiter, getSandboxSemaphore };
