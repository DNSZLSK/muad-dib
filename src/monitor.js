const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const { run } = require('./index.js');
const { runSandbox, isDockerAvailable } = require('./sandbox.js');
const { sendWebhook } = require('./webhook.js');

const STATE_FILE = path.join(__dirname, '..', 'data', 'monitor-state.json');
const ALERTS_FILE = path.join(__dirname, '..', 'data', 'monitor-alerts.json');
const POLL_INTERVAL = 60_000;
const MAX_TARBALL_SIZE = 50 * 1024 * 1024; // 50MB
const SCAN_TIMEOUT_MS = 180_000; // 3 minutes per package

// --- Stats counters ---

const stats = {
  scanned: 0,
  clean: 0,
  suspect: 0,
  errors: 0,
  totalTimeMs: 0,
  lastReportTime: Date.now()
};

// --- Scan queue (FIFO, sequential) ---

const scanQueue = [];

// --- Sandbox integration ---

let sandboxAvailable = false;

function isSandboxEnabled() {
  const env = process.env.MUADDIB_MONITOR_SANDBOX;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function hasHighOrCritical(result) {
  return result.summary.critical > 0 || result.summary.high > 0;
}

// --- Webhook alerting ---

function getWebhookUrl() {
  return process.env.MUADDIB_WEBHOOK_URL || null;
}

function shouldSendWebhook(result, sandboxResult) {
  if (!getWebhookUrl()) return false;
  if (hasHighOrCritical(result)) return true;
  if (sandboxResult && sandboxResult.score > 50) return true;
  return false;
}

function buildMonitorWebhookPayload(name, version, ecosystem, result, sandboxResult) {
  const payload = {
    event: 'malicious_package',
    package: name,
    version,
    ecosystem,
    timestamp: new Date().toISOString(),
    findings: result.threats.map(t => ({
      rule: t.rule_id || t.type,
      severity: t.severity
    }))
  };
  if (sandboxResult && sandboxResult.score > 0) {
    payload.sandbox = {
      score: sandboxResult.score,
      severity: sandboxResult.severity
    };
  }
  return payload;
}

async function trySendWebhook(name, version, ecosystem, result, sandboxResult) {
  if (!shouldSendWebhook(result, sandboxResult)) return;
  const url = getWebhookUrl();
  const payload = buildMonitorWebhookPayload(name, version, ecosystem, result, sandboxResult);
  // sendWebhook expects a results-like object; wrap payload for formatGeneric
  const webhookData = {
    target: `${ecosystem}/${name}@${version}`,
    timestamp: payload.timestamp,
    summary: result.summary,
    threats: result.threats
  };
  try {
    await sendWebhook(url, webhookData);
    console.log(`[MONITOR] Webhook sent for ${name}@${version}`);
  } catch (err) {
    console.error(`[MONITOR] Webhook failed for ${name}@${version}: ${err.message}`);
  }
}

// --- State persistence ---

function loadState() {
  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    const state = JSON.parse(raw);
    return {
      npmLastKey: typeof state.npmLastKey === 'number' ? state.npmLastKey : 0,
      pypiLastPackage: typeof state.pypiLastPackage === 'string' ? state.pypiLastPackage : ''
    };
  } catch {
    return { npmLastKey: 0, pypiLastPackage: '' };
  }
}

function saveState(state) {
  try {
    const dir = path.dirname(STATE_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf8');
  } catch (err) {
    console.error(`[MONITOR] Failed to save state: ${err.message}`);
  }
}

// --- HTTP helpers ---

function httpsGet(url, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        const location = res.headers.location;
        if (!location) return reject(new Error(`Redirect without Location for ${url}`));
        return httpsGet(location, timeoutMs).then(resolve, reject);
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Timeout for ${url}`));
    });
  });
}

// --- Download & extraction helpers ---

function downloadToFile(url, destPath, timeoutMs = 30_000) {
  return new Promise((resolve, reject) => {
    const doRequest = (requestUrl) => {
      const req = https.get(requestUrl, { timeout: timeoutMs }, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          res.resume();
          const location = res.headers.location;
          if (!location) return reject(new Error(`Redirect without Location for ${requestUrl}`));
          return doRequest(location);
        }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${requestUrl}`));
        }
        const contentLength = parseInt(res.headers['content-length'], 10);
        if (contentLength && contentLength > MAX_TARBALL_SIZE) {
          res.resume();
          return reject(new Error(`Package too large: ${contentLength} bytes (max ${MAX_TARBALL_SIZE})`));
        }
        const fileStream = fs.createWriteStream(destPath);
        let downloadedBytes = 0;
        res.on('data', (chunk) => {
          downloadedBytes += chunk.length;
          if (downloadedBytes > MAX_TARBALL_SIZE) {
            res.destroy();
            fileStream.destroy();
            try { fs.unlinkSync(destPath); } catch {}
            reject(new Error(`Package too large: ${downloadedBytes}+ bytes (max ${MAX_TARBALL_SIZE})`));
          }
        });
        res.pipe(fileStream);
        fileStream.on('finish', () => resolve(downloadedBytes));
        fileStream.on('error', (err) => {
          try { fs.unlinkSync(destPath); } catch {}
          reject(err);
        });
        res.on('error', (err) => {
          fileStream.destroy();
          try { fs.unlinkSync(destPath); } catch {}
          reject(err);
        });
      });
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Timeout downloading ${requestUrl}`));
      });
    };
    doRequest(url);
  });
}

function extractTarGz(tgzPath, destDir) {
  // Use --force-local on Windows so tar doesn't interpret C: as a remote host
  const forceLocal = process.platform === 'win32' ? ' --force-local' : '';
  execSync(`tar xzf "${tgzPath}"${forceLocal} -C "${destDir}"`, { timeout: 60_000, stdio: 'pipe' });
  // npm tarballs extract into a package/ subdirectory; detect it
  const packageSubdir = path.join(destDir, 'package');
  if (fs.existsSync(packageSubdir) && fs.statSync(packageSubdir).isDirectory()) {
    return packageSubdir;
  }
  // Otherwise return destDir itself (PyPI sdists vary)
  const entries = fs.readdirSync(destDir);
  if (entries.length === 1) {
    const single = path.join(destDir, entries[0]);
    if (fs.statSync(single).isDirectory()) return single;
  }
  return destDir;
}

// --- Tarball URL helpers ---

function getNpmTarballUrl(pkgData) {
  return (pkgData.dist && pkgData.dist.tarball) || null;
}

async function getPyPITarballUrl(packageName) {
  const url = `https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`;
  const body = await httpsGet(url);
  const data = JSON.parse(body);
  const version = (data.info && data.info.version) || '';
  const urls = data.urls || [];
  // Prefer sdist (.tar.gz)
  const sdist = urls.find(u => u.packagetype === 'sdist' && u.url);
  if (sdist) return { url: sdist.url, version };
  // Fallback: any .tar.gz
  const tarGz = urls.find(u => u.url && u.url.endsWith('.tar.gz'));
  if (tarGz) return { url: tarGz.url, version };
  // Fallback: first available file
  if (urls.length > 0 && urls[0].url) return { url: urls[0].url, version };
  return { url: null, version };
}

// --- Alerts persistence ---

function appendAlert(alert) {
  try {
    const dir = path.dirname(ALERTS_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    let alerts = [];
    try {
      alerts = JSON.parse(fs.readFileSync(ALERTS_FILE, 'utf8'));
    } catch {}
    alerts.push(alert);
    fs.writeFileSync(ALERTS_FILE, JSON.stringify(alerts, null, 2), 'utf8');
  } catch (err) {
    console.error(`[MONITOR] Failed to save alert: ${err.message}`);
  }
}

// --- Package scanning ---

async function scanPackage(name, version, ecosystem, tarballUrl) {
  const startTime = Date.now();
  const tmpBase = path.join(os.tmpdir(), 'muaddib-monitor');
  if (!fs.existsSync(tmpBase)) fs.mkdirSync(tmpBase, { recursive: true });
  const tmpDir = fs.mkdtempSync(path.join(tmpBase, `${name.replace(/\//g, '_')}-`));

  try {
    const tgzPath = path.join(tmpDir, 'package.tar.gz');
    await downloadToFile(tarballUrl, tgzPath);

    // Check downloaded size
    const fileSize = fs.statSync(tgzPath).size;
    if (fileSize > MAX_TARBALL_SIZE) {
      console.log(`[MONITOR] SKIP: ${name}@${version} — tarball too large (${(fileSize / 1024 / 1024).toFixed(1)}MB)`);
      stats.scanned++;
      return;
    }

    const extractedDir = extractTarGz(tgzPath, tmpDir);
    const result = await run(extractedDir, { _capture: true });

    if (result.summary.total === 0) {
      stats.scanned++;
      const elapsed = Date.now() - startTime;
      stats.totalTimeMs += elapsed;
      stats.clean++;
      console.log(`[MONITOR] CLEAN: ${name}@${version} (0 findings, ${(elapsed / 1000).toFixed(1)}s)`);
    } else {
      stats.suspect++;
      const counts = [];
      if (result.summary.critical > 0) counts.push(`${result.summary.critical} CRITICAL`);
      if (result.summary.high > 0) counts.push(`${result.summary.high} HIGH`);
      if (result.summary.medium > 0) counts.push(`${result.summary.medium} MEDIUM`);
      if (result.summary.low > 0) counts.push(`${result.summary.low} LOW`);
      console.log(`[MONITOR] SUSPECT: ${name}@${version} (${counts.join(', ')})`);

      // Sandbox: run dynamic analysis on HIGH/CRITICAL findings
      let sandboxResult = null;
      if (hasHighOrCritical(result) && isSandboxEnabled() && sandboxAvailable) {
        try {
          console.log(`[MONITOR] SANDBOX: launching for ${name}@${version}...`);
          sandboxResult = await runSandbox(name);
          console.log(`[MONITOR] SANDBOX: ${name}@${version} → score: ${sandboxResult.score}, severity: ${sandboxResult.severity}`);
        } catch (err) {
          console.error(`[MONITOR] SANDBOX error for ${name}@${version}: ${err.message}`);
        }
      }

      stats.scanned++;
      const elapsed = Date.now() - startTime;
      stats.totalTimeMs += elapsed;
      console.log(`[MONITOR] ${name}@${version} total time: ${(elapsed / 1000).toFixed(1)}s`);

      const alert = {
        timestamp: new Date().toISOString(),
        name,
        version,
        ecosystem,
        findings: result.threats.map(t => ({
          rule: t.rule_id || t.type,
          severity: t.severity,
          file: t.file
        }))
      };

      if (sandboxResult && sandboxResult.score > 0) {
        alert.sandbox = {
          score: sandboxResult.score,
          severity: sandboxResult.severity,
          findings: sandboxResult.findings
        };
      }

      appendAlert(alert);
      await trySendWebhook(name, version, ecosystem, result, sandboxResult);
    }
  } catch (err) {
    stats.errors++;
    stats.scanned++;
    stats.totalTimeMs += Date.now() - startTime;
    console.error(`[MONITOR] ERROR scanning ${name}@${version}: ${err.message}`);
  } finally {
    // Cleanup temp dir
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

function timeoutPromise(ms) {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error(`Scan timeout after ${ms / 1000}s`)), ms);
  });
}

async function processQueue() {
  while (scanQueue.length > 0) {
    const item = scanQueue.shift();
    try {
      await Promise.race([
        scanPackage(item.name, item.version, item.ecosystem, item.tarballUrl),
        timeoutPromise(SCAN_TIMEOUT_MS)
      ]);
    } catch (err) {
      stats.errors++;
      console.error(`[MONITOR] Queue error for ${item.name}: ${err.message}`);
    }
  }
}

// --- Stats reporting ---

function reportStats() {
  const avg = stats.scanned > 0 ? (stats.totalTimeMs / stats.scanned / 1000).toFixed(1) : '0.0';
  console.log(`[MONITOR] Stats: ${stats.scanned} scanned, ${stats.clean} clean, ${stats.suspect} suspect, ${stats.errors} error${stats.errors !== 1 ? 's' : ''}, avg ${avg}s/pkg`);
  stats.lastReportTime = Date.now();
}

// --- npm polling ---

/**
 * Parse the npm /-/all/since response.
 * Returns array of { name, version, tarball } and the max timestamp seen.
 */
function parseNpmResponse(body) {
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    return { packages: [], maxTimestamp: 0 };
  }

  const packages = [];
  let maxTimestamp = 0;

  // The response is an object keyed by package name.
  // Each value has name, "dist-tags", time, etc.
  // There is a special "_updated" key with the latest timestamp.
  for (const key of Object.keys(data)) {
    if (key === '_updated') {
      const ts = Number(data[key]);
      if (ts > maxTimestamp) maxTimestamp = ts;
      continue;
    }
    const pkg = data[key];
    if (!pkg || typeof pkg !== 'object' || !pkg.name) continue;
    const version = (pkg['dist-tags'] && pkg['dist-tags'].latest) || '';
    const tarball = (pkg.dist && pkg.dist.tarball) || '';
    packages.push({ name: pkg.name, version, tarball });
  }

  return { packages, maxTimestamp };
}

async function pollNpm(state) {
  // First run: use "now - 120s" so we don't get the entire registry
  const startKey = state.npmLastKey || (Date.now() - 120_000);
  const url = `https://registry.npmjs.org/-/all/since?stale=update_after&startkey=${startKey}`;

  try {
    const body = await httpsGet(url);
    const { packages, maxTimestamp } = parseNpmResponse(body);

    for (const pkg of packages) {
      console.log(`[MONITOR] New npm: ${pkg.name}@${pkg.version}`);
      if (pkg.tarball) {
        scanQueue.push({
          name: pkg.name,
          version: pkg.version,
          ecosystem: 'npm',
          tarballUrl: pkg.tarball
        });
      }
    }

    if (maxTimestamp > 0) {
      state.npmLastKey = maxTimestamp;
    } else if (packages.length > 0) {
      // Fallback: advance timestamp to now
      state.npmLastKey = Date.now();
    }

    return packages.length;
  } catch (err) {
    console.error(`[MONITOR] npm poll error: ${err.message}`);
    return 0;
  }
}

// --- PyPI polling ---

/**
 * Parse PyPI RSS XML (simple regex, no deps).
 * Returns array of package names from <title> tags inside <item>.
 */
function parsePyPIRss(xml) {
  const packages = [];
  // Match each <item>...</item> block
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const itemContent = match[1];
    // Extract <title>...</title> inside item
    const titleMatch = itemContent.match(/<title>([^<]+)<\/title>/);
    if (titleMatch) {
      // Title format is usually "package-name 1.0.0"
      const title = titleMatch[1].trim();
      // Extract just the package name (first word before space or version)
      const name = title.split(/\s+/)[0];
      if (name) {
        packages.push(name);
      }
    }
  }
  return packages;
}

async function pollPyPI(state) {
  const url = 'https://pypi.org/rss/packages.xml';

  try {
    const body = await httpsGet(url);
    const packages = parsePyPIRss(body);

    // Find new packages (those after the last seen one)
    let newPackages;
    if (!state.pypiLastPackage) {
      // First run: log all and remember the first one
      newPackages = packages;
    } else {
      const lastIdx = packages.indexOf(state.pypiLastPackage);
      if (lastIdx === -1) {
        // Last seen not in feed — all are new
        newPackages = packages;
      } else {
        // Items before lastIdx are newer (RSS is newest-first)
        newPackages = packages.slice(0, lastIdx);
      }
    }

    for (const name of newPackages) {
      console.log(`[MONITOR] New pypi: ${name}`);
      // Queue PyPI packages — tarball URL resolved during scan
      scanQueue.push({
        name,
        version: '',
        ecosystem: 'pypi',
        tarballUrl: null // resolved lazily in scanPackage wrapper
      });
    }

    // Remember the most recent package (first in RSS)
    if (packages.length > 0) {
      state.pypiLastPackage = packages[0];
    }

    return newPackages.length;
  } catch (err) {
    console.error(`[MONITOR] PyPI poll error: ${err.message}`);
    return 0;
  }
}

// --- Main loop ---

async function startMonitor() {
  console.log(`
╔════════════════════════════════════════════╗
║     MUAD'DIB - Registry Monitor           ║
║     Scanning npm + PyPI new packages      ║
╚════════════════════════════════════════════╝
  `);

  // Check sandbox availability
  if (isSandboxEnabled()) {
    sandboxAvailable = isDockerAvailable();
    if (sandboxAvailable) {
      console.log('[MONITOR] Docker detected — sandbox enabled for HIGH/CRITICAL findings');
    } else {
      console.log('[MONITOR] WARNING: Docker not available — running static analysis only');
    }
  } else {
    console.log('[MONITOR] Sandbox disabled (MUADDIB_MONITOR_SANDBOX=false)');
  }

  const state = loadState();
  console.log(`[MONITOR] State loaded — npm startKey: ${state.npmLastKey || 'none'}, pypi last: ${state.pypiLastPackage || 'none'}`);
  console.log(`[MONITOR] Polling every ${POLL_INTERVAL / 1000}s. Ctrl+C to stop.\n`);

  let running = true;

  // SIGINT: save state and exit
  process.on('SIGINT', () => {
    console.log('\n[MONITOR] Stopping — saving state...');
    saveState(state);
    reportStats();
    console.log('[MONITOR] State saved. Bye!');
    running = false;
    process.exit(0);
  });

  // Initial poll + scan
  await poll(state);
  saveState(state);
  await processQueue();

  // Interval polling
  while (running) {
    await sleep(POLL_INTERVAL);
    if (!running) break;
    await poll(state);
    saveState(state);
    await processQueue();

    // Hourly stats report
    if (Date.now() - stats.lastReportTime >= 3600_000) {
      reportStats();
    }
  }
}

async function poll(state) {
  const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
  console.log(`[MONITOR] ${timestamp} — polling registries...`);

  const [npmCount, pypiCount] = await Promise.all([
    pollNpm(state),
    pollPyPI(state)
  ]);

  console.log(`[MONITOR] Found ${npmCount} npm + ${pypiCount} PyPI new packages`);
}

/**
 * Wrapper to resolve PyPI tarball URLs before scanning.
 * For npm packages, tarballUrl is already set from the registry response.
 * For PyPI packages, we need to fetch the JSON API to get the tarball URL.
 */
async function resolveTarballAndScan(item) {
  if (item.ecosystem === 'pypi' && !item.tarballUrl) {
    try {
      const pypiInfo = await getPyPITarballUrl(item.name);
      if (!pypiInfo.url) {
        console.log(`[MONITOR] SKIP: ${item.name} — no tarball URL found on PyPI`);
        return;
      }
      item.tarballUrl = pypiInfo.url;
      if (pypiInfo.version) item.version = pypiInfo.version;
    } catch (err) {
      console.error(`[MONITOR] ERROR resolving PyPI tarball for ${item.name}: ${err.message}`);
      stats.errors++;
      return;
    }
  }
  await scanPackage(item.name, item.version, item.ecosystem, item.tarballUrl);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = {
  startMonitor,
  parseNpmResponse,
  parsePyPIRss,
  loadState,
  saveState,
  STATE_FILE,
  ALERTS_FILE,
  downloadToFile,
  extractTarGz,
  getNpmTarballUrl,
  getPyPITarballUrl,
  scanPackage,
  scanQueue,
  processQueue,
  appendAlert,
  timeoutPromise,
  reportStats,
  stats,
  resolveTarballAndScan,
  MAX_TARBALL_SIZE,
  isSandboxEnabled,
  hasHighOrCritical,
  get sandboxAvailable() { return sandboxAvailable; },
  set sandboxAvailable(v) { sandboxAvailable = v; },
  getWebhookUrl,
  shouldSendWebhook,
  buildMonitorWebhookPayload,
  trySendWebhook
};

// Standalone entry point: node src/monitor.js
if (require.main === module) {
  startMonitor().catch(err => {
    console.error('[MONITOR] Fatal error:', err.message);
    process.exit(1);
  });
}
