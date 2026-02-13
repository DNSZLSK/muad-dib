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
  lastReportTime: Date.now(),
  lastDailyReportTime: Date.now()
};

// Track daily suspects for the daily report (name, version, ecosystem, findingsCount)
const dailyAlerts = [];

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

function computeRiskLevel(summary) {
  if (summary.critical > 0) return 'CRITICAL';
  if (summary.high > 0) return 'HIGH';
  if (summary.medium > 0) return 'MEDIUM';
  if (summary.low > 0) return 'LOW';
  return 'CLEAN';
}

function computeRiskScore(summary) {
  const raw = (summary.critical || 0) * 25
            + (summary.high || 0) * 15
            + (summary.medium || 0) * 5
            + (summary.low || 0) * 1;
  return Math.min(raw, 100);
}

async function trySendWebhook(name, version, ecosystem, result, sandboxResult) {
  if (!shouldSendWebhook(result, sandboxResult)) return;
  const url = getWebhookUrl();
  const payload = buildMonitorWebhookPayload(name, version, ecosystem, result, sandboxResult);
  const webhookData = {
    target: `${ecosystem}/${name}@${version}`,
    timestamp: payload.timestamp,
    ecosystem,
    summary: {
      ...result.summary,
      riskLevel: computeRiskLevel(result.summary),
      riskScore: computeRiskScore(result.summary)
    },
    threats: result.threats
  };
  if (sandboxResult && sandboxResult.score > 0) {
    webhookData.sandbox = {
      score: sandboxResult.score,
      severity: sandboxResult.severity
    };
  }
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
      npmLastPackage: typeof state.npmLastPackage === 'string' ? state.npmLastPackage : '',
      pypiLastPackage: typeof state.pypiLastPackage === 'string' ? state.pypiLastPackage : ''
    };
  } catch {
    return { npmLastPackage: '', pypiLastPackage: '' };
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

// --- Bundled tooling false-positive filter ---

const KNOWN_BUNDLED_FILES = ['yarn.js', 'webpack.js', 'terser.js', 'esbuild.js', 'polyfills.js'];

function isBundledToolingOnly(threats) {
  if (threats.length === 0) return false;
  return threats.every(t => {
    if (!t.file) return false;
    const basename = path.basename(t.file);
    return KNOWN_BUNDLED_FILES.includes(basename);
  });
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
      const counts = [];
      if (result.summary.critical > 0) counts.push(`${result.summary.critical} CRITICAL`);
      if (result.summary.high > 0) counts.push(`${result.summary.high} HIGH`);
      if (result.summary.medium > 0) counts.push(`${result.summary.medium} MEDIUM`);
      if (result.summary.low > 0) counts.push(`${result.summary.low} LOW`);

      // Check if all findings come from bundled tooling files
      if (isBundledToolingOnly(result.threats)) {
        stats.scanned++;
        const elapsed = Date.now() - startTime;
        stats.totalTimeMs += elapsed;
        stats.clean++;
        console.log(`[MONITOR] SKIPPED (bundled tooling): ${name}@${version} (${counts.join(', ')})`);

        const alert = {
          timestamp: new Date().toISOString(),
          name,
          version,
          ecosystem,
          skipped: true,
          findings: result.threats.map(t => ({
            rule: t.rule_id || t.type,
            severity: t.severity,
            file: t.file
          }))
        };
        appendAlert(alert);
      } else {
        stats.suspect++;
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
        dailyAlerts.push({ name, version, ecosystem, findingsCount: result.summary.total });
        await trySendWebhook(name, version, ecosystem, result, sandboxResult);
      }
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
        resolveTarballAndScan(item),
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

const DAILY_REPORT_INTERVAL = 24 * 3600_000; // 24 hours

function buildDailyReportEmbed() {
  const avg = stats.scanned > 0 ? (stats.totalTimeMs / stats.scanned / 1000).toFixed(1) : '0.0';

  // Top 3 suspects sorted by findings count descending
  const top3 = dailyAlerts
    .slice()
    .sort((a, b) => b.findingsCount - a.findingsCount)
    .slice(0, 3);

  const top3Text = top3.length > 0
    ? top3.map((a, i) => `${i + 1}. **${a.ecosystem}/${a.name}@${a.version}** — ${a.findingsCount} finding(s)`).join('\n')
    : 'None';

  const now = new Date();
  const readableTime = now.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');

  return {
    embeds: [{
      title: '\uD83D\uDCCA MUAD\'DIB Daily Report',
      color: 0x3498db,
      fields: [
        { name: 'Packages Scanned', value: `${stats.scanned}`, inline: true },
        { name: 'Clean', value: `${stats.clean}`, inline: true },
        { name: 'Suspects', value: `${stats.suspect}`, inline: true },
        { name: 'Errors', value: `${stats.errors}`, inline: true },
        { name: 'Avg Scan Time', value: `${avg}s/pkg`, inline: true },
        { name: 'Top Suspects', value: top3Text, inline: false }
      ],
      footer: {
        text: `MUAD'DIB - Daily summary | ${readableTime}`
      },
      timestamp: now.toISOString()
    }]
  };
}

async function sendDailyReport() {
  const url = getWebhookUrl();
  if (!url) return;

  const payload = buildDailyReportEmbed();
  try {
    await sendWebhook(url, payload, { rawPayload: true });
    console.log('[MONITOR] Daily report sent');
  } catch (err) {
    console.error(`[MONITOR] Daily report webhook failed: ${err.message}`);
  }

  // Reset daily counters
  stats.scanned = 0;
  stats.clean = 0;
  stats.suspect = 0;
  stats.errors = 0;
  stats.totalTimeMs = 0;
  dailyAlerts.length = 0;
  stats.lastDailyReportTime = Date.now();
}

// --- npm polling ---

/**
 * Parse npm RSS XML (same regex approach as parsePyPIRss).
 * Returns array of package names from <title> tags inside <item>.
 */
function parseNpmRss(xml) {
  const packages = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const itemContent = match[1];
    const titleMatch = itemContent.match(/<title>([^<]+)<\/title>/);
    if (titleMatch) {
      const title = titleMatch[1].trim();
      const name = title.split(/\s+/)[0];
      if (name) {
        packages.push(name);
      }
    }
  }
  return packages;
}

/**
 * Fetch latest version metadata for an npm package.
 * Returns { version, tarball } or null on failure.
 */
async function getNpmLatestTarball(packageName) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}/latest`;
  const body = await httpsGet(url);
  const data = JSON.parse(body);
  const version = data.version || '';
  const tarball = (data.dist && data.dist.tarball) || null;
  return { version, tarball };
}

async function pollNpm(state) {
  const url = 'https://registry.npmjs.org/-/rss?descending=true&limit=50';

  try {
    const body = await httpsGet(url);
    const packages = parseNpmRss(body);

    // Find new packages (those after the last seen one)
    let newPackages;
    if (!state.npmLastPackage) {
      newPackages = packages;
    } else {
      const lastIdx = packages.indexOf(state.npmLastPackage);
      if (lastIdx === -1) {
        newPackages = packages;
      } else {
        newPackages = packages.slice(0, lastIdx);
      }
    }

    for (const name of newPackages) {
      console.log(`[MONITOR] New npm: ${name}`);
      // Queue npm packages — tarball URL resolved during scan
      scanQueue.push({
        name,
        version: '',
        ecosystem: 'npm',
        tarballUrl: null // resolved lazily via resolveTarballAndScan
      });
    }

    // Remember the most recent package (first in RSS)
    if (packages.length > 0) {
      state.npmLastPackage = packages[0];
    }

    return newPackages.length;
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
  console.log(`[MONITOR] State loaded — npm last: ${state.npmLastPackage || 'none'}, pypi last: ${state.pypiLastPackage || 'none'}`);
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

    // Daily webhook report
    if (Date.now() - stats.lastDailyReportTime >= DAILY_REPORT_INTERVAL) {
      await sendDailyReport();
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
  if (item.ecosystem === 'npm' && !item.tarballUrl) {
    try {
      const npmInfo = await getNpmLatestTarball(item.name);
      if (!npmInfo.tarball) {
        console.log(`[MONITOR] SKIP: ${item.name} — no tarball URL found on npm`);
        return;
      }
      item.tarballUrl = npmInfo.tarball;
      if (npmInfo.version) item.version = npmInfo.version;
    } catch (err) {
      console.error(`[MONITOR] ERROR resolving npm tarball for ${item.name}: ${err.message}`);
      stats.errors++;
      return;
    }
  }
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
  parseNpmRss,
  parsePyPIRss,
  loadState,
  saveState,
  STATE_FILE,
  ALERTS_FILE,
  downloadToFile,
  extractTarGz,
  getNpmTarballUrl,
  getNpmLatestTarball,
  getPyPITarballUrl,
  scanPackage,
  scanQueue,
  processQueue,
  appendAlert,
  timeoutPromise,
  reportStats,
  stats,
  dailyAlerts,
  resolveTarballAndScan,
  MAX_TARBALL_SIZE,
  KNOWN_BUNDLED_FILES,
  isBundledToolingOnly,
  isSandboxEnabled,
  hasHighOrCritical,
  get sandboxAvailable() { return sandboxAvailable; },
  set sandboxAvailable(v) { sandboxAvailable = v; },
  getWebhookUrl,
  shouldSendWebhook,
  buildMonitorWebhookPayload,
  trySendWebhook,
  computeRiskLevel,
  computeRiskScore,
  buildDailyReportEmbed,
  sendDailyReport,
  DAILY_REPORT_INTERVAL
};

// Standalone entry point: node src/monitor.js
if (require.main === module) {
  startMonitor().catch(err => {
    console.error('[MONITOR] Fatal error:', err.message);
    process.exit(1);
  });
}
