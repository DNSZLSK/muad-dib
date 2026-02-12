const https = require('https');
const fs = require('fs');
const path = require('path');

const STATE_FILE = path.join(__dirname, '..', 'data', 'monitor-state.json');
const POLL_INTERVAL = 60_000;

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

// --- npm polling ---

/**
 * Parse the npm /-/all/since response.
 * Returns array of { name, version } and the max timestamp seen.
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
    packages.push({ name: pkg.name, version });
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
║     Polling npm + PyPI for new packages   ║
╚════════════════════════════════════════════╝
  `);

  const state = loadState();
  console.log(`[MONITOR] State loaded — npm startKey: ${state.npmLastKey || 'none'}, pypi last: ${state.pypiLastPackage || 'none'}`);
  console.log(`[MONITOR] Polling every ${POLL_INTERVAL / 1000}s. Ctrl+C to stop.\n`);

  let running = true;

  // SIGINT: save state and exit
  process.on('SIGINT', () => {
    console.log('\n[MONITOR] Stopping — saving state...');
    saveState(state);
    console.log('[MONITOR] State saved. Bye!');
    running = false;
    process.exit(0);
  });

  // Initial poll
  await poll(state);
  saveState(state);

  // Interval polling
  while (running) {
    await sleep(POLL_INTERVAL);
    if (!running) break;
    await poll(state);
    saveState(state);
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = {
  startMonitor,
  parseNpmResponse,
  parsePyPIRss,
  loadState,
  saveState,
  STATE_FILE
};

// Standalone entry point: node src/monitor.js
if (require.main === module) {
  startMonitor().catch(err => {
    console.error('[MONITOR] Fatal error:', err.message);
    process.exit(1);
  });
}
