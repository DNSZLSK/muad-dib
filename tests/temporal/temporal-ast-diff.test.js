const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runCommand, BIN, TESTS_DIR, addSkipped
} = require('../test-utils');

async function runTemporalAstDiffTests() {
  // ============================================
  // TEMPORAL AST DIFF TESTS
  // ============================================

  console.log('\n=== TEMPORAL AST DIFF TESTS ===\n');

  const {
    extractDangerousPatterns,
    extractPatternsFromSource,
    fetchPackageTarball,
    compareAstPatterns,
    detectSuddenAstChanges,
    fetchVersionMetadata,
    SENSITIVE_PATHS,
    PATTERN_SEVERITY
  } = require('../../src/temporal-ast-diff.js');

  // --- Helper: create a temp dir with JS files ---

  function makeTempDir(files) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-astdiff-test-'));
    for (const [name, content] of Object.entries(files)) {
      const filePath = path.join(tmpDir, name);
      const dir = path.dirname(filePath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(filePath, content, 'utf8');
    }
    return tmpDir;
  }

  function cleanTempDir(dir) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  }

  // --- extractPatternsFromSource ---

  test('AST-DIFF: extractPatternsFromSource detects child_process require', () => {
    const patterns = new Set();
    extractPatternsFromSource('const cp = require("child_process"); cp.exec("ls");', patterns);
    assert(patterns.has('child_process'), 'Should detect child_process');
  });

  test('AST-DIFF: extractPatternsFromSource detects eval', () => {
    const patterns = new Set();
    extractPatternsFromSource('eval(data);', patterns);
    assert(patterns.has('eval'), 'Should detect eval');
  });

  test('AST-DIFF: extractPatternsFromSource detects new Function', () => {
    const patterns = new Set();
    extractPatternsFromSource('const fn = new Function("return 1");', patterns);
    assert(patterns.has('Function'), 'Should detect Function');
  });

  test('AST-DIFF: extractPatternsFromSource detects process.env', () => {
    const patterns = new Set();
    extractPatternsFromSource('const secret = process.env.SECRET;', patterns);
    assert(patterns.has('process.env'), 'Should detect process.env');
  });

  test('AST-DIFF: extractPatternsFromSource detects fetch', () => {
    const patterns = new Set();
    extractPatternsFromSource('fetch("https://example.com");', patterns);
    assert(patterns.has('fetch'), 'Should detect fetch');
  });

  test('AST-DIFF: extractPatternsFromSource detects http_request', () => {
    const patterns = new Set();
    extractPatternsFromSource('const http = require("http"); http.get("url", cb);', patterns);
    assert(patterns.has('http_request'), 'Should detect http_request');
  });

  test('AST-DIFF: extractPatternsFromSource detects https_request', () => {
    const patterns = new Set();
    extractPatternsFromSource('const https = require("https"); https.request({});', patterns);
    assert(patterns.has('https_request'), 'Should detect https_request');
  });

  test('AST-DIFF: extractPatternsFromSource detects dns.lookup', () => {
    const patterns = new Set();
    extractPatternsFromSource('const dns = require("dns"); dns.lookup("evil.com", cb);', patterns);
    assert(patterns.has('dns.lookup'), 'Should detect dns.lookup');
  });

  test('AST-DIFF: extractPatternsFromSource detects net.connect', () => {
    const patterns = new Set();
    extractPatternsFromSource('const net = require("net"); net.connect(1234);', patterns);
    assert(patterns.has('net.connect'), 'Should detect net.connect');
  });

  test('AST-DIFF: extractPatternsFromSource detects fs.readFile on sensitive path', () => {
    const patterns = new Set();
    extractPatternsFromSource('const fs = require("fs"); fs.readFileSync("/etc/passwd");', patterns);
    assert(patterns.has('fs.readFile_sensitive'), 'Should detect fs.readFile_sensitive');
  });

  test('AST-DIFF: extractPatternsFromSource detects import child_process', () => {
    const patterns = new Set();
    extractPatternsFromSource('import cp from "child_process";', patterns);
    assert(patterns.has('child_process'), 'Should detect child_process via import');
  });

  test('AST-DIFF: extractPatternsFromSource returns nothing for clean code', () => {
    const patterns = new Set();
    extractPatternsFromSource('const x = 1 + 2; console.log(x);', patterns);
    assert(patterns.size === 0, 'Should be empty for clean code, got ' + patterns.size);
  });

  test('AST-DIFF: extractPatternsFromSource handles unparseable code', () => {
    const patterns = new Set();
    extractPatternsFromSource('this is not valid javascript }{}{', patterns);
    assert(patterns.size === 0, 'Should be empty for unparseable code');
  });

  test('AST-DIFF: extractPatternsFromSource detects multiple patterns at once', () => {
    const patterns = new Set();
    extractPatternsFromSource(`
      const cp = require("child_process");
      eval("alert(1)");
      const secret = process.env.TOKEN;
      fetch("https://evil.com");
    `, patterns);
    assert(patterns.size === 4, 'Should have 4 patterns, got ' + patterns.size);
    assert(patterns.has('child_process'), 'child_process');
    assert(patterns.has('eval'), 'eval');
    assert(patterns.has('process.env'), 'process.env');
    assert(patterns.has('fetch'), 'fetch');
  });

  // --- extractDangerousPatterns (directory-level) ---

  test('AST-DIFF: extractDangerousPatterns finds child_process in temp dir', () => {
    const dir = makeTempDir({ 'index.js': 'const cp = require("child_process"); cp.exec("whoami");' });
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.has('child_process'), 'Should detect child_process');
    } finally { cleanTempDir(dir); }
  });

  test('AST-DIFF: extractDangerousPatterns finds eval in temp dir', () => {
    const dir = makeTempDir({ 'lib.js': 'eval(payload);' });
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.has('eval'), 'Should detect eval');
    } finally { cleanTempDir(dir); }
  });

  test('AST-DIFF: extractDangerousPatterns finds process.env in temp dir', () => {
    const dir = makeTempDir({ 'config.js': 'module.exports = process.env.SECRET_KEY;' });
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.has('process.env'), 'Should detect process.env');
    } finally { cleanTempDir(dir); }
  });

  test('AST-DIFF: extractDangerousPatterns finds fetch in temp dir', () => {
    const dir = makeTempDir({ 'net.js': 'fetch("https://example.com/data").then(r => r.json());' });
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.has('fetch'), 'Should detect fetch');
    } finally { cleanTempDir(dir); }
  });

  test('AST-DIFF: extractDangerousPatterns returns empty Set for clean dir', () => {
    const dir = makeTempDir({ 'clean.js': 'const x = 1;\nconsole.log(x);' });
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.size === 0, 'Should be empty for clean code, got ' + patterns.size);
    } finally { cleanTempDir(dir); }
  });

  test('AST-DIFF: extractDangerousPatterns aggregates across multiple files', () => {
    const dir = makeTempDir({
      'a.js': 'const cp = require("child_process");',
      'b.js': 'eval("code");',
      'sub/c.js': 'fetch("url");'
    });
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.has('child_process'), 'child_process from a.js');
      assert(patterns.has('eval'), 'eval from b.js');
      assert(patterns.has('fetch'), 'fetch from sub/c.js');
      assert(patterns.size === 3, 'Should have 3 patterns, got ' + patterns.size);
    } finally { cleanTempDir(dir); }
  });

  test('AST-DIFF: extractDangerousPatterns ignores non-JS files', () => {
    const dir = makeTempDir({
      'readme.md': 'eval("this is markdown")',
      'data.json': '{"eval": true}',
      'safe.js': 'console.log(42);'
    });
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.size === 0, 'Should ignore non-JS files, got ' + patterns.size);
    } finally { cleanTempDir(dir); }
  });

  test('AST-DIFF: extractDangerousPatterns handles empty directory', () => {
    const dir = makeTempDir({});
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.size === 0, 'Should return empty Set for empty dir');
    } finally { cleanTempDir(dir); }
  });

  // NOTE (audit 2026-07): the former « compare mock » tests re-implemented the
  // set-diff inline (extractDangerousPatterns + local filter). The diff itself is
  // now exercised against the REAL compareAstPatterns via the offline harness below.

  // --- SENSITIVE_PATHS ---

  test('AST-DIFF: SENSITIVE_PATHS contains expected entries', () => {
    assert(SENSITIVE_PATHS.includes('/etc/passwd'), '/etc/passwd');
    assert(SENSITIVE_PATHS.includes('.npmrc'), '.npmrc');
    assert(SENSITIVE_PATHS.includes('.ssh'), '.ssh');
    assert(SENSITIVE_PATHS.includes('.env'), '.env');
    assert(SENSITIVE_PATHS.includes('.aws/credentials'), '.aws/credentials');
  });

  // --- PATTERN_SEVERITY mapping ---

  test('AST-DIFF: PATTERN_SEVERITY maps child_process to CRITICAL', () => {
    assert(PATTERN_SEVERITY['child_process'] === 'CRITICAL', 'child_process should be CRITICAL');
    assert(PATTERN_SEVERITY['eval'] === 'CRITICAL', 'eval should be CRITICAL');
    assert(PATTERN_SEVERITY['Function'] === 'CRITICAL', 'Function should be CRITICAL');
    assert(PATTERN_SEVERITY['net.connect'] === 'CRITICAL', 'net.connect should be CRITICAL');
  });

  test('AST-DIFF: PATTERN_SEVERITY maps fetch/process.env to HIGH', () => {
    assert(PATTERN_SEVERITY['process.env'] === 'HIGH', 'process.env should be HIGH');
    assert(PATTERN_SEVERITY['fetch'] === 'HIGH', 'fetch should be HIGH');
    assert(PATTERN_SEVERITY['http_request'] === 'HIGH', 'http_request should be HIGH');
    assert(PATTERN_SEVERITY['https_request'] === 'HIGH', 'https_request should be HIGH');
  });

  test('AST-DIFF: PATTERN_SEVERITY maps dns.lookup/fs.readFile_sensitive to MEDIUM', () => {
    assert(PATTERN_SEVERITY['dns.lookup'] === 'MEDIUM', 'dns.lookup should be MEDIUM');
    assert(PATTERN_SEVERITY['fs.readFile_sensitive'] === 'MEDIUM', 'fs.readFile_sensitive should be MEDIUM');
  });

  // --- Offline harness: run the REAL compareAstPatterns / detectSuddenAstChanges ---
  //
  // Audit 2026-07: these two functions were previously only exercised by the opt-in
  // network tests (MUADDIB_TEST_NETWORK) — i.e. NEVER in CI. This harness routes
  // their network boundaries to local temp dirs so the real diff + severity mapping
  // run offline:
  //   - fetchPackageMetadata (src/scanner/temporal-analysis.js exports, destructured
  //     at load by temporal-ast-diff) → fake packument
  //   - https.request (used by the module-internal fetchVersionMetadata) → fake 200
  //     JSON with a dist.tarball URL (Module._load interception, scoped to the
  //     re-required scanner module)
  //   - downloadToFile / extractTarGz (src/shared/download.js exports) → no-op /
  //     returns the prepared local dir for the version encoded in the temp-dir name
  // All patched state (module exports, require.cache, Module._load) restored in finally.

  const Module = require('module');
  const EventEmitter = require('events');
  const taScannerPath = require.resolve('../../src/scanner/temporal-analysis.js');
  const dlPath = require.resolve('../../src/shared/download.js');
  const astScannerPath = require.resolve('../../src/scanner/temporal-ast-diff.js');
  const astShimPath = require.resolve('../../src/temporal-ast-diff.js');

  async function withMockedAstDiff({ metadata, versionDirs = {} }, testFn) {
    const taExports = require.cache[taScannerPath].exports;
    const dlExports = require.cache[dlPath].exports;
    const origFetchMeta = taExports.fetchPackageMetadata;
    const origDownload = dlExports.downloadToFile;
    const origExtract = dlExports.extractTarGz;
    const savedAstScanner = require.cache[astScannerPath];
    const savedAstShim = require.cache[astShimPath];

    taExports.fetchPackageMetadata = async () => metadata;
    dlExports.downloadToFile = async () => 0;
    dlExports.extractTarGz = (tgzPath) => {
      // fetchPackageTarball extracts inside a mkdtemp dir named `${safeName}-${version}-XXXXXX`
      const base = path.basename(path.dirname(tgzPath));
      const m = base.match(/-(\d+\.\d+\.\d+)-[^-]*$/);
      const dir = m && versionDirs[m[1]];
      if (!dir) throw new Error('withMockedAstDiff: no prepared dir for temp dir ' + base);
      return dir;
    };

    const mockHttps = {
      request: (options, callback) => {
        const res = new EventEmitter();
        res.statusCode = 200;
        res.resume = () => {};
        const req = new EventEmitter();
        req.setTimeout = () => {};
        req.destroy = () => {};
        req.end = () => {
          process.nextTick(() => {
            callback(res);
            process.nextTick(() => {
              const segs = String(options.path || '').split('/').filter(Boolean);
              const version = decodeURIComponent(segs[segs.length - 1] || '0.0.0');
              const name = decodeURIComponent(segs.slice(0, -1).join('/') || 'mock-pkg');
              res.emit('data', Buffer.from(JSON.stringify({
                name, version,
                dist: { tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz` }
              })));
              res.emit('end');
            });
          });
        };
        return req;
      }
    };

    const originalLoad = Module._load;
    Module._load = function (request, parent) {
      if (request === 'https' && parent && parent.filename === astScannerPath) return mockHttps;
      return originalLoad.apply(this, arguments);
    };

    delete require.cache[astScannerPath];
    delete require.cache[astShimPath];
    try {
      const mod = require(astShimPath);
      await testFn(mod);
    } finally {
      Module._load = originalLoad;
      taExports.fetchPackageMetadata = origFetchMeta;
      dlExports.downloadToFile = origDownload;
      dlExports.extractTarGz = origExtract;
      delete require.cache[astScannerPath];
      delete require.cache[astShimPath];
      if (savedAstScanner) require.cache[astScannerPath] = savedAstScanner;
      if (savedAstShim) require.cache[astShimPath] = savedAstShim;
    }
  }

  function makeTwoVersionMetadata(name) {
    return {
      name,
      time: {
        created: '2025-12-01T00:00:00.000Z',
        modified: '2026-02-01T00:00:00.000Z',
        '1.0.0': '2026-01-01T00:00:00.000Z',
        '1.1.0': '2026-02-01T00:00:00.000Z'
      },
      versions: { '1.0.0': {}, '1.1.0': {} }
    };
  }

  await asyncTest('AST-DIFF: REAL compareAstPatterns — added/removed computed by src code (offline)', async () => {
    const dirA = makeTempDir({ 'index.js': 'eval("legacy");' });
    const dirB = makeTempDir({ 'index.js': 'const cp = require("child_process"); fetch("https://x.example");' });
    try {
      await withMockedAstDiff({
        metadata: makeTwoVersionMetadata('fake-pkg'),
        versionDirs: { '1.0.0': dirA, '1.1.0': dirB }
      }, async (mod) => {
        const diff = await mod.compareAstPatterns('fake-pkg', '1.0.0', '1.1.0');
        assert(Array.isArray(diff.added) && Array.isArray(diff.removed), 'Should return added/removed arrays');
        assert(diff.added.length === 2, 'Should have 2 added, got ' + JSON.stringify(diff.added));
        assert(diff.added.includes('child_process'), 'added should include child_process');
        assert(diff.added.includes('fetch'), 'added should include fetch');
        assert(diff.removed.length === 1 && diff.removed[0] === 'eval',
          'removed should be [eval], got ' + JSON.stringify(diff.removed));
      });
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
  });

  await asyncTest('AST-DIFF: REAL compareAstPatterns — identical versions → empty diff (offline)', async () => {
    const src = 'const http = require("http"); http.get("url", cb);';
    const dirA = makeTempDir({ 'index.js': src });
    const dirB = makeTempDir({ 'index.js': src });
    try {
      await withMockedAstDiff({
        metadata: makeTwoVersionMetadata('fake-pkg'),
        versionDirs: { '1.0.0': dirA, '1.1.0': dirB }
      }, async (mod) => {
        const diff = await mod.compareAstPatterns('fake-pkg', '1.0.0', '1.1.0');
        assert(diff.added.length === 0, 'Should have 0 added, got ' + JSON.stringify(diff.added));
        assert(diff.removed.length === 0, 'Should have 0 removed, got ' + JSON.stringify(diff.removed));
      });
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
  });

  await asyncTest('AST-DIFF: REAL detectSuddenAstChanges — added APIs → suspicious with code-derived severities (offline)', async () => {
    const dirV1 = makeTempDir({ 'index.js': 'module.exports = 41;' });
    const dirV2 = makeTempDir({
      'index.js': 'const cp = require("child_process"); fetch("https://evil.example"); const dns = require("dns");'
    });
    try {
      await withMockedAstDiff({
        metadata: makeTwoVersionMetadata('fake-pkg'),
        versionDirs: { '1.0.0': dirV1, '1.1.0': dirV2 }
      }, async (mod) => {
        const result = await mod.detectSuddenAstChanges('fake-pkg');
        assert(result.packageName === 'fake-pkg', 'packageName should match');
        assert(result.suspicious === true, 'Should be suspicious');
        assert(result.latestVersion === '1.1.0', 'latestVersion from real getLatestVersions, got ' + result.latestVersion);
        assert(result.previousVersion === '1.0.0', 'previousVersion, got ' + result.previousVersion);
        assert(result.findings.length === 3, 'Should have 3 findings, got ' + result.findings.length);
        for (const f of result.findings) {
          assert(f.type === 'dangerous_api_added', 'type should be dangerous_api_added');
          assertIncludes(f.description, f.pattern, 'description should mention the pattern');
        }
        // Severities below are applied by detectSuddenAstChanges (PATTERN_SEVERITY in src),
        // NOT recomputed here — this is the assertion the old mock tests could never make.
        const bySeverity = {};
        for (const f of result.findings) bySeverity[f.pattern] = f.severity;
        assert(bySeverity['child_process'] === 'CRITICAL', 'child_process should be CRITICAL, got ' + bySeverity['child_process']);
        assert(bySeverity['fetch'] === 'HIGH', 'fetch should be HIGH, got ' + bySeverity['fetch']);
        assert(bySeverity['dns.lookup'] === 'MEDIUM', 'dns.lookup should be MEDIUM, got ' + bySeverity['dns.lookup']);
        assert(result.metadata.latestPublishedAt === '2026-02-01T00:00:00.000Z', 'latestPublishedAt');
        assert(result.metadata.previousPublishedAt === '2026-01-01T00:00:00.000Z', 'previousPublishedAt');
      });
    } finally { cleanTempDir(dirV1); cleanTempDir(dirV2); }
  });

  await asyncTest('AST-DIFF: REAL detectSuddenAstChanges — identical versions → not suspicious (offline)', async () => {
    const src = 'eval("same-in-both-versions");';
    const dirV1 = makeTempDir({ 'index.js': src });
    const dirV2 = makeTempDir({ 'index.js': src });
    try {
      await withMockedAstDiff({
        metadata: makeTwoVersionMetadata('fake-pkg'),
        versionDirs: { '1.0.0': dirV1, '1.1.0': dirV2 }
      }, async (mod) => {
        const result = await mod.detectSuddenAstChanges('fake-pkg');
        assert(result.suspicious === false, 'No new patterns → not suspicious');
        assert(result.findings.length === 0, 'Should have no findings');
        assert(result.latestVersion === '1.1.0' && result.previousVersion === '1.0.0', 'versions still reported');
      });
    } finally { cleanTempDir(dirV1); cleanTempDir(dirV2); }
  });

  await asyncTest('AST-DIFF: REAL detectSuddenAstChanges — single published version → not suspicious (offline)', async () => {
    const metadata = {
      name: 'single-version-pkg',
      time: { created: '2026-01-01T00:00:00.000Z', '1.0.0': '2026-01-01T00:00:00.000Z' },
      versions: { '1.0.0': {} }
    };
    await withMockedAstDiff({ metadata }, async (mod) => {
      const result = await mod.detectSuddenAstChanges('single-version-pkg');
      assert(result.suspicious === false, 'Single version should not be suspicious');
      assert(result.findings.length === 0, 'Single version should have no findings');
      assert(result.latestVersion === '1.0.0', 'latestVersion should be set');
      assert(result.previousVersion === null, 'previousVersion should be null');
      assert(result.metadata.latestPublishedAt === '2026-01-01T00:00:00.000Z', 'latestPublishedAt from real code');
      assert(result.metadata.previousPublishedAt === null, 'previousPublishedAt should be null');
    });
  });

  await asyncTest('AST-DIFF: REAL detectSuddenAstChanges — zero published versions → not suspicious (offline)', async () => {
    const metadata = { name: 'no-version-pkg', time: { created: '2026-01-01T00:00:00.000Z' }, versions: {} };
    await withMockedAstDiff({ metadata }, async (mod) => {
      const result = await mod.detectSuddenAstChanges('no-version-pkg');
      assert(result.suspicious === false, 'Zero versions should not be suspicious');
      assert(result.findings.length === 0, 'Zero versions should have no findings');
      assert(result.latestVersion === null, 'latestVersion should be null');
      assert(result.previousVersion === null, 'previousVersion should be null');
      assert(result.metadata.latestPublishedAt === null, 'latestPublishedAt should be null');
    });
  });

  // --- Rules and playbooks integration ---

  test('AST-DIFF: Rules MUADDIB-TEMPORAL-AST-001/002/003 exist', () => {
    const { getRule } = require('../../src/rules/index.js');
    const r1 = getRule('dangerous_api_added_critical');
    assert(r1.id === 'MUADDIB-TEMPORAL-AST-001', 'Rule 001 ID, got ' + r1.id);
    assert(r1.severity === 'CRITICAL', 'Rule 001 severity');
    const r2 = getRule('dangerous_api_added_high');
    assert(r2.id === 'MUADDIB-TEMPORAL-AST-002', 'Rule 002 ID, got ' + r2.id);
    assert(r2.severity === 'HIGH', 'Rule 002 severity');
    const r3 = getRule('dangerous_api_added_medium');
    assert(r3.id === 'MUADDIB-TEMPORAL-AST-003', 'Rule 003 ID, got ' + r3.id);
    assert(r3.severity === 'MEDIUM', 'Rule 003 severity');
  });

  test('AST-DIFF: Playbooks exist for dangerous_api_added threat types', () => {
    const { getPlaybook } = require('../../src/response/playbooks.js');
    const p1 = getPlaybook('dangerous_api_added_critical');
    assert(p1 && p1.includes('child_process'), 'Playbook for critical should mention child_process');
    const p2 = getPlaybook('dangerous_api_added_high');
    assert(p2 && p2.includes('process.env'), 'Playbook for high should mention process.env');
    const p3 = getPlaybook('dangerous_api_added_medium');
    assert(p3 && p3.includes('dns.lookup'), 'Playbook for medium should mention dns.lookup');
  });

  // --- Additional extractPatternsFromSource edge cases ---

  test('AST-DIFF: extractPatternsFromSource detects Function() call (not just new Function)', () => {
    const patterns = new Set();
    extractPatternsFromSource('const fn = Function("return 1");', patterns);
    assert(patterns.has('Function'), 'Should detect Function() call');
  });

  test('AST-DIFF: extractPatternsFromSource detects http.get member expression', () => {
    const patterns = new Set();
    extractPatternsFromSource('http.get("http://evil.com", cb);', patterns);
    assert(patterns.has('http_request'), 'Should detect http.get member expression');
  });

  test('AST-DIFF: extractPatternsFromSource detects https.request member expression', () => {
    const patterns = new Set();
    extractPatternsFromSource('https.request({hostname: "evil.com"});', patterns);
    assert(patterns.has('https_request'), 'Should detect https.request member expression');
  });

  test('AST-DIFF: extractPatternsFromSource detects fs.readFile on sensitive path', () => {
    const patterns = new Set();
    extractPatternsFromSource('fs.readFile(".env", "utf8", cb);', patterns);
    assert(patterns.has('fs.readFile_sensitive'), 'Should detect fs.readFile on .env');
  });

  test('AST-DIFF: extractPatternsFromSource does NOT detect fs.readFileSync on non-sensitive path', () => {
    const patterns = new Set();
    extractPatternsFromSource('fs.readFileSync("./data.json");', patterns);
    assert(!patterns.has('fs.readFile_sensitive'), 'Should NOT detect non-sensitive path');
  });

  test('AST-DIFF: extractPatternsFromSource detects import http', () => {
    const patterns = new Set();
    extractPatternsFromSource('import http from "http";', patterns);
    assert(patterns.has('http_request'), 'Should detect import http');
  });

  test('AST-DIFF: extractPatternsFromSource detects import https', () => {
    const patterns = new Set();
    extractPatternsFromSource('import https from "https";', patterns);
    assert(patterns.has('https_request'), 'Should detect import https');
  });

  test('AST-DIFF: extractPatternsFromSource detects import dns', () => {
    const patterns = new Set();
    extractPatternsFromSource('import dns from "dns";', patterns);
    assert(patterns.has('dns.lookup'), 'Should detect import dns');
  });

  test('AST-DIFF: extractPatternsFromSource detects import net', () => {
    const patterns = new Set();
    extractPatternsFromSource('import net from "net";', patterns);
    assert(patterns.has('net.connect'), 'Should detect import net');
  });

  test('AST-DIFF: extractPatternsFromSource detects dns.resolve member expression', () => {
    const patterns = new Set();
    extractPatternsFromSource('dns.resolve("evil.com", cb);', patterns);
    assert(patterns.has('dns.lookup'), 'Should detect dns.resolve via member expression');
  });

  test('AST-DIFF: extractPatternsFromSource detects net.createConnection member expression', () => {
    const patterns = new Set();
    extractPatternsFromSource('net.createConnection(1234, "evil.com");', patterns);
    assert(patterns.has('net.connect'), 'Should detect net.createConnection via member expression');
  });

  test('AST-DIFF: extractPatternsFromSource detects fs.readFileSync on .ssh sensitive path', () => {
    const patterns = new Set();
    extractPatternsFromSource('fs.readFileSync("/home/user/.ssh/id_rsa");', patterns);
    assert(patterns.has('fs.readFile_sensitive'), 'Should detect .ssh in path');
  });

  test('AST-DIFF: extractPatternsFromSource detects fs.readFile on .aws/credentials', () => {
    const patterns = new Set();
    extractPatternsFromSource('fs.readFile(".aws/credentials", cb);', patterns);
    assert(patterns.has('fs.readFile_sensitive'), 'Should detect .aws/credentials');
  });

  // --- extractDangerousPatterns edge cases ---

  test('AST-DIFF: extractDangerousPatterns skips files over MAX_FILE_SIZE (10MB)', () => {
    const dir = makeTempDir({ 'small.js': 'fetch("https://example.com");' });
    try {
      // big.js is VALID JS made entirely of eval() calls and strictly larger than
      // MAX_FILE_SIZE (10MB, src/shared/constants.js:113 — forEachSafeFile skips
      // files with stat.size > getMaxFileSize()). If the size guard ever breaks,
      // 'eval' WOULD be extracted and this test fails.
      const line = 'eval("x");\n';
      const oversized = line.repeat(Math.ceil((10 * 1024 * 1024 + 4096) / line.length));
      const bigPath = path.join(dir, 'big.js');
      fs.writeFileSync(bigPath, oversized, 'utf8');
      assert(fs.statSync(bigPath).size > 10 * 1024 * 1024, 'fixture must exceed 10MB');
      const patterns = extractDangerousPatterns(dir);
      assert(!patterns.has('eval'), 'Oversized file must be skipped (eval must NOT be extracted)');
      assert(patterns.has('fetch'), 'Normal-sized sibling file must still be scanned');
      assert(patterns.size === 1, 'Only patterns from small.js expected, got ' + patterns.size);
    } finally { cleanTempDir(dir); }
  });

  test('AST-DIFF: extractDangerousPatterns handles files with syntax errors gracefully', () => {
    const dir = makeTempDir({
      'broken.js': 'function { this is broken } ][',
      'good.js': 'eval("code");'
    });
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.has('eval'), 'Should still detect patterns from valid files');
      // Broken file should not cause a crash
    } finally { cleanTempDir(dir); }
  });

  test('AST-DIFF: extractDangerousPatterns handles deeply nested directories', () => {
    const dir = makeTempDir({
      'a/b/c/d/deep.js': 'const cp = require("child_process");'
    });
    try {
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.has('child_process'), 'Should detect patterns in deeply nested files');
    } finally { cleanTempDir(dir); }
  });

  // --- Integration tests (network-dependent) ---

  // Network tests are opt-IN: set MUADDIB_TEST_NETWORK=true to enable.
  // Default: always skipped (CI must work in airplane mode).
  const skipNetwork = process.env.MUADDIB_TEST_NETWORK !== 'true';

  if (!skipNetwork) {
    await asyncTest('AST-DIFF: fetchVersionMetadata fetches is-number@7.0.0', async () => {
      const meta = await fetchVersionMetadata('is-number', '7.0.0');
      assert(meta && typeof meta === 'object', 'Should return an object');
      assert(meta.name === 'is-number', 'Name should be is-number, got ' + meta.name);
      assert(meta.version === '7.0.0', 'Version should be 7.0.0, got ' + meta.version);
      assert(meta.dist && meta.dist.tarball, 'Should have dist.tarball');
    });

    await asyncTest('AST-DIFF: fetchVersionMetadata throws for non-existent version', async () => {
      let threw = false;
      try {
        await fetchVersionMetadata('is-number', '999.999.999');
      } catch (e) {
        threw = true;
        assert(e.message.includes('not found'), 'Error should mention not found, got: ' + e.message);
      }
      assert(threw, 'Should have thrown for non-existent version');
    });

    await asyncTest('AST-DIFF: fetchPackageTarball downloads and extracts is-number@7.0.0', async () => {
      const result = await fetchPackageTarball('is-number', '7.0.0');
      try {
        assert(typeof result.dir === 'string', 'Should return dir path');
        assert(typeof result.cleanup === 'function', 'Should return cleanup function');
        assert(fs.existsSync(result.dir), 'Extracted dir should exist');
        // is-number should have an index.js or package.json
        const pkgJson = path.join(result.dir, 'package.json');
        assert(fs.existsSync(pkgJson), 'Should contain package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgJson, 'utf8'));
        assert(pkg.name === 'is-number', 'package.json name should be is-number');
        assert(pkg.version === '7.0.0', 'package.json version should be 7.0.0');
      } finally {
        result.cleanup();
        assert(!fs.existsSync(result.dir), 'cleanup() should remove the temp dir');
      }
    });

    await asyncTest('AST-DIFF: compareAstPatterns on is-number 4.0.0 vs 7.0.0 returns valid result', async () => {
      const result = await compareAstPatterns('is-number', '4.0.0', '7.0.0');
      assert(typeof result === 'object', 'Should return an object');
      assert(Array.isArray(result.added), 'Should have added array');
      assert(Array.isArray(result.removed), 'Should have removed array');
      // Both versions are clean utility packages — no dangerous patterns expected
      // But the structure should be valid regardless
      for (const p of result.added) {
        assert(typeof p === 'string', 'Added items should be strings');
      }
      for (const p of result.removed) {
        assert(typeof p === 'string', 'Removed items should be strings');
      }
    });
    await asyncTest('AST-DIFF: detectSuddenAstChanges on is-number returns valid structure', async () => {
      const result = await detectSuddenAstChanges('is-number');
      assert(typeof result === 'object', 'Should return an object');
      assert(result.packageName === 'is-number', 'packageName should be is-number');
      assert(typeof result.latestVersion === 'string', 'latestVersion should be string');
      assert(typeof result.previousVersion === 'string', 'previousVersion should be string');
      assert(typeof result.suspicious === 'boolean', 'suspicious should be boolean');
      assert(Array.isArray(result.findings), 'findings should be array');
      assert(typeof result.metadata === 'object', 'metadata should be object');
      assert(typeof result.metadata.latestPublishedAt === 'string', 'latestPublishedAt');
      assert(typeof result.metadata.previousPublishedAt === 'string', 'previousPublishedAt');
      // Each finding (if any) should have the correct shape
      for (const f of result.findings) {
        assert(f.type === 'dangerous_api_added', 'type should be dangerous_api_added');
        assert(typeof f.pattern === 'string', 'pattern should be string');
        assert(['CRITICAL', 'HIGH', 'MEDIUM'].includes(f.severity), 'severity should be valid');
        assert(typeof f.description === 'string', 'description should be string');
      }
    });
  } else {
    console.log('[SKIP] AST-DIFF: network tests (CI/SKIP_NETWORK)');
    addSkipped(5);
  }
}

module.exports = { runTemporalAstDiffTests };
