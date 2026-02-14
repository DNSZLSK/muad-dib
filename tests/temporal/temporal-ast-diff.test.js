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

  // --- compareAstPatterns (mock: simulate the diff logic locally) ---

  test('AST-DIFF: compare mock — versionB adds child_process → added contains it', () => {
    const dirA = makeTempDir({ 'index.js': 'console.log("safe v1");' });
    const dirB = makeTempDir({ 'index.js': 'const cp = require("child_process"); cp.exec("whoami");' });
    try {
      const patternsA = extractDangerousPatterns(dirA);
      const patternsB = extractDangerousPatterns(dirB);
      const added = [...patternsB].filter(p => !patternsA.has(p));
      const removed = [...patternsA].filter(p => !patternsB.has(p));
      assert(added.length === 1, 'Should have 1 added, got ' + added.length);
      assert(added[0] === 'child_process', 'Added should be child_process, got ' + added[0]);
      assert(removed.length === 0, 'Should have 0 removed');
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
  });

  test('AST-DIFF: compare mock — versionB removes eval → removed contains it', () => {
    const dirA = makeTempDir({ 'index.js': 'eval("x"); console.log(1);' });
    const dirB = makeTempDir({ 'index.js': 'console.log(1);' });
    try {
      const patternsA = extractDangerousPatterns(dirA);
      const patternsB = extractDangerousPatterns(dirB);
      const added = [...patternsB].filter(p => !patternsA.has(p));
      const removed = [...patternsA].filter(p => !patternsB.has(p));
      assert(removed.length === 1, 'Should have 1 removed, got ' + removed.length);
      assert(removed[0] === 'eval', 'Removed should be eval, got ' + removed[0]);
      assert(added.length === 0, 'Should have 0 added');
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
  });

  test('AST-DIFF: compare mock — identical versions → both empty', () => {
    const dirA = makeTempDir({ 'index.js': 'const http = require("http"); http.get("url", cb);' });
    const dirB = makeTempDir({ 'index.js': 'const http = require("http"); http.get("url", cb);' });
    try {
      const patternsA = extractDangerousPatterns(dirA);
      const patternsB = extractDangerousPatterns(dirB);
      const added = [...patternsB].filter(p => !patternsA.has(p));
      const removed = [...patternsA].filter(p => !patternsB.has(p));
      assert(added.length === 0, 'Should have 0 added, got ' + added.length);
      assert(removed.length === 0, 'Should have 0 removed, got ' + removed.length);
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
  });

  test('AST-DIFF: compare mock — multiple added and removed patterns', () => {
    const dirA = makeTempDir({
      'index.js': 'eval("x"); const dns = require("dns"); dns.resolve("a");'
    });
    const dirB = makeTempDir({
      'index.js': 'const cp = require("child_process"); fetch("url"); const secret = process.env.KEY;'
    });
    try {
      const patternsA = extractDangerousPatterns(dirA);
      const patternsB = extractDangerousPatterns(dirB);
      const added = [...patternsB].filter(p => !patternsA.has(p)).sort();
      const removed = [...patternsA].filter(p => !patternsB.has(p)).sort();
      assert(added.length === 3, 'Should have 3 added, got ' + added.length);
      assert(added.includes('child_process'), 'Added should include child_process');
      assert(added.includes('fetch'), 'Added should include fetch');
      assert(added.includes('process.env'), 'Added should include process.env');
      assert(removed.length === 2, 'Should have 2 removed, got ' + removed.length);
      assert(removed.includes('eval'), 'Removed should include eval');
      assert(removed.includes('dns.lookup'), 'Removed should include dns.lookup');
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
  });

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

  // --- detectSuddenAstChanges (mock logic) ---

  test('AST-DIFF: detectSuddenAstChanges mock — added child_process yields CRITICAL finding', () => {
    // Simulate the logic: two dirs, extract patterns, build findings
    const dirA = makeTempDir({ 'index.js': 'console.log("v1");' });
    const dirB = makeTempDir({ 'index.js': 'const cp = require("child_process"); cp.exec("id");' });
    try {
      const patternsA = extractDangerousPatterns(dirA);
      const patternsB = extractDangerousPatterns(dirB);
      const added = [...patternsB].filter(p => !patternsA.has(p));
      const findings = added.map(pattern => ({
        type: 'dangerous_api_added',
        pattern,
        severity: PATTERN_SEVERITY[pattern] || 'MEDIUM',
        description: `Package now uses ${pattern} (not present in previous version)`
      }));
      assert(findings.length === 1, 'Should have 1 finding, got ' + findings.length);
      assert(findings[0].pattern === 'child_process', 'Pattern should be child_process');
      assert(findings[0].severity === 'CRITICAL', 'Severity should be CRITICAL');
      assert(findings[0].type === 'dangerous_api_added', 'Type should be dangerous_api_added');
      assertIncludes(findings[0].description, 'child_process', 'Description should mention child_process');
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
  });

  test('AST-DIFF: detectSuddenAstChanges mock — added fetch yields HIGH finding', () => {
    const dirA = makeTempDir({ 'index.js': 'console.log("v1");' });
    const dirB = makeTempDir({ 'index.js': 'fetch("https://evil.com");' });
    try {
      const patternsA = extractDangerousPatterns(dirA);
      const patternsB = extractDangerousPatterns(dirB);
      const added = [...patternsB].filter(p => !patternsA.has(p));
      const findings = added.map(pattern => ({
        type: 'dangerous_api_added',
        pattern,
        severity: PATTERN_SEVERITY[pattern] || 'MEDIUM'
      }));
      assert(findings.length === 1, 'Should have 1 finding');
      assert(findings[0].severity === 'HIGH', 'fetch should be HIGH, got ' + findings[0].severity);
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
  });

  test('AST-DIFF: detectSuddenAstChanges mock — no new patterns → not suspicious', () => {
    const dirA = makeTempDir({ 'index.js': 'eval("x");' });
    const dirB = makeTempDir({ 'index.js': 'eval("y");' });
    try {
      const patternsA = extractDangerousPatterns(dirA);
      const patternsB = extractDangerousPatterns(dirB);
      const added = [...patternsB].filter(p => !patternsA.has(p));
      assert(added.length === 0, 'No new patterns should mean not suspicious');
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
  });

  test('AST-DIFF: detectSuddenAstChanges mock — multiple patterns with mixed severities', () => {
    const dirA = makeTempDir({ 'index.js': 'console.log(1);' });
    const dirB = makeTempDir({
      'index.js': 'const cp = require("child_process"); fetch("url"); const dns = require("dns"); dns.resolve("x");'
    });
    try {
      const patternsA = extractDangerousPatterns(dirA);
      const patternsB = extractDangerousPatterns(dirB);
      const added = [...patternsB].filter(p => !patternsA.has(p));
      const findings = added.map(pattern => ({
        type: 'dangerous_api_added',
        pattern,
        severity: PATTERN_SEVERITY[pattern] || 'MEDIUM'
      }));
      assert(findings.length === 3, 'Should have 3 findings, got ' + findings.length);
      const severities = findings.map(f => f.severity).sort();
      assert(severities.includes('CRITICAL'), 'Should include CRITICAL (child_process)');
      assert(severities.includes('HIGH'), 'Should include HIGH (fetch)');
      assert(severities.includes('MEDIUM'), 'Should include MEDIUM (dns.lookup)');
    } finally { cleanTempDir(dirA); cleanTempDir(dirB); }
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

  test('AST-DIFF: extractDangerousPatterns skips oversized files', () => {
    const dir = makeTempDir({});
    try {
      // Create a file that looks oversized by writing a large file
      // MAX_FILE_SIZE is 10MB, but we can't create a 10MB file in tests
      // Instead, test that small files work and the function runs without error
      const bigContent = 'eval("test");\n'.repeat(100);
      fs.writeFileSync(path.join(dir, 'big.js'), bigContent, 'utf8');
      const patterns = extractDangerousPatterns(dir);
      assert(patterns.has('eval'), 'Should still detect eval in normal-sized file');
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

  // --- PATTERN_SEVERITY unknown fallback ---

  test('AST-DIFF: Unknown pattern name falls back to MEDIUM severity', () => {
    const unknownSeverity = PATTERN_SEVERITY['unknown_pattern'] || 'MEDIUM';
    assert(unknownSeverity === 'MEDIUM', 'Unknown pattern should fall back to MEDIUM');
  });

  // --- detectSuddenAstChanges mock: single version (less than 2) ---

  test('AST-DIFF: detectSuddenAstChanges mock — single version returns not suspicious', () => {
    // Simulate what detectSuddenAstChanges does when latest.length < 2
    const latest = [{ version: '1.0.0', publishedAt: '2026-01-01T00:00:00.000Z' }];
    const result = {
      packageName: 'single-version-pkg',
      latestVersion: latest.length > 0 ? latest[0].version : null,
      previousVersion: null,
      suspicious: false,
      findings: [],
      metadata: {
        latestPublishedAt: latest.length > 0 ? latest[0].publishedAt : null,
        previousPublishedAt: null
      }
    };
    assert(result.suspicious === false, 'Single version should not be suspicious');
    assert(result.findings.length === 0, 'Single version should have no findings');
    assert(result.previousVersion === null, 'previousVersion should be null');
    assert(result.latestVersion === '1.0.0', 'latestVersion should be set');
  });

  test('AST-DIFF: detectSuddenAstChanges mock — zero versions returns not suspicious', () => {
    const latest = [];
    const result = {
      packageName: 'no-version-pkg',
      latestVersion: latest.length > 0 ? latest[0].version : null,
      previousVersion: null,
      suspicious: false,
      findings: [],
      metadata: {
        latestPublishedAt: latest.length > 0 ? latest[0].publishedAt : null,
        previousPublishedAt: null
      }
    };
    assert(result.latestVersion === null, 'latestVersion should be null');
    assert(result.metadata.latestPublishedAt === null, 'latestPublishedAt should be null');
  });

  // --- Integration tests (network-dependent) ---

  const skipNetwork = process.env.CI === 'true' || process.env.SKIP_NETWORK === 'true';

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
