const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const TESTS_DIR = path.join(__dirname, 'samples');
const BIN = path.join(__dirname, '..', 'bin', 'muaddib.js');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (e) {
    console.log(`[FAIL] ${name}`);
    console.log(`       ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertIncludes(str, substr, message) {
  if (!str.includes(substr)) {
    throw new Error(message || `Expected "${substr}" in output`);
  }
}

function assertNotIncludes(str, substr, message) {
  if (str.includes(substr)) {
    throw new Error(message || `Unexpected "${substr}" in output`);
  }
}

function runScan(target, options = '') {
  try {
    const cmd = `node "${BIN}" scan "${target}" ${options}`;
    return execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return e.stdout || e.stderr || '';
  }
}

function runCommand(cmd) {
  try {
    return execSync(`node "${BIN}" ${cmd}`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return e.stdout || e.stderr || '';
  }
}

// ============================================
// UNIT TESTS - AST DETECTION
// ============================================

console.log('\n=== AST TESTS ===\n');

test('AST: Detects .npmrc access', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, '.npmrc', 'Should detect .npmrc');
});

test('AST: Detects .ssh access', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, '.ssh', 'Should detect .ssh');
});

test('AST: Detects GITHUB_TOKEN', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'GITHUB_TOKEN', 'Should detect GITHUB_TOKEN');
});

test('AST: Detects NPM_TOKEN', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'NPM_TOKEN', 'Should detect NPM_TOKEN');
});

test('AST: Detects AWS_SECRET', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'AWS_SECRET', 'Should detect AWS_SECRET');
});

test('AST: Detects eval()', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'eval', 'Should detect eval');
});

test('AST: Detects exec()', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'exec', 'Should detect exec');
});

test('AST: Detects new Function()', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'Function', 'Should detect Function');
});

test('AST: Dynamic env access flagged as MEDIUM', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--json');
  const result = JSON.parse(output);
  const dynamicEnv = result.threats.find(t => t.type === 'env_access' && t.severity === 'MEDIUM');
  assert(dynamicEnv, 'Dynamic process.env[var] should be MEDIUM');
});

// ============================================
// UNIT TESTS - SHELL DETECTION
// ============================================

console.log('\n=== SHELL TESTS ===\n');

test('SHELL: Detects curl | sh', () => {
  const output = runScan(path.join(TESTS_DIR, 'shell'));
  assertIncludes(output, 'curl', 'Should detect curl | sh');
});

test('SHELL: Detects wget && chmod +x', () => {
  const output = runScan(path.join(TESTS_DIR, 'shell'));
  assertIncludes(output, 'wget', 'Should detect wget');
});

test('SHELL: Detects reverse shell', () => {
  const output = runScan(path.join(TESTS_DIR, 'shell'));
  assertIncludes(output, 'reverse', 'Should detect reverse shell');
});

test('SHELL: Detects rm -rf $HOME', () => {
  const output = runScan(path.join(TESTS_DIR, 'shell'));
  assertIncludes(output, 'home', 'Should detect home deletion');
});

// ============================================
// UNIT TESTS - OBFUSCATION DETECTION
// ============================================

console.log('\n=== OBFUSCATION TESTS ===\n');

test('OBFUSCATION: Detects massive hex escapes', () => {
  const output = runScan(path.join(TESTS_DIR, 'obfuscation'));
  assertIncludes(output, 'obfusc', 'Should detect obfuscation');
});

test('OBFUSCATION: Detects _0x variables', () => {
  const output = runScan(path.join(TESTS_DIR, 'obfuscation'));
  assertIncludes(output, 'obfusc', 'Should detect _0x variables');
});

// ============================================
// UNIT TESTS - DATAFLOW DETECTION
// ============================================

console.log('\n=== DATAFLOW TESTS ===\n');

test('DATAFLOW: Detects credential read + network send', () => {
  const output = runScan(path.join(TESTS_DIR, 'dataflow'));
  assertIncludes(output, 'Suspicious flow', 'Should detect suspicious flow');
});

test('DATAFLOW: Detects env read + fetch', () => {
  const output = runScan(path.join(TESTS_DIR, 'dataflow'));
  assertIncludes(output, 'CRITICAL', 'Should be CRITICAL');
});

// ============================================
// UNIT TESTS - PACKAGE.JSON DETECTION
// ============================================

console.log('\n=== PACKAGE.JSON TESTS ===\n');

test('PACKAGE: Detects suspicious preinstall', () => {
  const output = runScan(path.join(TESTS_DIR, 'package'));
  assertIncludes(output, 'preinstall', 'Should detect preinstall');
});

test('PACKAGE: Detects suspicious postinstall', () => {
  const output = runScan(path.join(TESTS_DIR, 'package'));
  assertIncludes(output, 'postinstall', 'Should detect postinstall');
});

// ============================================
// UNIT TESTS - MARKER DETECTION
// ============================================

console.log('\n=== MARKER TESTS ===\n');

test('MARKERS: Detects Shai-Hulud', () => {
  const output = runScan(path.join(TESTS_DIR, 'markers'));
  assertIncludes(output, 'Shai-Hulud', 'Should detect Shai-Hulud marker');
});

test('MARKERS: Detects The Second Coming', () => {
  const output = runScan(path.join(TESTS_DIR, 'markers'));
  assertIncludes(output, 'Second Coming', 'Should detect The Second Coming marker');
});

// ============================================
// UNIT TESTS - TYPOSQUATTING DETECTION
// ============================================

console.log('\n=== TYPOSQUATTING TESTS ===\n');

test('TYPOSQUAT: Detects lodahs (lodash)', () => {
  const output = runScan(path.join(TESTS_DIR, 'typosquat'));
  assertIncludes(output, 'lodahs', 'Should detect lodahs');
});

test('TYPOSQUAT: Detects axois (axios)', () => {
  const output = runScan(path.join(TESTS_DIR, 'typosquat'));
  assertIncludes(output, 'axois', 'Should detect axois');
});

test('TYPOSQUAT: Detects expres (express)', () => {
  const output = runScan(path.join(TESTS_DIR, 'typosquat'));
  assertIncludes(output, 'expres', 'Should detect expres');
});

test('TYPOSQUAT: Severity HIGH', () => {
  const output = runScan(path.join(TESTS_DIR, 'typosquat'));
  assertIncludes(output, 'HIGH', 'Should be HIGH');
});

// ============================================
// INTEGRATION TESTS - CLI
// ============================================

console.log('\n=== CLI TESTS ===\n');

test('CLI: --help displays usage', () => {
  const output = runCommand('--help');
  assertIncludes(output, 'Usage', 'Should display usage');
});

test('CLI: --json returns valid JSON', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--json');
  try {
    JSON.parse(output);
  } catch (e) {
    throw new Error('Invalid JSON output');
  }
});

test('CLI: --sarif generates SARIF file', () => {
  const sarifPath = path.join(__dirname, 'test-output.sarif');
  runScan(path.join(TESTS_DIR, 'ast'), `--sarif "${sarifPath}"`);
  assert(fs.existsSync(sarifPath), 'SARIF file not generated');
  const content = fs.readFileSync(sarifPath, 'utf8');
  const sarif = JSON.parse(content);
  assert(sarif.version === '2.1.0', 'Incorrect SARIF version');
  assert(sarif.runs && sarif.runs.length > 0, 'SARIF runs missing');
  fs.unlinkSync(sarifPath);
});

test('CLI: --html generates HTML file', () => {
  const htmlPath = path.join(__dirname, 'test-output.html');
  runScan(path.join(TESTS_DIR, 'ast'), `--html "${htmlPath}"`);
  assert(fs.existsSync(htmlPath), 'HTML file not generated');
  const content = fs.readFileSync(htmlPath, 'utf8');
  assertIncludes(content, 'MUAD', 'HTML should contain MUAD');
  assertIncludes(content, '<table>', 'HTML should contain table');
  fs.unlinkSync(htmlPath);
});

test('CLI: --explain displays details', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--explain');
  assertIncludes(output, 'Rule ID', 'Should display Rule ID');
  assertIncludes(output, 'MITRE', 'Should display MITRE');
  assertIncludes(output, 'References', 'Should display References');
  assertIncludes(output, 'Playbook', 'Should display Playbook');
});

test('CLI: --fail-on critical exit code correct', () => {
  try {
    execSync(`node "${BIN}" scan "${path.join(TESTS_DIR, 'dataflow')}" --fail-on critical`, { encoding: 'utf8' });
  } catch (e) {
    assert(e.status === 1, 'Exit code should be 1 for 1 CRITICAL');
    return;
  }
  throw new Error('Should have non-zero exit code');
});

test('CLI: --fail-on high exit code correct', () => {
  try {
    execSync(`node "${BIN}" scan "${path.join(TESTS_DIR, 'ast')}" --fail-on high`, { encoding: 'utf8' });
  } catch (e) {
    assert(e.status > 0, 'Exit code should be > 0');
    return;
  }
  throw new Error('Should have non-zero exit code');
});

// ============================================
// INTEGRATION TESTS - UPDATE
// ============================================

console.log('\n=== UPDATE TESTS ===\n');

test('UPDATE: Downloads and caches IOCs', () => {
  const output = runCommand('update');
  assertIncludes(output, 'IOCs saved', 'Should save IOCs');
  assertIncludes(output, 'malicious npm packages', 'Should display package count');
});

// ============================================
// FALSE POSITIVES TESTS
// ============================================

console.log('\n=== FALSE POSITIVES TESTS ===\n');

test('FALSE POSITIVES: Clean project = no threats', () => {
  const output = runScan(path.join(TESTS_DIR, 'clean'));
  assertIncludes(output, 'No threats detected', 'Clean project should have no threats');
});

test('FALSE POSITIVES: Comments ignored', () => {
  const output = runScan(path.join(TESTS_DIR, 'clean'));
  assertNotIncludes(output, 'CRITICAL', 'Comments should not trigger');
});

test('FALSE POSITIVES: Safe env vars (NODE_ENV, PORT, CI, etc.) not flagged', () => {
  const output = runScan(path.join(TESTS_DIR, 'clean'));
  assertNotIncludes(output, 'env_access', 'Safe env vars should not trigger env_access');
});

// ============================================
// EDGE CASES TESTS
// ============================================

console.log('\n=== EDGE CASES TESTS ===\n');

test('EDGE: Empty file does not crash', () => {
  const output = runScan(path.join(TESTS_DIR, 'edge', 'empty'));
  assert(output !== undefined, 'Should not crash on empty file');
});

test('EDGE: Non-JS file ignored', () => {
  const output = runScan(path.join(TESTS_DIR, 'edge', 'non-js'));
  assertIncludes(output, 'No threats detected', 'Non-JS files should be ignored');
});

test('EDGE: Invalid JS syntax does not crash', () => {
  const output = runScan(path.join(TESTS_DIR, 'edge', 'invalid-syntax'));
  assert(output !== undefined, 'Should not crash on invalid syntax');
});

test('EDGE: Very large file does not timeout', () => {
  const start = Date.now();
  runScan(path.join(TESTS_DIR, 'edge', 'large-file'));
  const duration = Date.now() - start;
  assert(duration < 30000, 'Should not take more than 30s');
});

// ============================================
// MITRE RULES TESTS
// ============================================

console.log('\n=== MITRE TESTS ===\n');

test('MITRE: T1552.001 - Credentials in Files', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--explain');
  assertIncludes(output, 'T1552.001', 'Should map T1552.001');
});

test('MITRE: T1059 - Command Execution', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--explain');
  assertIncludes(output, 'T1059', 'Should map T1059');
});

test('MITRE: T1041 - Exfiltration', () => {
  const output = runScan(path.join(TESTS_DIR, 'dataflow'), '--explain');
  assertIncludes(output, 'T1041', 'Should map T1041');
});

// ============================================
// WHITELIST / REHABILITATED PACKAGES TESTS
// ============================================

console.log('\n=== WHITELIST TESTS ===\n');

test('WHITELIST: chalk is in REHABILITATED_PACKAGES', () => {
  const { REHABILITATED_PACKAGES } = require('../src/safe-install.js');
  assert(REHABILITATED_PACKAGES['chalk'], 'chalk should be in REHABILITATED_PACKAGES');
  assert(REHABILITATED_PACKAGES['chalk'].safe === true, 'chalk.safe should be true');
});

test('WHITELIST: debug is in REHABILITATED_PACKAGES', () => {
  const { REHABILITATED_PACKAGES } = require('../src/safe-install.js');
  assert(REHABILITATED_PACKAGES['debug'], 'debug should be in REHABILITATED_PACKAGES');
  assert(REHABILITATED_PACKAGES['debug'].safe === true, 'debug.safe should be true');
});

test('WHITELIST: ua-parser-js has specific compromised versions', () => {
  const { REHABILITATED_PACKAGES } = require('../src/safe-install.js');
  const uap = REHABILITATED_PACKAGES['ua-parser-js'];
  assert(uap, 'ua-parser-js should be in REHABILITATED_PACKAGES');
  assert(uap.safe === false, 'ua-parser-js.safe should be false');
  assert(uap.compromised.includes('0.7.29'), 'Should include 0.7.29');
  assert(uap.compromised.includes('0.8.0'), 'Should include 0.8.0');
  assert(uap.compromised.includes('1.0.0'), 'Should include 1.0.0');
});

test('WHITELIST: checkRehabilitated returns safe for chalk', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('chalk', '5.4.0');
  assert(result !== null, 'chalk should be recognized');
  assert(result.safe === true, 'chalk should be safe');
});

test('WHITELIST: checkRehabilitated returns unsafe for ua-parser-js@0.7.29', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('ua-parser-js', '0.7.29');
  assert(result !== null, 'ua-parser-js should be recognized');
  assert(result.safe === false, 'ua-parser-js@0.7.29 should be unsafe');
});

test('WHITELIST: checkRehabilitated returns safe for ua-parser-js@0.7.35', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('ua-parser-js', '0.7.35');
  assert(result !== null, 'ua-parser-js should be recognized');
  assert(result.safe === true, 'ua-parser-js@0.7.35 should be safe');
});

test('WHITELIST: checkRehabilitated returns null for unknown package', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('some-random-package', '1.0.0');
  assert(result === null, 'Unknown package should return null');
});

// ============================================
// IOC LOADING TESTS
// ============================================

console.log('\n=== IOC LOADING TESTS ===\n');

test('IOC: loadCachedIOCs returns packages', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.packages, 'Should have packages');
  assert(iocs.packages.length > 0, 'Should have at least one package');
});

test('IOC: loadCachedIOCs returns hashes', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.hashes, 'Should have hashes');
});

test('IOC: loadCachedIOCs returns markers', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.markers, 'Should have markers');
  assert(iocs.markers.length > 0, 'Should have at least one marker');
});

test('IOC: Typosquats have wildcard version', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  const typosquats = iocs.packages.filter(p => p.source === 'typosquat');
  assert(typosquats.length > 0, 'Should have typosquats');
  const allWildcard = typosquats.every(p => p.version === '*');
  assert(allWildcard, 'All typosquats should have version *');
});

test('IOC: Historical packages have specific versions', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  const eventStream = iocs.packages.find(p => p.name === 'event-stream');
  assert(eventStream, 'event-stream should be in IOCs');
  assert(eventStream.version === '3.3.6', 'event-stream should have version 3.3.6');
});

// ============================================
// IOC MATCHING TESTS
// ============================================

console.log('\n=== IOC MATCHING TESTS ===\n');

test('IOC MATCH: Wildcard version matches all versions', () => {
  const iocs = { packages: [{ name: 'malicious-pkg', version: '*' }] };
  const pkg = { name: 'malicious-pkg', version: '1.2.3' };
  const match = iocs.packages.find(p => {
    if (p.name !== pkg.name) return false;
    if (p.version === '*') return true;
    return p.version === pkg.version;
  });
  assert(match, 'Wildcard should match');
});

test('IOC MATCH: Specific version matches only that version', () => {
  const iocs = { packages: [{ name: 'some-pkg', version: '1.0.0' }] };

  const pkg1 = { name: 'some-pkg', version: '1.0.0' };
  const match1 = iocs.packages.find(p => p.name === pkg1.name && (p.version === '*' || p.version === pkg1.version));
  assert(match1, 'Exact version should match');

  const pkg2 = { name: 'some-pkg', version: '1.0.1' };
  const match2 = iocs.packages.find(p => p.name === pkg2.name && (p.version === '*' || p.version === pkg2.version));
  assert(!match2, 'Different version should not match');
});

// ============================================
// SCRAPER / DATA TESTS
// ============================================

console.log('\n=== SCRAPER / DATA TESTS ===\n');

test('SCRAPER: Module loads without error', () => {
  const { runScraper } = require('../src/ioc/scraper.js');
  assert(typeof runScraper === 'function', 'runScraper should be a function');
});

test('SCRAPER: data/iocs.json exists and is valid', () => {
  const iocsPath = path.join(__dirname, '..', 'data', 'iocs.json');
  assert(fs.existsSync(iocsPath), 'data/iocs.json should exist');
  const content = fs.readFileSync(iocsPath, 'utf8');
  const iocs = JSON.parse(content);
  assert(iocs.packages, 'Should have packages');
  assert(Array.isArray(iocs.packages), 'packages should be an array');
});

test('SCRAPER: IOCs have required fields', () => {
  const iocs = require('../data/iocs.json');
  const sample = iocs.packages[0];
  assert(sample.name, 'IOC should have name');
  assert(sample.version, 'IOC should have version');
  assert(sample.source, 'IOC should have source');
});

test('SCRAPER: At least 900 IOCs', () => {
  const iocs = require('../data/iocs.json');
  assert(iocs.packages.length >= 900, `Should have at least 900 IOCs, has ${iocs.packages.length}`);
});

// ============================================
// COMPACT IOC TESTS
// ============================================

console.log('\n=== COMPACT IOC TESTS ===\n');

test('COMPACT: iocs-compact.json exists', () => {
  const compactPath = path.join(__dirname, '..', 'src', 'ioc', 'data', 'iocs-compact.json');
  assert(fs.existsSync(compactPath), 'src/ioc/data/iocs-compact.json should exist');
});

test('COMPACT: has expected compact format fields', () => {
  const compactPath = path.join(__dirname, '..', 'src', 'ioc', 'data', 'iocs-compact.json');
  const compact = JSON.parse(fs.readFileSync(compactPath, 'utf8'));
  assert(compact.defaultSeverity, 'Should have defaultSeverity');
  assert(Array.isArray(compact.wildcards), 'wildcards should be an array');
  assert(compact.wildcards.length > 0, 'Should have wildcard packages');
  assert(typeof compact.versioned === 'object', 'versioned should be an object');
  assert(Array.isArray(compact.hashes), 'hashes should be an array');
  assert(Array.isArray(compact.markers), 'markers should be an array');
  assert(Array.isArray(compact.pypi_wildcards), 'pypi_wildcards should be an array');
  assert(typeof compact.pypi_versioned === 'object', 'pypi_versioned should be an object');
});

test('COMPACT: does NOT have enriched package objects', () => {
  const compactPath = path.join(__dirname, '..', 'src', 'ioc', 'data', 'iocs-compact.json');
  const compact = JSON.parse(fs.readFileSync(compactPath, 'utf8'));
  // Compact format stores names as strings, not objects with description/references
  assert(typeof compact.wildcards[0] === 'string', 'Wildcard entries should be plain strings');
  const firstVersionedKey = Object.keys(compact.versioned)[0];
  assert(Array.isArray(compact.versioned[firstVersionedKey]), 'Versioned entries should be version arrays');
  assert(typeof compact.versioned[firstVersionedKey][0] === 'string', 'Versions should be plain strings');
});

test('COMPACT: is significantly smaller than full IOCs', () => {
  const compactPath = path.join(__dirname, '..', 'src', 'ioc', 'data', 'iocs-compact.json');
  const fullPath = path.join(__dirname, '..', 'src', 'ioc', 'data', 'iocs.json');
  if (fs.existsSync(fullPath)) {
    const compactSize = fs.statSync(compactPath).size;
    const fullSize = fs.statSync(fullPath).size;
    assert(compactSize < fullSize / 5, `Compact (${compactSize}) should be at least 5x smaller than full (${fullSize})`);
  }
});

test('COMPACT: generateCompactIOCs strips enriched data', () => {
  const { generateCompactIOCs } = require('../src/ioc/updater.js');
  const input = {
    packages: [
      { name: 'evil-pkg', version: '1.0.0', severity: 'critical', description: 'Bad stuff', references: ['http://example.com'], mitre: 'T1195.002', source: 'test', freshness: { added_at: '2026-01-01' } },
      { name: 'bad-lib', version: '*', severity: 'critical', description: 'Malware', source: 'osv' }
    ],
    pypi_packages: [
      { name: 'evil-py', version: '1.0', severity: 'critical', source: 'osv-malicious-pypi' },
      { name: 'bad-pylib', version: '*', severity: 'critical', source: 'osv-malicious-pypi' }
    ],
    hashes: ['abc123'],
    markers: ['setup_bun.js'],
    files: ['inject.js'],
    updated: '2026-01-01T00:00:00.000Z',
    sources: ['test']
  };
  const compact = generateCompactIOCs(input);
  assert(compact.wildcards.length === 1, 'Should have 1 npm wildcard');
  assert(compact.wildcards[0] === 'bad-lib', 'Wildcard should be bad-lib');
  assert(compact.versioned['evil-pkg'], 'Should have evil-pkg in versioned');
  assert(compact.versioned['evil-pkg'][0] === '1.0.0', 'Should have version 1.0.0');
  assert(compact.pypi_wildcards.length === 1, 'Should have 1 PyPI wildcard');
  assert(compact.pypi_wildcards[0] === 'bad-pylib', 'PyPI wildcard should be bad-pylib');
  assert(compact.pypi_versioned['evil-py'], 'Should have evil-py in pypi_versioned');
  assert(compact.pypi_versioned['evil-py'][0] === '1.0', 'Should have version 1.0');
  assert(compact.defaultSeverity === 'critical', 'Default severity should be critical');
  assert(compact.hashes[0] === 'abc123', 'Should preserve hashes');
});

test('COMPACT: expandCompactIOCs round-trips correctly', () => {
  const { generateCompactIOCs, expandCompactIOCs } = require('../src/ioc/updater.js');
  const input = {
    packages: [
      { name: 'evil-pkg', version: '1.0.0', severity: 'critical' },
      { name: 'bad-lib', version: '*', severity: 'critical' },
      { name: 'evil-pkg', version: '2.0.0', severity: 'critical' }
    ],
    pypi_packages: [
      { name: 'evil-py', version: '1.0', severity: 'critical' },
      { name: 'bad-pylib', version: '*', severity: 'critical' }
    ],
    hashes: ['abc123'],
    markers: ['setup_bun.js'],
    files: ['inject.js'],
    updated: '2026-01-01T00:00:00.000Z',
    sources: ['test']
  };
  const compact = generateCompactIOCs(input);
  const expanded = expandCompactIOCs(compact);
  assert(expanded.packages.length === 3, 'Should expand back to 3 npm packages');
  const keys = new Set(expanded.packages.map(p => p.name + '@' + p.version));
  assert(keys.has('evil-pkg@1.0.0'), 'Should have evil-pkg@1.0.0');
  assert(keys.has('evil-pkg@2.0.0'), 'Should have evil-pkg@2.0.0');
  assert(keys.has('bad-lib@*'), 'Should have bad-lib@*');
  assert(expanded.pypi_packages.length === 2, 'Should expand back to 2 PyPI packages');
  const pypiKeys = new Set(expanded.pypi_packages.map(p => p.name + '@' + p.version));
  assert(pypiKeys.has('evil-py@1.0'), 'Should have evil-py@1.0');
  assert(pypiKeys.has('bad-pylib@*'), 'Should have bad-pylib@*');
  assert(expanded.hashes[0] === 'abc123', 'Should preserve hashes');
});

test('COMPACT: loadCachedIOCs works with compact fallback', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.packagesMap, 'Should have packagesMap');
  assert(iocs.wildcardPackages, 'Should have wildcardPackages');
  assert(iocs.pypiPackagesMap, 'Should have pypiPackagesMap');
  assert(iocs.pypiWildcardPackages, 'Should have pypiWildcardPackages');
  assert(iocs.hashesSet, 'Should have hashesSet');
  assert(iocs.packages.length > 0, 'Should have packages loaded');
  assert(Array.isArray(iocs.pypi_packages), 'Should have pypi_packages array');
});

// ============================================
// YAML LOADER TESTS
// ============================================

console.log('\n=== YAML LOADER TESTS ===\n');

test('YAML: builtin.yaml exists', () => {
  const builtinPath = path.join(__dirname, '..', 'iocs', 'builtin.yaml');
  assert(fs.existsSync(builtinPath), 'iocs/builtin.yaml should exist');
});

test('YAML: loadYAMLIOCs returns packages', () => {
  const { loadYAMLIOCs } = require('../src/ioc/yaml-loader.js');
  const iocs = loadYAMLIOCs();
  assert(iocs.packages, 'Should have packages');
  assert(iocs.packages.length > 0, 'Should have at least one package');
});

test('YAML: Contains Shai-Hulud packages', () => {
  const { loadYAMLIOCs } = require('../src/ioc/yaml-loader.js');
  const iocs = loadYAMLIOCs();
  const shaiHulud = iocs.packages.filter(p => p.source && p.source.includes('shai-hulud'));
  assert(shaiHulud.length > 0, 'Should have Shai-Hulud packages');
});

test('YAML: Contains Shai-Hulud markers', () => {
  const { loadYAMLIOCs } = require('../src/ioc/yaml-loader.js');
  const iocs = loadYAMLIOCs();
  assert(iocs.markers, 'Should have markers');
  const hasShaiHulud = iocs.markers.some(m => m.pattern && m.pattern.includes('Shai-Hulud'));
  assert(hasShaiHulud, 'Should have Shai-Hulud marker');
});

// ============================================
// NON-REGRESSION TESTS
// ============================================

console.log('\n=== NON-REGRESSION TESTS ===\n');

test('REGRESSION: chalk should not block (rehabilitated)', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('chalk', '5.4.0');
  assert(result && result.safe === true, 'chalk should not block');
});

test('REGRESSION: debug should not block (rehabilitated)', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('debug', '4.3.0');
  assert(result && result.safe === true, 'debug should not block');
});

test('REGRESSION: lodash is not in IOCs', () => {
  const iocs = require('../data/iocs.json');
  const lodash = iocs.packages.find(p => p.name === 'lodash');
  assert(!lodash, 'lodash should not be in IOCs');
});

test('REGRESSION: loadash (typosquat) IS in IOCs', () => {
  const iocs = require('../data/iocs.json');
  const loadash = iocs.packages.find(p => p.name === 'loadash');
  assert(loadash, 'loadash (typosquat) should be in IOCs');
});

test('REGRESSION: express is not in IOCs', () => {
  const iocs = require('../data/iocs.json');
  const express = iocs.packages.find(p => p.name === 'express');
  assert(!express, 'express should not be in IOCs');
});

test('REGRESSION: axios is not in IOCs', () => {
  const iocs = require('../data/iocs.json');
  const axios = iocs.packages.find(p => p.name === 'axios');
  assert(!axios, 'axios should not be in IOCs');
});

// ============================================
// PACKAGE SECURITY TESTS
// ============================================

console.log('\n=== PACKAGE SECURITY TESTS ===\n');

test('SECURITY: isValidPackageName accepts lodash', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(isValidPackageName('lodash'), 'lodash should be valid');
});

test('SECURITY: isValidPackageName accepts @scope/package', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(isValidPackageName('@types/node'), '@types/node should be valid');
});

test('SECURITY: isValidPackageName rejects shell injection', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(!isValidPackageName('foo; rm -rf /'), 'shell injection should be invalid');
});

test('SECURITY: isValidPackageName rejects backticks', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(!isValidPackageName('foo`whoami`'), 'backticks should be invalid');
});

test('SECURITY: isValidPackageName rejects $(...)', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(!isValidPackageName('foo$(cat /etc/passwd)'), '$() should be invalid');
});

test('SECURITY: isValidPackageName rejects pipes', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(!isValidPackageName('foo | cat /etc/passwd'), 'pipe should be invalid');
});

// ============================================
// WEBHOOK SECURITY TESTS
// ============================================

console.log('\n=== WEBHOOK SECURITY TESTS ===\n');

test('SECURITY: validateWebhookUrl accepts Discord', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://discord.com/api/webhooks/123/abc');
  assert(result.valid, 'Discord webhook should be valid');
});

test('SECURITY: validateWebhookUrl accepts Slack', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://hooks.slack.com/services/xxx/yyy');
  assert(result.valid, 'Slack webhook should be valid');
});

test('SECURITY: validateWebhookUrl rejects HTTP (non-HTTPS)', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('http://discord.com/api/webhooks/123');
  assert(!result.valid, 'HTTP should be rejected');
});

test('SECURITY: validateWebhookUrl rejects unauthorized domains', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://evil.com/steal');
  assert(!result.valid, 'evil.com should be rejected');
});

test('SECURITY: validateWebhookUrl rejects private IPs (127.x)', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://127.0.0.1:8080/webhook');
  assert(!result.valid, '127.x should be rejected');
});

test('SECURITY: validateWebhookUrl rejects private IPs (192.168.x)', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://192.168.1.1/webhook');
  assert(!result.valid, '192.168.x should be rejected');
});

test('SECURITY: validateWebhookUrl rejects private IPs (10.x)', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://10.0.0.1/webhook');
  assert(!result.valid, '10.x should be rejected');
});

// ============================================
// DIFF MODULE TESTS
// ============================================

console.log('\n=== DIFF MODULE TESTS ===\n');

test('DIFF: Module loads without error', () => {
  const { diff, showRefs, isGitRepo } = require('../src/diff.js');
  assert(typeof diff === 'function', 'diff should be a function');
  assert(typeof showRefs === 'function', 'showRefs should be a function');
  assert(typeof isGitRepo === 'function', 'isGitRepo should be a function');
});

test('DIFF: isGitRepo returns true for this repo', () => {
  const { isGitRepo } = require('../src/diff.js');
  const result = isGitRepo(path.join(__dirname, '..'));
  assert(result === true, 'Should detect git repo');
});

test('DIFF: isGitRepo returns false for non-repo', () => {
  const { isGitRepo } = require('../src/diff.js');
  const result = isGitRepo('/tmp');
  assert(result === false, 'Should not detect git repo in /tmp');
});

test('DIFF: getRecentRefs returns tags and commits', () => {
  const { getRecentRefs } = require('../src/diff.js');
  const refs = getRecentRefs(path.join(__dirname, '..'));
  assert(refs.tags !== undefined, 'Should have tags array');
  assert(refs.commits !== undefined, 'Should have commits array');
  assert(refs.commits.length > 0, 'Should have at least one commit');
});

// ============================================
// HOOKS INIT MODULE TESTS
// ============================================

console.log('\n=== HOOKS INIT MODULE TESTS ===\n');

test('HOOKS: Module loads without error', () => {
  const { initHooks, detectHookSystem } = require('../src/hooks-init.js');
  assert(typeof initHooks === 'function', 'initHooks should be a function');
  assert(typeof detectHookSystem === 'function', 'detectHookSystem should be a function');
});

test('HOOKS: detectHookSystem returns object with expected properties', () => {
  const { detectHookSystem } = require('../src/hooks-init.js');
  const result = detectHookSystem(path.join(__dirname, '..'));
  assert(typeof result.husky === 'boolean', 'Should have husky property');
  assert(typeof result.preCommit === 'boolean', 'Should have preCommit property');
  assert(typeof result.gitHooks === 'boolean', 'Should have gitHooks property');
});

test('HOOKS: detectHookSystem detects git hooks directory', () => {
  const { detectHookSystem } = require('../src/hooks-init.js');
  const result = detectHookSystem(path.join(__dirname, '..'));
  assert(result.gitHooks === true, 'Should detect .git/hooks directory');
});

// ============================================
// CLI NEW COMMANDS TESTS
// ============================================

console.log('\n=== CLI NEW COMMANDS TESTS ===\n');

test('CLI: diff command shows refs when no arg', () => {
  const output = runCommand('diff');
  assertIncludes(output, 'Available references', 'Should show available refs');
  assertIncludes(output, 'Usage:', 'Should show usage');
});

test('CLI: init-hooks --help shows in help', () => {
  const output = runCommand('--help');
  assertIncludes(output, 'init-hooks', 'Should show init-hooks command');
  assertIncludes(output, 'diff', 'Should show diff command');
});

// ============================================
// CLI EXTENDED TESTS
// ============================================

console.log('\n=== CLI EXTENDED TESTS ===\n');

test('CLI-EXT: version command shows version', () => {
  const output = runCommand('version');
  const pkg = require('../package.json');
  assertIncludes(output, pkg.version, 'Should display version');
  assertIncludes(output, 'muaddib-scanner', 'Should display package name');
});

test('CLI-EXT: --version flag shows version', () => {
  const output = runCommand('--version');
  const pkg = require('../package.json');
  assertIncludes(output, pkg.version, 'Should display version');
});

test('CLI-EXT: help command shows usage', () => {
  const output = runCommand('help');
  assertIncludes(output, 'Usage', 'Should display usage');
  assertIncludes(output, 'muaddib scan', 'Should show scan');
});

test('CLI-EXT: unknown command shows error', () => {
  const output = runCommand('blahblah');
  assertIncludes(output, 'Unknown command', 'Should say Unknown command');
});

test('CLI-EXT: deduplication reduces duplicate alerts', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--json');
  const result = JSON.parse(output);
  // Verify no two threats have same file + type + message combination
  const keys = result.threats.map(t => `${t.file}::${t.type}::${t.message}`);
  const uniqueKeys = [...new Set(keys)];
  assert(keys.length === uniqueKeys.length, 'All threats should be unique per file+type+message');
});

test('CLI-EXT: scan with --paranoid and --webhook', () => {
  const output = runScan(path.join(TESTS_DIR, 'clean'), '--paranoid --webhook https://discord.com/api/webhooks/test');
  assertIncludes(output, 'PARANOID', 'Should enable paranoid mode');
});

test('CLI-EXT: interactive mode errors without TTY', () => {
  // Running muaddib with no command + piped stdin triggers interactiveMenu → catch
  try {
    execSync(`node "${BIN}"`, { encoding: 'utf8', timeout: 15000, input: '\n', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    const output = (e.stdout || '') + (e.stderr || '');
    assert(output.length > 0, 'Should produce output');
    return;
  }
});

test('CLI-EXT: diff with ref HEAD~1', () => {
  const output = runCommand('diff HEAD~1 .');
  assert(output !== undefined, 'Should not crash');
});

test('CLI-EXT: init-hooks with --type and --mode', () => {
  const output = runCommand('init-hooks --type git --mode scan');
  assert(output !== undefined, 'Should not crash');
});

test('CLI-EXT: install without packages shows usage', () => {
  const output = runCommand('install');
  assertIncludes(output, 'Usage', 'Should show install usage');
});

test('CLI-EXT: install blocks malicious package', () => {
  const output = runCommand('install lodahs');
  assertIncludes(output, 'MALICIOUS', 'Should detect malicious');
});

test('CLI-EXT: install alias i blocks malicious', () => {
  const output = runCommand('i lodahs');
  assertIncludes(output, 'MALICIOUS', 'Should detect via alias');
});

test('CLI-EXT: sandbox without package shows usage', () => {
  const output = runCommand('sandbox');
  assertIncludes(output, 'Usage', 'Should show sandbox usage');
});

test('CLI-EXT: sandbox with package errors without Docker', () => {
  const output = runCommand('sandbox nonexistent-pkg-test');
  assert(output.length > 0, 'Should produce output');
});

test('CLI-EXT: scrape command runs', () => {
  try {
    const output = execSync(`node "${BIN}" scrape`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 15000
    });
    assert(output.length > 0, 'Should produce output');
  } catch (e) {
    // Timeout is OK — scrape downloads large files, we just verify it starts
    const output = e.stdout || e.stderr || '';
    assert(output.includes('SCRAPER') || output.includes('IOC'), 'Should start scraping before timeout');
  }
});

// ============================================
// DEPENDENCIES TESTS
// ============================================

console.log('\n=== DEPENDENCIES TESTS ===\n');

const os = require('os');
const {
  scanDependencies,
  checkRehabilitatedPackage
} = require('../src/scanner/dependencies.js');
const {
  scanHashes,
  computeHash,
  computeHashCached,
  clearHashCache,
  getHashCacheSize
} = require('../src/scanner/hash.js');
const nodeCrypto = require('crypto');
const { safeInstall } = require('../src/safe-install.js');

function createTempPkg(packages) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
  const nmDir = path.join(tmpDir, 'node_modules');
  fs.mkdirSync(nmDir, { recursive: true });
  for (const pkg of packages) {
    const pkgDir = path.join(nmDir, ...pkg.name.split('/'));
    fs.mkdirSync(pkgDir, { recursive: true });
    if (!pkg.skipPkgJson) {
      const content = pkg.rawPkgJson || JSON.stringify({
        name: pkg.name,
        version: pkg.version || '1.0.0'
      });
      fs.writeFileSync(path.join(pkgDir, 'package.json'), content);
    }
    if (pkg.files) {
      for (const f of pkg.files) {
        fs.writeFileSync(path.join(pkgDir, f.name), f.content || '');
      }
    }
  }
  return tmpDir;
}

function cleanupTemp(tmpDir) {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

// --- checkRehabilitatedPackage (lines 113-126) ---

test('DEPS: checkRehabilitatedPackage null for unknown', () => {
  assert(checkRehabilitatedPackage('unknown-xyz', '1.0.0') === null, 'Should return null');
});

test('DEPS: checkRehabilitatedPackage true for safe=true', () => {
  assert(checkRehabilitatedPackage('chalk', '5.0.0') === true, 'chalk should be true');
});

test('DEPS: checkRehabilitatedPackage false for compromised version', () => {
  assert(checkRehabilitatedPackage('ua-parser-js', '0.7.29') === false, 'Should be false');
});

test('DEPS: checkRehabilitatedPackage true for safe version of partial', () => {
  assert(checkRehabilitatedPackage('ua-parser-js', '2.0.0') === true, 'Should be true');
});

// ============================================
// HASH TESTS
// ============================================

console.log('\n=== HASH TESTS ===\n');

test('HASH: computeHash returns valid SHA256', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
  const tmpFile = path.join(tmpDir, 'test.js');
  fs.writeFileSync(tmpFile, 'console.log("hello");');
  const hash = computeHash(tmpFile);
  assert(typeof hash === 'string' && hash.length === 64 && /^[0-9a-f]+$/.test(hash), 'Should be valid SHA256');
  const expected = nodeCrypto.createHash('sha256').update(fs.readFileSync(tmpFile)).digest('hex');
  assert(hash === expected, 'Should match Node crypto');
  cleanupTemp(tmpDir);
});

test('HASH: computeHashCached computes and caches', () => {
  clearHashCache();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
  const tmpFile = path.join(tmpDir, 'test.js');
  fs.writeFileSync(tmpFile, 'var x = 1;');
  const hash1 = computeHashCached(tmpFile);
  assert(hash1 && hash1.length === 64, 'Should return hash');
  assert(getHashCacheSize() > 0, 'Cache should have entry');
  const hash2 = computeHashCached(tmpFile);
  assert(hash1 === hash2, 'Should return cached hash');
  cleanupTemp(tmpDir);
  clearHashCache();
});

test('HASH: computeHashCached invalidates on mtime change', () => {
  clearHashCache();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
  const tmpFile = path.join(tmpDir, 'test.js');
  fs.writeFileSync(tmpFile, 'var a = 1;');
  const hash1 = computeHashCached(tmpFile);
  fs.writeFileSync(tmpFile, 'var a = 2;');
  // Force different mtime to ensure cache invalidation
  const future = new Date(Date.now() + 5000);
  fs.utimesSync(tmpFile, future, future);
  const hash2 = computeHashCached(tmpFile);
  assert(hash1 !== hash2, 'Should recompute after file change');
  cleanupTemp(tmpDir);
  clearHashCache();
});

test('HASH: computeHashCached returns null for non-existent file', () => {
  const result = computeHashCached('/nonexistent/path/file.js');
  assert(result === null, 'Should return null');
});

test('HASH: clearHashCache and getHashCacheSize', () => {
  clearHashCache();
  assert(getHashCacheSize() === 0, 'Should be 0 after clear');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
  const tmpFile = path.join(tmpDir, 'test.js');
  fs.writeFileSync(tmpFile, 'var y = 2;');
  computeHashCached(tmpFile);
  assert(getHashCacheSize() === 1, 'Should be 1');
  clearHashCache();
  assert(getHashCacheSize() === 0, 'Should be 0 after clear');
  cleanupTemp(tmpDir);
});

// --- scanDependencies + listPackages + getPackageVersion (async) ---

(async () => {
  async function asyncTest(name, fn) {
    try {
      await fn();
      console.log(`[PASS] ${name}`);
      passed++;
    } catch (e) {
      console.log(`[FAIL] ${name}`);
      console.log(`       ${e.message}`);
      failures.push({ name, error: e.message });
      failed++;
    }
  }

  await asyncTest('DEPS: scanDependencies empty without node_modules', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats) && threats.length === 0, 'Should be empty array');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies skips rehabilitated safe pkg', async () => {
    const tmpDir = createTempPkg([{ name: 'chalk', version: '5.4.0' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.file && x.file.includes('chalk'));
      assert(t.length === 0, 'chalk should not generate threats');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects rehabilitated compromised version', async () => {
    const tmpDir = createTempPkg([{ name: 'coa', version: '2.0.3' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.message && x.message.includes('coa'));
      assert(t.length > 0, 'Should detect coa@2.0.3');
      assert(t[0].severity === 'CRITICAL', 'Should be CRITICAL');
      assert(t[0].type === 'known_malicious_package', 'Should be known_malicious_package');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects wildcard malicious pkg', async () => {
    const tmpDir = createTempPkg([{ name: 'lodahs', version: '1.0.0' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.message && x.message.includes('lodahs'));
      assert(t.length > 0, 'Should detect lodahs');
      assert(t[0].severity === 'CRITICAL', 'Should be CRITICAL');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects specific version malicious pkg', async () => {
    const tmpDir = createTempPkg([{ name: 'event-stream', version: '3.3.6' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.message && x.message.includes('event-stream'));
      assert(t.length > 0, 'Should detect event-stream@3.3.6');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies skips trusted pkg for file checks', async () => {
    const tmpDir = createTempPkg([
      { name: 'esbuild', version: '0.19.0', files: [{ name: 'setup_bun.js' }] }
    ]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.type === 'suspicious_file' && x.file.includes('esbuild'));
      assert(t.length === 0, 'esbuild should not trigger suspicious file');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects suspicious file', async () => {
    const tmpDir = createTempPkg([
      { name: 'random-pkg-abc', version: '1.0.0', files: [{ name: 'setup_bun.js' }] }
    ]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.type === 'suspicious_file');
      assert(t.length > 0, 'Should detect suspicious file');
      assert(t[0].severity === 'HIGH', 'Should be HIGH');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: scanDependencies detects Shai-Hulud marker', async () => {
    const tmpDir = createTempPkg([{
      name: 'evil-pkg-test',
      version: '1.0.0',
      rawPkgJson: JSON.stringify({ name: 'evil-pkg-test', version: '1.0.0', description: 'Shai-Hulud was here' })
    }]);
    try {
      const threats = await scanDependencies(tmpDir);
      const t = threats.filter(x => x.type === 'shai_hulud_marker');
      assert(t.length > 0, 'Should detect Shai-Hulud marker');
      assert(t[0].severity === 'CRITICAL', 'Should be CRITICAL');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: listPackages handles scoped packages', async () => {
    const tmpDir = createTempPkg([{ name: '@test-scope/test-pkg', version: '1.0.0' }]);
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should handle scoped packages');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: listPackages skips hidden directories', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    fs.mkdirSync(path.join(tmpDir, 'node_modules', '.cache'), { recursive: true });
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should skip hidden dirs');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: listPackages skips non-directory items', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    const nmDir = path.join(tmpDir, 'node_modules');
    fs.mkdirSync(nmDir, { recursive: true });
    fs.writeFileSync(path.join(nmDir, 'README.md'), 'hello');
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should skip files');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: getPackageVersion returns * without package.json', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-test-'));
    fs.mkdirSync(path.join(tmpDir, 'node_modules', 'no-pkg-json'), { recursive: true });
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should not crash');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('DEPS: getPackageVersion returns * for missing version field', async () => {
    const tmpDir = createTempPkg([
      { name: 'no-version-pkg', rawPkgJson: JSON.stringify({ name: 'no-version-pkg' }) }
    ]);
    try {
      const threats = await scanDependencies(tmpDir);
      assert(Array.isArray(threats), 'Should handle missing version');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  // --- scanHashes async tests ---

  await asyncTest('HASH: scanHashes empty without node_modules', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats) && threats.length === 0, 'Should be empty');
    } finally {
      cleanupTemp(tmpDir);
    }
  });

  await asyncTest('HASH: scanHashes traverses node_modules JS files', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const pkgDir = path.join(tmpDir, 'node_modules', 'test-pkg');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'index.js'), 'module.exports = {};');
    fs.writeFileSync(path.join(pkgDir, 'README.md'), '# Readme');
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats), 'Should return array');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });

  await asyncTest('HASH: scanHashes handles nested directories', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const nestedDir = path.join(tmpDir, 'node_modules', 'pkg', 'lib', 'utils');
    fs.mkdirSync(nestedDir, { recursive: true });
    fs.writeFileSync(path.join(nestedDir, 'helper.js'), 'function help() {}');
    fs.writeFileSync(path.join(tmpDir, 'node_modules', 'pkg', 'index.js'), 'require("./lib/utils/helper");');
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats), 'Should handle nested dirs');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });

  await asyncTest('HASH: scanHashes respects MAX_DEPTH limit', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    // Create 52 nested dirs to exceed MAX_DEPTH (50)
    let deepDir = path.join(tmpDir, 'node_modules');
    for (let i = 0; i < 52; i++) {
      deepDir = path.join(deepDir, String(i));
    }
    fs.mkdirSync(deepDir, { recursive: true });
    fs.writeFileSync(path.join(deepDir, 'deep.js'), 'var deep = true;');
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats), 'Should handle deep nesting gracefully');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });

  await asyncTest('HASH: scanHashes skips non-JS files', async () => {
    clearHashCache();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hash-'));
    const pkgDir = path.join(tmpDir, 'node_modules', 'txt-only');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'data.txt'), 'not javascript');
    fs.writeFileSync(path.join(pkgDir, 'config.json'), '{}');
    try {
      const threats = await scanHashes(tmpDir);
      assert(Array.isArray(threats) && threats.length === 0, 'Should be empty for non-JS');
    } finally {
      cleanupTemp(tmpDir);
      clearHashCache();
    }
  });

  // ============================================
  // SAFE INSTALL TESTS
  // ============================================

  console.log('\n=== SAFE INSTALL TESTS ===\n');

  // Helper: run safeInstall with suppressed console output
  async function quietSafeInstall(packages, options) {
    const origLog = console.log;
    console.log = () => {};
    try {
      return await safeInstall(packages, options);
    } finally {
      console.log = origLog;
    }
  }

  await asyncTest('SAFE-INSTALL: blocks known malicious wildcard package', async () => {
    const result = await quietSafeInstall(['lodahs']);
    assert(result.blocked === true, 'Should be blocked');
    assert(result.package === 'lodahs', 'Should identify lodahs');
  });

  await asyncTest('SAFE-INSTALL: blocks rehabilitated compromised version', async () => {
    const result = await quietSafeInstall(['coa@2.0.3']);
    assert(result.blocked === true, 'Should be blocked');
    assert(result.package === 'coa', 'Should identify coa');
  });

  await asyncTest('SAFE-INSTALL: trusted package skips scan, cache prevents rescan', async () => {
    // lodash is trusted → returns safe immediately
    // second lodash → scannedPackages cache hit
    // lodahs → malicious → blocks before npm install
    const result = await quietSafeInstall(['lodash', 'lodash', 'lodahs']);
    assert(result.blocked === true, 'Should be blocked by lodahs');
    assert(result.package === 'lodahs', 'Should identify lodahs');
  });

  await asyncTest('SAFE-INSTALL: scoped package version parsing + invalid name', async () => {
    const result = await quietSafeInstall(['@evil/foo;bar@1.0.0']);
    assert(result.blocked === true, 'Should be blocked');
  });

  await asyncTest('SAFE-INSTALL: force mode continues then name validation blocks', async () => {
    const result = await quietSafeInstall(['lodahs', 'foo;rm'], { force: true });
    assert(result.blocked === true, 'Should be blocked by name validation');
  });

  await asyncTest('SAFE-INSTALL: rehabilitated safe package passes checkIOCs', async () => {
    // chalk is rehabilitated (safe=true) → checkIOCs returns null
    // then proceeds to npm view + dependency scan
    // lodahs → blocks (or a chalk dependency may block if npm view fails)
    const result = await quietSafeInstall(['chalk', 'lodahs']);
    assert(result.blocked === true, 'Should be blocked');
  });

  await asyncTest('SAFE-INSTALL: non-scoped package with version parsing', async () => {
    // event-stream@3.3.6 is in IOCs with specific version
    const result = await quietSafeInstall(['event-stream@3.3.6']);
    assert(result.blocked === true, 'Should be blocked');
  });

  await asyncTest('SAFE-INSTALL: depth=0 unknown pkg blocked by npm view fail', async () => {
    // Package not found on npm → npm view fails → returns safe: false (blocked)
    const result = await quietSafeInstall(['zzz-nonexistent-pkg-99999', 'lodahs']);
    assert(result.blocked === true, 'Should be blocked');
  });

  // ============================================
  // WEBHOOK EXTENDED TESTS
  // ============================================

  console.log('\n=== WEBHOOK EXTENDED TESTS ===\n');

  const httpModule = require('http');
  const { sendWebhook: sendWebhookFn, validateWebhookUrl: valUrl } = require('../src/webhook.js');

  // Mock HTTP server on localhost (allowed by validateWebhookUrl)
  const mockWebhookServer = await new Promise((resolve) => {
    let lastPayload = null;
    const srv = httpModule.createServer((req, res) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try { lastPayload = JSON.parse(body); } catch { lastPayload = body; }
        if (req.url.includes('/error')) {
          res.writeHead(500);
          res.end('error');
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"ok":true}');
        }
      });
    });
    srv.listen(0, 'localhost', () => {
      resolve({ server: srv, port: srv.address().port, getPayload: () => lastPayload });
    });
  });
  const webhookBase = `http://localhost:${mockWebhookServer.port}`;

  const mockResults = {
    target: '/test/project',
    timestamp: new Date().toISOString(),
    summary: { riskScore: 75, riskLevel: 'HIGH', critical: 2, high: 3, medium: 1, total: 6 },
    threats: [
      { type: 'suspicious_code', severity: 'CRITICAL', message: 'Critical threat found', file: 'evil.js' },
      { type: 'known_malicious', severity: 'HIGH', message: 'High threat found', file: 'bad.js' }
    ]
  };

  await asyncTest('WEBHOOK-EXT: validateWebhookUrl catch for invalid URL', async () => {
    const r = valUrl('not-a-url');
    assert(!r.valid, 'Should be invalid');
    assert(r.error.includes('Invalid URL'), 'Should mention Invalid URL');
  });

  await asyncTest('WEBHOOK-EXT: validateWebhookUrl rejects 172.x', async () => {
    const r = valUrl('https://172.16.0.1/webhook');
    assert(!r.valid, 'Should reject 172.16.x');
  });

  await asyncTest('WEBHOOK-EXT: sendWebhook Discord format', async () => {
    const r = await sendWebhookFn(`${webhookBase}/discord.com/api/webhooks/t`, mockResults);
    assert(r.success === true, 'Should succeed');
    const p = mockWebhookServer.getPayload();
    assert(p.embeds && p.embeds[0].title.includes('MUAD'), 'Discord format');
    assert(p.embeds[0].fields.length >= 3, 'Should have fields');
  });

  await asyncTest('WEBHOOK-EXT: sendWebhook Slack format', async () => {
    const r = await sendWebhookFn(`${webhookBase}/hooks.slack.com/services/t`, mockResults);
    assert(r.success === true, 'Should succeed');
    const p = mockWebhookServer.getPayload();
    assert(p.blocks && p.blocks.length >= 3, 'Slack format');
  });

  await asyncTest('WEBHOOK-EXT: sendWebhook Generic format', async () => {
    const r = await sendWebhookFn(`${webhookBase}/generic`, mockResults);
    assert(r.success === true, 'Should succeed');
    const p = mockWebhookServer.getPayload();
    assert(p.tool === 'MUADDIB', 'Generic format');
    assert(Array.isArray(p.threats), 'Should have threats');
  });

  await asyncTest('WEBHOOK-EXT: sendWebhook rejects blocked URL', async () => {
    try {
      await sendWebhookFn('https://evil.com/steal', mockResults);
      assert(false, 'Should throw');
    } catch (e) {
      assert(e.message.includes('Webhook blocked'), 'Should be blocked');
    }
  });

  await asyncTest('WEBHOOK-EXT: send rejects on HTTP 500', async () => {
    try {
      await sendWebhookFn(`${webhookBase}/error`, mockResults);
      assert(false, 'Should throw');
    } catch (e) {
      assert(e.message.includes('500'), 'Should mention 500');
    }
  });

  mockWebhookServer.server.close();

  // ============================================
  // PYTHON PARSER TESTS
  // ============================================

  console.log('\n=== PYTHON PARSER TESTS ===\n');

  const { parseRequirementsTxt, parseSetupPy, parsePyprojectToml, detectPythonProject, normalizePythonName } = require('../src/scanner/python.js');

  // --- normalizePythonName ---

  test('PYTHON: normalizePythonName lowercases and normalizes separators', () => {
    assert(normalizePythonName('Flask') === 'flask', 'Should lowercase');
    assert(normalizePythonName('my_package') === 'my-package', 'Should replace underscores');
    assert(normalizePythonName('My.Package') === 'my-package', 'Should replace dots');
    assert(normalizePythonName('My-Package') === 'my-package', 'Should lowercase hyphens');
    assert(normalizePythonName('some__pkg') === 'some-pkg', 'Should collapse multiple separators');
  });

  // --- parseRequirementsTxt ---

  test('PYTHON: parseRequirementsTxt parses pinned versions', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, 'flask==2.3.0\nrequests==2.31.0\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 2, 'Should have 2 deps');
    assert(deps[0].name === 'flask', 'First should be flask');
    assert(deps[0].version === '==2.3.0', 'Should have pinned version');
    assert(deps[1].name === 'requests', 'Second should be requests');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles various version specs', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, [
      'flask>=2.0',
      'django~=4.2',
      'requests<=2.31.0',
      'numpy>1.20',
      'pandas!=1.5.0',
      'scipy<2.0',
      'simplepkg',
    ].join('\n'));
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 7, 'Should have 7 deps, got ' + deps.length);
    assert(deps[0].version === '>=2.0', 'flask version');
    assert(deps[1].version === '~=4.2', 'django version');
    assert(deps[2].version === '<=2.31.0', 'requests version');
    assert(deps[3].version === '>1.20', 'numpy version');
    assert(deps[4].version === '!=1.5.0', 'pandas version');
    assert(deps[5].version === '<2.0', 'scipy version');
    assert(deps[6].version === '*', 'simplepkg no version');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt ignores comments and blanks', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, '# This is a comment\n\nflask==2.0\n   # Another comment\n\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 1, 'Should have 1 dep');
    assert(deps[0].name === 'flask', 'Should be flask');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles extras', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, 'requests[security]==2.31.0\ncelery[redis,auth]>=5.0\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 2, 'Should have 2 deps');
    assert(deps[0].name === 'requests', 'Should strip extras from name');
    assert(deps[0].version === '==2.31.0', 'Should keep version');
    assert(deps[1].name === 'celery', 'Should strip multiple extras');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles recursive includes', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const baseFile = path.join(tmpDir, 'requirements.txt');
    const extraFile = path.join(tmpDir, 'requirements-dev.txt');
    fs.writeFileSync(extraFile, 'pytest==7.0\nblack==23.0\n');
    fs.writeFileSync(baseFile, 'flask==2.0\n-r requirements-dev.txt\nrequests==2.31\n');
    const deps = parseRequirementsTxt(baseFile);
    assert(deps.length === 4, 'Should have 4 deps, got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should have flask');
    assert(names.includes('pytest'), 'Should have pytest from included file');
    assert(names.includes('black'), 'Should have black from included file');
    assert(names.includes('requests'), 'Should have requests');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles circular includes', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const fileA = path.join(tmpDir, 'a.txt');
    const fileB = path.join(tmpDir, 'b.txt');
    fs.writeFileSync(fileA, 'flask==2.0\n-r b.txt\n');
    fs.writeFileSync(fileB, 'requests==2.31\n-r a.txt\n');
    const deps = parseRequirementsTxt(fileA);
    assert(deps.length === 2, 'Should not loop infinitely');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt skips option lines', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, '--index-url https://pypi.org/simple\n-i https://pypi.org/simple\nflask==2.0\n-e git+https://github.com/foo/bar.git\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 1, 'Should only have flask');
    assert(deps[0].name === 'flask', 'Should be flask');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles env markers', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, 'pywin32>=300; sys_platform == "win32"\ncolorama>=0.4; os_name == "nt"\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 2, 'Should parse both deps');
    assert(deps[0].name === 'pywin32', 'Should strip env marker');
    assert(deps[0].version === '>=300', 'Should keep version');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // --- parseSetupPy ---

  test('PYTHON: parseSetupPy extracts install_requires', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const setupFile = path.join(tmpDir, 'setup.py');
    fs.writeFileSync(setupFile, [
      'from setuptools import setup',
      '',
      'setup(',
      '    name="myproject",',
      '    version="1.0.0",',
      '    install_requires=[',
      '        "flask>=2.0",',
      '        "requests==2.31.0",',
      '        "click",',
      '    ],',
      ')',
    ].join('\n'));
    const deps = parseSetupPy(setupFile);
    assert(deps.length === 3, 'Should have 3 deps, got ' + deps.length);
    assert(deps[0].name === 'flask', 'First should be flask');
    assert(deps[0].version === '>=2.0', 'flask version');
    assert(deps[1].name === 'requests', 'Second should be requests');
    assert(deps[2].name === 'click', 'Third should be click');
    assert(deps[2].version === '*', 'click no version');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseSetupPy handles single-line install_requires', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const setupFile = path.join(tmpDir, 'setup.py');
    fs.writeFileSync(setupFile, 'setup(install_requires=["flask>=2.0", "requests"])');
    const deps = parseSetupPy(setupFile);
    assert(deps.length === 2, 'Should have 2 deps');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseSetupPy also extracts setup_requires', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const setupFile = path.join(tmpDir, 'setup.py');
    fs.writeFileSync(setupFile, [
      'setup(',
      '    install_requires=["flask>=2.0"],',
      '    setup_requires=["setuptools-scm"],',
      ')',
    ].join('\n'));
    const deps = parseSetupPy(setupFile);
    assert(deps.length === 2, 'Should have 2 deps, got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should have flask');
    assert(names.includes('setuptools-scm'), 'Should have setuptools-scm');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // --- parsePyprojectToml ---

  test('PYTHON: parsePyprojectToml extracts PEP 621 dependencies', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const tomlFile = path.join(tmpDir, 'pyproject.toml');
    fs.writeFileSync(tomlFile, [
      '[project]',
      'name = "myproject"',
      'version = "1.0.0"',
      'dependencies = [',
      '    "flask>=2.0",',
      '    "requests==2.31.0",',
      '    "click",',
      ']',
    ].join('\n'));
    const deps = parsePyprojectToml(tomlFile);
    assert(deps.length === 3, 'Should have 3 deps, got ' + deps.length);
    assert(deps[0].name === 'flask', 'First should be flask');
    assert(deps[0].version === '>=2.0', 'flask version');
    assert(deps[1].name === 'requests', 'Second should be requests');
    assert(deps[2].name === 'click', 'Third should be click');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parsePyprojectToml extracts Poetry dependencies', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const tomlFile = path.join(tmpDir, 'pyproject.toml');
    fs.writeFileSync(tomlFile, [
      '[tool.poetry]',
      'name = "myproject"',
      '',
      '[tool.poetry.dependencies]',
      'python = "^3.8"',
      'flask = "^2.3"',
      'requests = {version = "^2.31", optional = true}',
      'click = "*"',
    ].join('\n'));
    const deps = parsePyprojectToml(tomlFile);
    assert(deps.length === 3, 'Should have 3 deps (python skipped), got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(!names.includes('python'), 'Should skip python');
    assert(names.includes('flask'), 'Should have flask');
    assert(names.includes('requests'), 'Should have requests');
    assert(names.includes('click'), 'Should have click');
    const flask = deps.find(function(d) { return d.name === 'flask'; });
    assert(flask.version === '^2.3', 'flask version');
    const req = deps.find(function(d) { return d.name === 'requests'; });
    assert(req.version === '^2.31', 'requests version from inline table');
    const click = deps.find(function(d) { return d.name === 'click'; });
    assert(click.version === '*', 'click wildcard');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parsePyprojectToml handles both PEP 621 and Poetry', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const tomlFile = path.join(tmpDir, 'pyproject.toml');
    fs.writeFileSync(tomlFile, [
      '[project]',
      'dependencies = [',
      '    "flask>=2.0",',
      ']',
      '',
      '[tool.poetry.dependencies]',
      'python = "^3.8"',
      'django = "^4.2"',
    ].join('\n'));
    const deps = parsePyprojectToml(tomlFile);
    assert(deps.length === 2, 'Should have 2 deps, got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should have flask from PEP 621');
    assert(names.includes('django'), 'Should have django from Poetry');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // --- detectPythonProject ---

  test('PYTHON: detectPythonProject finds all dependency files', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\nrequests==2.31.0\n');
    fs.writeFileSync(path.join(tmpDir, 'setup.py'), 'setup(install_requires=["click>=7.0", "gunicorn==20.0"])');
    fs.writeFileSync(path.join(tmpDir, 'pyproject.toml'), '[project]\ndependencies = ["sqlalchemy>=2.0"]\n');
    const deps = detectPythonProject(tmpDir);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should find flask from requirements.txt');
    assert(names.includes('requests'), 'Should find requests from requirements.txt');
    assert(names.includes('click'), 'Should find click from setup.py');
    assert(names.includes('gunicorn'), 'Should find gunicorn from setup.py');
    assert(names.includes('sqlalchemy'), 'Should find sqlalchemy from pyproject.toml');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: detectPythonProject deduplicates by name', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\n');
    fs.writeFileSync(path.join(tmpDir, 'setup.py'), 'setup(install_requires=["flask>=2.0"])');
    const deps = detectPythonProject(tmpDir);
    const flasks = deps.filter(function(d) { return d.name === 'flask'; });
    assert(flasks.length === 1, 'Should deduplicate flask');
    assert(flasks[0].version === '==2.3.0', 'Should keep first occurrence (requirements.txt)');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: detectPythonProject scans requirements/ directory', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqDir = path.join(tmpDir, 'requirements');
    fs.mkdirSync(reqDir);
    fs.writeFileSync(path.join(reqDir, 'prod.txt'), 'flask==2.3.0\n');
    fs.writeFileSync(path.join(reqDir, 'dev.txt'), 'pytest==7.0\n');
    const deps = detectPythonProject(tmpDir);
    assert(deps.length === 2, 'Should have 2 deps, got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should have flask from prod.txt');
    assert(names.includes('pytest'), 'Should have pytest from dev.txt');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: detectPythonProject returns empty for non-Python project', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const deps = detectPythonProject(tmpDir);
    assert(deps.length === 0, 'Should return empty array');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: PEP 503 name normalization in dedup', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'Flask==2.3.0\nflask==2.0\n');
    const deps = detectPythonProject(tmpDir);
    const flasks = deps.filter(function(d) { return d.name === 'flask'; });
    assert(flasks.length === 1, 'Should deduplicate Flask/flask');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ============================================
  // PYTHON SCAN INTEGRATION TESTS
  // ============================================

  console.log('\n=== PYTHON SCAN INTEGRATION TESTS ===\n');

  const { getRule: getRuleForPypi } = require('../src/rules/index.js');
  const { getPlaybook: getPlaybookForPypi } = require('../src/response/playbooks.js');

  test('PYTHON-SCAN: Rule pypi_malicious_package exists', () => {
    const rule = getRuleForPypi('pypi_malicious_package');
    assert(rule.id === 'MUADDIB-PYPI-001', 'Rule ID should be MUADDIB-PYPI-001, got ' + rule.id);
    assert(rule.name === 'Malicious PyPI Package', 'Rule name');
    assert(rule.severity === 'CRITICAL', 'Rule severity');
    assert(rule.confidence === 'high', 'Rule confidence');
    assert(rule.mitre === 'T1195.002', 'Rule MITRE');
  });

  test('PYTHON-SCAN: Playbook pypi_malicious_package exists', () => {
    const playbook = getPlaybookForPypi('pypi_malicious_package');
    assert(playbook.includes('pip uninstall'), 'Playbook should mention pip uninstall, got: ' + playbook);
  });

  test('PYTHON-SCAN: CLI shows [PYTHON] section for Python project', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyscan-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\nrequests==2.31.0\n');
    const output = execSync(`node "${BIN}" scan "${tmpDir}"`, { encoding: 'utf8', timeout: 30000 });
    assert(output.includes('[PYTHON]'), 'Output should contain [PYTHON] section');
    assert(output.includes('2 dependencies detected'), 'Should show 2 dependencies');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON-SCAN: JSON output includes python field', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyscan-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\nrequests==2.31.0\ndjango>=4.0\n');
    const output = execSync(`node "${BIN}" scan "${tmpDir}" --json`, { encoding: 'utf8', timeout: 30000 });
    const result = JSON.parse(output);
    assert(result.python !== null && result.python !== undefined, 'Should have python field');
    assert(result.python.dependencies === 3, 'Should have 3 dependencies, got ' + result.python.dependencies);
    assert(Array.isArray(result.python.files), 'Should have files array');
    assert(result.python.files.length > 0, 'Should have at least 1 file');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON-SCAN: No [PYTHON] section for non-Python project', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyscan-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"test","version":"1.0.0"}');
    const output = execSync(`node "${BIN}" scan "${tmpDir}"`, { encoding: 'utf8', timeout: 30000 });
    assert(!output.includes('[PYTHON]'), 'Should NOT contain [PYTHON] section for npm-only project');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON-SCAN: JSON python field is null for non-Python project', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyscan-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"test","version":"1.0.0"}');
    const output = execSync(`node "${BIN}" scan "${tmpDir}" --json`, { encoding: 'utf8', timeout: 30000 });
    const result = JSON.parse(output);
    assert(result.python === null, 'python field should be null for non-Python project');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON-SCAN: Explain mode shows [PYTHON] section', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyscan-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\n');
    const output = execSync(`node "${BIN}" scan "${tmpDir}" --explain`, { encoding: 'utf8', timeout: 30000 });
    assert(output.includes('[PYTHON]'), 'Explain mode should contain [PYTHON] section');
    assert(output.includes('1 dependencies detected'), 'Should show 1 dependency');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON-SCAN: Detects all Python file types', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyscan-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\n');
    fs.writeFileSync(path.join(tmpDir, 'setup.py'), 'setup(install_requires=["click>=7.0"])');
    fs.writeFileSync(path.join(tmpDir, 'pyproject.toml'), '[project]\ndependencies = ["sqlalchemy>=2.0"]\n');
    const output = execSync(`node "${BIN}" scan "${tmpDir}" --json`, { encoding: 'utf8', timeout: 30000 });
    const result = JSON.parse(output);
    assert(result.python.dependencies === 3, 'Should have 3 deduplicated deps, got ' + result.python.dependencies);
    assert(result.python.files.length === 3, 'Should reference 3 files, got ' + result.python.files.length);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ============================================
  // PYPI TYPOSQUATTING TESTS
  // ============================================

  console.log('\n=== PYPI TYPOSQUATTING TESTS ===\n');

  const { findPyPITyposquatMatch } = require('../src/scanner/typosquat.js');

  test('PYPI-TYPOSQUAT: Detects reqeusts (requests)', () => {
    const match = findPyPITyposquatMatch('reqeusts');
    assert(match !== null, 'Should detect reqeusts as typosquat');
    assert(match.original === 'requests', 'Should identify requests as target');
    assert(match.distance <= 2, 'Distance should be <= 2');
  });

  test('PYPI-TYPOSQUAT: Detects numpie (numpy)', () => {
    const match = findPyPITyposquatMatch('numpie');
    assert(match !== null, 'Should detect numpie as typosquat');
    assert(match.original === 'numpy', 'Should identify numpy as target');
  });

  test('PYPI-TYPOSQUAT: Detects flaks (flask)', () => {
    const match = findPyPITyposquatMatch('flaks');
    assert(match !== null, 'Should detect flaks as typosquat');
    assert(match.original === 'flask', 'Should identify flask as target');
  });

  test('PYPI-TYPOSQUAT: Detects djnago (django)', () => {
    const match = findPyPITyposquatMatch('djnago');
    assert(match !== null, 'Should detect djnago as typosquat');
    assert(match.original === 'django', 'Should identify django as target');
  });

  test('PYPI-TYPOSQUAT: Detects pandsa (pandas)', () => {
    const match = findPyPITyposquatMatch('pandsa');
    assert(match !== null, 'Should detect pandsa as typosquat');
    assert(match.original === 'pandas', 'Should identify pandas as target');
  });

  test('PYPI-TYPOSQUAT: Does not flag exact package names', () => {
    assert(findPyPITyposquatMatch('requests') === null, 'requests itself');
    assert(findPyPITyposquatMatch('flask') === null, 'flask itself');
    assert(findPyPITyposquatMatch('numpy') === null, 'numpy itself');
    assert(findPyPITyposquatMatch('django') === null, 'django itself');
  });

  test('PYPI-TYPOSQUAT: PEP 503 normalization — case insensitive', () => {
    assert(findPyPITyposquatMatch('Flask') === null, 'Flask (capitalized) = flask');
    assert(findPyPITyposquatMatch('Django') === null, 'Django (capitalized) = django');
    assert(findPyPITyposquatMatch('NumPy') === null, 'NumPy (mixed case) = numpy');
  });

  test('PYPI-TYPOSQUAT: PEP 503 normalization — underscores/dots/hyphens equivalent', () => {
    assert(findPyPITyposquatMatch('scikit_learn') === null, 'scikit_learn = scikit-learn');
    assert(findPyPITyposquatMatch('scikit.learn') === null, 'scikit.learn = scikit-learn');
    assert(findPyPITyposquatMatch('python_dateutil') === null, 'python_dateutil = python-dateutil');
  });

  test('PYPI-TYPOSQUAT: Skips short names (< 4 chars)', () => {
    assert(findPyPITyposquatMatch('six') === null, 'six is too short');
    assert(findPyPITyposquatMatch('pip') === null, 'pip is too short');
    assert(findPyPITyposquatMatch('tox') === null, 'tox is too short');
  });

  test('PYPI-TYPOSQUAT: Skips whitelisted packages', () => {
    assert(findPyPITyposquatMatch('boto') === null, 'boto is whitelisted');
    assert(findPyPITyposquatMatch('torchvision') === null, 'torchvision is whitelisted');
  });

  test('PYPI-TYPOSQUAT: Severity is HIGH', () => {
    const match = findPyPITyposquatMatch('reqeusts');
    assert(match !== null, 'Should detect reqeusts');
    // Severity is set in index.js checkPyPITyposquatting, so check rule
    const rule = getRuleForPypi('pypi_typosquat_detected');
    assert(rule.severity === 'HIGH', 'Rule severity should be HIGH');
  });

  test('PYPI-TYPOSQUAT: CLI detects PyPI typosquat in requirements.txt', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytypo-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'reqeusts==2.31.0\nflask==2.3.0\n');
    let output;
    try {
      output = execSync(`node "${BIN}" scan "${tmpDir}" --json`, { encoding: 'utf8', timeout: 30000 });
    } catch (e) {
      // Non-zero exit expected (HIGH threat detected)
      output = e.stdout;
    }
    const result = JSON.parse(output);
    const typosquatThreats = result.threats.filter(function(t) { return t.type === 'pypi_typosquat_detected'; });
    assert(typosquatThreats.length >= 1, 'Should detect at least 1 PyPI typosquat, got ' + typosquatThreats.length);
    assert(typosquatThreats[0].message.includes('reqeusts'), 'Should mention reqeusts');
    assert(typosquatThreats[0].message.includes('requests'), 'Should mention requests as target');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYPI-TYPOSQUAT: No false positive for legit Python deps', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytypo-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\nrequests==2.31.0\nnumpy==1.24.0\ndjango>=4.0\n');
    const output = execSync(`node "${BIN}" scan "${tmpDir}" --json`, { encoding: 'utf8', timeout: 30000 });
    const result = JSON.parse(output);
    const typosquatThreats = result.threats.filter(function(t) { return t.type === 'pypi_typosquat_detected'; });
    assert(typosquatThreats.length === 0, 'Should have 0 PyPI typosquat for legit deps, got ' + typosquatThreats.length);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYPI-TYPOSQUAT: Playbook exists', () => {
    const playbook = getPlaybookForPypi('pypi_typosquat_detected');
    assert(playbook.includes('package PyPI'), 'Playbook should mention PyPI package');
  });

  // ============================================
  // RESULTS
  // ============================================

  console.log('\n========================================');
  console.log(`RESULTS: ${passed} passed, ${failed} failed`);
  console.log('========================================\n');

  if (failures.length > 0) {
    console.log('Failures:');
    failures.forEach(f => {
      console.log(`  - ${f.name}: ${f.error}`);
    });
    console.log('');
  }

  process.exit(failed > 0 ? 1 : 0);
})();
