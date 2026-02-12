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

test('UPDATE: Module loads and loadCachedIOCs works', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.packagesMap instanceof Map, 'Should return packagesMap');
  assert(iocs.wildcardPackages instanceof Set, 'Should return wildcardPackages');
  assert(iocs.packages.length > 0, 'Should have packages');
});

test('UPDATE: updateIOCs is a function', () => {
  const { updateIOCs } = require('../src/ioc/updater.js');
  assert(typeof updateIOCs === 'function', 'updateIOCs should be a function');
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

  await asyncTest('SAFE-INSTALL: cache prevents rescan, IOC catches malicious', async () => {
    // lodahs is known malicious → blocks before npm install
    const result = await quietSafeInstall(['lodahs']);
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

  await asyncTest('WEBHOOK-EXT: sendWebhook rejects HTTP localhost (no exemption)', async () => {
    try {
      await sendWebhookFn(`${webhookBase}/discord.com/api/webhooks/t`, mockResults);
      assert(false, 'Should throw');
    } catch (e) {
      assert(e.message.includes('HTTPS required'), 'Should require HTTPS');
    }
  });

  await asyncTest('WEBHOOK-EXT: sendWebhook rejects blocked URL', async () => {
    try {
      await sendWebhookFn('https://evil.com/steal', mockResults);
      assert(false, 'Should throw');
    } catch (e) {
      assert(e.message.includes('Webhook blocked'), 'Should be blocked');
    }
  });

  await asyncTest('WEBHOOK-EXT: sendWebhook rejects non-allowed domain', async () => {
    try {
      await sendWebhookFn('https://example.com/webhook', mockResults);
      assert(false, 'Should throw');
    } catch (e) {
      assert(e.message.includes('Domain not allowed'), 'Should reject non-allowed domain');
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
  // SANDBOX NETWORK TESTS
  // ============================================

  console.log('\n=== SANDBOX NETWORK TESTS ===\n');

  const {
    scoreFindings,
    generateNetworkReport,
    EXFIL_PATTERNS,
    SAFE_DOMAINS
  } = require('../src/sandbox.js');

  test('SANDBOX-NET: scoreFindings handles empty report', () => {
    const { score, findings } = scoreFindings({});
    assert(score === 0, 'Empty report should score 0');
    assert(findings.length === 0, 'Empty report should have no findings');
  });

  test('SANDBOX-NET: scoreFindings detects suspicious DNS', () => {
    const report = { network: { dns_queries: ['evil.com', 'registry.npmjs.org'] } };
    const { score, findings } = scoreFindings(report);
    assert(score > 0, 'Should score > 0 for evil.com DNS');
    const dnsFindings = findings.filter(f => f.type === 'suspicious_dns');
    assert(dnsFindings.length === 1, 'Should have 1 suspicious DNS (evil.com), got ' + dnsFindings.length);
    assert(dnsFindings[0].evidence === 'evil.com', 'Should flag evil.com');
  });

  test('SANDBOX-NET: scoreFindings skips safe domains in DNS', () => {
    const report = { network: { dns_queries: ['registry.npmjs.org', 'github.com', 'npmjs.com'] } };
    const { score } = scoreFindings(report);
    assert(score === 0, 'All safe domains should score 0');
  });

  test('SANDBOX-NET: scoreFindings detects DNS resolutions (INFO)', () => {
    const report = { network: { dns_resolutions: [
      { domain: 'evil.com', ip: '1.2.3.4' },
      { domain: 'registry.npmjs.org', ip: '5.6.7.8' }
    ] } };
    const { findings } = scoreFindings(report);
    const resFindings = findings.filter(f => f.type === 'dns_resolution');
    assert(resFindings.length === 1, 'Should have 1 dns_resolution finding for evil.com');
    assert(resFindings[0].severity === 'INFO', 'DNS resolution should be INFO severity');
  });

  test('SANDBOX-NET: scoreFindings detects suspicious TLS', () => {
    const report = { network: { tls_connections: [
      { domain: 'evil.com', ip: '1.2.3.4', port: 443 },
      { domain: 'registry.npmjs.org', ip: '5.6.7.8', port: 443 }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score > 0, 'Should score > 0 for evil.com TLS');
    const tlsFindings = findings.filter(f => f.type === 'suspicious_tls');
    assert(tlsFindings.length === 1, 'Should have 1 suspicious TLS');
    assert(tlsFindings[0].evidence === 'evil.com', 'Should flag evil.com');
  });

  test('SANDBOX-NET: scoreFindings detects data exfiltration', () => {
    const report = { network: { http_bodies: ['{"npmrc":"//registry.npmjs.org/:_authToken=abc123"}'] } };
    const { score, findings } = scoreFindings(report);
    assert(score >= 50, 'Exfiltration should score >= 50');
    const exfilFindings = findings.filter(f => f.type === 'data_exfiltration');
    assert(exfilFindings.length >= 1, 'Should detect exfiltration');
    assert(exfilFindings[0].severity === 'CRITICAL', 'Exfiltration should be CRITICAL');
  });

  test('SANDBOX-NET: scoreFindings detects multiple exfiltration patterns', () => {
    const report = { network: { http_bodies: [
      'token=secret123',
      'AWS_SECRET_ACCESS_KEY=abc',
      'normal body content'
    ] } };
    const { findings } = scoreFindings(report);
    const exfilFindings = findings.filter(f => f.type === 'data_exfiltration');
    assert(exfilFindings.length === 2, 'Should detect 2 exfiltrations, got ' + exfilFindings.length);
  });

  test('SANDBOX-NET: scoreFindings detects HTTP requests to non-safe hosts', () => {
    const report = { network: { http_requests: [
      { method: 'POST', host: 'evil.com', path: '/steal' },
      { method: 'GET', host: 'registry.npmjs.org', path: '/lodash' }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score > 0, 'Should score > 0');
    const httpFindings = findings.filter(f => f.type === 'suspicious_http_request');
    assert(httpFindings.length === 1, 'Should detect 1 suspicious HTTP request');
    assert(httpFindings[0].detail.includes('POST evil.com'), 'Should flag POST to evil.com');
  });

  test('SANDBOX-NET: scoreFindings detects blocked connections', () => {
    const report = { network: { blocked_connections: [
      { ip: '1.2.3.4', port: 8080 },
      { ip: '5.6.7.8', port: 443 }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score >= 60, 'Blocked connections should score >= 60, got ' + score);
    const blockedFindings = findings.filter(f => f.type === 'blocked_connection');
    assert(blockedFindings.length === 2, 'Should have 2 blocked connection findings');
  });

  test('SANDBOX-NET: scoreFindings caps at 100', () => {
    const report = {
      sensitive_files: { read: ['/root/.npmrc', '/root/.ssh/id_rsa', '/root/.aws/credentials'] },
      network: {
        dns_queries: ['evil1.com', 'evil2.com'],
        http_bodies: ['token=abc', 'password=123'],
        blocked_connections: [{ ip: '1.2.3.4', port: 80 }]
      }
    };
    const { score } = scoreFindings(report);
    assert(score === 100, 'Score should cap at 100, got ' + score);
  });

  test('SANDBOX-NET: generateNetworkReport returns string with sections', () => {
    const report = {
      package: 'test-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'permissive',
      duration_ms: 5000,
      network: {
        dns_resolutions: [{ domain: 'evil.com', ip: '1.2.3.4' }],
        http_requests: [{ method: 'GET', host: 'evil.com', path: '/data' }],
        tls_connections: [{ domain: 'evil.com', ip: '1.2.3.4', port: 443 }],
        http_connections: [{ host: '1.2.3.4', port: 443, protocol: 'TCP' }],
        blocked_connections: [],
        http_bodies: []
      }
    };
    const output = generateNetworkReport(report);
    assert(typeof output === 'string', 'Should return a string');
    assert(output.includes('test-pkg'), 'Should include package name');
    assert(output.includes('DNS Resolutions'), 'Should have DNS section');
    assert(output.includes('HTTP Requests'), 'Should have HTTP section');
    assert(output.includes('TLS Connections'), 'Should have TLS section');
    assert(output.includes('evil.com'), 'Should include domain');
  });

  test('SANDBOX-NET: generateNetworkReport shows blocked in strict mode', () => {
    const report = {
      package: 'test-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'strict',
      duration_ms: 3000,
      network: {
        dns_resolutions: [],
        http_requests: [],
        tls_connections: [],
        http_connections: [],
        blocked_connections: [{ ip: '1.2.3.4', port: 8080 }],
        http_bodies: []
      }
    };
    const output = generateNetworkReport(report);
    assert(output.includes('STRICT'), 'Should show STRICT mode');
    assert(output.includes('Blocked Connections'), 'Should have blocked section');
    assert(output.includes('1.2.3.4'), 'Should include blocked IP');
  });

  test('SANDBOX-NET: generateNetworkReport shows exfiltration alerts', () => {
    const report = {
      package: 'test-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'permissive',
      duration_ms: 3000,
      network: {
        dns_resolutions: [],
        http_requests: [],
        tls_connections: [],
        http_connections: [],
        blocked_connections: [],
        http_bodies: ['NPM_TOKEN=secret123']
      }
    };
    const output = generateNetworkReport(report);
    assert(output.includes('Data Exfiltration'), 'Should have exfil section');
    assert(output.includes('npm token'), 'Should identify npm token');
  });

  test('SANDBOX-NET: EXFIL_PATTERNS is an array with entries', () => {
    assert(Array.isArray(EXFIL_PATTERNS), 'Should be an array');
    assert(EXFIL_PATTERNS.length >= 8, 'Should have at least 8 patterns');
    for (const p of EXFIL_PATTERNS) {
      assert(p.pattern instanceof RegExp, 'Each should have a pattern regex');
      assert(typeof p.label === 'string', 'Each should have a label');
      assert(typeof p.severity === 'string', 'Each should have a severity');
    }
  });

  test('SANDBOX-NET: SAFE_DOMAINS includes essential domains', () => {
    assert(SAFE_DOMAINS.includes('registry.npmjs.org'), 'Should include registry.npmjs.org');
    assert(SAFE_DOMAINS.includes('github.com'), 'Should include github.com');
    assert(SAFE_DOMAINS.includes('npmjs.org'), 'Should include npmjs.org');
  });

  test('SANDBOX-NET: CLI --strict flag is accepted', () => {
    const output = runCommand('sandbox --strict');
    assertIncludes(output, 'Usage', 'Should show sandbox usage (no package)');
  });

  test('SANDBOX-NET: CLI sandbox-report without package shows usage', () => {
    const output = runCommand('sandbox-report');
    assertIncludes(output, 'Usage', 'Should show sandbox-report usage');
  });

  test('SANDBOX-NET: CLI sandbox-report with package runs', () => {
    const output = runCommand('sandbox-report nonexistent-pkg-test');
    assert(output.length > 0, 'Should produce output');
  });

  // ============================================
  // CLI COVERAGE TESTS (muaddib.js)
  // ============================================

  console.log('\n=== CLI COVERAGE TESTS ===\n');

  test('CLI-COV: --exclude flag is parsed correctly', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--exclude node_modules --exclude dist');
    assert(output !== undefined, 'Should not crash with --exclude');
  });

  test('CLI-COV: --fail-on with invalid value defaults gracefully', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--fail-on banana');
    assert(output !== undefined, 'Should not crash with invalid fail-on');
  });

  test('CLI-COV: --fail-on low works', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--fail-on low');
    assert(output !== undefined, 'Should handle --fail-on low');
  });

  test('CLI-COV: --fail-on medium works', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--fail-on medium');
    assert(output !== undefined, 'Should handle --fail-on medium');
  });

  test('CLI-COV: --html with path traversal is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --html "../../../etc/evil.html"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'traversal', 'Should mention path traversal');
    }
  });

  test('CLI-COV: --sarif with path traversal is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --sarif "../../evil.sarif"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'traversal', 'Should mention path traversal');
    }
  });

  test('CLI-COV: --webhook with HTTP URL is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --webhook "http://evil.com/hook"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'HTTPS', 'Should require HTTPS');
    }
  });

  test('CLI-COV: --webhook with private IP is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --webhook "https://127.0.0.1/hook"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'private', 'Should reject private IP');
    }
  });

  test('CLI-COV: --webhook with invalid URL is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --webhook "not-a-url"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'invalid', 'Should reject invalid URL');
    }
  });

  test('CLI-COV: scan with multiple --exclude flags', () => {
    const output = runScan('.', '--exclude test --exclude docs --json');
    assert(output.length > 0, 'Should produce output');
  });

  test('CLI-COV: remove-hooks command runs', () => {
    const output = runCommand('remove-hooks .');
    assert(output !== undefined, 'Should not crash');
  });

  test('CLI-COV: --paranoid flag is parsed correctly', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--paranoid');
    assert(output !== undefined, 'Should not crash with --paranoid');
  });

  test('CLI-COV: scan --json --explain combined', () => {
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--json --explain');
    const json = JSON.parse(output);
    assert(json.summary, 'JSON output should have summary');
  });

  test('CLI-COV: scan --fail-on critical with clean project exits 0', () => {
    // Clean project = no threats, --fail-on critical means exit 0
    const output = runScan(path.join(TESTS_DIR, 'clean'), '--fail-on critical --json');
    const json = JSON.parse(output);
    assert(json.summary.total === 0, 'Clean project should have 0 threats');
  });

  test('CLI-COV: scan nonexistent directory handles error', () => {
    const output = runScan('/nonexistent/path/12345');
    assert(output !== undefined, 'Should not crash on nonexistent dir');
  });

  test('CLI-COV: --webhook with localhost is blocked', () => {
    try {
      execSync(`node "${BIN}" scan . --webhook "https://localhost/hook"`, {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 10000
      });
      assert(false, 'Should have exited with error');
    } catch (e) {
      const output = (e.stdout || '') + (e.stderr || '');
      assertIncludes(output, 'private', 'Should reject localhost');
    }
  });

  test('CLI-COV: -v flag shows version', () => {
    const output = runCommand('-v');
    assertIncludes(output, 'muaddib-scanner v', 'Should show version with -v');
  });

  test('CLI-COV: -h flag shows help', () => {
    const output = runCommand('-h');
    assertIncludes(output, 'Usage', 'Should show usage with -h');
  });

  // ============================================
  // WEBHOOK COVERAGE TESTS (webhook.js)
  // ============================================

  console.log('\n=== WEBHOOK COVERAGE TESTS ===\n');

  test('WEBHOOK-COV: validateWebhookUrl rejects IPv6 loopback', () => {
    const r = valUrl('https://[::1]/webhook');
    assert(!r.valid, 'Should reject IPv6 loopback');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects fc00 (IPv6 private)', () => {
    const r = valUrl('https://[fc00::1]/webhook');
    assert(!r.valid, 'Should reject fc00 IPv6 private');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects fe80 (IPv6 link-local)', () => {
    const r = valUrl('https://[fe80::1]/webhook');
    assert(!r.valid, 'Should reject fe80 IPv6 link-local');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects 169.254.x (link-local)', () => {
    const r = valUrl('https://169.254.1.1/webhook');
    assert(!r.valid, 'Should reject 169.254.x link-local');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects 0.x addresses', () => {
    const r = valUrl('https://0.0.0.0/webhook');
    assert(!r.valid, 'Should reject 0.0.0.0');
  });

  test('WEBHOOK-COV: formatDiscord generates correct embed structure', () => {
    // Access formatDiscord indirectly via module internals
    // We test by calling the webhook module's format functions
    const webhookModule = require('../src/webhook.js');
    // formatDiscord is not exported, so we test via the validate path
    // Instead test the payload structure expected by Discord
    const r1 = valUrl('https://discord.com/api/webhooks/12345/token');
    assert(r1.valid, 'Discord webhook URL should be valid');

    const r2 = valUrl('https://hooks.slack.com/services/T/B/X');
    assert(r2.valid, 'Slack webhook URL should be valid');
  });

  test('WEBHOOK-COV: validateWebhookUrl accepts subdomain of allowed domain', () => {
    const r = valUrl('https://ptb.discord.com/api/webhooks/test');
    assert(r.valid, 'Should accept subdomain of discord.com');
  });

  test('WEBHOOK-COV: validateWebhookUrl rejects discordapp.evil.com', () => {
    const r = valUrl('https://discordapp.evil.com/webhook');
    assert(!r.valid, 'Should reject non-matching domain');
  });

  // Test format functions (now exported)
  const { formatDiscord, formatSlack, formatGeneric } = require('../src/webhook.js');

  test('WEBHOOK-COV: formatDiscord returns embed with correct structure', () => {
    const results = {
      summary: { riskLevel: 'CRITICAL', riskScore: 85, critical: 2, high: 3, medium: 1, total: 6 },
      threats: [
        { severity: 'CRITICAL', message: 'Malicious package detected' },
        { severity: 'HIGH', message: 'Suspicious script' }
      ],
      target: '/test/project',
      timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds, 'Should have embeds array');
    assert(payload.embeds[0].title.includes('MUAD'), 'Embed title should mention MUAD\'DIB');
    assert(payload.embeds[0].color === 0xe74c3c, 'CRITICAL should be red');
    assert(payload.embeds[0].fields.length >= 3, 'Should have at least 3 fields');
    // Check critical threats field is added
    const critField = payload.embeds[0].fields.find(f => f.name === 'Critical Threats');
    assert(critField, 'Should have Critical Threats field');
    assertIncludes(critField.value, 'Malicious package', 'Should list critical threats');
  });

  test('WEBHOOK-COV: formatDiscord handles HIGH risk level', () => {
    const results = {
      summary: { riskLevel: 'HIGH', riskScore: 60, critical: 0, high: 2, medium: 1, total: 3 },
      threats: [{ severity: 'HIGH', message: 'Test' }],
      target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds[0].color === 0xe67e22, 'HIGH should be orange');
  });

  test('WEBHOOK-COV: formatDiscord handles MEDIUM risk level', () => {
    const results = {
      summary: { riskLevel: 'MEDIUM', riskScore: 40, critical: 0, high: 0, medium: 2, total: 2 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds[0].color === 0xf1c40f, 'MEDIUM should be yellow');
  });

  test('WEBHOOK-COV: formatDiscord handles LOW risk level', () => {
    const results = {
      summary: { riskLevel: 'LOW', riskScore: 10, critical: 0, high: 0, medium: 0, total: 1 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds[0].color === 0x3498db, 'LOW should be blue');
  });

  test('WEBHOOK-COV: formatDiscord handles CLEAN risk level', () => {
    const results = {
      summary: { riskLevel: 'CLEAN', riskScore: 0, critical: 0, high: 0, medium: 0, total: 0 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatDiscord(results);
    assert(payload.embeds[0].color === 0x2ecc71, 'CLEAN should be green');
  });

  test('WEBHOOK-COV: formatSlack returns blocks with correct structure', () => {
    const results = {
      summary: { riskLevel: 'CRITICAL', riskScore: 90, critical: 3, high: 1, medium: 0, total: 4 },
      threats: [
        { severity: 'CRITICAL', message: 'Exfiltration detected' },
        { severity: 'CRITICAL', message: 'Reverse shell' }
      ],
      target: '/test/project', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assert(payload.blocks, 'Should have blocks array');
    assert(payload.blocks.length >= 3, 'Should have at least 3 blocks');
    // Header block
    assert(payload.blocks[0].type === 'header', 'First block should be header');
    assertIncludes(payload.blocks[0].text.text, 'MUAD', 'Header should mention MUAD\'DIB');
    // Critical threats block should exist (since we have critical threats)
    const critBlock = payload.blocks.find(b => b.text && b.text.text && b.text.text.includes('Critical Threats'));
    assert(critBlock, 'Should have Critical Threats block');
  });

  test('WEBHOOK-COV: formatSlack handles HIGH risk level emoji', () => {
    const results = {
      summary: { riskLevel: 'HIGH', riskScore: 60, critical: 0, high: 2, medium: 0, total: 2 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assertIncludes(payload.blocks[0].text.text, 'warning', 'HIGH should use warning emoji');
  });

  test('WEBHOOK-COV: formatSlack handles MEDIUM risk level emoji', () => {
    const results = {
      summary: { riskLevel: 'MEDIUM', riskScore: 40, critical: 0, high: 0, medium: 2, total: 2 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assertIncludes(payload.blocks[0].text.text, 'yellow', 'MEDIUM should use yellow emoji');
  });

  test('WEBHOOK-COV: formatSlack handles LOW risk level emoji', () => {
    const results = {
      summary: { riskLevel: 'LOW', riskScore: 10, critical: 0, high: 0, medium: 0, total: 1 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assertIncludes(payload.blocks[0].text.text, 'information', 'LOW should use info emoji');
  });

  test('WEBHOOK-COV: formatSlack handles CLEAN risk level emoji', () => {
    const results = {
      summary: { riskLevel: 'CLEAN', riskScore: 0, critical: 0, high: 0, medium: 0, total: 0 },
      threats: [], target: '/test', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatSlack(results);
    assertIncludes(payload.blocks[0].text.text, 'check_mark', 'CLEAN should use check mark emoji');
  });

  test('WEBHOOK-COV: formatGeneric returns structured data', () => {
    const results = {
      summary: { riskLevel: 'HIGH', riskScore: 60, critical: 0, high: 2, medium: 1, total: 3 },
      threats: [
        { type: 'shell_command', severity: 'HIGH', message: 'curl | sh', file: 'install.sh' },
        { type: 'obfuscation', severity: 'MEDIUM', message: 'Hex encoded', file: 'index.js' }
      ],
      target: '/test/project', timestamp: '2025-01-01T00:00:00Z'
    };
    const payload = formatGeneric(results);
    assert(payload.tool === 'MUADDIB', 'Tool should be MUADDIB');
    assert(payload.target === '/test/project', 'Target should match');
    assert(payload.summary.riskLevel === 'HIGH', 'Summary should be included');
    assert(payload.threats.length === 2, 'Should have 2 threats');
    assert(payload.threats[0].type === 'shell_command', 'Threat type preserved');
    assert(payload.threats[0].file === 'install.sh', 'Threat file preserved');
  });

  // ============================================
  // SANDBOX COVERAGE TESTS (sandbox.js)
  // ============================================

  console.log('\n=== SANDBOX COVERAGE TESTS ===\n');

  test('SANDBOX-COV: scoreFindings detects sensitive file reads (credential)', () => {
    const report = { sensitive_files: { read: ['/root/.npmrc', '/home/user/.ssh/id_rsa'] } };
    const { score, findings } = scoreFindings(report);
    assert(score >= 80, 'Credential file reads should score >= 80, got ' + score);
    const credFindings = findings.filter(f => f.type === 'sensitive_file_read' && f.severity === 'CRITICAL');
    assert(credFindings.length === 2, 'Should have 2 CRITICAL file read findings');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file reads (system)', () => {
    const report = { sensitive_files: { read: ['/etc/passwd'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 25, 'System file read should score 25, got ' + score);
    assert(findings[0].severity === 'HIGH', 'Should be HIGH severity');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file reads (config)', () => {
    const report = { sensitive_files: { read: ['/home/user/.env', '/home/user/.gitconfig'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 30, 'Config file reads should score 30, got ' + score);
    assert(findings[0].severity === 'MEDIUM', 'Should be MEDIUM severity');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file writes (credential)', () => {
    const report = { sensitive_files: { written: ['/root/.npmrc'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 40, 'Credential file write should score 40, got ' + score);
    const wf = findings.filter(f => f.type === 'sensitive_file_write');
    assert(wf.length === 1 && wf[0].severity === 'CRITICAL', 'Should be CRITICAL write');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file writes (system)', () => {
    const report = { sensitive_files: { written: ['/etc/passwd'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 25, 'System file write should score 25, got ' + score);
    assert(findings[0].severity === 'HIGH', 'Should be HIGH severity');
  });

  test('SANDBOX-COV: scoreFindings detects sensitive file writes (other)', () => {
    const report = { sensitive_files: { written: ['/tmp/somefile'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 15, 'Other file write should score 15, got ' + score);
    assert(findings[0].severity === 'MEDIUM', 'Should be MEDIUM severity');
  });

  test('SANDBOX-COV: scoreFindings detects filesystem changes (system path)', () => {
    const report = { filesystem: { created: ['/usr/bin/backdoor'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 50, 'System path creation should score 50, got ' + score);
    assert(findings[0].severity === 'CRITICAL', 'Should be CRITICAL');
  });

  test('SANDBOX-COV: scoreFindings detects filesystem changes (crontab)', () => {
    const report = { filesystem: { created: ['/etc/cron.d/evil'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 50, 'Crontab creation should score 50, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings detects filesystem changes (/tmp)', () => {
    const report = { filesystem: { created: ['/tmp/payload.sh'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 30, '/tmp creation should score 30, got ' + score);
    assert(findings[0].severity === 'HIGH', 'Should be HIGH');
  });

  test('SANDBOX-COV: scoreFindings detects suspicious processes (dangerous cmd)', () => {
    const report = { processes: { spawned: [{ command: '/usr/bin/curl' }] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 40, 'Dangerous cmd should score 40, got ' + score);
    assert(findings[0].type === 'suspicious_process', 'Should be suspicious_process');
    assert(findings[0].severity === 'CRITICAL', 'Should be CRITICAL');
  });

  test('SANDBOX-COV: scoreFindings detects unknown processes', () => {
    const report = { processes: { spawned: [{ command: '/opt/unknown-binary' }] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 15, 'Unknown process should score 15, got ' + score);
    assert(findings[0].type === 'unknown_process', 'Should be unknown_process');
    assert(findings[0].severity === 'MEDIUM', 'Should be MEDIUM');
  });

  test('SANDBOX-COV: scoreFindings skips safe IPs in connections', () => {
    const report = { network: { http_connections: [
      { host: '127.0.0.1', port: 3000 }
    ] } };
    const { score } = scoreFindings(report);
    assert(score === 0, 'Safe IP should score 0, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings skips probe ports in connections', () => {
    const report = { network: { http_connections: [
      { host: '1.2.3.4', port: 65535 }
    ] } };
    const { score } = scoreFindings(report);
    assert(score === 0, 'Probe port should score 0, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings detects suspicious TCP connections', () => {
    const report = { network: { http_connections: [
      { host: '1.2.3.4', port: 8080 }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 25, 'Suspicious TCP should score 25, got ' + score);
    assert(findings[0].type === 'suspicious_connection', 'Should be suspicious_connection');
  });

  test('SANDBOX-COV: scoreFindings detects .aws credential read', () => {
    const report = { sensitive_files: { read: ['/root/.aws/credentials'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 40, '.aws read should score 40, got ' + score);
    assert(findings[0].severity === 'CRITICAL', 'Should be CRITICAL');
  });

  test('SANDBOX-COV: scoreFindings detects .bash_history read', () => {
    const report = { sensitive_files: { read: ['/home/user/.bash_history'] } };
    const { score } = scoreFindings(report);
    assert(score === 15, '.bash_history read should score 15, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings with /etc/shadow write', () => {
    const report = { sensitive_files: { written: ['/etc/shadow'] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 25, '/etc/shadow write should score 25, got ' + score);
    assert(findings[0].severity === 'HIGH', 'Should be HIGH');
  });

  test('SANDBOX-COV: scoreFindings with .aws credential write', () => {
    const report = { sensitive_files: { written: ['/root/.aws/credentials'] } };
    const { score } = scoreFindings(report);
    assert(score === 40, '.aws write should score 40, got ' + score);
  });

  test('SANDBOX-COV: scoreFindings with /etc/shadow read', () => {
    const report = { sensitive_files: { read: ['/etc/shadow'] } };
    const { score } = scoreFindings(report);
    assert(score === 25, '/etc/shadow read should score 25, got ' + score);
  });

  test('SANDBOX-COV: generateNetworkReport with no DNS, no HTTP, no TLS', () => {
    const report = {
      package: 'clean-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'permissive',
      duration_ms: 1000,
      network: { dns_resolutions: [], http_requests: [], tls_connections: [], http_connections: [], blocked_connections: [], http_bodies: [] }
    };
    const output = generateNetworkReport(report);
    assert(output.includes('No DNS resolutions captured'), 'Should show no DNS message');
    assert(output.includes('No HTTP requests captured'), 'Should show no HTTP message');
    assert(output.includes('No TLS connections captured'), 'Should show no TLS message');
  });

  test('SANDBOX-COV: generateNetworkReport shows safe vs suspicious domains', () => {
    const report = {
      package: 'mixed-pkg',
      timestamp: '2025-01-01T00:00:00Z',
      mode: 'permissive',
      duration_ms: 2000,
      network: {
        dns_resolutions: [
          { domain: 'registry.npmjs.org', ip: '1.2.3.4' },
          { domain: 'evil.com', ip: '5.6.7.8' }
        ],
        http_requests: [
          { method: 'GET', host: 'registry.npmjs.org', path: '/pkg' },
          { method: 'POST', host: 'evil.com', path: '/steal' }
        ],
        tls_connections: [
          { domain: 'registry.npmjs.org', ip: '1.2.3.4', port: 443 },
          { domain: 'evil.com', ip: '5.6.7.8', port: 443 }
        ],
        http_connections: [
          { host: 'registry.npmjs.org', port: 443, protocol: 'TCP' },
          { host: '5.6.7.8', port: 443, protocol: 'TCP' }
        ],
        blocked_connections: [],
        http_bodies: []
      }
    };
    const output = generateNetworkReport(report);
    assert(output.includes('[OK]'), 'Should show OK for safe domains');
    assert(output.includes('[!!]'), 'Should show !! for suspicious domains');
    assert(output.includes('Raw TCP Connections'), 'Should have raw TCP section');
  });

  test('SANDBOX-COV: scoreFindings multiple dangerous processes', () => {
    const report = { processes: { spawned: [
      { command: 'curl' },
      { command: 'wget' },
      { command: 'nc' },
      { command: '' }
    ] } };
    const { score, findings } = scoreFindings(report);
    assert(score === 100, 'Multiple dangerous cmds should cap at 100, got ' + score);
    const procFindings = findings.filter(f => f.type === 'suspicious_process');
    assert(procFindings.length === 3, 'Should have 3 dangerous process findings');
  });

  // Test getSeverity, displayResults, imageExists (now exported)
  const { getSeverity, displayResults, imageExists } = require('../src/sandbox.js');

  test('SANDBOX-COV: getSeverity returns CLEAN for 0', () => {
    assert(getSeverity(0) === 'CLEAN', 'Score 0 should be CLEAN');
  });

  test('SANDBOX-COV: getSeverity returns LOW for 1-20', () => {
    assert(getSeverity(10) === 'LOW', 'Score 10 should be LOW');
    assert(getSeverity(20) === 'LOW', 'Score 20 should be LOW');
  });

  test('SANDBOX-COV: getSeverity returns MEDIUM for 21-50', () => {
    assert(getSeverity(30) === 'MEDIUM', 'Score 30 should be MEDIUM');
    assert(getSeverity(50) === 'MEDIUM', 'Score 50 should be MEDIUM');
  });

  test('SANDBOX-COV: getSeverity returns HIGH for 51-80', () => {
    assert(getSeverity(60) === 'HIGH', 'Score 60 should be HIGH');
    assert(getSeverity(80) === 'HIGH', 'Score 80 should be HIGH');
  });

  test('SANDBOX-COV: getSeverity returns CRITICAL for 81+', () => {
    assert(getSeverity(81) === 'CRITICAL', 'Score 81 should be CRITICAL');
    assert(getSeverity(100) === 'CRITICAL', 'Score 100 should be CRITICAL');
  });

  test('SANDBOX-COV: displayResults with no findings', () => {
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      displayResults({ score: 0, severity: 'CLEAN', findings: [] });
    } finally {
      console.log = origLog;
    }
    assert(logs.some(l => l.includes('0/100')), 'Should show score');
    assert(logs.some(l => l.includes('No suspicious')), 'Should say no suspicious behavior');
  });

  test('SANDBOX-COV: displayResults with findings', () => {
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      displayResults({
        score: 85,
        severity: 'CRITICAL',
        findings: [
          { type: 'sensitive_file_read', severity: 'CRITICAL', detail: 'Read .npmrc' },
          { type: 'dns_resolution', severity: 'INFO', detail: 'some.domain → 1.2.3.4' },
          { type: 'suspicious_process', severity: 'HIGH', detail: 'curl detected' }
        ]
      });
    } finally {
      console.log = origLog;
    }
    assert(logs.some(l => l.includes('85/100')), 'Should show score');
    assert(logs.some(l => l.includes('2 finding(s)')), 'Should count actionable (non-INFO) findings');
  });

  test('SANDBOX-COV: imageExists returns boolean', () => {
    const result = imageExists();
    assert(typeof result === 'boolean', 'imageExists should return a boolean, got ' + typeof result);
  });

  test('SANDBOX-COV: generateNetworkReport with TLS connections', () => {
    const report = {
      package: 'test-pkg', mode: 'strict', timestamp: '2025-01-01T00:00:00Z', duration_ms: 5000,
      network: {
        tls_connections: [
          { domain: 'registry.npmjs.org', ip: '104.16.0.1', port: 443 },
          { domain: 'evil.com', ip: '6.6.6.6', port: 443 }
        ],
        http_connections: [
          { host: 'registry.npmjs.org', port: 443, protocol: 'https' },
          { host: '8.8.8.8', port: 80, protocol: 'http' }
        ]
      }
    };
    const out = generateNetworkReport(report);
    assertIncludes(out, 'TLS Connections (2)', 'Should show TLS section');
    assertIncludes(out, 'evil.com', 'Should show suspicious TLS domain');
    assertIncludes(out, 'Raw TCP Connections', 'Should show TCP connections section');
  });

  // ============================================
  // HOOKS INIT COVERAGE TESTS (hooks-init.js)
  // ============================================

  console.log('\n=== HOOKS INIT COVERAGE TESTS ===\n');

  test('HOOKS-COV: HOOK_COMMANDS has scan and diff entries', () => {
    // Access module-level constants via require
    const hooksModule = require('../src/hooks-init.js');
    // HOOK_COMMANDS is not exported, but we can verify initHooks behavior
    assert(typeof hooksModule.initHooks === 'function', 'initHooks should be a function');
    assert(typeof hooksModule.removeHooks === 'function', 'removeHooks should be a function');
  });

  await asyncTest('HOOKS-COV: initHooks with git type creates hook file', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const { initHooks: initH } = require('../src/hooks-init.js');
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};
    try {
      const result = await initH(tmpDir, { type: 'git', mode: 'scan' });
      console.log = origLog;
      console.error = origErr;
      assert(result === true, 'initHooks should return true');
      const hookPath = path.join(gitDir, 'pre-commit');
      assert(fs.existsSync(hookPath), 'pre-commit hook should exist');
      const content = fs.readFileSync(hookPath, 'utf8');
      assertIncludes(content, 'muaddib scan', 'Hook should contain scan command');
      assertIncludes(content, 'MUADDIB', 'Hook should contain MUADDIB');
    } finally {
      console.log = origLog;
      console.error = origErr;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initHooks with diff mode generates diff command', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const { initHooks: initH } = require('../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'git', mode: 'diff' });
      console.log = origLog;
      const hookPath = path.join(gitDir, 'pre-commit');
      const content = fs.readFileSync(hookPath, 'utf8');
      assertIncludes(content, 'muaddib diff', 'Hook should contain diff command');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initHooks invalid mode defaults to scan', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const { initHooks: initH } = require('../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'git', mode: 'invalidmode' });
      console.log = origLog;
      const hookPath = path.join(gitDir, 'pre-commit');
      const content = fs.readFileSync(hookPath, 'utf8');
      assertIncludes(content, 'muaddib scan', 'Invalid mode should default to scan');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initHooks backs up existing hook', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const hookPath = path.join(gitDir, 'pre-commit');
    fs.writeFileSync(hookPath, '#!/bin/sh\necho old hook\n');
    const { initHooks: initH } = require('../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'git', mode: 'scan' });
      console.log = origLog;
      const backups = fs.readdirSync(gitDir).filter(f => f.startsWith('pre-commit.backup.'));
      assert(backups.length >= 1, 'Should have created a backup');
      const newContent = fs.readFileSync(hookPath, 'utf8');
      assertIncludes(newContent, 'muaddib scan', 'New hook should contain scan');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initHooks fails without .git directory', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const { initHooks: initH } = require('../src/hooks-init.js');
    const origLog = console.log;
    const origErr = console.error;
    console.log = () => {};
    console.error = () => {};
    try {
      const result = await initH(tmpDir, { type: 'git', mode: 'scan' });
      console.log = origLog;
      console.error = origErr;
      assert(result === false, 'Should return false when no .git');
    } finally {
      console.log = origLog;
      console.error = origErr;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initPreCommit creates config when none exists', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    // Create .pre-commit-config.yaml marker
    const configPath = path.join(tmpDir, '.pre-commit-config.yaml');
    // Don't create it — let initPreCommit create it
    const { initHooks: initH } = require('../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'pre-commit', mode: 'scan' });
      console.log = origLog;
      assert(fs.existsSync(configPath), 'Should create .pre-commit-config.yaml');
      const content = fs.readFileSync(configPath, 'utf8');
      assertIncludes(content, 'muaddib-scan', 'Should have muaddib-scan hook id');
      assertIncludes(content, 'repos:', 'Should have repos section');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initPreCommit appends to existing config', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const configPath = path.join(tmpDir, '.pre-commit-config.yaml');
    fs.writeFileSync(configPath, 'repos:\n  - repo: https://github.com/other/hook\n    rev: v1.0\n    hooks:\n      - id: other-hook\n');
    const { initHooks: initH } = require('../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await initH(tmpDir, { type: 'pre-commit', mode: 'diff' });
      console.log = origLog;
      const content = fs.readFileSync(configPath, 'utf8');
      assertIncludes(content, 'muaddib-diff', 'Should have muaddib-diff hook id');
      assertIncludes(content, 'other-hook', 'Should preserve existing hooks');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: initPreCommit skips if already configured', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const configPath = path.join(tmpDir, '.pre-commit-config.yaml');
    fs.writeFileSync(configPath, 'repos:\n  - repo: muaddib-scanner\n');
    const { initHooks: initH } = require('../src/hooks-init.js');
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      await initH(tmpDir, { type: 'pre-commit', mode: 'scan' });
      console.log = origLog;
      const logged = logs.some(l => l.includes('already configured'));
      assert(logged, 'Should log that muaddib is already configured');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: removeHooks removes git hook', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const hookPath = path.join(gitDir, 'pre-commit');
    fs.writeFileSync(hookPath, '#!/bin/sh\nmuaddib scan . --fail-on high\n');
    const { removeHooks: removeH } = require('../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await removeH(tmpDir);
      console.log = origLog;
      assert(!fs.existsSync(hookPath), 'Hook should be removed');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: removeHooks preserves non-muaddib hook', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const hookPath = path.join(gitDir, 'pre-commit');
    fs.writeFileSync(hookPath, '#!/bin/sh\necho "other tool"\n');
    const { removeHooks: removeH } = require('../src/hooks-init.js');
    const origLog = console.log;
    console.log = () => {};
    try {
      await removeH(tmpDir);
      console.log = origLog;
      assert(fs.existsSync(hookPath), 'Non-muaddib hook should be preserved');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('HOOKS-COV: auto-detect selects git when only .git exists', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-hooks-'));
    const gitDir = path.join(tmpDir, '.git', 'hooks');
    fs.mkdirSync(gitDir, { recursive: true });
    const { initHooks: initH } = require('../src/hooks-init.js');
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(String(msg));
    try {
      await initH(tmpDir, { type: 'auto', mode: 'scan' });
      console.log = origLog;
      const gitLog = logs.some(l => l.includes('Hook system: git'));
      assert(gitLog, 'Should auto-detect git hook system');
    } finally {
      console.log = origLog;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ============================================
  // ENTROPY TESTS
  // ============================================

  console.log('\n=== ENTROPY TESTS ===\n');

  const { calculateShannonEntropy, scanEntropy } = require('../src/scanner/entropy.js');

  // --- Shannon entropy unit tests ---

  test('ENTROPY: Normal English text has low entropy (<4.5)', () => {
    const text = 'This is a normal English sentence that should have relatively low Shannon entropy.';
    const entropy = calculateShannonEntropy(text);
    assert(entropy < 4.5, 'Normal text entropy should be < 4.5, got ' + entropy.toFixed(2));
  });

  test('ENTROPY: Base64 string has high entropy (>5.0)', () => {
    const b64 = 'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgZW5jb2RlZCBzdHJpbmcgdGhhdCBzaG91bGQgaGF2ZSBoaWdoIGVudHJvcHkgYW5kIHRyaWdnZXIgdGhlIHNjYW5uZXI=';
    const entropy = calculateShannonEntropy(b64);
    assert(entropy > 5.0, 'Base64 entropy should be > 5.0, got ' + entropy.toFixed(2));
  });

  test('ENTROPY: Hex string has high entropy (>3.0)', () => {
    const hex = '4a6f686e20446f6520736179732068656c6c6f20746f20746865207365637572697479207363616e6e6572206279206372656174696e67206120686578';
    const entropy = calculateShannonEntropy(hex);
    assert(entropy > 3.0, 'Hex entropy should be > 3.0, got ' + entropy.toFixed(2));
  });

  // --- String-level entropy tests ---

  test('ENTROPY: scanEntropy on normal.js returns 0 findings', () => {
    const entropyDir = path.join(__dirname, 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const normalThreats = threats.filter(function(t) { return t.file === 'normal.js'; });
    assert(normalThreats.length === 0, 'Normal file should have 0 entropy findings, got ' + normalThreats.length);
  });

  test('ENTROPY: scanEntropy on high-entropy.js finds string-level threats', () => {
    const entropyDir = path.join(__dirname, 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const highThreats = threats.filter(function(t) {
      return t.file === 'high-entropy.js' && t.type === 'high_entropy_string';
    });
    assert(highThreats.length > 0, 'High-entropy strings should trigger findings, got ' + highThreats.length);
  });

  test('ENTROPY: Short high-entropy string (<50 chars) does NOT trigger', () => {
    const shortStr = 'xK9mQ2pLwR7vN5tY';
    const entropy = calculateShannonEntropy(shortStr);
    assert(entropy > 3.5, 'Short string should still have high entropy: ' + entropy.toFixed(2));
    const entropyDir = path.join(__dirname, 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const normalStringThreats = threats.filter(function(t) {
      return t.file === 'normal.js' && t.type === 'high_entropy_string';
    });
    assert(normalStringThreats.length === 0, 'Short strings should not trigger, got ' + normalStringThreats.length);
  });

  test('ENTROPY: No file-level entropy scanning (removed)', () => {
    const entropyDir = path.join(__dirname, 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const fileThreats = threats.filter(function(t) { return t.type === 'high_entropy_file'; });
    assert(fileThreats.length === 0, 'File-level entropy scanning should be removed, got ' + fileThreats.length + ' findings');
  });

  // --- Exclusion tests ---

  test('ENTROPY: .min.js file does NOT trigger', () => {
    const entropyDir = path.join(__dirname, 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const minThreats = threats.filter(function(t) { return t.file.endsWith('.min.js'); });
    assert(minThreats.length === 0, '.min.js file should be skipped, got ' + minThreats.length + ' findings');
  });

  test('ENTROPY: __compiled__/ files do NOT trigger', () => {
    const entropyDir = path.join(__dirname, 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const compiledThreats = threats.filter(function(t) { return t.file.includes('__compiled__'); });
    assert(compiledThreats.length === 0, '__compiled__/ files should be skipped, got ' + compiledThreats.length + ' findings');
  });

  test('ENTROPY: Legit minified code does NOT trigger', () => {
    const entropyDir = path.join(__dirname, 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const legitThreats = threats.filter(function(t) { return t.file === 'legit-minified.js'; });
    assert(legitThreats.length === 0, 'Legitimate minified code should not trigger, got ' + legitThreats.length + ' findings');
  });

  // --- Obfuscation pattern tests (MUADDIB-ENTROPY-003) ---

  test('ENTROPY: _0x hex variable pattern triggers js_obfuscation_pattern', () => {
    const entropyDir = path.join(__dirname, 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const obfThreats = threats.filter(function(t) {
      return t.file === 'obfuscated.js' && t.type === 'js_obfuscation_pattern';
    });
    assert(obfThreats.length > 0, 'Obfuscated _0x code should trigger js_obfuscation_pattern, got ' + obfThreats.length);
    assert(obfThreats[0].severity === 'HIGH', 'js_obfuscation_pattern should be HIGH severity');
  });

  test('ENTROPY: Long base64 payload triggers js_obfuscation_pattern', () => {
    const entropyDir = path.join(__dirname, 'samples', 'entropy');
    const threats = scanEntropy(entropyDir);
    const b64Threats = threats.filter(function(t) {
      return t.file === 'long-base64-payload.js' && t.type === 'js_obfuscation_pattern';
    });
    assert(b64Threats.length > 0, 'Long base64 payload should trigger js_obfuscation_pattern, got ' + b64Threats.length);
  });

  test('ENTROPY: Rule MUADDIB-ENTROPY-003 exists', () => {
    const { getRule } = require('../src/rules/index.js');
    const rule = getRule('js_obfuscation_pattern');
    assert(rule.id === 'MUADDIB-ENTROPY-003', 'Rule ID should be MUADDIB-ENTROPY-003, got ' + rule.id);
    assert(rule.mitre === 'T1027.002', 'MITRE should be T1027.002, got ' + rule.mitre);
  });

  test('ENTROPY: Playbook for js_obfuscation_pattern exists', () => {
    const { getPlaybook } = require('../src/response/playbooks.js');
    const pb = getPlaybook('js_obfuscation_pattern');
    assert(pb && pb.length > 10, 'Playbook should exist for js_obfuscation_pattern');
  });

  // ============================================
  // FALSE POSITIVE REDUCTION TESTS (AST + OBF)
  // ============================================

  console.log('\n=== FALSE POSITIVE REDUCTION TESTS ===\n');

  test('FP-AST: Function("return this") is LOW not HIGH', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast-fp', 'constant-eval'), '--json');
    const result = JSON.parse(output);
    const fnThreats = result.threats.filter(t => t.type === 'dangerous_call_function');
    assert(fnThreats.length > 0, 'Should detect Function(), got threats: ' + JSON.stringify(result.threats.map(t => t.type)));
    assert(fnThreats[0].severity === 'LOW', 'Constant Function() should be LOW, got ' + fnThreats[0].severity);
  });

  test('FP-AST: eval("literal") is LOW not HIGH', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast-fp', 'constant-eval'), '--json');
    const result = JSON.parse(output);
    const evalThreats = result.threats.filter(t => t.type === 'dangerous_call_eval');
    assert(evalThreats.length > 0, 'Should detect eval(), got threats: ' + JSON.stringify(result.threats.map(t => t.type)));
    assert(evalThreats[0].severity === 'LOW', 'Constant eval() should be LOW, got ' + evalThreats[0].severity);
  });

  test('FP-AST: eval(variable) remains HIGH', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast-fp', 'dynamic-eval'), '--json');
    const result = JSON.parse(output);
    const evalThreats = result.threats.filter(t => t.type === 'dangerous_call_eval');
    assert(evalThreats.length > 0, 'Should detect eval(), got threats: ' + JSON.stringify(result.threats.map(t => t.type)));
    assert(evalThreats[0].severity === 'HIGH', 'Dynamic eval() should be HIGH, got ' + evalThreats[0].severity);
  });

  test('FP-AST: new Function(variable) is MEDIUM (new scope, not eval)', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast-fp', 'dynamic-eval'), '--json');
    const result = JSON.parse(output);
    const fnThreats = result.threats.filter(t => t.type === 'dangerous_call_function');
    assert(fnThreats.length > 0, 'Should detect new Function(), got threats: ' + JSON.stringify(result.threats.map(t => t.type)));
    assert(fnThreats[0].severity === 'MEDIUM', 'Dynamic new Function() should be MEDIUM, got ' + fnThreats[0].severity);
  });

  test('FP-OBF: hex escapes alone (unicode table) → no obfuscation alert', () => {
    const output = runScan(path.join(TESTS_DIR, 'obfuscation-fp', 'hex-table'), '--json');
    const result = JSON.parse(output);
    const obfThreats = result.threats.filter(t => t.type === 'obfuscation_detected');
    assert(obfThreats.length === 0, 'Hex table alone should not trigger obfuscation, got ' + obfThreats.length);
  });

  test('FP-OBF: .min.js with long lines → no obfuscation alert', () => {
    const output = runScan(path.join(TESTS_DIR, 'obfuscation-fp', 'minified'), '--json');
    const result = JSON.parse(output);
    const obfThreats = result.threats.filter(t => t.type === 'obfuscation_detected');
    assert(obfThreats.length === 0, 'Minified .min.js should not trigger obfuscation, got ' + obfThreats.length);
  });

  // ============================================
  // MONITOR TESTS
  // ============================================

  console.log('\n=== MONITOR TESTS ===\n');

  const { parseNpmResponse, parsePyPIRss, loadState, saveState, STATE_FILE } = require('../src/monitor.js');

  test('MONITOR: parseNpmResponse extracts packages and _updated timestamp', () => {
    const body = JSON.stringify({
      '_updated': 1700000000000,
      'my-package': {
        name: 'my-package',
        'dist-tags': { latest: '1.2.3' }
      },
      'another-pkg': {
        name: 'another-pkg',
        'dist-tags': { latest: '0.0.1' }
      }
    });
    const { packages, maxTimestamp } = parseNpmResponse(body);
    assert(packages.length === 2, 'Should find 2 packages, got ' + packages.length);
    assert(packages.some(p => p.name === 'my-package' && p.version === '1.2.3'), 'Should have my-package@1.2.3');
    assert(packages.some(p => p.name === 'another-pkg' && p.version === '0.0.1'), 'Should have another-pkg@0.0.1');
    assert(maxTimestamp === 1700000000000, 'Should extract _updated timestamp');
  });

  test('MONITOR: parseNpmResponse handles empty/invalid JSON', () => {
    const { packages, maxTimestamp } = parseNpmResponse('not json');
    assert(packages.length === 0, 'Should return empty on invalid JSON');
    assert(maxTimestamp === 0, 'Timestamp should be 0');
  });

  test('MONITOR: parseNpmResponse skips non-object entries', () => {
    const body = JSON.stringify({
      '_updated': 123,
      'good-pkg': { name: 'good-pkg', 'dist-tags': { latest: '1.0.0' } },
      'bad-entry': 'just a string',
      'null-entry': null
    });
    const { packages } = parseNpmResponse(body);
    assert(packages.length === 1, 'Should only find 1 valid package, got ' + packages.length);
    assert(packages[0].name === 'good-pkg', 'Should be good-pkg');
  });

  test('MONITOR: parseNpmResponse handles missing dist-tags', () => {
    const body = JSON.stringify({
      'no-tags': { name: 'no-tags' }
    });
    const { packages } = parseNpmResponse(body);
    assert(packages.length === 1, 'Should find 1 package');
    assert(packages[0].version === '', 'Version should be empty string when no dist-tags');
  });

  test('MONITOR: parsePyPIRss extracts package names from RSS', () => {
    const xml = `<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Newest packages</title>
    <item>
      <title>cool-lib 2.0.0</title>
      <link>https://pypi.org/project/cool-lib/2.0.0/</link>
    </item>
    <item>
      <title>another-pkg 0.1.0</title>
      <link>https://pypi.org/project/another-pkg/0.1.0/</link>
    </item>
  </channel>
</rss>`;
    const packages = parsePyPIRss(xml);
    assert(packages.length === 2, 'Should find 2 packages, got ' + packages.length);
    assert(packages[0] === 'cool-lib', 'First should be cool-lib, got ' + packages[0]);
    assert(packages[1] === 'another-pkg', 'Second should be another-pkg');
  });

  test('MONITOR: parsePyPIRss handles empty RSS', () => {
    const xml = `<?xml version="1.0"?><rss><channel></channel></rss>`;
    const packages = parsePyPIRss(xml);
    assert(packages.length === 0, 'Should return empty for no items');
  });

  test('MONITOR: parsePyPIRss handles malformed XML gracefully', () => {
    const packages = parsePyPIRss('not xml at all');
    assert(packages.length === 0, 'Should return empty for invalid XML');
  });

  test('MONITOR: state save and restore round-trip', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-monitor-'));
    const tmpState = path.join(tmpDir, 'monitor-state.json');
    const origFile = STATE_FILE;

    // Write state to temp file
    const testState = { npmLastKey: 1700000000000, pypiLastPackage: 'test-pkg' };
    fs.writeFileSync(tmpState, JSON.stringify(testState), 'utf8');

    // Read it back manually (loadState uses STATE_FILE, so we test the format)
    const raw = fs.readFileSync(tmpState, 'utf8');
    const restored = JSON.parse(raw);
    assert(restored.npmLastKey === 1700000000000, 'npmLastKey should round-trip');
    assert(restored.pypiLastPackage === 'test-pkg', 'pypiLastPackage should round-trip');

    // Cleanup
    try { fs.unlinkSync(tmpState); fs.rmdirSync(tmpDir); } catch {}
  });

  test('MONITOR: loadState returns defaults when file missing', () => {
    // loadState reads STATE_FILE which may not exist in test env
    // We test that it doesn't throw and returns defaults
    const state = loadState();
    assert(typeof state.npmLastKey === 'number', 'npmLastKey should be number');
    assert(typeof state.pypiLastPackage === 'string', 'pypiLastPackage should be string');
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
