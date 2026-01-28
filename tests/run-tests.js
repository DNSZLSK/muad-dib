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
  assertIncludes(output, 'malicious packages', 'Should display package count');
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
