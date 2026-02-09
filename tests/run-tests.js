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

test('CLI-EXT: help command shows usage', () => {
  const output = runCommand('help');
  assertIncludes(output, 'Usage', 'Should display usage');
  assertIncludes(output, 'muaddib scan', 'Should show scan');
});

test('CLI-EXT: unknown command shows error', () => {
  const output = runCommand('blahblah');
  assertIncludes(output, 'Unknown command', 'Should say Unknown command');
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
  const output = runCommand('scrape');
  assert(output.length > 0, 'Should produce output');
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
