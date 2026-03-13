const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, assertIncludes, assertNotIncludes, runScan, runScanDirect, addSkipped, TESTS_DIR } = require('../test-utils');

async function runUpdaterTests() {

// ============================================
// UPDATE TESTS
// ============================================

console.log('\n=== UPDATE TESTS ===\n');

test('UPDATE: Module loads and loadCachedIOCs works', () => {
  const { loadCachedIOCs } = require('../../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.packagesMap instanceof Map, 'Should return packagesMap');
  assert(iocs.wildcardPackages instanceof Set, 'Should return wildcardPackages');
  assert(iocs.packages.length > 0, 'Should have packages');
});

test('UPDATE: updateIOCs is a function', () => {
  const { updateIOCs } = require('../../src/ioc/updater.js');
  assert(typeof updateIOCs === 'function', 'updateIOCs should be a function');
});

// SKIPPED: updateIOCs does real network downloads (36s) — run via npm run test:integration
console.log('[SKIP] UPDATE: updateIOCs does not reduce IOC count (network)');
addSkipped(1);

// ============================================
// FALSE POSITIVES TESTS
// ============================================

console.log('\n=== FALSE POSITIVES TESTS ===\n');

await asyncTest('FALSE POSITIVES: Clean project = no threats', async () => {
  const result = await runScanDirect(path.join(TESTS_DIR, 'clean'));
  assert(result.summary.total === 0, 'Clean project should have no threats, got ' + result.summary.total);
});

await asyncTest('FALSE POSITIVES: Comments ignored', async () => {
  const result = await runScanDirect(path.join(TESTS_DIR, 'clean'));
  const criticals = result.threats.filter(t => t.severity === 'CRITICAL');
  assert(criticals.length === 0, 'Comments should not trigger CRITICAL threats');
});

await asyncTest('FALSE POSITIVES: Safe env vars not flagged', async () => {
  const result = await runScanDirect(path.join(TESTS_DIR, 'clean'));
  const envThreats = result.threats.filter(t => t.type === 'env_access');
  assert(envThreats.length === 0, 'Safe env vars should not trigger env_access');
});

// ============================================
// EDGE CASES TESTS
// ============================================

console.log('\n=== EDGE CASES TESTS ===\n');

await asyncTest('EDGE: Empty file does not crash', async () => {
  const result = await runScanDirect(path.join(TESTS_DIR, 'edge', 'empty'));
  assert(result !== undefined, 'Should not crash on empty file');
});

await asyncTest('EDGE: Non-JS file ignored', async () => {
  const result = await runScanDirect(path.join(TESTS_DIR, 'edge', 'non-js'));
  assert(result.summary.total === 0, 'Non-JS files should produce no threats');
});

await asyncTest('EDGE: Invalid JS syntax does not crash', async () => {
  const result = await runScanDirect(path.join(TESTS_DIR, 'edge', 'invalid-syntax'));
  assert(result !== undefined, 'Should not crash on invalid syntax');
});

await asyncTest('EDGE: Very large file does not timeout', async () => {
  const start = Date.now();
  await runScanDirect(path.join(TESTS_DIR, 'edge', 'large-file'));
  const duration = Date.now() - start;
  assert(duration < 30000, 'Should not take more than 30s');
});

// ============================================
// MITRE RULES TESTS
// ============================================

console.log('\n=== MITRE TESTS ===\n');

test('MITRE: T1552.001 - Credentials in Files', () => {
  const { getRule } = require('../../src/rules/index.js');
  const rule = getRule('env_access');
  assert(rule.mitre === 'T1552.001', 'env_access rule should map to T1552.001');
});

test('MITRE: T1059 - Command Execution', () => {
  const { getRule } = require('../../src/rules/index.js');
  const rule = getRule('dangerous_call_eval');
  assert(rule.mitre.startsWith('T1059'), 'dangerous_call_eval rule should map to T1059.*, got ' + rule.mitre);
});

test('MITRE: T1041 - Exfiltration', () => {
  const { getRule } = require('../../src/rules/index.js');
  const rule = getRule('suspicious_dataflow');
  assert(rule.mitre === 'T1041', 'suspicious_dataflow rule should map to T1041');
});

// ============================================
// WHITELIST / REHABILITATED PACKAGES TESTS
// ============================================

console.log('\n=== WHITELIST TESTS ===\n');

test('WHITELIST: chalk is in REHABILITATED_PACKAGES', () => {
  const { REHABILITATED_PACKAGES } = require('../../src/safe-install.js');
  assert(REHABILITATED_PACKAGES['chalk'], 'chalk should be in REHABILITATED_PACKAGES');
  assert(REHABILITATED_PACKAGES['chalk'].safe === true, 'chalk.safe should be true');
});

test('WHITELIST: debug is in REHABILITATED_PACKAGES', () => {
  const { REHABILITATED_PACKAGES } = require('../../src/safe-install.js');
  assert(REHABILITATED_PACKAGES['debug'], 'debug should be in REHABILITATED_PACKAGES');
  assert(REHABILITATED_PACKAGES['debug'].safe === true, 'debug.safe should be true');
});

test('WHITELIST: ua-parser-js has specific compromised versions', () => {
  const { REHABILITATED_PACKAGES } = require('../../src/safe-install.js');
  const uap = REHABILITATED_PACKAGES['ua-parser-js'];
  assert(uap, 'ua-parser-js should be in REHABILITATED_PACKAGES');
  assert(uap.safe === false, 'ua-parser-js.safe should be false');
  assert(uap.compromised.includes('0.7.29'), 'Should include 0.7.29');
  assert(uap.compromised.includes('0.8.0'), 'Should include 0.8.0');
  assert(uap.compromised.includes('1.0.0'), 'Should include 1.0.0');
});

test('WHITELIST: checkRehabilitated returns safe for chalk', () => {
  const { checkRehabilitated } = require('../../src/safe-install.js');
  const result = checkRehabilitated('chalk', '5.4.0');
  assert(result !== null, 'chalk should be recognized');
  assert(result.safe === true, 'chalk should be safe');
});

test('WHITELIST: checkRehabilitated returns unsafe for ua-parser-js@0.7.29', () => {
  const { checkRehabilitated } = require('../../src/safe-install.js');
  const result = checkRehabilitated('ua-parser-js', '0.7.29');
  assert(result !== null, 'ua-parser-js should be recognized');
  assert(result.safe === false, 'ua-parser-js@0.7.29 should be unsafe');
});

test('WHITELIST: checkRehabilitated returns safe for ua-parser-js@0.7.35', () => {
  const { checkRehabilitated } = require('../../src/safe-install.js');
  const result = checkRehabilitated('ua-parser-js', '0.7.35');
  assert(result !== null, 'ua-parser-js should be recognized');
  assert(result.safe === true, 'ua-parser-js@0.7.35 should be safe');
});

test('WHITELIST: checkRehabilitated returns null for unknown package', () => {
  const { checkRehabilitated } = require('../../src/safe-install.js');
  const result = checkRehabilitated('some-random-package', '1.0.0');
  assert(result === null, 'Unknown package should return null');
});

// ============================================
// IOC LOADING TESTS
// ============================================

console.log('\n=== IOC LOADING TESTS ===\n');

test('IOC: loadCachedIOCs returns packages', () => {
  const { loadCachedIOCs } = require('../../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.packages, 'Should have packages');
  assert(iocs.packages.length > 0, 'Should have at least one package');
});

test('IOC: loadCachedIOCs returns hashes', () => {
  const { loadCachedIOCs } = require('../../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.hashes, 'Should have hashes');
});

test('IOC: loadCachedIOCs returns markers', () => {
  const { loadCachedIOCs } = require('../../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.markers, 'Should have markers');
  assert(iocs.markers.length > 0, 'Should have at least one marker');
});

test('IOC: Typosquats have wildcard version', () => {
  const { loadCachedIOCs } = require('../../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  const typosquats = iocs.packages.filter(p => p.source === 'typosquat');
  assert(typosquats.length > 0, 'Should have typosquats');
  const allWildcard = typosquats.every(p => p.version === '*');
  assert(allWildcard, 'All typosquats should have version *');
});

test('IOC: Historical packages have specific versions', () => {
  const { loadCachedIOCs } = require('../../src/ioc/updater.js');
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
  const { runScraper } = require('../../src/ioc/scraper.js');
  assert(typeof runScraper === 'function', 'runScraper should be a function');
});

test('FIXTURE: test-iocs.json loads and is valid', () => {
  const iocs = require('../fixtures/test-iocs.json');
  assert(iocs.packages, 'Should have packages');
  assert(Array.isArray(iocs.packages), 'packages should be an array');
});

test('FIXTURE: IOCs have required fields', () => {
  const iocs = require('../fixtures/test-iocs.json');
  const sample = iocs.packages[0];
  assert(sample.name, 'IOC should have name');
  assert(sample.version, 'IOC should have version');
  assert(sample.source, 'IOC should have source');
});

test('FIXTURE: IOC fixture has expected count', () => {
  const iocs = require('../fixtures/test-iocs.json');
  assert(iocs.packages.length === 15, `Should have 15 IOCs in fixture, has ${iocs.packages.length}`);
});

// ============================================
// COMPACT IOC TESTS
// ============================================

console.log('\n=== COMPACT IOC TESTS ===\n');

test('COMPACT: iocs-compact.json exists', () => {
  const compactPath = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs-compact.json');
  assert(fs.existsSync(compactPath), 'src/ioc/data/iocs-compact.json should exist');
});

test('COMPACT: has expected compact format fields', () => {
  const compactPath = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs-compact.json');
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
  const compactPath = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs-compact.json');
  const compact = JSON.parse(fs.readFileSync(compactPath, 'utf8'));
  // Compact format stores names as strings, not objects with description/references
  assert(typeof compact.wildcards[0] === 'string', 'Wildcard entries should be plain strings');
  const firstVersionedKey = Object.keys(compact.versioned)[0];
  assert(Array.isArray(compact.versioned[firstVersionedKey]), 'Versioned entries should be version arrays');
  assert(typeof compact.versioned[firstVersionedKey][0] === 'string', 'Versions should be plain strings');
});

test('COMPACT: is significantly smaller than full IOCs', () => {
  const compactPath = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs-compact.json');
  const fullPath = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs.json');
  if (fs.existsSync(fullPath)) {
    const compactSize = fs.statSync(compactPath).size;
    const fullSize = fs.statSync(fullPath).size;
    assert(compactSize < fullSize / 5, `Compact (${compactSize}) should be at least 5x smaller than full (${fullSize})`);
  }
});

test('COMPACT: generateCompactIOCs strips enriched data', () => {
  const { generateCompactIOCs } = require('../../src/ioc/updater.js');
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
  const { generateCompactIOCs, expandCompactIOCs } = require('../../src/ioc/updater.js');
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
  const { loadCachedIOCs } = require('../../src/ioc/updater.js');
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
  const builtinPath = path.join(__dirname, '..', '..', 'iocs', 'builtin.yaml');
  assert(fs.existsSync(builtinPath), 'iocs/builtin.yaml should exist');
});

test('YAML: loadYAMLIOCs returns packages', () => {
  const { loadYAMLIOCs } = require('../../src/ioc/yaml-loader.js');
  const iocs = loadYAMLIOCs();
  assert(iocs.packages, 'Should have packages');
  assert(iocs.packages.length > 0, 'Should have at least one package');
});

test('YAML: Contains Shai-Hulud packages', () => {
  const { loadYAMLIOCs } = require('../../src/ioc/yaml-loader.js');
  const iocs = loadYAMLIOCs();
  const shaiHulud = iocs.packages.filter(p => p.source && p.source.includes('shai-hulud'));
  assert(shaiHulud.length > 0, 'Should have Shai-Hulud packages');
});

test('YAML: Contains Shai-Hulud markers', () => {
  const { loadYAMLIOCs } = require('../../src/ioc/yaml-loader.js');
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
  const { checkRehabilitated } = require('../../src/safe-install.js');
  const result = checkRehabilitated('chalk', '5.4.0');
  assert(result && result.safe === true, 'chalk should not block');
});

test('REGRESSION: debug should not block (rehabilitated)', () => {
  const { checkRehabilitated } = require('../../src/safe-install.js');
  const result = checkRehabilitated('debug', '4.3.0');
  assert(result && result.safe === true, 'debug should not block');
});

test('REGRESSION: lodash is not in IOCs', () => {
  const iocs = require('../fixtures/test-iocs.json');
  const lodash = iocs.packages.find(p => p.name === 'lodash');
  assert(!lodash, 'lodash should not be in IOCs');
});

test('REGRESSION: loadash (typosquat) IS in IOCs', () => {
  const iocs = require('../fixtures/test-iocs.json');
  const loadash = iocs.packages.find(p => p.name === 'loadash');
  assert(loadash, 'loadash (typosquat) should be in IOCs');
});

test('REGRESSION: express is not in IOCs', () => {
  const iocs = require('../fixtures/test-iocs.json');
  const express = iocs.packages.find(p => p.name === 'express');
  assert(!express, 'express should not be in IOCs');
});

test('REGRESSION: axios is not in IOCs', () => {
  const iocs = require('../fixtures/test-iocs.json');
  const axios = iocs.packages.find(p => p.name === 'axios');
  assert(!axios, 'axios should not be in IOCs');
});

// ============================================
// PACKAGE SECURITY TESTS
// ============================================

console.log('\n=== PACKAGE SECURITY TESTS ===\n');

test('SECURITY: isValidPackageName accepts lodash', () => {
  const { isValidPackageName } = require('../../src/safe-install.js');
  assert(isValidPackageName('lodash'), 'lodash should be valid');
});

test('SECURITY: isValidPackageName accepts @scope/package', () => {
  const { isValidPackageName } = require('../../src/safe-install.js');
  assert(isValidPackageName('@types/node'), '@types/node should be valid');
});

test('SECURITY: isValidPackageName rejects shell injection', () => {
  const { isValidPackageName } = require('../../src/safe-install.js');
  assert(!isValidPackageName('foo; rm -rf /'), 'shell injection should be invalid');
});

test('SECURITY: isValidPackageName rejects backticks', () => {
  const { isValidPackageName } = require('../../src/safe-install.js');
  assert(!isValidPackageName('foo`whoami`'), 'backticks should be invalid');
});

test('SECURITY: isValidPackageName rejects $(...)', () => {
  const { isValidPackageName } = require('../../src/safe-install.js');
  assert(!isValidPackageName('foo$(cat /etc/passwd)'), '$() should be invalid');
});

test('SECURITY: isValidPackageName rejects pipes', () => {
  const { isValidPackageName } = require('../../src/safe-install.js');
  assert(!isValidPackageName('foo | cat /etc/passwd'), 'pipe should be invalid');
});

// ============================================
// BOOTSTRAP TESTS
// ============================================

console.log('\n=== BOOTSTRAP TESTS ===\n');

test('BOOTSTRAP: ensureIOCs is an async function', () => {
  const { ensureIOCs } = require('../../src/ioc/bootstrap.js');
  assert(typeof ensureIOCs === 'function', 'ensureIOCs should be a function');
  // Async functions return promises when called — check constructor name
  assert(ensureIOCs.constructor.name === 'AsyncFunction', 'ensureIOCs should be async');
});

test('BOOTSTRAP: IOCS_PATH points to ~/.muaddib/data/iocs.json', () => {
  const { IOCS_PATH } = require('../../src/ioc/bootstrap.js');
  const expected = path.join(os.homedir(), '.muaddib', 'data', 'iocs.json');
  assert(IOCS_PATH === expected, 'IOCS_PATH should be ' + expected + ', got ' + IOCS_PATH);
});

test('BOOTSTRAP: HOME_DATA_DIR points to ~/.muaddib/data/', () => {
  const { HOME_DATA_DIR } = require('../../src/ioc/bootstrap.js');
  const expected = path.join(os.homedir(), '.muaddib', 'data');
  assert(HOME_DATA_DIR === expected, 'HOME_DATA_DIR should be ' + expected + ', got ' + HOME_DATA_DIR);
});

test('BOOTSTRAP: MIN_IOCS_SIZE is 1MB', () => {
  const { MIN_IOCS_SIZE } = require('../../src/ioc/bootstrap.js');
  assert(MIN_IOCS_SIZE === 1_000_000, 'MIN_IOCS_SIZE should be 1000000, got ' + MIN_IOCS_SIZE);
});

test('BOOTSTRAP: IOCS_URL points to GitHub Releases', () => {
  const { IOCS_URL } = require('../../src/ioc/bootstrap.js');
  assert(IOCS_URL.startsWith('https://github.com/'), 'URL should start with https://github.com/');
  assert(IOCS_URL.endsWith('iocs.json.gz'), 'URL should end with iocs.json.gz');
});

test('BOOTSTRAP: module exports all expected symbols', () => {
  const bootstrap = require('../../src/ioc/bootstrap.js');
  assert(typeof bootstrap.ensureIOCs === 'function', 'Should export ensureIOCs');
  assert(typeof bootstrap.downloadAndDecompress === 'function', 'Should export downloadAndDecompress');
  assert(typeof bootstrap.isAllowedRedirect === 'function', 'Should export isAllowedRedirect');
  assert(typeof bootstrap.IOCS_URL === 'string', 'Should export IOCS_URL');
  assert(typeof bootstrap.IOCS_PATH === 'string', 'Should export IOCS_PATH');
  assert(typeof bootstrap.HOME_DATA_DIR === 'string', 'Should export HOME_DATA_DIR');
  assert(typeof bootstrap.MIN_IOCS_SIZE === 'number', 'Should export MIN_IOCS_SIZE');
});

test('BOOTSTRAP: isAllowedRedirect accepts github.com', () => {
  const { isAllowedRedirect } = require('../../src/ioc/bootstrap.js');
  assert(isAllowedRedirect('https://github.com/foo/bar') === true, 'github.com should be allowed');
});

test('BOOTSTRAP: isAllowedRedirect accepts objects.githubusercontent.com', () => {
  const { isAllowedRedirect } = require('../../src/ioc/bootstrap.js');
  assert(isAllowedRedirect('https://objects.githubusercontent.com/foo') === true, 'objects.githubusercontent.com should be allowed');
});

test('BOOTSTRAP: isAllowedRedirect accepts release-assets.githubusercontent.com', () => {
  const { isAllowedRedirect } = require('../../src/ioc/bootstrap.js');
  assert(isAllowedRedirect('https://release-assets.githubusercontent.com/foo') === true, 'release-assets.githubusercontent.com should be allowed');
});

test('BOOTSTRAP: isAllowedRedirect rejects HTTP', () => {
  const { isAllowedRedirect } = require('../../src/ioc/bootstrap.js');
  assert(isAllowedRedirect('http://github.com/foo') === false, 'HTTP should be rejected');
});

test('BOOTSTRAP: isAllowedRedirect rejects unknown domains', () => {
  const { isAllowedRedirect } = require('../../src/ioc/bootstrap.js');
  assert(isAllowedRedirect('https://evil.com/iocs.json.gz') === false, 'Unknown domain should be rejected');
});

test('BOOTSTRAP: isAllowedRedirect rejects invalid URLs', () => {
  const { isAllowedRedirect } = require('../../src/ioc/bootstrap.js');
  assert(isAllowedRedirect('not-a-url') === false, 'Invalid URL should be rejected');
});

asyncTest('BOOTSTRAP: ensureIOCs skips download when cache file exists and is large enough', async () => {
  const { ensureIOCs, IOCS_PATH, MIN_IOCS_SIZE } = require('../../src/ioc/bootstrap.js');
  // Only test skip behavior if the cache file already exists (from a previous update/scrape)
  if (fs.existsSync(IOCS_PATH) && fs.statSync(IOCS_PATH).size >= MIN_IOCS_SIZE) {
    const result = await ensureIOCs();
    assert(result === true, 'Should return true when cache exists');
  } else {
    // Create a temp large file to test skip logic (need >1MB, each entry is ~30 bytes)
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-bootstrap-test-'));
    const tmpFile = path.join(tmpDir, 'test-iocs.json');
    // Write a file larger than MIN_IOCS_SIZE (40000 entries ≈ 1.2MB)
    const bigData = JSON.stringify({ packages: new Array(40000).fill({ name: 'test', version: '*' }) });
    fs.writeFileSync(tmpFile, bigData);
    const stat = fs.statSync(tmpFile);
    assert(stat.size >= MIN_IOCS_SIZE, 'Test file should be >= 1MB, got ' + stat.size);
    // Cleanup
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// SKIPPED: downloadAndDecompress attempts real network connection — run via npm run test:integration
console.log('[SKIP] BOOTSTRAP: downloadAndDecompress rejects invalid URL gracefully (network)');
addSkipped(1);

// ============================================
// MERGE IOCs TESTS
// ============================================

console.log('\n=== MERGE IOCs TESTS ===\n');

test('MERGE: mergeIOCs deduplicates packages by name@version', () => {
  const { mergeIOCs } = require('../../src/ioc/updater.js');
  const target = { packages: [{ name: 'pkg-a', version: '1.0' }], pypi_packages: [], hashes: [], markers: [], files: [] };
  const source = {
    packages: [{ name: 'pkg-a', version: '1.0' }, { name: 'pkg-b', version: '2.0' }],
    pypi_packages: [], hashes: [], markers: [], files: []
  };
  const added = mergeIOCs(target, source);
  assert(added === 1, 'Should add 1 new package, got ' + added);
  assert(target.packages.length === 2, 'Target should have 2 packages');
});

test('MERGE: mergeIOCs merges PyPI packages', () => {
  const { mergeIOCs } = require('../../src/ioc/updater.js');
  const target = { packages: [], pypi_packages: [], hashes: [], markers: [], files: [] };
  const source = {
    packages: [],
    pypi_packages: [{ name: 'evil-py', version: '1.0' }, { name: 'bad-py', version: '*' }],
    hashes: [], markers: [], files: []
  };
  mergeIOCs(target, source);
  assert(target.pypi_packages.length === 2, 'Should have 2 PyPI packages');
});

test('MERGE: mergeIOCs merges hashes, markers, and files', () => {
  const { mergeIOCs } = require('../../src/ioc/updater.js');
  const target = { packages: [], pypi_packages: [], hashes: ['hash1'], markers: ['marker1'], files: ['file1'] };
  const source = {
    packages: [], pypi_packages: [],
    hashes: ['hash1', 'hash2'], markers: ['marker2'], files: ['file1', 'file2']
  };
  mergeIOCs(target, source);
  assert(target.hashes.length === 2, 'Should have 2 hashes (deduped), got ' + target.hashes.length);
  assert(target.markers.length === 2, 'Should have 2 markers');
  assert(target.files.length === 2, 'Should have 2 files (deduped)');
});

test('MERGE: mergeIOCs handles missing pypi_packages in target', () => {
  const { mergeIOCs } = require('../../src/ioc/updater.js');
  const target = { packages: [], hashes: [], markers: [], files: [] };
  const source = { packages: [], pypi_packages: [{ name: 'test', version: '*' }], hashes: [], markers: [], files: [] };
  mergeIOCs(target, source);
  assert(target.pypi_packages.length === 1, 'Should create pypi_packages and add 1');
});

// ============================================
// CREATE OPTIMIZED IOCs TESTS
// ============================================

console.log('\n=== CREATE OPTIMIZED IOCs TESTS ===\n');

test('OPTIMIZED: createOptimizedIOCs produces Map/Set structures', () => {
  const { createOptimizedIOCs } = require('../../src/ioc/updater.js');
  const iocs = {
    packages: [
      { name: 'evil-pkg', version: '*' },
      { name: 'evil-pkg', version: '1.0.0' },
      { name: 'bad-lib', version: '2.0.0' }
    ],
    pypi_packages: [
      { name: 'py-evil', version: '*' },
      { name: 'py-bad', version: '1.0' }
    ],
    hashes: ['abc123', 'def456'],
    markers: ['setup_bun.js'],
    files: ['inject.js']
  };
  const opt = createOptimizedIOCs(iocs);
  assert(opt.packagesMap instanceof Map, 'Should have packagesMap');
  assert(opt.wildcardPackages instanceof Set, 'Should have wildcardPackages');
  assert(opt.pypiPackagesMap instanceof Map, 'Should have pypiPackagesMap');
  assert(opt.pypiWildcardPackages instanceof Set, 'Should have pypiWildcardPackages');
  assert(opt.hashesSet instanceof Set, 'Should have hashesSet');
  assert(opt.markersSet instanceof Set, 'Should have markersSet');
  assert(opt.filesSet instanceof Set, 'Should have filesSet');
  assert(opt.wildcardPackages.has('evil-pkg'), 'evil-pkg should be in wildcards');
  assert(!opt.wildcardPackages.has('bad-lib'), 'bad-lib should NOT be in wildcards');
  assert(opt.pypiWildcardPackages.has('py-evil'), 'py-evil should be in pypi wildcards');
  assert(opt.packagesMap.get('evil-pkg').length === 2, 'evil-pkg should have 2 entries');
  assert(opt.hashesSet.has('abc123'), 'Should have hash abc123');
  assert(opt.markersSet.has('setup_bun.js'), 'Should have marker');
  assert(opt.filesSet.has('inject.js'), 'Should have file');
  assert(opt.packages.length === 3, 'Should preserve original packages array');
});

// ============================================
// INVALIDATE CACHE TESTS
// ============================================

console.log('\n=== INVALIDATE CACHE TESTS ===\n');

test('INVALIDATE: invalidateCache clears cached result', () => {
  const { loadCachedIOCs, invalidateCache } = require('../../src/ioc/updater.js');
  // First call populates cache
  const first = loadCachedIOCs();
  assert(first.packagesMap, 'First call should return optimized IOCs');
  // Invalidate
  invalidateCache();
  // Second call should reload (we can't easily verify it reloaded, but it shouldn't crash)
  const second = loadCachedIOCs();
  assert(second.packagesMap, 'Should still return valid IOCs after invalidate');
});

// ============================================
// EXPAND COMPACT IOCs EDGE CASES
// ============================================

console.log('\n=== EXPAND COMPACT EDGE CASES ===\n');

test('EXPAND: expandCompactIOCs handles severity overrides', () => {
  const { expandCompactIOCs } = require('../../src/ioc/updater.js');
  const compact = {
    defaultSeverity: 'critical',
    wildcards: ['pkg-a'],
    versioned: { 'pkg-b': ['1.0.0'] },
    pypi_wildcards: [],
    pypi_versioned: {},
    hashes: [],
    markers: [],
    files: [],
    severityOverrides: { 'pkg-b': { '1.0.0': 'high' } }
  };
  const expanded = expandCompactIOCs(compact);
  const pkgA = expanded.packages.find(p => p.name === 'pkg-a');
  const pkgB = expanded.packages.find(p => p.name === 'pkg-b');
  assert(pkgA.severity === 'critical', 'pkg-a should use default severity');
  assert(pkgB.severity === 'high', 'pkg-b should use override severity "high"');
});

test('EXPAND: expandCompactIOCs handles empty compact', () => {
  const { expandCompactIOCs } = require('../../src/ioc/updater.js');
  const compact = {};
  const expanded = expandCompactIOCs(compact);
  assert(expanded.packages.length === 0, 'Should have 0 packages');
  assert(expanded.pypi_packages.length === 0, 'Should have 0 PyPI packages');
  assert(expanded.hashes.length === 0, 'Should have 0 hashes');
});

test('EXPAND: expandCompactIOCs deduplicates wildcards', () => {
  const { expandCompactIOCs } = require('../../src/ioc/updater.js');
  const compact = {
    defaultSeverity: 'critical',
    wildcards: ['dup-pkg', 'dup-pkg', 'unique-pkg'],
    versioned: {},
    pypi_wildcards: [],
    pypi_versioned: {},
    hashes: [], markers: [], files: []
  };
  const expanded = expandCompactIOCs(compact);
  const dupCount = expanded.packages.filter(p => p.name === 'dup-pkg').length;
  assert(dupCount === 1, 'Duplicate wildcards should be deduped, got ' + dupCount);
});

test('COMPACT: generateCompactIOCs skips __proto__ keys', () => {
  const { generateCompactIOCs } = require('../../src/ioc/updater.js');
  const input = {
    packages: [
      { name: '__proto__', version: '1.0', severity: 'high' },
      { name: 'normal-pkg', version: '*', severity: 'critical' }
    ],
    pypi_packages: [], hashes: [], markers: [], files: []
  };
  const compact = generateCompactIOCs(input);
  assert(!compact.versioned['__proto__'], '__proto__ should be skipped in versioned');
  assert(compact.wildcards.includes('normal-pkg'), 'normal-pkg should be in wildcards');
});

// ============================================
// BOOTSTRAP COVERAGE TESTS
// ============================================

console.log('\n=== BOOTSTRAP COVERAGE TESTS ===\n');

const { isAllowedRedirect: bootstrapIsAllowedRedirect, ensureIOCs: bootstrapEnsureIOCs, downloadAndDecompress, IOCS_PATH: BOOTSTRAP_IOCS_PATH, HOME_DATA_DIR: BOOTSTRAP_HOME_DATA_DIR, MIN_IOCS_SIZE: BOOTSTRAP_MIN_IOCS_SIZE } = require('../../src/ioc/bootstrap.js');

test('BOOTSTRAP-COV: isAllowedRedirect allows github.com', () => {
  assert(bootstrapIsAllowedRedirect('https://github.com/some/path') === true, 'github.com should be allowed');
});

test('BOOTSTRAP-COV: isAllowedRedirect allows objects.githubusercontent.com', () => {
  assert(bootstrapIsAllowedRedirect('https://objects.githubusercontent.com/some/path') === true, 'objects.githubusercontent.com should be allowed');
});

test('BOOTSTRAP-COV: isAllowedRedirect allows release-assets.githubusercontent.com', () => {
  assert(bootstrapIsAllowedRedirect('https://release-assets.githubusercontent.com/some/path') === true, 'release-assets.githubusercontent.com should be allowed');
});

test('BOOTSTRAP-COV: isAllowedRedirect blocks HTTP protocol', () => {
  assert(bootstrapIsAllowedRedirect('http://github.com/path') === false, 'HTTP should be blocked');
});

test('BOOTSTRAP-COV: isAllowedRedirect blocks unknown domain', () => {
  assert(bootstrapIsAllowedRedirect('https://evil.com/path') === false, 'Unknown domain should be blocked');
});

test('BOOTSTRAP-COV: isAllowedRedirect blocks invalid URL', () => {
  assert(bootstrapIsAllowedRedirect('not-a-url') === false, 'Invalid URL should be blocked');
});

test('BOOTSTRAP-COV: isAllowedRedirect blocks empty string', () => {
  assert(bootstrapIsAllowedRedirect('') === false, 'Empty string should be blocked');
});

await asyncTest('BOOTSTRAP-COV: ensureIOCs returns true when IOC file exists and is large enough', async () => {
  const origExists = fs.existsSync;
  const origStat = fs.statSync;
  fs.existsSync = (p) => {
    if (p === BOOTSTRAP_HOME_DATA_DIR) return true;
    if (p === BOOTSTRAP_IOCS_PATH) return true;
    return origExists(p);
  };
  fs.statSync = (p) => {
    if (p === BOOTSTRAP_IOCS_PATH) return { size: 10_000_000 }; // 10MB > MIN_IOCS_SIZE
    return origStat(p);
  };
  try {
    const result = await bootstrapEnsureIOCs();
    assert(result === true, 'Should return true when IOCs exist');
  } finally {
    fs.existsSync = origExists;
    fs.statSync = origStat;
  }
});

await asyncTest('BOOTSTRAP-COV: ensureIOCs handles download failure gracefully', async () => {
  const origExists = fs.existsSync;
  const origMkdir = fs.mkdirSync;
  const origStderr = process.stderr.write;
  const stderrOutput = [];
  fs.existsSync = (p) => {
    if (p === BOOTSTRAP_HOME_DATA_DIR) return true;
    if (p === BOOTSTRAP_IOCS_PATH) return false; // IOCs don't exist
    return origExists(p);
  };
  process.stderr.write = (msg) => { stderrOutput.push(msg); };
  try {
    const result = await bootstrapEnsureIOCs();
    // Should return false since download fails (no network mock)
    assert(result === false, 'Should return false when download fails');
  } finally {
    fs.existsSync = origExists;
    process.stderr.write = origStderr;
  }
});

await asyncTest('BOOTSTRAP-COV: downloadAndDecompress rejects on invalid URL', async () => {
  try {
    await downloadAndDecompress('https://localhost:1/nonexistent', path.join(os.tmpdir(), 'test-iocs-' + Date.now() + '.json'));
    assert(false, 'Should have thrown');
  } catch (err) {
    assert(err instanceof Error, 'Should throw an Error');
  }
});

// ============================================
// UPDATER COVERAGE TESTS
// ============================================

console.log('\n=== UPDATER COVERAGE TESTS ===\n');

test('UPDATER-COV: generateCompactIOCs handles severity overrides', () => {
  const { generateCompactIOCs } = require('../../src/ioc/updater.js');
  const fullIOCs = {
    packages: [
      { name: 'pkg1', version: '*', severity: 'critical' },
      { name: 'pkg2', version: '1.0', severity: 'high' },
      { name: 'pkg3', version: '2.0', severity: 'medium' }
    ],
    pypi_packages: []
  };
  const compact = generateCompactIOCs(fullIOCs);
  assert(compact.wildcards.includes('pkg1'), 'pkg1 should be in wildcards');
  assert(compact.versioned['pkg2'] !== undefined, 'pkg2 should be in versioned');
  assert(compact.severityOverrides['pkg2'] !== undefined, 'pkg2 should have severity override');
  assert(compact.severityOverrides['pkg2']['1.0'] === 'high', 'pkg2 1.0 should be high');
  assert(compact.severityOverrides['pkg3'] !== undefined, 'pkg3 should have severity override');
  assert(compact.severityOverrides['pkg3']['2.0'] === 'medium', 'pkg3 2.0 should be medium');
  // critical severity should NOT appear in overrides (it's the default)
  assert(!compact.severityOverrides['pkg1'], 'pkg1 (critical) should not have severity override');
});

test('UPDATER-COV: generateCompactIOCs handles PyPI packages', () => {
  const { generateCompactIOCs } = require('../../src/ioc/updater.js');
  const fullIOCs = {
    packages: [],
    pypi_packages: [
      { name: 'py-evil', version: '*' },
      { name: 'py-bad', version: '1.0' }
    ]
  };
  const compact = generateCompactIOCs(fullIOCs);
  assert(compact.pypi_wildcards.includes('py-evil'), 'Should have pypi wildcard');
  assert(compact.pypi_versioned['py-bad'] !== undefined, 'Should have pypi versioned');
  assert(compact.pypi_versioned['py-bad'][0] === '1.0', 'Should have pypi version 1.0');
});

test('UPDATER-COV: generateCompactIOCs skips dangerous keys in severity overrides', () => {
  const { generateCompactIOCs } = require('../../src/ioc/updater.js');
  const fullIOCs = {
    packages: [
      { name: '__proto__', version: '1.0', severity: 'high' },
      { name: 'constructor', version: '2.0', severity: 'medium' },
      { name: 'prototype', version: '3.0', severity: 'high' },
      { name: 'safe-pkg', version: '1.0', severity: 'high' }
    ],
    pypi_packages: []
  };
  const compact = generateCompactIOCs(fullIOCs);
  // __proto__, constructor, prototype should be skipped from severity_overrides
  assert(!compact.severityOverrides || !compact.severityOverrides['__proto__'], 'Should skip __proto__ in severity overrides');
  assert(!compact.severityOverrides || !compact.severityOverrides['constructor'], 'Should skip constructor in severity overrides');
  assert(!compact.severityOverrides || !compact.severityOverrides['prototype'], 'Should skip prototype in severity overrides');
  // safe-pkg should still have its override
  assert(compact.severityOverrides['safe-pkg'] !== undefined, 'safe-pkg should have severity override');
  assert(compact.severityOverrides['safe-pkg']['1.0'] === 'high', 'safe-pkg 1.0 should be high');
});

test('UPDATER-COV: generateCompactIOCs skips dangerous version keys too', () => {
  const { generateCompactIOCs } = require('../../src/ioc/updater.js');
  const fullIOCs = {
    packages: [
      { name: 'some-pkg', version: '__proto__', severity: 'high' },
      { name: 'other-pkg', version: 'constructor', severity: 'medium' }
    ],
    pypi_packages: []
  };
  const compact = generateCompactIOCs(fullIOCs);
  // Packages with dangerous version keys should be skipped from severity_overrides
  assert(!compact.severityOverrides || !compact.severityOverrides['some-pkg'], 'Should skip pkg with __proto__ version from severity overrides');
  assert(!compact.severityOverrides || !compact.severityOverrides['other-pkg'], 'Should skip pkg with constructor version from severity overrides');
});

test('UPDATER-COV: loadCachedIOCs compact file fallback path', () => {
  const { invalidateCache, loadCachedIOCs } = require('../../src/ioc/updater.js');
  // Invalidate cache to force reload
  invalidateCache();

  const origExistsSync = fs.existsSync;
  const origReadFileSync = fs.readFileSync;

  // Mock fs.existsSync to simulate: LOCAL_IOC_FILE does not exist, LOCAL_COMPACT_FILE exists
  const LOCAL_IOC_FILE = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs.json');
  const LOCAL_COMPACT_FILE = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs-compact.json');

  fs.existsSync = (p) => {
    if (p === LOCAL_IOC_FILE) return false; // Force compact fallback
    return origExistsSync(p);
  };

  try {
    const iocs = loadCachedIOCs();
    assert(iocs.packagesMap instanceof Map, 'Should return packagesMap from compact fallback');
    assert(iocs.wildcardPackages instanceof Set, 'Should return wildcardPackages from compact fallback');
  } finally {
    fs.existsSync = origExistsSync;
    // Invalidate cache so mocked results don't affect other tests
    invalidateCache();
  }
});

test('UPDATER-COV: loadCachedIOCs handles compact file load error', () => {
  const { invalidateCache, loadCachedIOCs } = require('../../src/ioc/updater.js');
  invalidateCache();

  const origExistsSync = fs.existsSync;
  const origReadFileSync = fs.readFileSync;
  const origLog = console.log;
  const logs = [];

  const LOCAL_IOC_FILE = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs.json');
  const LOCAL_COMPACT_FILE = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs-compact.json');

  fs.existsSync = (p) => {
    if (p === LOCAL_IOC_FILE) return false; // Force compact fallback
    return origExistsSync(p);
  };
  fs.readFileSync = (p, enc) => {
    if (p === LOCAL_COMPACT_FILE) throw new Error('test compact read error');
    return origReadFileSync(p, enc);
  };
  console.log = (msg) => logs.push(msg);

  try {
    const iocs = loadCachedIOCs();
    assert(iocs.packagesMap instanceof Map, 'Should still return valid IOCs on compact error');
    assert(logs.some(l => l.includes('Failed to load compact IOC database')), 'Should log compact load error');
  } finally {
    fs.existsSync = origExistsSync;
    fs.readFileSync = origReadFileSync;
    console.log = origLog;
    invalidateCache();
  }
});

test('UPDATER-COV: loadCachedIOCs handles cached IOC file load error', () => {
  const { invalidateCache, loadCachedIOCs } = require('../../src/ioc/updater.js');
  invalidateCache();

  const origExistsSync = fs.existsSync;
  const origReadFileSync = fs.readFileSync;
  const origLog = console.log;
  const logs = [];

  const CACHE_IOC_FILE = path.join(os.homedir(), '.muaddib', 'data', 'iocs.json');

  fs.existsSync = (p) => {
    if (p === CACHE_IOC_FILE) return true; // Simulate cache file exists
    return origExistsSync(p);
  };
  fs.readFileSync = (p, enc) => {
    if (p === CACHE_IOC_FILE) throw new Error('test cache read error');
    return origReadFileSync(p, enc);
  };
  console.log = (msg) => logs.push(msg);

  try {
    const iocs = loadCachedIOCs();
    assert(iocs.packagesMap instanceof Map, 'Should still return valid IOCs on cache error');
    assert(logs.some(l => l.includes('Failed to load cached IOCs')), 'Should log cached IOC load error');
  } finally {
    fs.existsSync = origExistsSync;
    fs.readFileSync = origReadFileSync;
    console.log = origLog;
    invalidateCache();
  }
});

// ============================================
// IOC STALENESS TESTS
// ============================================

console.log('\n=== IOC STALENESS TESTS ===\n');

test('STALENESS: checkIOCStaleness returns null for fresh files', () => {
  const { checkIOCStaleness } = require('../../src/ioc/updater.js');
  // Compact file should exist and be recent (we just ran tests)
  const result = checkIOCStaleness(30);
  // If the file is less than 30 days old, should return null
  const compactPath = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs-compact.json');
  if (fs.existsSync(compactPath)) {
    const ageDays = (Date.now() - fs.statSync(compactPath).mtimeMs) / (1000 * 60 * 60 * 24);
    if (ageDays <= 30) {
      assert(result === null, 'Fresh files should return null, got: ' + result);
    } else {
      assert(typeof result === 'string', 'Old files should return a warning string');
      assert(result.includes('muaddib update'), 'Warning should suggest running muaddib update');
    }
  }
});

test('STALENESS: checkIOCStaleness returns warning for old files', () => {
  const { checkIOCStaleness } = require('../../src/ioc/updater.js');
  // With maxAge=0, any existing file should trigger a warning
  const compactPath = path.join(__dirname, '..', '..', 'src', 'ioc', 'data', 'iocs-compact.json');
  if (fs.existsSync(compactPath)) {
    const result = checkIOCStaleness(0);
    assert(typeof result === 'string', 'Should return a warning when maxAge=0');
    assert(result.includes('muaddib update'), 'Warning should suggest muaddib update');
    assert(result.includes('days old'), 'Warning should mention age in days');
  }
});

test('STALENESS: checkIOCStaleness returns null when no IOC files exist', () => {
  const { checkIOCStaleness } = require('../../src/ioc/updater.js');
  const origStatSync = fs.statSync;
  fs.statSync = (p) => { throw new Error('ENOENT'); };
  try {
    const result = checkIOCStaleness(30);
    assert(result === null, 'Should return null when no IOC files exist');
  } finally {
    fs.statSync = origStatSync;
  }
});

test('STALENESS: checkIOCStaleness is exported from updater', () => {
  const updater = require('../../src/ioc/updater.js');
  assert(typeof updater.checkIOCStaleness === 'function', 'checkIOCStaleness should be exported');
});

// --- NEVER_WILDCARD guard tests ---

test('UPDATER: generateCompactIOCs blocks NEVER_WILDCARD packages from wildcards', () => {
  const { generateCompactIOCs, NEVER_WILDCARD } = require('../../src/ioc/updater.js');
  assert(NEVER_WILDCARD instanceof Set, 'NEVER_WILDCARD should be exported as a Set');
  assert(NEVER_WILDCARD.has('event-stream'), 'NEVER_WILDCARD should contain event-stream');

  const fullIOCs = {
    packages: [
      { name: 'event-stream', version: '*', severity: 'critical' },
      { name: 'evil-typosquat', version: '*', severity: 'critical' }
    ],
    pypi_packages: []
  };
  const compact = generateCompactIOCs(fullIOCs);
  assert(!compact.wildcards.includes('event-stream'), 'event-stream should be blocked from wildcards');
  assert(compact.wildcards.includes('evil-typosquat'), 'evil-typosquat should be in wildcards');
});

test('UPDATER: generateCompactIOCs allows NEVER_WILDCARD versioned entries', () => {
  const { generateCompactIOCs } = require('../../src/ioc/updater.js');
  const fullIOCs = {
    packages: [
      { name: 'event-stream', version: '3.3.6', severity: 'critical' },
      { name: 'event-stream', version: '*', severity: 'critical' },
      { name: 'ua-parser-js', version: '0.7.29', severity: 'critical' }
    ],
    pypi_packages: []
  };
  const compact = generateCompactIOCs(fullIOCs);
  // event-stream wildcard blocked, but versioned entry should be present
  assert(!compact.wildcards.includes('event-stream'), 'event-stream wildcard should be blocked');
  assert(compact.versioned['event-stream'] !== undefined, 'event-stream should have versioned entries');
  assert(compact.versioned['event-stream'].includes('3.3.6'), 'event-stream 3.3.6 should be in versioned');
  // ua-parser-js versioned entry should also work
  assert(compact.versioned['ua-parser-js'] !== undefined, 'ua-parser-js should have versioned entries');
  assert(compact.versioned['ua-parser-js'].includes('0.7.29'), 'ua-parser-js 0.7.29 should be in versioned');
});

test('UPDATER: generateCompactIOCs allows non-NEVER_WILDCARD wildcards', () => {
  const { generateCompactIOCs } = require('../../src/ioc/updater.js');
  const fullIOCs = {
    packages: [
      { name: 'totally-evil-pkg', version: '*', severity: 'critical' },
      { name: 'another-malware', version: '*', severity: 'critical' }
    ],
    pypi_packages: []
  };
  const compact = generateCompactIOCs(fullIOCs);
  assert(compact.wildcards.includes('totally-evil-pkg'), 'Non-protected pkg should be in wildcards');
  assert(compact.wildcards.includes('another-malware'), 'Non-protected pkg should be in wildcards');
});

}

module.exports = { runUpdaterTests };
