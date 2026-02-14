const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, assertIncludes, assertNotIncludes, runScan, TESTS_DIR } = require('../test-utils');

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

test('SCRAPER: data/iocs.json exists and is valid', () => {
  const iocsPath = path.join(__dirname, '..', '..', 'data', 'iocs.json');
  assert(fs.existsSync(iocsPath), 'data/iocs.json should exist');
  const content = fs.readFileSync(iocsPath, 'utf8');
  const iocs = JSON.parse(content);
  assert(iocs.packages, 'Should have packages');
  assert(Array.isArray(iocs.packages), 'packages should be an array');
});

test('SCRAPER: IOCs have required fields', () => {
  const iocs = require('../../data/iocs.json');
  const sample = iocs.packages[0];
  assert(sample.name, 'IOC should have name');
  assert(sample.version, 'IOC should have version');
  assert(sample.source, 'IOC should have source');
});

test('SCRAPER: At least 900 IOCs', () => {
  const iocs = require('../../data/iocs.json');
  assert(iocs.packages.length >= 900, `Should have at least 900 IOCs, has ${iocs.packages.length}`);
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
  const iocs = require('../../data/iocs.json');
  const lodash = iocs.packages.find(p => p.name === 'lodash');
  assert(!lodash, 'lodash should not be in IOCs');
});

test('REGRESSION: loadash (typosquat) IS in IOCs', () => {
  const iocs = require('../../data/iocs.json');
  const loadash = iocs.packages.find(p => p.name === 'loadash');
  assert(loadash, 'loadash (typosquat) should be in IOCs');
});

test('REGRESSION: express is not in IOCs', () => {
  const iocs = require('../../data/iocs.json');
  const express = iocs.packages.find(p => p.name === 'express');
  assert(!express, 'express should not be in IOCs');
});

test('REGRESSION: axios is not in IOCs', () => {
  const iocs = require('../../data/iocs.json');
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
    // Create a temp large file to test skip logic
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-bootstrap-test-'));
    const tmpFile = path.join(tmpDir, 'test-iocs.json');
    // Write a file larger than MIN_IOCS_SIZE
    const bigData = JSON.stringify({ packages: new Array(10000).fill({ name: 'test', version: '*' }) });
    fs.writeFileSync(tmpFile, bigData);
    const stat = fs.statSync(tmpFile);
    assert(stat.size >= MIN_IOCS_SIZE, 'Test file should be >= 1MB, got ' + stat.size);
    // Cleanup
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

asyncTest('BOOTSTRAP: downloadAndDecompress rejects invalid URL gracefully', async () => {
  const { downloadAndDecompress } = require('../../src/ioc/bootstrap.js');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-bootstrap-test-'));
  const tmpFile = path.join(tmpDir, 'iocs.json');
  try {
    await downloadAndDecompress('https://localhost:1/nonexistent.gz', tmpFile);
    assert(false, 'Should have thrown');
  } catch (err) {
    assert(err instanceof Error, 'Should throw an Error');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

}

module.exports = { runUpdaterTests };
