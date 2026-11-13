'use strict';

/**
 * scripts/check-overrides.js - guard on npm `overrides` (supply-chain + forgotten pins).
 * Behavioral: the exported checkOverrides() is driven with hand-built package.json /
 * lockfile objects, one per attack or drift shape; plus the real repo files.
 */

const fs = require('fs');
const path = require('path');
const { test, assert } = require('../test-utils');
const { checkOverrides, satisfies, admitsAtLeast } = require('../../scripts/check-overrides.js');

const REG = {
  minimatch: { spec: '11.0.5', advisory: 'x', reason: 'x', firstPatched: '11.0.1', parents: ['eslint', '@eslint/config-array'] }
};

function lockWith({ mm = '11.0.5', eslintRange = '^10.2.6', configRange = '^10.2.4', extra = {} } = {}) {
  return {
    lockfileVersion: 3,
    packages: {
      '': {},
      'node_modules/eslint': { version: '10.10.0', dependencies: { minimatch: eslintRange } },
      'node_modules/@eslint/config-array': { version: '0.23.5', dependencies: { minimatch: configRange } },
      'node_modules/minimatch': { version: mm },
      ...extra
    }
  };
}

function runCheckOverridesTests() {
  console.log('\n=== check-overrides guard ===\n');

  test('OVERRIDES: documented, plain, locked and still needed -> pass', () => {
    const p = checkOverrides({ overrides: { minimatch: '11.0.5' } }, lockWith(), REG);
    assert(p.length === 0, 'expected no violation, got ' + JSON.stringify(p));
  });

  test('OVERRIDES: undocumented override fails', () => {
    const p = checkOverrides({ overrides: { minimatch: '11.0.5', lodash: '4.17.21' } }, lockWith(), REG);
    assert(p.some(x => /"lodash" is not documented/.test(x)), JSON.stringify(p));
  });

  test('OVERRIDES: redirection specs are refused (alias, URL, git, file, link, $ref, nested, wildcard)', () => {
    for (const spec of ['npm:evil-minimatch@1.0.0', 'https://evil.example/mm.tgz', 'git+https://github.com/evil/mm.git',
      'github:evil/mm', 'file:../mm', 'link:../mm', '$minimatch', '*', 'latest', '>=11.0.1', { '.': '11.0.5' }]) {
      const p = checkOverrides({ overrides: { minimatch: spec } }, lockWith(), REG);
      assert(p.some(x => /must be a plain semver/.test(x)), `spec ${JSON.stringify(spec)} accepted: ` + JSON.stringify(p));
    }
  });

  test('OVERRIDES: spec silently changed from the documented one fails', () => {
    const p = checkOverrides({ overrides: { minimatch: '^11.0.5' } }, lockWith(), REG);
    assert(p.some(x => /documented spec is "11.0.5"/.test(x)), JSON.stringify(p));
  });

  test('OVERRIDES: lockfile not regenerated (still resolves the old version) fails', () => {
    const p = checkOverrides({ overrides: { minimatch: '11.0.5' } }, lockWith({ mm: '10.2.6' }), REG);
    assert(p.some(x => /locked at 10.2.6/.test(x)), JSON.stringify(p));
    const nested = lockWith({ extra: { 'node_modules/foo/node_modules/minimatch': { version: '9.0.5' } } });
    const q = checkOverrides({ overrides: { minimatch: '11.0.5' } }, nested, REG);
    assert(q.some(x => /foo\/node_modules\/minimatch is locked at 9.0.5/.test(x)), 'nested instance must be checked: ' + JSON.stringify(q));
  });

  test('OVERRIDES: override no longer needed (every parent accepts the patched version) fails', () => {
    const p = checkOverrides({ overrides: { minimatch: '11.0.5' } }, lockWith({ eslintRange: '^11.0.2', configRange: '^11.0.1' }), REG);
    assert(p.some(x => /no longer needed/.test(x)), JSON.stringify(p));
    const one = checkOverrides({ overrides: { minimatch: '11.0.5' } }, lockWith({ eslintRange: '^11.0.2' }), REG);
    assert(one.length === 0, 'still needed while one parent declares ^10: ' + JSON.stringify(one));
  });

  test('OVERRIDES: admitsAtLeast() asks whether a patched version is reachable', () => {
    assert(admitsAtLeast('^10.2.6', '11.0.1') === false, '^10.2.6 cannot reach 11.0.1');
    assert(admitsAtLeast('^11.0.2', '11.0.1') === true, '^11.0.2 reaches patched versions even though it excludes 11.0.1 itself');
    assert(admitsAtLeast('~10.9.0', '11.0.1') === false && admitsAtLeast('~11.0.0', '11.0.1') === true, 'tilde');
    assert(admitsAtLeast('10.2.6', '11.0.1') === false && admitsAtLeast('11.0.3', '11.0.1') === true, 'exact');
    assert(admitsAtLeast('^0.3.0', '0.3.5') === true && admitsAtLeast('^0.3.0', '0.4.0') === false, '^0.x');
    assert(admitsAtLeast('>=10', '11.0.1') === null, 'unsupported shape');
  });

  test('OVERRIDES: parent range the guard cannot evaluate fails closed', () => {
    // Shapes the hand-written comparison does not model (union, hyphen range, x-range,
    // comparator set, pre-release) must never be read as 'still needed' or 'not needed':
    // the guard refuses and asks for a human review.
    for (const range of ['>=10 <12', '^10.2.6 || ^11.0.1', '10.0.0 - 11.0.5', '11.x', '^11.0.1-rc.1', '*']) {
      const p = checkOverrides({ overrides: { minimatch: '11.0.5' } }, lockWith({ eslintRange: range, configRange: range }), REG);
      assert(p.some(x => /cannot evaluate/.test(x)) && !p.some(x => /no longer needed/.test(x)),
        'range ' + range + ' must fail closed: ' + JSON.stringify(p));
    }
  });

  test('OVERRIDES: stale REGISTRY entry without an override fails', () => {
    const p = checkOverrides({}, lockWith(), REG);
    assert(p.some(x => /REGISTRY documents "minimatch"/.test(x)), JSON.stringify(p));
  });

  test('OVERRIDES: satisfies() for exact, caret and tilde', () => {
    assert(satisfies('11.0.1', '^10.2.6') === false, '^10 excludes 11');
    assert(satisfies('11.0.1', '^11.0.0') === true, '^11.0.0 accepts 11.0.1');
    assert(satisfies('11.0.1', '~11.0.2') === false, '~11.0.2 excludes 11.0.1');
    assert(satisfies('0.3.1', '^0.3.0') === true && satisfies('0.4.0', '^0.3.0') === false, '^0.x semantics');
    assert(satisfies('11.0.5', '11.0.5') === true && satisfies('11.0.6', '11.0.5') === false, 'exact');
    assert(satisfies('11.0.5', '>=11') === null, 'unsupported range shape returns null');
  });

  test('OVERRIDES: the repository package.json + lockfile pass the guard', () => {
    const root = path.join(__dirname, '..', '..');
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
    const p = checkOverrides(pkg, lock);
    assert(p.length === 0, 'repo overrides must pass: ' + JSON.stringify(p));
  });
}

module.exports = { runCheckOverridesTests };
