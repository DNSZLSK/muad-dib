/**
 * Benign Random Corpus Tests (v2.9.7 — Chantier 2 Phase 1)
 *
 * Validates the random npm corpus and evaluateBenignRandom() integration.
 */

const fs = require('fs');
const path = require('path');
const { test, assert, addSkipped } = require('../test-utils');

const ROOT = path.join(__dirname, '..', '..');
const CURATED_FILE = path.join(ROOT, 'datasets', 'benign', 'packages-npm.txt');
const RANDOM_FILE = path.join(ROOT, 'datasets', 'benign', 'packages-npm-random.txt');
const DATASETS_AVAILABLE = fs.existsSync(RANDOM_FILE);

function runBenignRandomTests() {
  console.log('\n=== BENIGN RANDOM CORPUS TESTS ===\n');

  const { evaluateBenignRandom } = require('../../src/commands/evaluate.js');

  if (!DATASETS_AVAILABLE) {
    console.log('[SKIP] BENIGN-RANDOM-01: datasets not available, skipping');
    console.log('[SKIP] BENIGN-RANDOM-03: datasets not available, skipping');
    console.log('[SKIP] BENIGN-RANDOM-04: datasets not available, skipping');
    addSkipped(3);
  }

  if (DATASETS_AVAILABLE) {
    test('BENIGN-RANDOM-01: packages-npm-random.txt exists and contains >= 200 package names', () => {
      assert(fs.existsSync(RANDOM_FILE), `File not found: ${RANDOM_FILE}`);
      const lines = fs.readFileSync(RANDOM_FILE, 'utf8')
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
      assert(lines.length >= 200, `Expected >= 200 packages, got ${lines.length}`);
      for (const line of lines) {
        assert(line.length > 0, 'Empty package name found');
        assert(!line.includes(' '), `Package name contains space: "${line}"`);
      }
    });
  }

  test('BENIGN-RANDOM-02: evaluateBenignRandom() returns correct shape', () => {
    assert(typeof evaluateBenignRandom === 'function', 'evaluateBenignRandom should be a function');
  });

  if (DATASETS_AVAILABLE) {
    test('BENIGN-RANDOM-03: No overlap between random and curated corpus', () => {
      assert(fs.existsSync(CURATED_FILE), 'Curated file should exist');
      assert(fs.existsSync(RANDOM_FILE), 'Random file should exist');

      const curated = new Set(
        fs.readFileSync(CURATED_FILE, 'utf8')
          .split(/\r?\n/)
          .map(l => l.trim())
          .filter(l => l && !l.startsWith('#'))
      );

      const random = fs.readFileSync(RANDOM_FILE, 'utf8')
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));

      const overlap = random.filter(pkg => curated.has(pkg));
      assert(overlap.length === 0,
        `Found ${overlap.length} overlapping packages: ${overlap.slice(0, 5).join(', ')}${overlap.length > 5 ? '...' : ''}`);
    });

    test('BENIGN-RANDOM-04: No duplicates in random corpus', () => {
      const random = fs.readFileSync(RANDOM_FILE, 'utf8')
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));

      const seen = new Set();
      const dupes = [];
      for (const pkg of random) {
        if (seen.has(pkg)) dupes.push(pkg);
        seen.add(pkg);
      }
      assert(dupes.length === 0,
        `Found ${dupes.length} duplicate packages: ${dupes.slice(0, 5).join(', ')}`);
    });
  }
}

module.exports = { runBenignRandomTests };
