const fs = require('fs');
const path = require('path');
const os = require('os');

let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

async function test(name, fn) {
  try {
    await fn();
    console.log('[PASS] ' + name);
    passed++;
  } catch (e) {
    console.log('[FAIL] ' + name);
    console.log('       ' + e.message);
    failures.push({ name, error: e.message });
    failed++;
  }
}

// ── Mock setup ──
// Replace npm-registry.js in require.cache BEFORE typosquat.js loads,
// because typosquat.js captures getPackageMetadata by value at import time.

const npmRegistryPath = require.resolve('../src/scanner/npm-registry.js');

let mockMetadata = {};  // packageName -> metadata (or null for 404)
let apiCallCount = 0;

require.cache[npmRegistryPath] = {
  id: npmRegistryPath,
  filename: npmRegistryPath,
  loaded: true,
  exports: {
    getPackageMetadata: async function(packageName) {
      apiCallCount++;
      if (packageName in mockMetadata) {
        return mockMetadata[packageName];
      }
      return null; // 404 by default
    }
  }
};

// Clear typosquat.js from cache so it picks up our mock
const typosquatPath = require.resolve('../src/scanner/typosquat.js');
delete require.cache[typosquatPath];

const { scanTyposquatting, clearMetadataCache } = require('../src/scanner/typosquat.js');

// ── Helpers ──

function createTempPkg(deps) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'typo-mf-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
    dependencies: deps
  }));
  return tmp;
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

function resetMock(metadata) {
  mockMetadata = metadata;
  apiCallCount = 0;
  clearMetadataCache();
}

// ── Tests ──

(async () => {
  console.log('\n=== TYPOSQUAT MULTI-FACTOR TESTS ===\n');

  // Test 1: Recent package (< 7 days) → CRITICAL + age<7d
  await test('MF: age < 7 days scores CRITICAL with age<7d factor', async () => {
    resetMock({
      'lodahs': {
        created_at: new Date(Date.now() - 3 * 86400000).toISOString(),
        age_days: 3,
        weekly_downloads: 5,
        author_package_count: 1,
        has_readme: false,
        has_repository: false
      }
    });
    const tmp = createTempPkg({ 'lodahs': '^1.0.0' });
    try {
      const threats = await scanTyposquatting(tmp);
      assert(threats.length === 1, 'Should detect 1 typosquat, got ' + threats.length);
      assert(threats[0].severity === 'CRITICAL', 'Severity should be CRITICAL, got ' + threats[0].severity);
      assert(threats[0].details.factors.includes('age<7d'), 'Factors should include age<7d, got ' + threats[0].details.factors);
    } finally {
      cleanup(tmp);
    }
  });

  // Test 2: Low downloads (< 100) → downloads<100 factor
  await test('MF: downloads < 100 has downloads<100 factor', async () => {
    resetMock({
      'axois': {
        created_at: '2020-01-01T00:00:00.000Z',
        age_days: 2000,
        weekly_downloads: 50,
        author_package_count: 10,
        has_readme: true,
        has_repository: true
      }
    });
    const tmp = createTempPkg({ 'axois': '^1.0.0' });
    try {
      const threats = await scanTyposquatting(tmp);
      assert(threats.length === 1, 'Should detect 1 typosquat');
      assert(threats[0].details.factors.includes('downloads<100'), 'Factors should include downloads<100, got ' + threats[0].details.factors);
      assert(threats[0].details.composite_score >= 25, 'Composite score should be >= 25, got ' + threats[0].details.composite_score);
    } finally {
      cleanup(tmp);
    }
  });

  // Test 3: Single author package → single_pkg_author factor
  await test('MF: author_package_count <= 1 has single_pkg_author factor', async () => {
    resetMock({
      'expres': {
        created_at: '2020-01-01T00:00:00.000Z',
        age_days: 2000,
        weekly_downloads: 5000,
        author_package_count: 1,
        has_readme: true,
        has_repository: true
      }
    });
    const tmp = createTempPkg({ 'expres': '^4.0.0' });
    try {
      const threats = await scanTyposquatting(tmp);
      assert(threats.length === 1, 'Should detect 1 typosquat');
      assert(threats[0].details.factors.includes('single_pkg_author'), 'Factors should include single_pkg_author, got ' + threats[0].details.factors);
      assert(threats[0].details.composite_score >= 20, 'Composite score should be >= 20, got ' + threats[0].details.composite_score);
    } finally {
      cleanup(tmp);
    }
  });

  // Test 4: Legitimate packages do NOT trigger typosquat
  await test('MF: lodash and express do NOT trigger typosquat', async () => {
    resetMock({});
    const tmp = createTempPkg({ 'lodash': '^4.0.0', 'express': '^4.0.0' });
    try {
      const threats = await scanTyposquatting(tmp);
      assert(threats.length === 0, 'Should detect 0 typosquats, got ' + threats.length);
      assert(apiCallCount === 0, 'Should make 0 API calls, made ' + apiCallCount);
    } finally {
      cleanup(tmp);
    }
  });

  // Test 5: Package not on npm (404) → not_on_npm factor + 20 points
  await test('MF: 404 package has not_on_npm factor and +20 points', async () => {
    resetMock({}); // empty = everything returns null (404)
    const tmp = createTempPkg({ 'lodahs': '^1.0.0' });
    try {
      const threats = await scanTyposquatting(tmp);
      assert(threats.length === 1, 'Should detect 1 typosquat');
      assert(threats[0].details.factors.includes('not_on_npm'), 'Factors should include not_on_npm, got ' + threats[0].details.factors);
      assert(threats[0].details.composite_score === 20, 'Composite score should be 20, got ' + threats[0].details.composite_score);
      assert(threats[0].message.includes('not found on npm'), 'Message should mention not found on npm');
    } finally {
      cleanup(tmp);
    }
  });

  // Test 6: Cache — two scans with same package = only one API call
  await test('MF: cache prevents duplicate API calls', async () => {
    resetMock({
      'lodahs': {
        created_at: '2020-01-01T00:00:00.000Z',
        age_days: 2000,
        weekly_downloads: 50,
        author_package_count: 5,
        has_readme: true,
        has_repository: true
      }
    });
    const tmp = createTempPkg({ 'lodahs': '^1.0.0' });
    try {
      await scanTyposquatting(tmp);
      assert(apiCallCount === 1, 'First scan should make 1 API call, made ' + apiCallCount);

      // Second scan — cache should prevent another API call
      await scanTyposquatting(tmp);
      assert(apiCallCount === 1, 'Second scan should still be 1 API call (cached), made ' + apiCallCount);
    } finally {
      cleanup(tmp);
    }
  });

  // Test 7: Multiple factors combine correctly
  await test('MF: multiple factors combine (no_readme + no_repo + downloads<100)', async () => {
    resetMock({
      'axois': {
        created_at: '2020-01-01T00:00:00.000Z',
        age_days: 2000,
        weekly_downloads: 10,
        author_package_count: 50,
        has_readme: false,
        has_repository: false
      }
    });
    const tmp = createTempPkg({ 'axois': '^1.0.0' });
    try {
      const threats = await scanTyposquatting(tmp);
      assert(threats.length === 1, 'Should detect 1 typosquat');
      const factors = threats[0].details.factors;
      assert(factors.includes('downloads<100'), 'Should have downloads<100');
      assert(factors.includes('no_readme'), 'Should have no_readme');
      assert(factors.includes('no_repo'), 'Should have no_repo');
      // 25 (downloads) + 10 (readme) + 10 (repo) = 45
      assert(threats[0].details.composite_score === 45, 'Composite score should be 45, got ' + threats[0].details.composite_score);
    } finally {
      cleanup(tmp);
    }
  });

  // Test 8: Message format includes metadata details
  await test('MF: message includes Age, Downloads, Confidence', async () => {
    resetMock({
      'lodahs': {
        created_at: '2020-01-01T00:00:00.000Z',
        age_days: 2000,
        weekly_downloads: 50,
        author_package_count: 5,
        has_readme: true,
        has_repository: true
      }
    });
    const tmp = createTempPkg({ 'lodahs': '^1.0.0' });
    try {
      const threats = await scanTyposquatting(tmp);
      const msg = threats[0].message;
      assert(msg.includes('resembles "lodash"'), 'Message should mention lodash');
      assert(msg.includes('Age:'), 'Message should include Age');
      assert(msg.includes('Downloads:'), 'Message should include Downloads');
      assert(msg.includes('Confidence:'), 'Message should include Confidence');
    } finally {
      cleanup(tmp);
    }
  });

  // ── Results ──

  console.log('\n========================================');
  console.log('MULTI-FACTOR RESULTS: ' + passed + ' passed, ' + failed + ' failed');
  console.log('========================================\n');

  if (failures.length > 0) {
    console.log('Failures:');
    failures.forEach(function(f) {
      console.log('  - ' + f.name + ': ' + f.error);
    });
    console.log('');
  }

  process.exit(failed > 0 ? 1 : 0);
})();
