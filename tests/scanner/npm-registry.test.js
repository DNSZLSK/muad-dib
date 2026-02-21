const { test, asyncTest, assert } = require('../test-utils');

async function runNpmRegistryTests() {
  console.log('\n=== NPM REGISTRY TESTS ===\n');

  const modulePath = require.resolve('../../src/scanner/npm-registry.js');

  // Helper: replace global fetch with a mock, run test, then restore
  async function withMockedFetch(mockFn, testFn) {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFn;
    try {
      // Clear module cache to pick up mocked fetch
      delete require.cache[modulePath];
      const { getPackageMetadata } = require('../../src/scanner/npm-registry.js');
      await testFn(getPackageMetadata);
    } finally {
      globalThis.fetch = originalFetch;
      delete require.cache[modulePath];
    }
  }

  // --- Input validation ---

  await asyncTest('REGISTRY: Rejects invalid package name (path traversal)', async () => {
    await withMockedFetch(
      () => { throw new Error('fetch should not be called'); },
      async (getPackageMetadata) => {
        const result = await getPackageMetadata('../../../etc/passwd');
        assert(result === null, 'Invalid package name should return null');
      }
    );
  });

  await asyncTest('REGISTRY: Rejects empty package name', async () => {
    await withMockedFetch(
      () => { throw new Error('fetch should not be called'); },
      async (getPackageMetadata) => {
        const result = await getPackageMetadata('');
        assert(result === null, 'Empty package name should return null');
      }
    );
  });

  await asyncTest('REGISTRY: Rejects package name with uppercase', async () => {
    await withMockedFetch(
      () => { throw new Error('fetch should not be called'); },
      async (getPackageMetadata) => {
        const result = await getPackageMetadata('BadPackage');
        assert(result === null, 'Uppercase package name should return null');
      }
    );
  });

  // --- Successful metadata fetch ---

  await asyncTest('REGISTRY: Returns correct metadata for valid package', async () => {
    const registryResponse = {
      time: {
        created: '2020-01-15T00:00:00Z',
        '1.0.0': '2020-01-15T00:00:00Z',
        '1.1.0': '2020-06-15T00:00:00Z'
      },
      'dist-tags': { latest: '1.1.0' },
      versions: {
        '1.1.0': {
          maintainers: [{ name: 'testauthor' }],
          repository: { url: 'https://github.com/test/pkg' }
        }
      },
      readme: 'A'.repeat(200),
      maintainers: [{ name: 'testauthor' }]
    };

    const downloadsResponse = { downloads: 50000 };
    const searchResponse = { total: 15 };

    let fetchCallCount = 0;
    const mockFetch = async (url) => {
      fetchCallCount++;
      if (url.includes('registry.npmjs.org/-/v1/search')) {
        return { ok: true, status: 200, json: async () => searchResponse, headers: new Map() };
      }
      if (url.includes('api.npmjs.org/downloads')) {
        return { ok: true, status: 200, json: async () => downloadsResponse, headers: new Map() };
      }
      // Registry metadata
      return { ok: true, status: 200, json: async () => registryResponse, headers: new Map() };
    };

    await withMockedFetch(mockFetch, async (getPackageMetadata) => {
      const result = await getPackageMetadata('express');
      assert(result !== null, 'Should return metadata for valid package');
      assert(result.created_at === '2020-01-15T00:00:00Z', 'created_at should match');
      assert(result.age_days > 0, 'age_days should be positive');
      assert(result.weekly_downloads === 50000, 'weekly_downloads should be 50000');
      assert(result.author_package_count === 15, 'author_package_count should be 15');
      assert(result.has_readme === true, 'has_readme should be true (readme > 100 chars)');
      assert(result.has_repository === true, 'has_repository should be true');
    });
  });

  // --- 404 handling ---

  await asyncTest('REGISTRY: Returns null for 404 (package not found)', async () => {
    const mockFetch = async () => ({
      ok: false,
      status: 404,
      text: async () => 'Not Found',
      headers: new Map()
    });

    await withMockedFetch(mockFetch, async (getPackageMetadata) => {
      const result = await getPackageMetadata('nonexistent-pkg-xyz');
      assert(result === null, '404 should return null');
    });
  });

  // --- Network error handling ---

  await asyncTest('REGISTRY: Returns null on network error (all retries fail)', async () => {
    const mockFetch = async () => {
      throw new Error('Network error');
    };

    await withMockedFetch(mockFetch, async (getPackageMetadata) => {
      const result = await getPackageMetadata('some-package');
      assert(result === null, 'Network errors should return null after retries');
    });
  });

  // --- Non-OK status handling ---

  await asyncTest('REGISTRY: Returns null on 500 server error', async () => {
    const mockFetch = async () => ({
      ok: false,
      status: 500,
      text: async () => 'Internal Server Error',
      headers: new Map()
    });

    await withMockedFetch(mockFetch, async (getPackageMetadata) => {
      const result = await getPackageMetadata('some-package');
      assert(result === null, '500 should return null');
    });
  });

  // --- Metadata with missing fields ---

  await asyncTest('REGISTRY: Handles missing readme and repository gracefully', async () => {
    const registryResponse = {
      time: { created: '2023-06-01T00:00:00Z', '1.0.0': '2023-06-01T00:00:00Z' },
      'dist-tags': { latest: '1.0.0' },
      versions: { '1.0.0': {} }
    };

    const mockFetch = async (url) => {
      if (url.includes('api.npmjs.org/downloads')) {
        return { ok: true, status: 200, json: async () => ({ downloads: 0 }), headers: new Map() };
      }
      return { ok: true, status: 200, json: async () => registryResponse, headers: new Map() };
    };

    await withMockedFetch(mockFetch, async (getPackageMetadata) => {
      const result = await getPackageMetadata('bare-pkg');
      assert(result !== null, 'Should return metadata');
      assert(result.has_readme === false, 'has_readme should be false when no readme');
      assert(result.has_repository === false, 'has_repository should be false when no repository');
      assert(result.weekly_downloads === 0, 'weekly_downloads should be 0');
      assert(result.author_package_count === 0, 'author_package_count should be 0 when no maintainer');
    });
  });

  // --- Scoped package name ---

  await asyncTest('REGISTRY: Accepts scoped package name @scope/pkg', async () => {
    const registryResponse = {
      time: { created: '2023-01-01T00:00:00Z', '1.0.0': '2023-01-01T00:00:00Z' },
      'dist-tags': { latest: '1.0.0' },
      versions: { '1.0.0': { maintainers: [{ name: 'author' }] } },
      readme: 'x'.repeat(200),
      maintainers: [{ name: 'author' }]
    };

    const mockFetch = async (url) => {
      if (url.includes('api.npmjs.org/downloads')) {
        return { ok: true, status: 200, json: async () => ({ downloads: 100 }), headers: new Map() };
      }
      if (url.includes('search')) {
        return { ok: true, status: 200, json: async () => ({ total: 5 }), headers: new Map() };
      }
      return { ok: true, status: 200, json: async () => registryResponse, headers: new Map() };
    };

    await withMockedFetch(mockFetch, async (getPackageMetadata) => {
      const result = await getPackageMetadata('@babel/core');
      assert(result !== null, 'Should accept scoped package name');
      assert(result.created_at === '2023-01-01T00:00:00Z', 'created_at should match');
    });
  });

  // --- 429 rate limit (retry behavior) ---

  await asyncTest('REGISTRY: Retries on 429 rate limit', async () => {
    let callCount = 0;
    const registryResponse = {
      time: { created: '2023-01-01T00:00:00Z', '1.0.0': '2023-01-01T00:00:00Z' },
      'dist-tags': { latest: '1.0.0' },
      versions: { '1.0.0': {} }
    };

    const mockFetch = async (url) => {
      callCount++;
      // First call: 429, second call: success
      if (callCount === 1 && url.includes('registry.npmjs.org/') && !url.includes('search') && !url.includes('downloads')) {
        return {
          ok: false,
          status: 429,
          text: async () => 'Too Many Requests',
          headers: new Map([['retry-after', '1']])
        };
      }
      if (url.includes('api.npmjs.org/downloads')) {
        return { ok: true, status: 200, json: async () => ({ downloads: 10 }), headers: new Map() };
      }
      return { ok: true, status: 200, json: async () => registryResponse, headers: new Map() };
    };

    await withMockedFetch(mockFetch, async (getPackageMetadata) => {
      const result = await getPackageMetadata('rate-limited-pkg');
      assert(result !== null, 'Should succeed after 429 retry');
      assert(callCount >= 2, 'Should have retried at least once, got ' + callCount + ' calls');
    });
  });
}

module.exports = { runNpmRegistryTests };
