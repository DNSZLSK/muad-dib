'use strict';

const { test, asyncTest, assert } = require('../test-utils');

async function runPyPIRegistryTests() {
  console.log('\n=== PYPI REGISTRY TESTS ===\n');

  const modulePath = require.resolve('../../src/scanner/pypi-registry.js');

  // Replace globalThis.fetch with a mock, then re-require pypi-registry.
  async function withMockedFetch(mockFn, testFn) {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mockFn;
    try {
      delete require.cache[modulePath];
      const mod = require('../../src/scanner/pypi-registry.js');
      await testFn(mod);
    } finally {
      globalThis.fetch = originalFetch;
      delete require.cache[modulePath];
    }
  }

  // ---- Pure helpers (no network needed) ----

  test('PYPI-REGISTRY: extractMaintainerEmails handles simple + wrapped + multi', () => {
    const { extractMaintainerEmails } = require('../../src/scanner/pypi-registry.js')._internal;
    assert(extractMaintainerEmails({ author_email: 'a@b.com' })[0] === 'a@b.com');
    assert(extractMaintainerEmails({ author_email: 'Alice <alice@example.com>' })[0] === 'alice@example.com');
    const multi = extractMaintainerEmails({ author_email: 'a@b.com, c@d.com', maintainer_email: 'm@e.com' });
    assert(multi.length === 3, `expected 3, got ${multi.length}`);
    const dedup = extractMaintainerEmails({ author_email: 'A@B.com', maintainer_email: 'a@b.com' });
    assert(dedup.length === 1, `dedupe failed, got ${dedup.length}`);
    assert(extractMaintainerEmails({}).length === 0, 'empty info should yield empty');
    assert(extractMaintainerEmails(null).length === 0, 'null info should yield empty');
  });

  test('PYPI-REGISTRY: extractReleaseTimes picks earliest file per version', () => {
    const { extractReleaseTimes } = require('../../src/scanner/pypi-registry.js')._internal;
    const out = extractReleaseTimes({
      '0.1.0': [{ upload_time_iso_8601: '2020-01-15T12:00:00Z' }, { upload_time_iso_8601: '2020-01-15T11:00:00Z' }],
      '0.2.0': [{ upload_time_iso_8601: '2020-02-01T08:00:00Z' }],
      'empty': []
    });
    assert(out['0.1.0'] === '2020-01-15T11:00:00Z', 'should pick earliest file');
    assert(out['0.2.0'] === '2020-02-01T08:00:00Z');
    assert(!('empty' in out), 'empty release should be skipped');
  });

  test('PYPI-REGISTRY: PYPI_PACKAGE_REGEX accepts/rejects per PEP 503', () => {
    const { PYPI_PACKAGE_REGEX } = require('../../src/scanner/pypi-registry.js')._internal;
    assert(PYPI_PACKAGE_REGEX.test('requests'));
    assert(PYPI_PACKAGE_REGEX.test('eth-security-auditor'));
    assert(PYPI_PACKAGE_REGEX.test('my_pkg.sub'));
    assert(!PYPI_PACKAGE_REGEX.test('foo/bar'));
    assert(!PYPI_PACKAGE_REGEX.test('../../../etc/passwd'));
    assert(!PYPI_PACKAGE_REGEX.test(''));
  });

  // ---- Network-mocked behaviour ----

  await asyncTest('PYPI-REGISTRY: invalid package name returns null without fetching', async () => {
    let called = false;
    await withMockedFetch(
      () => { called = true; throw new Error('should not fetch'); },
      async ({ getPyPIPackageMetadata }) => {
        const result = await getPyPIPackageMetadata('../../etc');
        assert(result === null);
        assert(!called, 'fetch must NOT be called for invalid names');
      }
    );
  });

  await asyncTest('PYPI-REGISTRY: 404 returns null', async () => {
    await withMockedFetch(
      async () => ({ ok: false, status: 404, headers: { get: () => null }, text: async () => '' }),
      async ({ getPyPIPackageMetadata, _internal }) => {
        _internal._resetCache();
        const result = await getPyPIPackageMetadata('nonexistent-package-xyz-12345');
        assert(result === null, '404 should return null');
      }
    );
  });

  await asyncTest('PYPI-REGISTRY: parses well-formed PyPI JSON', async () => {
    const fakePyPI = {
      info: {
        name: 'fake-pkg',
        version: '1.2.3',
        summary: 'A test package',
        author_email: 'Alice <alice@example.com>',
        maintainer_email: 'bob@example.com',
        home_page: 'https://example.com',
        project_urls: { Source: 'https://github.com/x/y' }
      },
      releases: {
        '1.0.0': [{ upload_time_iso_8601: '2020-01-01T00:00:00Z', yanked: false }],
        '1.1.0': [{ upload_time_iso_8601: '2020-06-01T00:00:00Z', yanked: false }],
        '1.2.3': [{ upload_time_iso_8601: '2021-01-01T00:00:00Z', yanked: false }]
      }
    };
    await withMockedFetch(
      async () => ({ ok: true, status: 200, json: async () => fakePyPI }),
      async ({ getPyPIPackageMetadata, _internal }) => {
        _internal._resetCache();
        const meta = await getPyPIPackageMetadata('fake-pkg');
        assert(meta !== null, 'meta should not be null');
        assert(meta.latest_version === '1.2.3', `got ${meta.latest_version}`);
        assert(meta.version_count === 3, `got ${meta.version_count}`);
        assert(meta.created_at === '2020-01-01T00:00:00Z', `got ${meta.created_at}`);
        assert(meta.latest_release_at === '2021-01-01T00:00:00Z');
        assert(meta.maintainer_emails.length === 2, `got ${meta.maintainer_emails.length}`);
        assert(meta.maintainer_emails.includes('alice@example.com'));
        assert(meta.maintainer_emails.includes('bob@example.com'));
        assert(meta.home_page === 'https://example.com');
        assert(meta.yanked === false);
      }
    );
  });

  await asyncTest('PYPI-REGISTRY: yanked detection on latest version', async () => {
    const fakePyPI = {
      info: { name: 'yanked-pkg', version: '1.0.0' },
      releases: { '1.0.0': [{ upload_time_iso_8601: '2024-01-01T00:00:00Z', yanked: true }] }
    };
    await withMockedFetch(
      async () => ({ ok: true, status: 200, json: async () => fakePyPI }),
      async ({ getPyPIPackageMetadata, _internal }) => {
        _internal._resetCache();
        const meta = await getPyPIPackageMetadata('yanked-pkg');
        assert(meta.yanked === true);
      }
    );
  });

  await asyncTest('PYPI-REGISTRY: cache returns same data within TTL (one fetch only)', async () => {
    let fetchCount = 0;
    await withMockedFetch(
      async () => {
        fetchCount++;
        return {
          ok: true, status: 200,
          json: async () => ({ info: { name: 'cached-pkg', version: '1.0.0' }, releases: { '1.0.0': [{ upload_time_iso_8601: '2024-01-01T00:00:00Z' }] } })
        };
      },
      async ({ getPyPIPackageMetadata, _internal }) => {
        _internal._resetCache();
        await getPyPIPackageMetadata('cached-pkg');
        await getPyPIPackageMetadata('cached-pkg');
        await getPyPIPackageMetadata('cached-pkg');
        assert(fetchCount === 1, `cache should serve subsequent calls, got ${fetchCount} fetches`);
      }
    );
  });

  await asyncTest('PYPI-REGISTRY: negative cache (null) honored within TTL', async () => {
    let fetchCount = 0;
    await withMockedFetch(
      async () => { fetchCount++; return { ok: false, status: 404, headers: { get: () => null }, text: async () => '' }; },
      async ({ getPyPIPackageMetadata, _internal }) => {
        _internal._resetCache();
        await getPyPIPackageMetadata('definitely-not-a-package');
        await getPyPIPackageMetadata('definitely-not-a-package');
        assert(fetchCount === 1, `404 should also be cached, got ${fetchCount} fetches`);
      }
    );
  });
}

module.exports = { runPyPIRegistryTests };
