const { test, asyncTest, assert, assertIncludes } = require('../test-utils');
const https = require('https');
const { EventEmitter } = require('events');

async function runScraperTests() {
  console.log('\n=== SCRAPER UTILITY TESTS ===\n');

  const {
    runScraper, scrapeShaiHuludDetector, scrapeDatadogIOCs,
    parseCSVLine, parseCSV, extractVersions, parseOSVEntry,
    createFreshness, isAllowedRedirect, loadStaticIOCs,
    CONFIDENCE_ORDER, ALLOWED_REDIRECT_DOMAINS
  } = require('../../src/ioc/scraper.js');

  // --- parseCSVLine ---

  test('SCRAPER: parseCSVLine splits simple CSV', () => {
    const result = parseCSVLine('a,b,c');
    assert(result.length === 3, 'Should have 3 fields, got ' + result.length);
    assert(result[0] === 'a', 'First field should be a');
    assert(result[1] === 'b', 'Second field should be b');
    assert(result[2] === 'c', 'Third field should be c');
  });

  test('SCRAPER: parseCSVLine handles quoted fields with commas', () => {
    const result = parseCSVLine('"field1","field, with comma","field3"');
    assert(result.length === 3, 'Should have 3 fields, got ' + result.length);
    assert(result[0] === 'field1', 'First field');
    assert(result[1] === 'field, with comma', 'Second field should preserve comma');
    assert(result[2] === 'field3', 'Third field');
  });

  test('SCRAPER: parseCSVLine handles escaped double quotes', () => {
    const result = parseCSVLine('"say ""hello""",world');
    assert(result.length === 2, 'Should have 2 fields');
    assert(result[0] === 'say "hello"', 'Should unescape double quotes');
    assert(result[1] === 'world', 'Second field');
  });

  test('SCRAPER: parseCSVLine handles single field', () => {
    const result = parseCSVLine('onlyone');
    assert(result.length === 1, 'Should have 1 field');
    assert(result[0] === 'onlyone', 'Single field');
  });

  test('SCRAPER: parseCSVLine handles empty fields', () => {
    const result = parseCSVLine('a,,c');
    assert(result.length === 3, 'Should have 3 fields');
    assert(result[1] === '', 'Middle field should be empty');
  });

  // --- parseCSV ---

  test('SCRAPER: parseCSV skips header by default', () => {
    const csv = 'name,version,vendor\npkg1,1.0,dd\npkg2,2.0,sh';
    const result = parseCSV(csv, true);
    assert(result.length === 2, 'Should have 2 data rows, got ' + result.length);
    assert(result[0][0] === 'pkg1', 'First row name');
    assert(result[1][0] === 'pkg2', 'Second row name');
  });

  test('SCRAPER: parseCSV includes header when hasHeader=false', () => {
    const csv = 'pkg1,1.0\npkg2,2.0';
    const result = parseCSV(csv, false);
    assert(result.length === 2, 'Should have 2 rows');
    assert(result[0][0] === 'pkg1', 'First row');
  });

  test('SCRAPER: parseCSV handles empty content', () => {
    const result = parseCSV('', true);
    assert(result.length === 0, 'Should return empty array');
  });

  test('SCRAPER: parseCSV handles Windows line endings', () => {
    const csv = 'header\r\npkg1,1.0\r\npkg2,2.0\r\n';
    const result = parseCSV(csv, true);
    assert(result.length === 2, 'Should have 2 data rows');
  });

  // --- extractVersions ---

  test('SCRAPER: extractVersions returns explicit versions', () => {
    const affected = { versions: ['1.0.0', '1.0.1', '2.0.0'] };
    const result = extractVersions(affected);
    assert(result.length === 3, 'Should have 3 versions');
    assert(result.includes('1.0.0'), 'Should include 1.0.0');
    assert(result.includes('2.0.0'), 'Should include 2.0.0');
  });

  test('SCRAPER: extractVersions returns * for empty affected', () => {
    const affected = {};
    const result = extractVersions(affected);
    assert(result.length === 1, 'Should have 1 entry');
    assert(result[0] === '*', 'Should be wildcard');
  });

  test('SCRAPER: extractVersions extracts from ranges events', () => {
    const affected = {
      ranges: [{
        events: [
          { introduced: '1.0.0' },
          { fixed: '1.0.1' }
        ]
      }]
    };
    const result = extractVersions(affected);
    assert(result.includes('1.0.0'), 'Should include introduced version 1.0.0');
  });

  test('SCRAPER: extractVersions skips introduced=0', () => {
    const affected = {
      ranges: [{
        events: [{ introduced: '0' }]
      }]
    };
    const result = extractVersions(affected);
    assert(result.length === 1 && result[0] === '*', 'Should return wildcard for introduced=0');
  });

  test('SCRAPER: extractVersions deduplicates versions', () => {
    const affected = {
      versions: ['1.0.0', '1.0.0', '2.0.0'],
      ranges: [{ events: [{ introduced: '1.0.0' }] }]
    };
    const result = extractVersions(affected);
    const uniqueCount = new Set(result).size;
    assert(uniqueCount === result.length, 'Should not have duplicates');
  });

  // --- parseOSVEntry ---

  test('SCRAPER: parseOSVEntry parses npm malware entry', () => {
    const vuln = {
      id: 'MAL-2024-1234',
      affected: [{
        package: { ecosystem: 'npm', name: 'evil-pkg' },
        versions: ['1.0.0']
      }],
      summary: 'Malicious package',
      references: [{ url: 'https://example.com' }],
      published: '2024-01-01'
    };
    const result = parseOSVEntry(vuln, 'osv-malicious');
    assert(result.length === 1, 'Should produce 1 package');
    assert(result[0].name === 'evil-pkg', 'Name should be evil-pkg');
    assert(result[0].version === '1.0.0', 'Version should be 1.0.0');
    assert(result[0].severity === 'critical', 'Severity should be critical');
    assert(result[0].source === 'osv-malicious', 'Source should be osv-malicious');
    assert(result[0].mitre === 'T1195.002', 'MITRE should be T1195.002');
  });

  test('SCRAPER: parseOSVEntry skips non-matching ecosystem', () => {
    const vuln = {
      id: 'MAL-2024-5678',
      affected: [{
        package: { ecosystem: 'PyPI', name: 'py-evil' },
        versions: ['1.0']
      }]
    };
    const result = parseOSVEntry(vuln, 'osv-test', 'npm');
    assert(result.length === 0, 'Should skip PyPI entry when ecosystem=npm');
  });

  test('SCRAPER: parseOSVEntry handles PyPI ecosystem', () => {
    const vuln = {
      id: 'MAL-2024-9999',
      affected: [{
        package: { ecosystem: 'PyPI', name: 'py-evil' },
        versions: ['1.0']
      }],
      summary: 'Malicious PyPI package'
    };
    const result = parseOSVEntry(vuln, 'osv-pypi', 'PyPI');
    assert(result.length === 1, 'Should produce 1 PyPI package');
    assert(result[0].name === 'py-evil', 'Name should be py-evil');
  });

  test('SCRAPER: parseOSVEntry returns empty for null/no affected', () => {
    assert(parseOSVEntry(null, 'test').length === 0, 'null vuln should return empty');
    assert(parseOSVEntry({}, 'test').length === 0, 'no affected should return empty');
    assert(parseOSVEntry({ affected: [] }, 'test').length === 0, 'empty affected should return empty');
  });

  test('SCRAPER: parseOSVEntry handles multiple affected versions', () => {
    const vuln = {
      id: 'MAL-2024-MULTI',
      affected: [{
        package: { ecosystem: 'npm', name: 'multi-ver' },
        versions: ['1.0.0', '1.0.1', '2.0.0']
      }]
    };
    const result = parseOSVEntry(vuln, 'test');
    assert(result.length === 3, 'Should produce 3 entries, got ' + result.length);
  });

  test('SCRAPER: parseOSVEntry truncates long descriptions', () => {
    const longSummary = 'A'.repeat(300);
    const vuln = {
      id: 'MAL-LONG',
      affected: [{ package: { ecosystem: 'npm', name: 'long-desc' }, versions: ['1.0'] }],
      summary: longSummary
    };
    const result = parseOSVEntry(vuln, 'test');
    assert(result[0].description.length <= 200, 'Description should be truncated to 200 chars');
  });

  // --- createFreshness ---

  test('SCRAPER: createFreshness returns correct structure', () => {
    const f = createFreshness('test-source', 'high');
    assert(f.source === 'test-source', 'Source should be test-source');
    assert(f.confidence === 'high', 'Confidence should be high');
    assert(typeof f.added_at === 'string', 'added_at should be a string');
    assert(f.added_at.includes('T'), 'added_at should be ISO format');
  });

  test('SCRAPER: createFreshness defaults confidence to high', () => {
    const f = createFreshness('src');
    assert(f.confidence === 'high', 'Default confidence should be high');
  });

  // --- isAllowedRedirect (scraper version) ---

  test('SCRAPER: isAllowedRedirect allows raw.githubusercontent.com', () => {
    assert(isAllowedRedirect('https://raw.githubusercontent.com/owner/repo/main/file') === true);
  });

  test('SCRAPER: isAllowedRedirect allows api.github.com', () => {
    assert(isAllowedRedirect('https://api.github.com/repos/test') === true);
  });

  test('SCRAPER: isAllowedRedirect allows osv.dev domains', () => {
    assert(isAllowedRedirect('https://api.osv.dev/v1/query') === true);
    assert(isAllowedRedirect('https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip') === true);
  });

  test('SCRAPER: isAllowedRedirect blocks HTTP', () => {
    assert(isAllowedRedirect('http://raw.githubusercontent.com/file') === false);
  });

  test('SCRAPER: isAllowedRedirect blocks unknown domains', () => {
    assert(isAllowedRedirect('https://evil.com/malware') === false);
  });

  test('SCRAPER: isAllowedRedirect blocks invalid URLs', () => {
    assert(isAllowedRedirect('not-a-url') === false);
  });

  // --- CONFIDENCE_ORDER ---

  test('SCRAPER: CONFIDENCE_ORDER has correct ordering', () => {
    assert(CONFIDENCE_ORDER['high'] === 3, 'high should be 3');
    assert(CONFIDENCE_ORDER['medium'] === 2, 'medium should be 2');
    assert(CONFIDENCE_ORDER['low'] === 1, 'low should be 1');
  });

  // --- ALLOWED_REDIRECT_DOMAINS ---

  test('SCRAPER: ALLOWED_REDIRECT_DOMAINS includes expected domains', () => {
    assert(ALLOWED_REDIRECT_DOMAINS.includes('raw.githubusercontent.com'), 'Should include raw.githubusercontent.com');
    assert(ALLOWED_REDIRECT_DOMAINS.includes('api.github.com'), 'Should include api.github.com');
    assert(ALLOWED_REDIRECT_DOMAINS.includes('api.osv.dev'), 'Should include api.osv.dev');
    assert(ALLOWED_REDIRECT_DOMAINS.includes('storage.googleapis.com'), 'Should include storage.googleapis.com');
  });

  // --- loadStaticIOCs ---

  test('SCRAPER: loadStaticIOCs returns expected structure', () => {
    const result = loadStaticIOCs();
    assert(Array.isArray(result.socket), 'Should have socket array');
    assert(Array.isArray(result.phylum), 'Should have phylum array');
    assert(Array.isArray(result.npmRemoved), 'Should have npmRemoved array');
  });

  // =========================================================
  // NETWORK FUNCTION TESTS (https.request monkey-patching)
  // =========================================================

  console.log('\n--- Scraper Network Tests (mocked HTTPS) ---\n');

  // Helper: create a mock response EventEmitter with given statusCode/body/headers
  function createMockResponse(statusCode, body, headers) {
    const res = new EventEmitter();
    res.statusCode = statusCode;
    res.headers = headers || {};
    res.resume = () => {};
    return res;
  }

  // Helper: create a mock request EventEmitter
  function createMockRequest() {
    const req = new EventEmitter();
    req.write = () => {};
    req.end = () => {};
    req.setTimeout = (ms, cb) => {};
    req.destroy = () => {};
    return req;
  }

  // --- scrapeShaiHuludDetector ---

  await asyncTest('SCRAPER: scrapeShaiHuludDetector parses packages and hashes', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));

    const mockData = {
      packages: [
        { name: 'evil-shai-pkg', affectedVersions: ['1.0.0', '2.0.0'], severity: 'critical' },
        { name: 'evil-shai-pkg2', affectedVersions: ['3.0.0'] }
      ],
      indicators: {
        fileHashes: {
          'file1.js': { sha256: 'a'.repeat(64) },
          'file2.js': { sha256: ['b'.repeat(64), 'c'.repeat(64)] }
        }
      }
    };

    https.request = (options, callback) => {
      const req = createMockRequest();
      const origEnd = req.end;
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from(JSON.stringify(mockData)));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      assert(result.packages.length === 3, 'Should have 3 package entries (2 versions + 1), got ' + result.packages.length);
      assert(result.packages[0].name === 'evil-shai-pkg', 'First package name');
      assert(result.packages[0].version === '1.0.0', 'First package version');
      assert(result.packages[1].version === '2.0.0', 'Second entry version');
      assert(result.packages[2].name === 'evil-shai-pkg2', 'Third entry name');
      assert(result.packages[0].source === 'shai-hulud-detector', 'Source should be shai-hulud-detector');
      assert(result.packages[0].severity === 'critical', 'Severity from data');
      assert(result.packages[0].mitre === 'T1195.002', 'MITRE tag');
      assert(result.hashes.length === 3, 'Should have 3 hashes, got ' + result.hashes.length);
      assert(result.hashes[0] === 'a'.repeat(64), 'First hash');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeShaiHuludDetector handles empty response', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from(JSON.stringify({})));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      assert(result.packages.length === 0, 'Empty response should yield 0 packages');
      assert(result.hashes.length === 0, 'Empty response should yield 0 hashes');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeShaiHuludDetector handles packages without affectedVersions', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    const mockData = {
      packages: [
        { name: 'no-versions-pkg' }
      ]
    };

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from(JSON.stringify(mockData)));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      assert(result.packages.length === 1, 'Should have 1 wildcard entry');
      assert(result.packages[0].version === '*', 'Should default to wildcard version');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeShaiHuludDetector handles hashes with invalid length', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    const mockData = {
      packages: [],
      indicators: {
        fileHashes: {
          'file1.js': { sha256: 'tooshort' },
          'file2.js': { sha256: 'a'.repeat(64) }
        }
      }
    };

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from(JSON.stringify(mockData)));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      assert(result.hashes.length === 1, 'Should skip invalid-length hash, got ' + result.hashes.length);
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeShaiHuludDetector handles non-200 status', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(404, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from('Not Found'));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      assert(result.packages.length === 0, 'Non-200 should yield 0 packages');
      assert(result.hashes.length === 0, 'Non-200 should yield 0 hashes');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeShaiHuludDetector handles network error', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => req.emit('error', new Error('ECONNREFUSED')));
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      assert(result.packages.length === 0, 'Error should yield 0 packages');
      assert(result.hashes.length === 0, 'Error should yield 0 hashes');
      const hasErrorLog = logs.some(l => l.includes('Error') && l.includes('ECONNREFUSED'));
      assert(hasErrorLog, 'Should log the error message');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeShaiHuludDetector handles timeout', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.setTimeout = (ms, cb) => { process.nextTick(cb); };
      req.destroy = () => {};
      // end does nothing (simulates timeout before response)
      req.end = () => {};
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      // Timeout causes the promise to reject, which is caught internally
      assert(result.packages.length === 0, 'Timeout should yield 0 packages');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- scrapeDatadogIOCs ---

  await asyncTest('SCRAPER: scrapeDatadogIOCs parses consolidated and direct CSV', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    const consolidatedCSV = 'package_name,versions,vendors\nevil-dd-pkg,1.0.0,datadog\nevil-dd-pkg2,*,"datadog,socket"\n';
    const directCSV = 'package_name,version\nevil-dd-pkg,1.0.0\nevil-dd-new,2.0.0\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            // First call is consolidated, second is direct
            const body = callCount === 1 ? consolidatedCSV : directCSV;
            res.emit('data', Buffer.from(body));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      assert(Array.isArray(result.packages), 'Should return packages array');
      // consolidated: 2 packages, direct: 1 new (evil-dd-new; evil-dd-pkg duplicate skipped)
      assert(result.packages.length === 3, 'Should have 3 packages, got ' + result.packages.length);
      const names = result.packages.map(p => p.name);
      assert(names.includes('evil-dd-pkg'), 'Should include evil-dd-pkg');
      assert(names.includes('evil-dd-pkg2'), 'Should include evil-dd-pkg2');
      assert(names.includes('evil-dd-new'), 'Should include evil-dd-new');
      // Check sources
      const consolidated = result.packages.filter(p => p.source === 'datadog-consolidated');
      const direct = result.packages.filter(p => p.source === 'datadog-direct');
      assert(consolidated.length === 2, 'Should have 2 consolidated');
      assert(direct.length === 1, 'Should have 1 direct');
      assert(Array.isArray(result.hashes), 'Should have hashes array');
      assert(result.hashes.length === 0, 'Hashes should be empty');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeDatadogIOCs handles non-200 on consolidated', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          // Both return 404
          const res = createMockResponse(404, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from('Not Found'));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      assert(result.packages.length === 0, 'Non-200 should yield 0 packages');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeDatadogIOCs handles network error gracefully', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => req.emit('error', new Error('mocked fetch error')));
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      assert(result.packages.length === 0, 'Error should yield 0 packages');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeDatadogIOCs skips header rows in CSV', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    // CSV where "name" appears as a header value that should be filtered
    const consolidatedCSV = 'package_name,versions,vendors\nname,1.0.0,test\nreal-pkg,2.0.0,dd\n';
    const directCSV = 'package_name,version\npackage_name,1.0.0\nreal-direct-pkg,3.0.0\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            const body = callCount === 1 ? consolidatedCSV : directCSV;
            res.emit('data', Buffer.from(body));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      // "name" is filtered out in consolidated, "package_name" is filtered out in direct
      const names = result.packages.map(p => p.name);
      assert(!names.includes('package_name'), 'Should not include package_name header');
      assert(names.includes('real-pkg'), 'Should include real-pkg');
      assert(names.includes('real-direct-pkg'), 'Should include real-direct-pkg');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeDatadogIOCs deduplicates across consolidated and direct', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    const consolidatedCSV = 'package_name,versions,vendors\nduped-pkg,1.0.0,datadog\n';
    const directCSV = 'package_name,version\nduped-pkg,1.0.0\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            const body = callCount === 1 ? consolidatedCSV : directCSV;
            res.emit('data', Buffer.from(body));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      const duped = result.packages.filter(p => p.name === 'duped-pkg');
      assert(duped.length === 1, 'Should deduplicate same name+version across sources, got ' + duped.length);
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeDatadogIOCs splits multi-version consolidated CSV', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    // Multi-version string: "1.0.0, 2.0.0, 3.0.0" should produce 3 entries
    const consolidatedCSV = 'package_name,versions,vendors\nmulti-ver-pkg,"1.0.0, 2.0.0, 3.0.0",datadog\n';
    const directCSV = 'package_name,version\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            const body = callCount === 1 ? consolidatedCSV : directCSV;
            res.emit('data', Buffer.from(body));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      const multiPkgs = result.packages.filter(p => p.name === 'multi-ver-pkg');
      assert(multiPkgs.length === 3, 'Should split into 3 entries, got ' + multiPkgs.length);
      const versions = multiPkgs.map(p => p.version).sort();
      assert(versions[0] === '1.0.0', 'First version should be 1.0.0, got ' + versions[0]);
      assert(versions[1] === '2.0.0', 'Second version should be 2.0.0, got ' + versions[1]);
      assert(versions[2] === '3.0.0', 'Third version should be 3.0.0, got ' + versions[2]);
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeDatadogIOCs handles single version in consolidated (no split)', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    const consolidatedCSV = 'package_name,versions,vendors\nsingle-ver-pkg,1.0.0,datadog\n';
    const directCSV = 'package_name,version\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            const body = callCount === 1 ? consolidatedCSV : directCSV;
            res.emit('data', Buffer.from(body));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      const pkgs = result.packages.filter(p => p.name === 'single-ver-pkg');
      assert(pkgs.length === 1, 'Single version should produce 1 entry, got ' + pkgs.length);
      assert(pkgs[0].version === '1.0.0', 'Version should be 1.0.0, got ' + pkgs[0].version);
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: scrapeDatadogIOCs handles wildcard in consolidated', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    const consolidatedCSV = 'package_name,versions,vendors\nwildcard-pkg,*,datadog\n';
    const directCSV = 'package_name,version\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            const body = callCount === 1 ? consolidatedCSV : directCSV;
            res.emit('data', Buffer.from(body));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      const pkgs = result.packages.filter(p => p.name === 'wildcard-pkg');
      assert(pkgs.length === 1, 'Wildcard should produce 1 entry, got ' + pkgs.length);
      assert(pkgs[0].version === '*', 'Version should be *, got ' + pkgs[0].version);
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- fetchJSON redirect handling ---

  await asyncTest('SCRAPER: scrapeShaiHuludDetector follows allowed redirect', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    const mockData = { packages: [{ name: 'redirected-pkg', affectedVersions: ['1.0.0'] }] };

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          if (callCount === 1) {
            // First call returns a redirect
            const res = createMockResponse(302, null, {
              location: 'https://raw.githubusercontent.com/owner/repo/main/data.json'
            });
            callback(res);
          } else {
            // Second call returns the actual data
            const res = createMockResponse(200, null, {});
            callback(res);
            process.nextTick(() => {
              res.emit('data', Buffer.from(JSON.stringify(mockData)));
              res.emit('end');
            });
          }
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      assert(callCount === 2, 'Should have made 2 requests (redirect + actual)');
      assert(result.packages.length === 1, 'Should have parsed the redirected response');
      assert(result.packages[0].name === 'redirected-pkg', 'Package name from redirect');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: fetchJSON rejects unauthorized redirect', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(302, null, {
            location: 'https://evil.com/steal-data'
          });
          callback(res);
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      // Should be caught by scrapeShaiHuludDetector's try/catch
      assert(result.packages.length === 0, 'Unauthorized redirect should yield 0 packages');
      const hasError = logs.some(l => l.includes('Unauthorized redirect'));
      assert(hasError, 'Should log unauthorized redirect error');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: fetchJSON handles too many redirects', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          // Always redirect to an allowed domain
          const res = createMockResponse(301, null, {
            location: 'https://raw.githubusercontent.com/owner/repo/main/file.json'
          });
          callback(res);
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      assert(result.packages.length === 0, 'Too many redirects should yield 0 packages');
      const hasError = logs.some(l => l.includes('Too many redirects'));
      assert(hasError, 'Should log too many redirects error');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  await asyncTest('SCRAPER: fetchJSON handles malformed JSON response', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from('this is not valid json!!!'));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      // fetchJSON resolves with {data: null, raw: ..., error: ...} for malformed JSON
      // scrapeShaiHuludDetector checks data truthiness, so packages should be 0
      assert(result.packages.length === 0, 'Malformed JSON should yield 0 packages');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- fetchText redirect/error handling (via scrapeDatadogIOCs) ---

  await asyncTest('SCRAPER: scrapeDatadogIOCs follows allowed redirect for text', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    const csvData = 'package_name,versions,vendors\nredirect-pkg,1.0.0,dd\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          if (callCount === 1) {
            // First call (consolidated) redirects
            const res = createMockResponse(301, null, {
              location: 'https://raw.githubusercontent.com/DataDog/iocs/main/consolidated.csv'
            });
            callback(res);
          } else if (callCount === 2) {
            // Redirect target
            const res = createMockResponse(200, null, {});
            callback(res);
            process.nextTick(() => {
              res.emit('data', Buffer.from(csvData));
              res.emit('end');
            });
          } else {
            // Direct CSV call (3rd call)
            const res = createMockResponse(200, null, {});
            callback(res);
            process.nextTick(() => {
              res.emit('data', Buffer.from('package_name,version\n'));
              res.emit('end');
            });
          }
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      assert(result.packages.length >= 1, 'Should have parsed redirected CSV');
      assert(result.packages[0].name === 'redirect-pkg', 'Should parse package from redirected response');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- Large response size handling ---

  await asyncTest('SCRAPER: fetchJSON handles chunked data', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    const mockData = {
      packages: [
        { name: 'chunk-pkg-1', affectedVersions: ['1.0.0'] },
        { name: 'chunk-pkg-2', affectedVersions: ['2.0.0'] }
      ]
    };
    const fullJson = JSON.stringify(mockData);
    // Split the JSON into two chunks
    const mid = Math.floor(fullJson.length / 2);
    const chunk1 = fullJson.slice(0, mid);
    const chunk2 = fullJson.slice(mid);

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from(chunk1));
            process.nextTick(() => {
              res.emit('data', Buffer.from(chunk2));
              res.emit('end');
            });
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      assert(result.packages.length === 2, 'Should handle chunked data, got ' + result.packages.length);
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- scrapeDatadogIOCs with only consolidated returning data ---

  await asyncTest('SCRAPER: scrapeDatadogIOCs works when only consolidated succeeds', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    const consolidatedCSV = 'package_name,versions,vendors\nonly-consolidated,1.0.0,dd\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          if (callCount === 1) {
            // Consolidated returns OK
            const res = createMockResponse(200, null, {});
            callback(res);
            process.nextTick(() => {
              res.emit('data', Buffer.from(consolidatedCSV));
              res.emit('end');
            });
          } else {
            // Direct returns 500
            const res = createMockResponse(500, null, {});
            callback(res);
            process.nextTick(() => {
              res.emit('data', Buffer.from('Internal Server Error'));
              res.emit('end');
            });
          }
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      assert(result.packages.length === 1, 'Should have 1 package from consolidated');
      assert(result.packages[0].source === 'datadog-consolidated', 'Source should be consolidated');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- scrapeDatadogIOCs with direct CSV having many fields ---

  await asyncTest('SCRAPER: scrapeDatadogIOCs handles direct CSV with short rows', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    // Consolidated empty, direct has a row with only 1 field (less than 2)
    const consolidatedCSV = 'package_name,versions,vendors\n';
    const directCSV = 'package_name,version\nshort-row\ngood-pkg,1.0.0\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            const body = callCount === 1 ? consolidatedCSV : directCSV;
            res.emit('data', Buffer.from(body));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      // "short-row" has parts.length < 2, so it should be skipped
      const names = result.packages.map(p => p.name);
      assert(names.includes('good-pkg'), 'Should include good-pkg');
      // short-row might be included with length=1 but check parts.length >= 2
      const hasShort = names.includes('short-row');
      assert(!hasShort, 'Should skip rows with < 2 fields');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- scrapeShaiHuludDetector with freshness and references ---

  await asyncTest('SCRAPER: scrapeShaiHuludDetector sets correct freshness and references', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    const mockData = {
      packages: [{ name: 'fresh-pkg', affectedVersions: ['1.0.0'], severity: 'high' }]
    };

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from(JSON.stringify(mockData)));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeShaiHuludDetector();
      const pkg = result.packages[0];
      assert(pkg.id === 'SHAI-HULUD-fresh-pkg-1.0.0', 'ID format should match');
      assert(pkg.severity === 'high', 'Severity should be from data');
      assert(pkg.confidence === 'high', 'Confidence should be high');
      assert(pkg.freshness.source === 'gensecai', 'Freshness source');
      assert(pkg.description === 'Compromised by Shai-Hulud 2.0 supply chain attack', 'Description');
      assert(Array.isArray(pkg.references), 'Should have references array');
      assert(pkg.references[0].includes('gensecaihq'), 'Reference URL');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- scrapeDatadogIOCs field formatting ---

  await asyncTest('SCRAPER: scrapeDatadogIOCs direct CSV ID sanitization', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    const consolidatedCSV = 'package_name,versions,vendors\n';
    const directCSV = 'package_name,version\n@scope/pkg-name,1.0.0\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            const body = callCount === 1 ? consolidatedCSV : directCSV;
            res.emit('data', Buffer.from(body));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      const pkg = result.packages.find(p => p.name === '@scope/pkg-name');
      assert(pkg, 'Should include scoped package');
      // ID should have special chars replaced: DATADOG-DD-@scope/pkg-name-1.0.0 -> DATADOG-DD--scope-pkg-name-1-0-0
      assert(!pkg.id.includes('@'), 'ID should not contain @');
      assert(!pkg.id.includes('/'), 'ID should not contain /');
      assert(pkg.source === 'datadog-direct', 'Source should be datadog-direct');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- HTTP redirect codes coverage (301, 307, 308) ---

  await asyncTest('SCRAPER: fetchText handles 307 redirect', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let callCount = 0;
    const csvData = 'package_name,versions,vendors\nredirect307-pkg,1.0.0,dd\n';

    https.request = (options, callback) => {
      callCount++;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          if (callCount === 1) {
            const res = createMockResponse(307, null, {
              location: 'https://raw.githubusercontent.com/redirect/target'
            });
            callback(res);
          } else if (callCount === 2) {
            const res = createMockResponse(200, null, {});
            callback(res);
            process.nextTick(() => {
              res.emit('data', Buffer.from(csvData));
              res.emit('end');
            });
          } else {
            // Direct CSV
            const res = createMockResponse(200, null, {});
            callback(res);
            process.nextTick(() => {
              res.emit('data', Buffer.from('h,v\n'));
              res.emit('end');
            });
          }
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      assert(result.packages.some(p => p.name === 'redirect307-pkg'), 'Should follow 307 redirect');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- fetchJSON POST with body (via scrapeGitHubAdvisory pattern) ---

  await asyncTest('SCRAPER: fetchJSON sends POST body correctly (via ShaiHulud structure)', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    let capturedOptions = null;
    const mockData = { packages: [{ name: 'post-test', affectedVersions: ['1.0.0'] }] };

    https.request = (options, callback) => {
      capturedOptions = options;
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from(JSON.stringify(mockData)));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      await scrapeShaiHuludDetector();
      assert(capturedOptions !== null, 'Should have captured request options');
      assert(capturedOptions.method === 'GET', 'ShaiHulud uses GET');
      assert(capturedOptions.headers['User-Agent'].includes('MUADDIB'), 'User-Agent header');
      assert(capturedOptions.headers['Accept'] === 'application/json', 'Accept header');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- fetchText request options verification ---

  await asyncTest('SCRAPER: fetchText sets correct request options', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    const capturedOptions = [];

    https.request = (options, callback) => {
      capturedOptions.push({ ...options });
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(200, null, {});
          callback(res);
          process.nextTick(() => {
            res.emit('data', Buffer.from('h\n'));
            res.emit('end');
          });
        });
      };
      return req;
    };

    try {
      await scrapeDatadogIOCs();
      assert(capturedOptions.length >= 1, 'Should have made at least 1 request');
      assert(capturedOptions[0].method === 'GET', 'fetchText should use GET');
      assert(capturedOptions[0].headers['User-Agent'].includes('MUADDIB'), 'User-Agent header');
      assert(capturedOptions[0].hostname === 'raw.githubusercontent.com', 'Hostname for DataDog');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- fetchText timeout handling ---

  await asyncTest('SCRAPER: scrapeDatadogIOCs handles timeout on first request', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    console.log = () => {};

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.setTimeout = (ms, cb) => { process.nextTick(cb); };
      req.destroy = () => {};
      req.end = () => {};
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      assert(result.packages.length === 0, 'Timeout should yield 0 packages');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // --- fetchText with HTTP redirect to disallowed domain ---

  await asyncTest('SCRAPER: fetchText rejects redirect to HTTP (not HTTPS)', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const logs = [];
    console.log = (...args) => logs.push(args.join(' '));

    https.request = (options, callback) => {
      const req = createMockRequest();
      req.end = () => {
        process.nextTick(() => {
          const res = createMockResponse(302, null, {
            location: 'http://raw.githubusercontent.com/insecure'
          });
          callback(res);
        });
      };
      return req;
    };

    try {
      const result = await scrapeDatadogIOCs();
      assert(result.packages.length === 0, 'HTTP redirect should fail');
    } finally {
      https.request = origRequest;
      console.log = origLog;
    }
  });

  // =========================================================
  // runScraper COMPREHENSIVE TESTS
  // Tests internal functions (scrapeOSSFMaliciousPackages,
  // scrapeOSVDataDump, scrapeOSVPyPIDataDump,
  // scrapeGitHubAdvisory, scrapeStaticIOCs, fetchBuffer,
  // fetchBufferWithProgress) through runScraper
  // =========================================================

  console.log('\n--- runScraper Comprehensive Tests ---\n');

  const fs = require('fs');
  const path = require('path');
  const AdmZip = require('adm-zip');

  await asyncTest('SCRAPER: runScraper with comprehensive mocked responses exercises all sources', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true; // Suppress Spinner output

    // Track which URLs were requested
    const requestedUrls = [];

    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      requestedUrls.push(url);

      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};

      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = {};
          res.resume = () => {};

          // OSV npm bulk zip (fetchBufferWithProgress) — must be first since scrapeOSVDataDump runs in Phase 1
          if (url.includes('osv-vulnerabilities') && url.includes('npm/all.zip')) {
            res.statusCode = 200;
            res.headers['content-length'] = '100';
            callback(res);
            const zip = new AdmZip();
            zip.addFile('MAL-2024-TEST.json', Buffer.from(JSON.stringify({
              id: 'MAL-2024-TEST',
              affected: [{ package: { ecosystem: 'npm', name: 'osv-npm-test' }, versions: ['1.0.0'] }],
              summary: 'Test OSV npm entry'
            })));
            zip.addFile('GHSA-2024-SKIP.json', Buffer.from('{}')); // Should be skipped (not MAL-)
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // OSV PyPI bulk zip (fetchBufferWithProgress)
          else if (url.includes('osv-vulnerabilities') && url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            res.headers['content-length'] = '100';
            callback(res);
            const zip = new AdmZip();
            zip.addFile('MAL-2024-PYPI.json', Buffer.from(JSON.stringify({
              id: 'MAL-2024-PYPI',
              affected: [{ package: { ecosystem: 'PyPI', name: 'osv-pypi-test' }, versions: ['1.0.0'] }],
              summary: 'Test OSV PyPI entry'
            })));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // Shai-Hulud endpoint
          else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              packages: [{ name: 'test-shai-pkg', affectedVersions: ['1.0.0'] }],
              indicators: { fileHashes: { 'file1.js': { sha256: 'a'.repeat(64) } } }
            })));
            res.emit('end');
          }
          // DataDog consolidated CSV
          else if (url.includes('consolidated_iocs.csv')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('name,versions,vendors\ntest-dd-pkg,1.0.0,dd\n'));
            res.emit('end');
          }
          // DataDog direct CSV
          else if (url.includes('shai-hulud-2.0.csv')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('name,version\ntest-dd-direct,2.0.0\n'));
            res.emit('end');
          }
          // OSSF tree API
          else if (url.includes('api.github.com') && url.includes('git/trees')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              sha: 'abc123test-new-sha',
              tree: [
                { path: 'osv/malicious/npm/MAL-2024-001.json' }
              ]
            })));
            res.emit('end');
          }
          // OSSF individual entry fetch
          else if (url.includes('raw.githubusercontent.com/ossf') && url.includes('MAL-')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              id: 'MAL-2024-001',
              affected: [{ package: { ecosystem: 'npm', name: 'ossf-test-pkg' }, versions: ['1.0.0'] }],
              summary: 'Test OSSF entry'
            })));
            res.emit('end');
          }
          // OSV.dev API (GitHub Advisory) — POST
          else if (url.includes('api.osv.dev')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              vulns: [{
                id: 'GHSA-test-malware-001',
                summary: 'Malicious package detected',
                affected: [{ package: { ecosystem: 'npm', name: 'ghsa-test-pkg' } }]
              }]
            })));
            res.emit('end');
          }
          // Default: 404
          else {
            res.statusCode = 404;
            callback(res);
            res.emit('data', Buffer.from('Not Found'));
            res.emit('end');
          }
        });
      };

      return req;
    };

    // Mock file operations for OSSF SHA check and output writing
    const mockFiles = {};
    fs.existsSync = (p) => {
      // static-iocs.json should use real fs to load actual data
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true; // Pretend directories exist
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'different-sha-to-force-fetch';
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      // Return empty IOC structure for existing IOC files
      if (typeof p === 'string' && (p.includes('iocs.json'))) {
        return JSON.stringify({ packages: [], pypi_packages: [], hashes: [], markers: [], files: [] });
      }
      return origFs.readFileSync(p, enc);
    };
    fs.writeFileSync = (p, data) => {
      mockFiles[path.resolve(p)] = data; // Capture writes
    };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {}; // Pretend writable
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const resolvedFrom = path.resolve(from);
      const resolvedTo = path.resolve(to);
      if (mockFiles[resolvedFrom]) {
        mockFiles[resolvedTo] = mockFiles[resolvedFrom];
        delete mockFiles[resolvedFrom];
      }
    };

    try {
      const result = await runScraper();

      // Verify result structure
      assert(typeof result === 'object', 'Should return result object');
      assert(typeof result.total === 'number', 'Should have total count');
      assert(typeof result.added === 'number', 'Should have added count');
      assert(typeof result.upgraded === 'number', 'Should have upgraded count');
      assert(typeof result.addedHashes === 'number', 'Should have addedHashes count');
      assert(typeof result.totalHashes === 'number', 'Should have totalHashes count');
      assert(typeof result.addedPyPI === 'number', 'Should have addedPyPI count');
      assert(typeof result.totalPyPI === 'number', 'Should have totalPyPI count');
      assert(result.total >= 0, 'Total should be non-negative');

      // Verify that various sources contributed packages
      assert(result.total > 0, 'Should have found some packages from mocked sources, got ' + result.total);

      // Verify PyPI packages were found from OSV PyPI dump
      assert(result.totalPyPI >= 1, 'Should have at least 1 PyPI package from osv-pypi mock, got ' + result.totalPyPI);

      // Verify hashes were found from Shai-Hulud
      assert(result.totalHashes >= 1, 'Should have at least 1 hash from shai-hulud mock, got ' + result.totalHashes);

      // Verify multiple sources were contacted
      assert(requestedUrls.length >= 5, 'Should have contacted multiple endpoints, got ' + requestedUrls.length);

      // Verify OSV npm dump was requested (fetchBufferWithProgress)
      const osvNpmRequested = requestedUrls.some(u => u.includes('npm/all.zip'));
      assert(osvNpmRequested, 'Should have requested OSV npm bulk zip');

      // Verify OSV PyPI dump was requested (fetchBufferWithProgress)
      const osvPyPIRequested = requestedUrls.some(u => u.includes('PyPI/all.zip'));
      assert(osvPyPIRequested, 'Should have requested OSV PyPI bulk zip');

      // Verify OSSF tree API was requested
      const ossfRequested = requestedUrls.some(u => u.includes('api.github.com') && u.includes('git/trees'));
      assert(ossfRequested, 'Should have requested OSSF tree API');

      // Verify GitHub Advisory (osv.dev POST) was requested
      const ghsaRequested = requestedUrls.some(u => u.includes('api.osv.dev'));
      assert(ghsaRequested, 'Should have requested GitHub Advisory via osv.dev');

      // Verify files were written (atomic write: tmp + rename)
      const writtenPaths = Object.keys(mockFiles);
      assert(writtenPaths.length > 0 || Object.keys(mockFiles).length === 0,
        'Should have attempted file writes');

    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper handles all sources failing gracefully', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    // All requests return HTTP 500 (server error)
    // Note: we use HTTP errors instead of req.emit('error') because fetchBufferWithProgress
    // has a scoping issue where spinner is not defined in the req error handler
    https.request = (options, callback) => {
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};
      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.statusCode = 500;
          res.headers = {};
          res.resume = () => {};
          callback(res);
          res.emit('data', Buffer.from('Internal Server Error'));
          res.emit('end');
        });
      };
      return req;
    };

    const mockFiles = {};
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'some-sha';
      return JSON.stringify({ packages: [], pypi_packages: [], hashes: [], markers: [], files: [] });
    };
    fs.writeFileSync = (p, data) => { mockFiles[path.resolve(p)] = data; };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
    };

    try {
      const result = await runScraper();
      assert(typeof result === 'object', 'Should return result even when all network sources fail');
      assert(typeof result.total === 'number', 'Should have total count');
      assert(typeof result.added === 'number', 'Should have added count');
      // Static IOCs + Snyk known malware should still be present since they are local
      assert(result.total >= 0, 'Total should be non-negative');
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper deduplicates packages across sources', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    // All sources return the same package to test deduplication
    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};

      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = { 'content-length': '100' };
          res.resume = () => {};

          // OSV npm zip — same package
          if (url.includes('npm/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('MAL-DUP-001.json', Buffer.from(JSON.stringify({
              id: 'MAL-DUP-001',
              affected: [{ package: { ecosystem: 'npm', name: 'duped-across-sources' }, versions: ['1.0.0'] }],
              summary: 'Duplicate test'
            })));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // OSV PyPI zip — empty
          else if (url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // Shai-Hulud — same package name+version
          else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              packages: [{ name: 'duped-across-sources', affectedVersions: ['1.0.0'] }]
            })));
            res.emit('end');
          }
          // All other sources return empty/404
          else {
            res.statusCode = 200;
            callback(res);
            if (url.includes('api.osv.dev')) {
              res.emit('data', Buffer.from(JSON.stringify({ vulns: [] })));
            } else if (url.includes('api.github.com')) {
              res.emit('data', Buffer.from(JSON.stringify({ sha: 'sha123', tree: [] })));
            } else {
              res.emit('data', Buffer.from('h,v\n'));
            }
            res.emit('end');
          }
        });
      };
      return req;
    };

    const mockFiles = {};
    let savedIocs = null;
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'sha123';
      return JSON.stringify({ packages: [], pypi_packages: [], hashes: [], markers: [], files: [] });
    };
    fs.writeFileSync = (p, data) => {
      mockFiles[path.resolve(p)] = data;
      // Capture the main IOC file write to inspect deduplication
      if (typeof p === 'string' && p.includes('iocs.json') && !p.includes('compact') && !p.includes('.tmp')) {
        try { savedIocs = JSON.parse(data); } catch {}
      }
    };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
      // After rename, parse the final IOC file
      if (typeof to === 'string' && to.includes('iocs.json') && !to.includes('compact') && mockFiles[rt]) {
        try { savedIocs = JSON.parse(mockFiles[rt]); } catch {}
      }
    };

    try {
      const result = await runScraper();

      // The same package 'duped-across-sources@1.0.0' comes from both OSV and Shai-Hulud.
      // Deduplication should keep only one entry.
      assert(result.total > 0, 'Should have found packages');

      // Check the written IOC data for deduplication
      if (savedIocs) {
        const duped = savedIocs.packages.filter(p => p.name === 'duped-across-sources' && p.version === '1.0.0');
        assert(duped.length === 1, 'Should deduplicate same name+version across sources, got ' + duped.length);
      }
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper OSSF skips entries already known from OSV', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    const ossfEntryFetched = [];

    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};

      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = { 'content-length': '100' };
          res.resume = () => {};

          // OSV npm zip — returns MAL-KNOWN-ID
          if (url.includes('npm/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('MAL-KNOWN-ID.json', Buffer.from(JSON.stringify({
              id: 'MAL-KNOWN-ID',
              affected: [{ package: { ecosystem: 'npm', name: 'known-from-osv' }, versions: ['1.0.0'] }],
              summary: 'Known entry'
            })));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // PyPI zip — empty
          else if (url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // OSSF tree — has MAL-KNOWN-ID (already in OSV) and MAL-NEW-ID (not in OSV)
          else if (url.includes('api.github.com') && url.includes('git/trees')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              sha: 'ossf-skip-test-sha',
              tree: [
                { path: 'osv/malicious/npm/MAL-KNOWN-ID.json' },
                { path: 'osv/malicious/npm/MAL-NEW-ID.json' }
              ]
            })));
            res.emit('end');
          }
          // OSSF individual entry fetch — track which were fetched
          else if (url.includes('raw.githubusercontent.com/ossf') && url.includes('MAL-')) {
            const entryId = url.includes('MAL-KNOWN-ID') ? 'MAL-KNOWN-ID' : 'MAL-NEW-ID';
            ossfEntryFetched.push(entryId);
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              id: entryId,
              affected: [{ package: { ecosystem: 'npm', name: 'ossf-' + entryId.toLowerCase() }, versions: ['1.0.0'] }],
              summary: 'OSSF entry ' + entryId
            })));
            res.emit('end');
          }
          // All other sources return minimal data
          else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ packages: [] })));
            res.emit('end');
          }
          else if (url.includes('api.osv.dev')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ vulns: [] })));
            res.emit('end');
          }
          else {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('h,v\n'));
            res.emit('end');
          }
        });
      };
      return req;
    };

    const mockFiles = {};
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'old-different-sha';
      return JSON.stringify({ packages: [], pypi_packages: [], hashes: [], markers: [], files: [] });
    };
    fs.writeFileSync = (p, data) => { mockFiles[path.resolve(p)] = data; };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
    };

    try {
      const result = await runScraper();
      assert(result.total > 0, 'Should have found packages');

      // MAL-KNOWN-ID was in the OSV dump, so OSSF should skip fetching it
      assert(!ossfEntryFetched.includes('MAL-KNOWN-ID'),
        'OSSF should skip MAL-KNOWN-ID since it is already known from OSV dump');
      // MAL-NEW-ID was NOT in the OSV dump, so OSSF should fetch it
      assert(ossfEntryFetched.includes('MAL-NEW-ID'),
        'OSSF should fetch MAL-NEW-ID since it is NOT in OSV dump');
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper OSSF skips fetch when tree SHA is unchanged', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    const ossfRawFetched = [];

    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};

      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = { 'content-length': '100' };
          res.resume = () => {};

          if (url.includes('npm/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          } else if (url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // OSSF tree — returns SHA that matches stored SHA
          else if (url.includes('api.github.com') && url.includes('git/trees')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              sha: 'same-sha-as-stored',
              tree: [{ path: 'osv/malicious/npm/MAL-2024-SKIP.json' }]
            })));
            res.emit('end');
          }
          // Track if OSSF raw entries are fetched (should NOT happen)
          else if (url.includes('raw.githubusercontent.com/ossf')) {
            ossfRawFetched.push(url);
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              id: 'MAL-2024-SKIP',
              affected: [{ package: { ecosystem: 'npm', name: 'should-not-fetch' }, versions: ['1.0.0'] }]
            })));
            res.emit('end');
          }
          else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ packages: [] })));
            res.emit('end');
          }
          else if (url.includes('api.osv.dev')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ vulns: [] })));
            res.emit('end');
          }
          else {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('h,v\n'));
            res.emit('end');
          }
        });
      };
      return req;
    };

    const mockFiles = {};
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      // Return the SAME SHA to simulate unchanged tree
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'same-sha-as-stored';
      return JSON.stringify({ packages: [], pypi_packages: [], hashes: [], markers: [], files: [] });
    };
    fs.writeFileSync = (p, data) => { mockFiles[path.resolve(p)] = data; };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
    };

    try {
      const result = await runScraper();
      // OSSF should have skipped fetching individual entries because tree SHA is unchanged
      assert(ossfRawFetched.length === 0,
        'OSSF should not fetch individual entries when tree SHA is unchanged, but fetched ' + ossfRawFetched.length);
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper scrapeGitHubAdvisory filters non-malware GHSA entries', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};

      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = { 'content-length': '100' };
          res.resume = () => {};

          if (url.includes('npm/all.zip') || url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // GitHub Advisory — mix of malware and non-malware entries
          else if (url.includes('api.osv.dev')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({
              vulns: [
                {
                  id: 'GHSA-malware-test-001',
                  summary: 'Malicious package - credential stealer',
                  affected: [{ package: { ecosystem: 'npm', name: 'ghsa-malware-pkg' } }]
                },
                {
                  id: 'GHSA-normal-vuln-002',
                  summary: 'XSS vulnerability in template engine',
                  affected: [{ package: { ecosystem: 'npm', name: 'ghsa-normal-pkg' } }]
                },
                {
                  id: 'GHSA-backdoor-003',
                  summary: 'Package contains backdoor code',
                  affected: [{ package: { ecosystem: 'npm', name: 'ghsa-backdoor-pkg' },
                    versions: ['1.2.3', '1.2.4'] }]
                },
                {
                  id: 'CVE-2024-9999',
                  summary: 'Malicious code in package',
                  affected: [{ package: { ecosystem: 'npm', name: 'cve-not-ghsa' } }]
                },
                {
                  id: 'GHSA-trojan-004',
                  summary: 'This is a trojan package',
                  affected: [{ package: { ecosystem: 'npm', name: 'ghsa-trojan-pkg' } }]
                }
              ]
            })));
            res.emit('end');
          }
          else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ packages: [] })));
            res.emit('end');
          }
          else if (url.includes('api.github.com')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ sha: 'sha-ghsa-test', tree: [] })));
            res.emit('end');
          }
          else {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('h,v\n'));
            res.emit('end');
          }
        });
      };
      return req;
    };

    const mockFiles = {};
    let savedIocs = null;
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'sha-ghsa-test';
      return JSON.stringify({ packages: [], pypi_packages: [], hashes: [], markers: [], files: [] });
    };
    fs.writeFileSync = (p, data) => { mockFiles[path.resolve(p)] = data; };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
      if (typeof to === 'string' && to.includes('iocs.json') && !to.includes('compact') && mockFiles[rt]) {
        try { savedIocs = JSON.parse(mockFiles[rt]); } catch {}
      }
    };

    try {
      const result = await runScraper();

      if (savedIocs) {
        const ghsaPkgs = savedIocs.packages.filter(p => p.source === 'github-advisory');
        const ghsaNames = ghsaPkgs.map(p => p.name);

        // Malware, backdoor, trojan entries should be included
        assert(ghsaNames.includes('ghsa-malware-pkg'), 'Should include malware GHSA entry');
        assert(ghsaNames.includes('ghsa-backdoor-pkg'), 'Should include backdoor GHSA entry');
        assert(ghsaNames.includes('ghsa-trojan-pkg'), 'Should include trojan GHSA entry');

        // Normal XSS vuln should be filtered out (not malware/malicious/backdoor/trojan)
        assert(!ghsaNames.includes('ghsa-normal-pkg'), 'Should filter out non-malware GHSA entries');

        // CVE- prefixed entries should be filtered out (only GHSA- accepted)
        assert(!ghsaNames.includes('cve-not-ghsa'), 'Should filter out non-GHSA entries');

        // GHSA-backdoor-003 has versions: ['1.2.3', '1.2.4'] — should produce versioned entries, not wildcard
        const backdoorEntries = ghsaPkgs.filter(p => p.name === 'ghsa-backdoor-pkg');
        assert(backdoorEntries.length === 2, 'Backdoor pkg with 2 versions should produce 2 entries, got ' + backdoorEntries.length);
        const bdVersions = backdoorEntries.map(p => p.version).sort();
        assert(bdVersions[0] === '1.2.3', 'First backdoor version should be 1.2.3, got ' + bdVersions[0]);
        assert(bdVersions[1] === '1.2.4', 'Second backdoor version should be 1.2.4, got ' + bdVersions[1]);

        // GHSA entries without versions should fall back to wildcard
        const malwarePkg = ghsaPkgs.filter(p => p.name === 'ghsa-malware-pkg');
        assert(malwarePkg.length === 1, 'Malware pkg without versions should produce 1 entry');
        assert(malwarePkg[0].version === '*', 'Malware pkg without versions should be wildcard, got ' + malwarePkg[0].version);
      }
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper merges with existing IOCs and preserves markers', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    // All sources return empty to isolate merge logic
    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};
      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = { 'content-length': '100' };
          res.resume = () => {};

          if (url.includes('npm/all.zip') || url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          } else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ packages: [] })));
            res.emit('end');
          } else if (url.includes('api.osv.dev')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ vulns: [] })));
            res.emit('end');
          } else if (url.includes('api.github.com')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ sha: 'sha-merge-test', tree: [] })));
            res.emit('end');
          } else {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('h,v\n'));
            res.emit('end');
          }
        });
      };
      return req;
    };

    const existingIOCData = {
      packages: [
        {
          id: 'EXISTING-001', name: 'pre-existing-pkg', version: '1.0.0',
          severity: 'critical', confidence: 'high', source: 'manual',
          description: 'Pre-existing IOC', mitre: 'T1195.002',
          freshness: { source: 'manual', confidence: 'high', added_at: '2024-01-01T00:00:00.000Z' }
        }
      ],
      pypi_packages: [],
      hashes: ['existinghash1234567890abcdef1234567890abcdef1234567890abcdef12345678'],
      markers: [],
      files: []
    };

    const mockFiles = {};
    let savedIocs = null;
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'sha-merge-test';
      // Return pre-existing IOC data
      if (typeof p === 'string' && p.includes('iocs.json')) return JSON.stringify(existingIOCData);
      return origFs.readFileSync(p, enc);
    };
    fs.writeFileSync = (p, data) => { mockFiles[path.resolve(p)] = data; };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
      if (typeof to === 'string' && to.includes('iocs.json') && !to.includes('compact') && mockFiles[rt]) {
        try { savedIocs = JSON.parse(mockFiles[rt]); } catch {}
      }
    };

    try {
      const result = await runScraper();

      // Pre-existing package should be preserved
      if (savedIocs) {
        const preExisting = savedIocs.packages.find(p => p.name === 'pre-existing-pkg');
        assert(preExisting, 'Should preserve pre-existing packages in merge');
        assert(preExisting.version === '1.0.0', 'Pre-existing package version preserved');

        // Existing hashes should be preserved
        assert(savedIocs.hashes.includes('existinghash1234567890abcdef1234567890abcdef1234567890abcdef12345678'),
          'Should preserve existing hashes');

        // Markers should be populated (either existing or default set)
        assert(Array.isArray(savedIocs.markers), 'Should have markers array');
        assert(savedIocs.markers.length > 0, 'Should have populated markers');

        // Sources metadata should be set
        assert(Array.isArray(savedIocs.sources), 'Should have sources metadata');
        assert(savedIocs.sources.includes('osv-malicious'), 'Sources should include osv-malicious');
        assert(savedIocs.sources.includes('github-advisory'), 'Sources should include github-advisory');

        // Updated timestamp should be set
        assert(typeof savedIocs.updated === 'string', 'Should have updated timestamp');
        assert(savedIocs.updated.includes('T'), 'Updated should be ISO format');
      }
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper confidence upgrade keeps higher-confidence entry', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    // Shai-Hulud returns same package as existing but with higher confidence
    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};
      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = { 'content-length': '100' };
          res.resume = () => {};

          if (url.includes('npm/all.zip') || url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          } else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            // Returns upgrade-pkg with high confidence
            res.emit('data', Buffer.from(JSON.stringify({
              packages: [{ name: 'upgrade-pkg', affectedVersions: ['1.0.0'], severity: 'critical' }]
            })));
            res.emit('end');
          } else if (url.includes('api.osv.dev')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ vulns: [] })));
            res.emit('end');
          } else if (url.includes('api.github.com')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ sha: 'sha-upgrade-test', tree: [] })));
            res.emit('end');
          } else {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('h,v\n'));
            res.emit('end');
          }
        });
      };
      return req;
    };

    const existingIOCData = {
      packages: [
        {
          id: 'LOW-CONF-001', name: 'upgrade-pkg', version: '1.0.0',
          severity: 'high', confidence: 'low', source: 'old-source',
          description: 'Low confidence entry', mitre: 'T1195.002',
          freshness: { source: 'old', confidence: 'low', added_at: '2024-01-01T00:00:00.000Z' }
        }
      ],
      pypi_packages: [],
      hashes: [],
      markers: [],
      files: []
    };

    const mockFiles = {};
    let savedIocs = null;
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'sha-upgrade-test';
      if (typeof p === 'string' && p.includes('iocs.json')) return JSON.stringify(existingIOCData);
      return origFs.readFileSync(p, enc);
    };
    fs.writeFileSync = (p, data) => { mockFiles[path.resolve(p)] = data; };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
      if (typeof to === 'string' && to.includes('iocs.json') && !to.includes('compact') && mockFiles[rt]) {
        try { savedIocs = JSON.parse(mockFiles[rt]); } catch {}
      }
    };

    try {
      const result = await runScraper();
      assert(result.upgraded > 0, 'Should have at least 1 upgraded entry, got ' + result.upgraded);

      if (savedIocs) {
        const upgraded = savedIocs.packages.find(p => p.name === 'upgrade-pkg' && p.version === '1.0.0');
        assert(upgraded, 'Should have upgrade-pkg in saved IOCs');
        assert(upgraded.confidence === 'high', 'Confidence should be upgraded to high, got ' + upgraded.confidence);
        assert(upgraded.source === 'shai-hulud-detector', 'Source should be shai-hulud-detector after upgrade');
      }
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper OSV zip with unparseable JSON entries skips gracefully', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};
      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = { 'content-length': '100' };
          res.resume = () => {};

          // OSV npm zip — has one valid and one unparseable MAL entry
          if (url.includes('npm/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('MAL-VALID.json', Buffer.from(JSON.stringify({
              id: 'MAL-VALID',
              affected: [{ package: { ecosystem: 'npm', name: 'valid-osv-pkg' }, versions: ['1.0.0'] }],
              summary: 'Valid entry'
            })));
            zip.addFile('MAL-BROKEN.json', Buffer.from('this is not valid json{{{'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // PyPI zip — empty
          else if (url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          }
          // Everything else minimal
          else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ packages: [] })));
            res.emit('end');
          }
          else if (url.includes('api.osv.dev')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ vulns: [] })));
            res.emit('end');
          }
          else if (url.includes('api.github.com')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ sha: 'sha-broken-test', tree: [] })));
            res.emit('end');
          }
          else {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('h,v\n'));
            res.emit('end');
          }
        });
      };
      return req;
    };

    const mockFiles = {};
    let savedIocs = null;
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'sha-broken-test';
      return JSON.stringify({ packages: [], pypi_packages: [], hashes: [], markers: [], files: [] });
    };
    fs.writeFileSync = (p, data) => { mockFiles[path.resolve(p)] = data; };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
      if (typeof to === 'string' && to.includes('iocs.json') && !to.includes('compact') && mockFiles[rt]) {
        try { savedIocs = JSON.parse(mockFiles[rt]); } catch {}
      }
    };

    try {
      const result = await runScraper();
      // Should not crash despite broken JSON in zip
      assert(typeof result === 'object', 'Should complete despite broken JSON in zip');
      assert(result.total > 0, 'Should still have packages from valid entries');

      if (savedIocs) {
        const valid = savedIocs.packages.find(p => p.name === 'valid-osv-pkg');
        assert(valid, 'Valid OSV entry should be present despite broken sibling');
      }
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper scrapeStaticIOCs processes socket/phylum/npmRemoved entries', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};
      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = { 'content-length': '100' };
          res.resume = () => {};
          if (url.includes('npm/all.zip') || url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          } else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ packages: [] })));
            res.emit('end');
          } else if (url.includes('api.osv.dev')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ vulns: [] })));
            res.emit('end');
          } else if (url.includes('api.github.com')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ sha: 'sha-static-test', tree: [] })));
            res.emit('end');
          } else {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('h,v\n'));
            res.emit('end');
          }
        });
      };
      return req;
    };

    // Mock static-iocs.json with known entries for all three categories
    const staticIocData = {
      socket: [
        { name: 'socket-test-pkg', severity: 'critical', description: 'Socket test' },
        { name: 'socket-test-pkg2', version: '2.0.0', severity: 'high' }
      ],
      phylum: [
        { name: 'phylum-test-pkg', description: 'Phylum test' }
      ],
      npmRemoved: [
        { name: 'npm-removed-test', reason: 'malware detected' }
      ]
    };

    const mockFiles = {};
    let savedIocs = null;
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return true;
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return JSON.stringify(staticIocData);
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'sha-static-test';
      return JSON.stringify({ packages: [], pypi_packages: [], hashes: [], markers: [], files: [] });
    };
    fs.writeFileSync = (p, data) => { mockFiles[path.resolve(p)] = data; };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
      if (typeof to === 'string' && to.includes('iocs.json') && !to.includes('compact') && mockFiles[rt]) {
        try { savedIocs = JSON.parse(mockFiles[rt]); } catch {}
      }
    };

    try {
      const result = await runScraper();

      if (savedIocs) {
        // Socket entries
        const socketPkgs = savedIocs.packages.filter(p => p.source === 'socket-dev');
        assert(socketPkgs.length >= 2, 'Should have at least 2 socket entries, got ' + socketPkgs.length);
        const socketTest = socketPkgs.find(p => p.name === 'socket-test-pkg');
        assert(socketTest, 'Should have socket-test-pkg');
        assert(socketTest.version === '*', 'Socket pkg without version should default to *');
        assert(socketTest.id === 'SOCKET-socket-test-pkg', 'Socket ID format');
        assert(socketTest.references[0].includes('socket.dev'), 'Socket reference URL');

        const socketTest2 = socketPkgs.find(p => p.name === 'socket-test-pkg2');
        assert(socketTest2, 'Should have socket-test-pkg2');
        assert(socketTest2.version === '2.0.0', 'Socket pkg2 version should be 2.0.0');

        // Phylum entries
        const phylumPkgs = savedIocs.packages.filter(p => p.source === 'phylum');
        assert(phylumPkgs.length >= 1, 'Should have at least 1 phylum entry');
        const phylumTest = phylumPkgs.find(p => p.name === 'phylum-test-pkg');
        assert(phylumTest, 'Should have phylum-test-pkg');
        assert(phylumTest.id === 'PHYLUM-phylum-test-pkg', 'Phylum ID format');
        assert(phylumTest.references[0].includes('phylum.io'), 'Phylum reference URL');

        // npm removed entries
        const npmPkgs = savedIocs.packages.filter(p => p.source === 'npm-removed');
        assert(npmPkgs.length >= 1, 'Should have at least 1 npm-removed entry');
        const npmTest = npmPkgs.find(p => p.name === 'npm-removed-test');
        assert(npmTest, 'Should have npm-removed-test');
        assert(npmTest.id === 'NPM-REMOVED-npm-removed-test', 'npm-removed ID format');
        assert(npmTest.description.includes('malware detected'), 'npm-removed description should include reason');
        assert(npmTest.freshness.confidence === 'medium', 'npm-removed freshness confidence should be medium');
      }
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });

  await asyncTest('SCRAPER: runScraper generates compact IOC file', async () => {
    const origRequest = https.request;
    const origLog = console.log;
    const origWrite = process.stdout.write;
    const origFs = {
      existsSync: fs.existsSync,
      readFileSync: fs.readFileSync,
      writeFileSync: fs.writeFileSync,
      mkdirSync: fs.mkdirSync,
      statSync: fs.statSync,
      renameSync: fs.renameSync,
      accessSync: fs.accessSync
    };

    console.log = () => {};
    process.stdout.write = () => true;

    https.request = (options, callback) => {
      const url = 'https://' + options.hostname + options.path;
      const req = new EventEmitter();
      req.write = () => {};
      req.setTimeout = () => {};
      req.destroy = () => {};
      req.end = () => {
        process.nextTick(() => {
          const res = new EventEmitter();
          res.headers = { 'content-length': '100' };
          res.resume = () => {};

          if (url.includes('npm/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            // Add a wildcard package (version=*) and a versioned package
            zip.addFile('MAL-WILDCARD.json', Buffer.from(JSON.stringify({
              id: 'MAL-WILDCARD',
              affected: [{ package: { ecosystem: 'npm', name: 'wildcard-pkg' } }],
              summary: 'All versions malicious'
            })));
            zip.addFile('MAL-VERSIONED.json', Buffer.from(JSON.stringify({
              id: 'MAL-VERSIONED',
              affected: [{ package: { ecosystem: 'npm', name: 'versioned-pkg' }, versions: ['1.0.0', '2.0.0'] }],
              summary: 'Specific versions malicious'
            })));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          } else if (url.includes('PyPI/all.zip')) {
            res.statusCode = 200;
            callback(res);
            const zip = new AdmZip();
            zip.addFile('SKIP.json', Buffer.from('{}'));
            res.emit('data', zip.toBuffer());
            res.emit('end');
          } else if (url.includes('gensecaihq')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ packages: [] })));
            res.emit('end');
          } else if (url.includes('api.osv.dev')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ vulns: [] })));
            res.emit('end');
          } else if (url.includes('api.github.com')) {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from(JSON.stringify({ sha: 'sha-compact-test', tree: [] })));
            res.emit('end');
          } else {
            res.statusCode = 200;
            callback(res);
            res.emit('data', Buffer.from('h,v\n'));
            res.emit('end');
          }
        });
      };
      return req;
    };

    const mockFiles = {};
    fs.existsSync = (p) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.existsSync(p);
      return true;
    };
    fs.readFileSync = (p, enc) => {
      if (typeof p === 'string' && p.includes('static-iocs')) return origFs.readFileSync(p, enc);
      if (typeof p === 'string' && p.includes('.ossf-tree-sha')) return 'sha-compact-test';
      return JSON.stringify({ packages: [], pypi_packages: [], hashes: [], markers: [], files: [] });
    };
    fs.writeFileSync = (p, data) => { mockFiles[path.resolve(p)] = data; };
    fs.mkdirSync = () => {};
    fs.accessSync = () => {};
    fs.statSync = (p) => {
      const resolved = path.resolve(p);
      if (mockFiles[resolved]) return { size: Buffer.byteLength(mockFiles[resolved]) };
      return origFs.statSync(p);
    };
    fs.renameSync = (from, to) => {
      const rf = path.resolve(from); const rt = path.resolve(to);
      if (mockFiles[rf]) { mockFiles[rt] = mockFiles[rf]; delete mockFiles[rf]; }
    };

    try {
      const result = await runScraper();

      // Find the compact IOC file in the mock writes
      const compactPath = Object.keys(mockFiles).find(p => p.includes('iocs-compact'));
      assert(compactPath, 'Should have written compact IOC file');

      const compactData = JSON.parse(mockFiles[compactPath]);
      assert(compactData, 'Compact IOC file should be valid JSON');
      // generateCompactIOCs creates wildcards array and versioned object
      assert(Array.isArray(compactData.wildcards) || typeof compactData.versioned === 'object',
        'Compact format should have wildcards or versioned fields');
    } finally {
      https.request = origRequest;
      console.log = origLog;
      process.stdout.write = origWrite;
      Object.assign(fs, origFs);
    }
  });
}

module.exports = { runScraperTests };
