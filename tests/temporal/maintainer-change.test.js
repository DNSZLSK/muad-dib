const fs = require('fs');
const path = require('path');
const {
  test, asyncTest, assert, assertIncludes, assertNotIncludes,
  runScan, runCommand, BIN, TESTS_DIR, addSkipped
} = require('../test-utils');

async function runMaintainerChangeTests() {
  // ============================================
  // MAINTAINER CHANGE DETECTION TESTS
  // ============================================

  console.log('\n=== MAINTAINER CHANGE TESTS ===\n');

  const {
    getMaintainersHistory,
    analyzeMaintainerRisk,
    detectMaintainerChange,
    getVersionMaintainers,
    GENERIC_NAME_PATTERNS,
    MIN_NAME_LENGTH,
    DIGIT_RATIO_THRESHOLD
  } = require('../../src/maintainer-change.js');

  // --- analyzeMaintainerRisk ---

  test('MAINTAINER: analyzeMaintainerRisk npm-user-12345 → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'npm-user-12345', email: '' });
    assert(result.riskLevel === 'HIGH', 'Should be HIGH, got ' + result.riskLevel);
    assert(result.reasons.length > 0, 'Should have reasons');
    assertIncludes(result.reasons[0], 'Generic', 'Reason should mention Generic');
  });

  test('MAINTAINER: analyzeMaintainerRisk user123 → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'user123', email: '' });
    assert(result.riskLevel === 'HIGH', 'Should be HIGH, got ' + result.riskLevel);
    assert(result.reasons.length > 0, 'Should have reasons');
  });

  test('MAINTAINER: analyzeMaintainerRisk ab → HIGH (too short)', () => {
    const result = analyzeMaintainerRisk({ name: 'ab', email: '' });
    assert(result.riskLevel === 'HIGH', 'Should be HIGH, got ' + result.riskLevel);
    const shortReason = result.reasons.find(r => r.includes('short'));
    assert(shortReason, 'Should have short name reason');
  });

  test('MAINTAINER: analyzeMaintainerRisk a1b2c3d4e5 → HIGH (>50% digits)', () => {
    const result = analyzeMaintainerRisk({ name: 'a1b2c3d4e5', email: '' });
    assert(result.riskLevel === 'HIGH', 'Should be HIGH, got ' + result.riskLevel);
    const digitReason = result.reasons.find(r => r.includes('digit'));
    assert(digitReason, 'Should have digit ratio reason');
  });

  test('MAINTAINER: analyzeMaintainerRisk johnsmith → LOW', () => {
    const result = analyzeMaintainerRisk({ name: 'johnsmith', email: '' });
    assert(result.riskLevel === 'LOW', 'Should be LOW, got ' + result.riskLevel);
    assert(result.reasons.length === 0, 'Should have no reasons');
  });

  test('MAINTAINER: analyzeMaintainerRisk sindresorhus → LOW', () => {
    const result = analyzeMaintainerRisk({ name: 'sindresorhus', email: '' });
    assert(result.riskLevel === 'LOW', 'Should be LOW, got ' + result.riskLevel);
    assert(result.reasons.length === 0, 'Should have no reasons');
  });

  test('MAINTAINER: analyzeMaintainerRisk empty name → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: '', email: '' });
    assert(result.riskLevel === 'HIGH', 'Should be HIGH for empty name');
    assertIncludes(result.reasons[0], 'Empty', 'Should mention empty');
  });

  test('MAINTAINER: analyzeMaintainerRisk test → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'test', email: '' });
    assert(result.riskLevel === 'HIGH', 'Should be HIGH, got ' + result.riskLevel);
  });

  test('MAINTAINER: analyzeMaintainerRisk admin → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'admin', email: '' });
    assert(result.riskLevel === 'HIGH', 'Should be HIGH, got ' + result.riskLevel);
  });

  test('MAINTAINER: analyzeMaintainerRisk root → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'root', email: '' });
    assert(result.riskLevel === 'HIGH', 'Should be HIGH, got ' + result.riskLevel);
  });

  test('MAINTAINER: analyzeMaintainerRisk default → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'default', email: '' });
    assert(result.riskLevel === 'HIGH', 'default should be HIGH');
  });

  test('MAINTAINER: analyzeMaintainerRisk temp → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'temp', email: '' });
    assert(result.riskLevel === 'HIGH', 'temp should be HIGH');
  });

  test('MAINTAINER: analyzeMaintainerRisk tmp → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'tmp', email: '' });
    assert(result.riskLevel === 'HIGH', 'tmp should be HIGH');
  });

  test('MAINTAINER: analyzeMaintainerRisk owner → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'owner', email: '' });
    assert(result.riskLevel === 'HIGH', 'owner should be HIGH');
  });

  test('MAINTAINER: analyzeMaintainerRisk maintainer → HIGH', () => {
    const result = analyzeMaintainerRisk({ name: 'maintainer', email: '' });
    assert(result.riskLevel === 'HIGH', 'maintainer should be HIGH');
  });

  test('MAINTAINER: analyzeMaintainerRisk null input → HIGH', () => {
    const result = analyzeMaintainerRisk(null);
    assert(result.riskLevel === 'HIGH', 'null should be HIGH');
  });

  // --- getMaintainersHistory ---

  test('MAINTAINER: getMaintainersHistory with 2 maintainers → returns both', () => {
    const metadata = {
      maintainers: [
        { name: 'alice', email: 'alice@example.com' },
        { name: 'bob', email: 'bob@example.com' }
      ]
    };
    const result = getMaintainersHistory(metadata);
    assert(result.count === 2, 'Should have count 2, got ' + result.count);
    assert(result.current.length === 2, 'Should have 2 maintainers');
    assert(result.current[0].name === 'alice', 'First should be alice');
    assert(result.current[1].name === 'bob', 'Second should be bob');
    assert(result.current[0].email === 'alice@example.com', 'Email should match');
  });

  test('MAINTAINER: getMaintainersHistory without maintainers → empty', () => {
    const result = getMaintainersHistory({});
    assert(result.count === 0, 'Should have count 0, got ' + result.count);
    assert(result.current.length === 0, 'Should have empty array');
  });

  test('MAINTAINER: getMaintainersHistory with null → empty', () => {
    const result = getMaintainersHistory(null);
    assert(result.count === 0, 'Should have count 0 for null');
    assert(result.current.length === 0, 'Should have empty array for null');
  });

  // --- getVersionMaintainers ---

  test('MAINTAINER: getVersionMaintainers extracts publisher and maintainers', () => {
    const versionData = {
      _npmUser: { name: 'alice', email: 'alice@x.com' },
      maintainers: [
        { name: 'alice', email: 'alice@x.com' },
        { name: 'bob', email: 'bob@x.com' }
      ]
    };
    const result = getVersionMaintainers(versionData);
    assert(result.publisher.name === 'alice', 'Publisher should be alice');
    assert(result.maintainers.length === 2, 'Should have 2 maintainers');
  });

  test('MAINTAINER: getVersionMaintainers handles null', () => {
    const result = getVersionMaintainers(null);
    assert(result.publisher === null, 'Publisher should be null');
    assert(result.maintainers.length === 0, 'Should have empty maintainers');
  });

  test('MAINTAINER: getVersionMaintainers handles missing _npmUser', () => {
    const result = getVersionMaintainers({ maintainers: [{ name: 'x', email: '' }] });
    assert(result.publisher === null, 'Publisher should be null when no _npmUser');
    assert(result.maintainers.length === 1, 'Should have 1 maintainer');
  });

  test('MAINTAINER: getVersionMaintainers with empty maintainers array', () => {
    const result = getVersionMaintainers({ _npmUser: { name: 'x', email: 'x@y.com' }, maintainers: [] });
    assert(result.publisher.name === 'x', 'Publisher should exist');
    assert(result.maintainers.length === 0, 'Maintainers should be empty');
  });

  test('MAINTAINER: getMaintainersHistory with missing name/email fields', () => {
    const metadata = {
      maintainers: [
        { name: 'alice' },
        { email: 'bob@x.com' },
        {}
      ]
    };
    const result = getMaintainersHistory(metadata);
    assert(result.count === 3, 'Should have 3 maintainers');
    assert(result.current[0].email === '', 'Missing email defaults to empty');
    assert(result.current[1].name === '', 'Missing name defaults to empty');
    assert(result.current[2].name === '', 'Both missing defaults to empty');
  });

  test('MAINTAINER: getMaintainersHistory with non-array maintainers', () => {
    const result = getMaintainersHistory({ maintainers: 'not-array' });
    assert(result.count === 0, 'Non-array should return count 0');
    assert(result.current.length === 0, 'Non-array should return empty');
  });

  // --- Constants ---

  test('MAINTAINER: constants have expected values', () => {
    assert(MIN_NAME_LENGTH === 3, 'MIN_NAME_LENGTH should be 3');
    assert(DIGIT_RATIO_THRESHOLD === 0.5, 'DIGIT_RATIO_THRESHOLD should be 0.5');
    assert(Array.isArray(GENERIC_NAME_PATTERNS), 'GENERIC_NAME_PATTERNS should be array');
    assert(GENERIC_NAME_PATTERNS.length >= 5, 'Should have at least 5 patterns');
  });

  // --- detectMaintainerChange (mock) ---

  test('MAINTAINER: mock — sole maintainer changed from trusteddev to npm-user-99999', () => {
    // Simulate the detection logic with mock metadata
    const metadata = {
      maintainers: [{ name: 'npm-user-99999', email: 'x@y.com' }],
      time: {
        created: '2020-01-01T00:00:00Z',
        modified: '2026-01-15T00:00:00Z',
        '1.0.0': '2020-01-01T00:00:00Z',
        '1.0.1': '2026-01-15T00:00:00Z'
      },
      versions: {
        '1.0.0': {
          version: '1.0.0',
          _npmUser: { name: 'trusteddev', email: 'trusted@dev.com' },
          maintainers: [{ name: 'trusteddev', email: 'trusted@dev.com' }]
        },
        '1.0.1': {
          version: '1.0.1',
          _npmUser: { name: 'npm-user-99999', email: 'x@y.com' },
          maintainers: [{ name: 'npm-user-99999', email: 'x@y.com' }]
        }
      }
    };

    const maintainersInfo = getMaintainersHistory(metadata);
    const newestMaint = getVersionMaintainers(metadata.versions['1.0.1']);
    const previousMaint = getVersionMaintainers(metadata.versions['1.0.0']);

    const previousNames = new Set(previousMaint.maintainers.map(m => m.name.toLowerCase()));
    const findings = [];

    // NEW_MAINTAINER check
    for (const m of newestMaint.maintainers) {
      if (m.name && !previousNames.has(m.name.toLowerCase())) {
        const risk = analyzeMaintainerRisk(m);
        findings.push({ type: 'new_maintainer', severity: risk.riskLevel === 'HIGH' ? 'CRITICAL' : 'HIGH', maintainer: m });
      }
    }

    // SUSPICIOUS_MAINTAINER check
    for (const m of maintainersInfo.current) {
      const risk = analyzeMaintainerRisk(m);
      if (risk.riskLevel === 'HIGH') {
        const already = findings.some(f => f.type === 'new_maintainer' && f.maintainer.name === m.name);
        if (!already) {
          findings.push({ type: 'suspicious_maintainer', severity: 'HIGH', maintainer: m });
        }
      }
    }

    // SOLE_MAINTAINER_CHANGE check
    if (previousMaint.maintainers.length === 1 && newestMaint.maintainers.length === 1) {
      const prevN = previousMaint.maintainers[0].name.toLowerCase();
      const newN = newestMaint.maintainers[0].name.toLowerCase();
      if (prevN !== newN) {
        const already = findings.some(f => f.type === 'new_maintainer' && f.maintainer.name.toLowerCase() === newN);
        if (!already) {
          findings.push({ type: 'sole_maintainer_change', severity: 'HIGH' });
        }
      }
    }

    assert(findings.length >= 1, 'Should have at least 1 finding, got ' + findings.length);
    const newMaint = findings.find(f => f.type === 'new_maintainer');
    assert(newMaint, 'Should have new_maintainer finding');
    assert(newMaint.severity === 'CRITICAL', 'new_maintainer with suspicious name should be CRITICAL');
    assert(newMaint.maintainer.name === 'npm-user-99999', 'Should reference npm-user-99999');
  });

  test('MAINTAINER: mock — new maintainer added to existing team', () => {
    const metadata = {
      maintainers: [
        { name: 'alice', email: 'a@x.com' },
        { name: 'bob', email: 'b@x.com' },
        { name: 'charlie', email: 'c@x.com' }
      ],
      time: {
        '1.0.0': '2024-01-01T00:00:00Z',
        '1.0.1': '2026-01-15T00:00:00Z'
      },
      versions: {
        '1.0.0': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [
            { name: 'alice', email: 'a@x.com' },
            { name: 'bob', email: 'b@x.com' }
          ]
        },
        '1.0.1': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [
            { name: 'alice', email: 'a@x.com' },
            { name: 'bob', email: 'b@x.com' },
            { name: 'charlie', email: 'c@x.com' }
          ]
        }
      }
    };

    const newestMaint = getVersionMaintainers(metadata.versions['1.0.1']);
    const previousMaint = getVersionMaintainers(metadata.versions['1.0.0']);
    const previousNames = new Set(previousMaint.maintainers.map(m => m.name.toLowerCase()));

    const newMaintainers = newestMaint.maintainers.filter(m => !previousNames.has(m.name.toLowerCase()));
    assert(newMaintainers.length === 1, 'Should detect 1 new maintainer, got ' + newMaintainers.length);
    assert(newMaintainers[0].name === 'charlie', 'New maintainer should be charlie');

    const risk = analyzeMaintainerRisk(newMaintainers[0]);
    assert(risk.riskLevel === 'LOW', 'charlie should be LOW risk');
  });

  test('MAINTAINER: mock — no change → no findings', () => {
    const metadata = {
      maintainers: [{ name: 'alice', email: 'a@x.com' }],
      time: {
        '1.0.0': '2024-01-01T00:00:00Z',
        '1.0.1': '2024-06-01T00:00:00Z'
      },
      versions: {
        '1.0.0': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [{ name: 'alice', email: 'a@x.com' }]
        },
        '1.0.1': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [{ name: 'alice', email: 'a@x.com' }]
        }
      }
    };

    const newestMaint = getVersionMaintainers(metadata.versions['1.0.1']);
    const previousMaint = getVersionMaintainers(metadata.versions['1.0.0']);
    const previousNames = new Set(previousMaint.maintainers.map(m => m.name.toLowerCase()));

    const newMaintainers = newestMaint.maintainers.filter(m => !previousNames.has(m.name.toLowerCase()));
    assert(newMaintainers.length === 0, 'Should have no new maintainers');

    // No sole_maintainer_change either
    const prevN = previousMaint.maintainers[0].name.toLowerCase();
    const newN = newestMaint.maintainers[0].name.toLowerCase();
    assert(prevN === newN, 'Sole maintainer should be the same');
  });

  test('MAINTAINER: mock — publisher changed to unknown user', () => {
    const newestData = {
      _npmUser: { name: 'npm-user-77777', email: 'x@y.com' },
      maintainers: [
        { name: 'trusteddev', email: 't@d.com' },
        { name: 'npm-user-77777', email: 'x@y.com' }
      ]
    };
    const previousData = {
      _npmUser: { name: 'trusteddev', email: 't@d.com' },
      maintainers: [{ name: 'trusteddev', email: 't@d.com' }]
    };

    const newestMaint = getVersionMaintainers(newestData);
    const previousMaint = getVersionMaintainers(previousData);
    const previousNames = new Set(previousMaint.maintainers.map(m => m.name.toLowerCase()));

    // Publisher change detection
    const prevPublisher = previousMaint.publisher.name.toLowerCase();
    const newPublisher = newestMaint.publisher.name.toLowerCase();
    assert(prevPublisher !== newPublisher, 'Publisher should have changed');
    assert(!previousNames.has(newPublisher), 'New publisher should not be in previous maintainers');

    const risk = analyzeMaintainerRisk(newestMaint.publisher);
    assert(risk.riskLevel === 'HIGH', 'npm-user-77777 should be HIGH risk');
  });

  // --- detectMaintainerChange (mocked fetchPackageMetadata) ---

  const temporalPath = require.resolve('../../src/temporal-analysis.js');
  const maintainerPath = require.resolve('../../src/maintainer-change.js');

  async function withMockedFetchMaint(mockFn, testFn) {
    const origFetch = require.cache[temporalPath].exports.fetchPackageMetadata;
    require.cache[temporalPath].exports.fetchPackageMetadata = mockFn;
    delete require.cache[maintainerPath];
    try {
      const mod = require(maintainerPath);
      await testFn(mod.detectMaintainerChange);
    } finally {
      require.cache[temporalPath].exports.fetchPackageMetadata = origFetch;
      delete require.cache[maintainerPath];
    }
  }

  await asyncTest('MAINTAINER: detectMaintainerChange detects sole maintainer change', async () => {
    const metadata = {
      maintainers: [{ name: 'npm-user-99999', email: 'x@y.com' }],
      time: { '1.0.0': '2020-01-01T00:00:00Z', '1.0.1': '2026-01-15T00:00:00Z' },
      versions: {
        '1.0.0': {
          _npmUser: { name: 'trusteddev', email: 'trusted@dev.com' },
          maintainers: [{ name: 'trusteddev', email: 'trusted@dev.com' }]
        },
        '1.0.1': {
          _npmUser: { name: 'npm-user-99999', email: 'x@y.com' },
          maintainers: [{ name: 'npm-user-99999', email: 'x@y.com' }]
        }
      }
    };
    await withMockedFetchMaint(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      assert(result.packageName === 'test-pkg', 'Package name should match');
      const newMaint = result.findings.find(f => f.type === 'new_maintainer');
      assert(newMaint, 'Should have new_maintainer finding');
      assert(newMaint.severity === 'CRITICAL', 'Suspicious new maintainer should be CRITICAL');
    });
  });

  await asyncTest('MAINTAINER: detectMaintainerChange detects new legitimate maintainer', async () => {
    const metadata = {
      maintainers: [
        { name: 'alice', email: 'a@x.com' },
        { name: 'bob', email: 'b@x.com' },
        { name: 'charlie', email: 'c@x.com' }
      ],
      time: { '1.0.0': '2024-01-01T00:00:00Z', '1.0.1': '2026-01-15T00:00:00Z' },
      versions: {
        '1.0.0': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [{ name: 'alice', email: 'a@x.com' }, { name: 'bob', email: 'b@x.com' }]
        },
        '1.0.1': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [
            { name: 'alice', email: 'a@x.com' },
            { name: 'bob', email: 'b@x.com' },
            { name: 'charlie', email: 'c@x.com' }
          ]
        }
      }
    };
    await withMockedFetchMaint(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      const newMaint = result.findings.find(f => f.type === 'new_maintainer');
      assert(newMaint, 'Should have new_maintainer finding');
      assert(newMaint.severity === 'HIGH', 'Legitimate new maintainer should be HIGH');
      assert(newMaint.maintainer.name === 'charlie', 'Should reference charlie');
    });
  });

  await asyncTest('MAINTAINER: detectMaintainerChange detects publisher change', async () => {
    const metadata = {
      maintainers: [{ name: 'trusteddev', email: 't@d.com' }, { name: 'newpublisher', email: 'n@p.com' }],
      time: { '1.0.0': '2024-01-01T00:00:00Z', '1.0.1': '2026-01-15T00:00:00Z' },
      versions: {
        '1.0.0': {
          _npmUser: { name: 'trusteddev', email: 't@d.com' },
          maintainers: [{ name: 'trusteddev', email: 't@d.com' }]
        },
        '1.0.1': {
          _npmUser: { name: 'newpublisher', email: 'n@p.com' },
          maintainers: [{ name: 'trusteddev', email: 't@d.com' }, { name: 'newpublisher', email: 'n@p.com' }]
        }
      }
    };
    await withMockedFetchMaint(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      const pubChange = result.findings.find(f => f.type === 'new_publisher');
      assert(pubChange, 'Should have new_publisher finding');
    });
  });

  await asyncTest('MAINTAINER: detectMaintainerChange no changes → not suspicious', async () => {
    const metadata = {
      maintainers: [{ name: 'alice', email: 'a@x.com' }],
      time: { '1.0.0': '2024-01-01T00:00:00Z', '1.0.1': '2024-06-01T00:00:00Z' },
      versions: {
        '1.0.0': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [{ name: 'alice', email: 'a@x.com' }]
        },
        '1.0.1': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [{ name: 'alice', email: 'a@x.com' }]
        }
      }
    };
    await withMockedFetchMaint(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === false, 'Should not be suspicious');
      assert(result.findings.length === 0, 'Should have no findings');
    });
  });

  await asyncTest('MAINTAINER: detectMaintainerChange single version → not suspicious', async () => {
    const metadata = {
      maintainers: [{ name: 'alice', email: 'a@x.com' }],
      time: { '1.0.0': '2024-01-01T00:00:00Z' },
      versions: {
        '1.0.0': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [{ name: 'alice', email: 'a@x.com' }]
        }
      }
    };
    await withMockedFetchMaint(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === false, 'Should not be suspicious');
      assert(result.findings.length === 0, 'Should have no findings');
      assert(result.maintainers.count === 1, 'Should have 1 maintainer');
    });
  });

  await asyncTest('MAINTAINER: detectMaintainerChange detects suspicious existing maintainer', async () => {
    const metadata = {
      maintainers: [{ name: 'npm-user-12345', email: 'x@y.com' }, { name: 'alice', email: 'a@x.com' }],
      time: { '1.0.0': '2024-01-01T00:00:00Z', '1.0.1': '2024-06-01T00:00:00Z' },
      versions: {
        '1.0.0': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [{ name: 'npm-user-12345', email: 'x@y.com' }, { name: 'alice', email: 'a@x.com' }]
        },
        '1.0.1': {
          _npmUser: { name: 'alice', email: 'a@x.com' },
          maintainers: [{ name: 'npm-user-12345', email: 'x@y.com' }, { name: 'alice', email: 'a@x.com' }]
        }
      }
    };
    await withMockedFetchMaint(async () => metadata, async (detect) => {
      const result = await detect('test-pkg');
      assert(result.suspicious === true, 'Should be suspicious');
      const susp = result.findings.find(f => f.type === 'suspicious_maintainer');
      assert(susp, 'Should have suspicious_maintainer finding');
      assert(susp.severity === 'HIGH', 'Suspicious maintainer severity should be HIGH');
    });
  });

  // --- Rules and playbooks ---

  test('MAINTAINER: Rules MUADDIB-MAINTAINER-001/002/003/004 exist', () => {
    const { getRule } = require('../../src/rules/index.js');

    const r1 = getRule('new_maintainer');
    assert(r1.id === 'MUADDIB-MAINTAINER-001', 'new_maintainer rule ID should be MUADDIB-MAINTAINER-001, got ' + r1.id);
    assert(r1.severity === 'HIGH', 'new_maintainer severity should be HIGH');

    const r2 = getRule('suspicious_maintainer');
    assert(r2.id === 'MUADDIB-MAINTAINER-002', 'suspicious_maintainer rule ID should be MUADDIB-MAINTAINER-002, got ' + r2.id);
    assert(r2.severity === 'CRITICAL', 'suspicious_maintainer severity should be CRITICAL');

    const r3 = getRule('sole_maintainer_change');
    assert(r3.id === 'MUADDIB-MAINTAINER-003', 'sole_maintainer_change rule ID should be MUADDIB-MAINTAINER-003, got ' + r3.id);
    assert(r3.severity === 'HIGH', 'sole_maintainer_change severity should be HIGH');

    const r4 = getRule('new_publisher');
    assert(r4.id === 'MUADDIB-MAINTAINER-004', 'new_publisher rule ID should be MUADDIB-MAINTAINER-004, got ' + r4.id);
    assert(r4.severity === 'MEDIUM', 'new_publisher severity should be MEDIUM');
  });

  test('MAINTAINER: Playbooks exist for maintainer threat types', () => {
    const { getPlaybook } = require('../../src/response/playbooks.js');

    const p1 = getPlaybook('new_maintainer');
    assertIncludes(p1, 'maintainer', 'new_maintainer playbook should mention maintainer');

    const p2 = getPlaybook('suspicious_maintainer');
    assertIncludes(p2, 'suspicious', 'suspicious_maintainer playbook should mention suspicious');

    const p3 = getPlaybook('sole_maintainer_change');
    assertIncludes(p3, 'sole maintainer', 'sole_maintainer_change playbook should mention sole maintainer');

    const p4 = getPlaybook('new_publisher');
    assertIncludes(p4, 'publisher', 'new_publisher playbook should mention publisher');
  });

  // --- Integration test (network) ---

  const skipNetwork = process.env.SKIP_NETWORK === 'true' || process.env.CI === 'true';

  if (!skipNetwork) {
    await asyncTest('MAINTAINER: detectMaintainerChange on lodash returns valid structure', async () => {
      const result = await detectMaintainerChange('lodash');
      assert(result.packageName === 'lodash', 'packageName should be lodash');
      assert(typeof result.suspicious === 'boolean', 'suspicious should be boolean');
      assert(Array.isArray(result.findings), 'findings should be array');
      assert(result.maintainers, 'maintainers should exist');
      assert(result.maintainers.count > 0, 'lodash should have maintainers, got ' + result.maintainers.count);
      assert(result.maintainers.current.length > 0, 'Should have current maintainers');
      assert(typeof result.maintainers.current[0].name === 'string', 'Maintainer should have name');
    });
  } else {
    console.log('[SKIP] MAINTAINER network tests (SKIP_NETWORK=true or CI=true)');
    addSkipped(1);
  }
}

module.exports = { runMaintainerChangeTests };
