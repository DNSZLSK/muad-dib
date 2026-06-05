/**
 * Sandbox waste-cut decision tests (v2.11.6x).
 *
 * Covers the two detection-safe skip paths added to stop the monitor from burning
 * sandbox slots (and the scan worker that block-waits on them) for no new verdict:
 *   1. memory match  — re-sandboxing an already-known package the webhook would suppress
 *      anyway (dominant cost: restart-replay of the changes-stream backlog), with a
 *      SANDBOX_REVALIDATE_MS canary-revalidation cadence.
 *   2. native binary shard — platform prebuilts that hang the install and always time out.
 *
 * Behavioral, not source-grep: every case calls the exported pure helpers
 * (classifyNativeShard / shouldSkipSandbox) and the state-memory plumbing
 * (markSandboxed / recordScanMemory) and asserts the RETURN/side-effect — no sandbox,
 * no disk, no Docker.
 */

const {
  test, assert
} = require('../test-utils');

const {
  classifyNativeShard, shouldSkipSandbox, SANDBOX_REVALIDATE_MS
} = require('../../src/monitor/queue.js');

const {
  getScanMemoryCache, setScanMemoryCache, loadScanMemory,
  recordScanMemory, markSandboxed
} = require('../../src/monitor/state.js');

const DAY = 24 * 60 * 60 * 1000;

function runSandboxDecisionTests() {
  console.log('\n=== SANDBOX DECISION (waste-cut) TESTS ===\n');

  // ─────────────────────────────────────────────────────────────────────────
  // classifyNativeShard — is this a prebuilt platform shard?
  // ─────────────────────────────────────────────────────────────────────────

  test('NATIVE+: os/cpu constraint + trivial JS + no scripts → shard, no lifecycle', () => {
    const r = classifyNativeShard('@scope/core', 1, { os: ['linux'], cpu: ['x64'] });
    assert(r.isShard === true, 'os/cpu + 1 JS file should classify as a shard');
    assert(r.hasLifecycleScripts === false, 'no scripts → hasLifecycleScripts false');
  });

  test('NATIVE+: name pattern (no os/cpu) + trivial JS → shard (name match)', () => {
    const r = classifyNativeShard('@undes.ai/core-linux-x64', 2, {});
    assert(r.isShard === true, 'name like *-linux-x64 should match the shard pattern');
  });

  test('NATIVE+: musl/abi suffix name still matches', () => {
    const r = classifyNativeShard('@next/swc-linux-x64-musl', 1, {});
    assert(r.isShard === true, '*-linux-x64-musl should match');
  });

  test('NATIVE−: platform constraint but substantial JS → NOT a pure shard', () => {
    const r = classifyNativeShard('@scope/thing', 25, { os: ['linux'] });
    assert(r.isShard === false, '25 JS files means real logic, not a thin binary wrapper');
  });

  test('NATIVE−: ordinary package, no os/cpu, no shard name → not a shard', () => {
    const r = classifyNativeShard('lodash', 60, {});
    assert(r.isShard === false, 'lodash is not a platform shard');
  });

  test('NATIVE: lifecycle script is surfaced (so caller keeps sandboxing it)', () => {
    const r = classifyNativeShard('@scope/core-linux-x64', 1, {
      os: ['linux'], scripts: { postinstall: 'node install.js' }
    });
    assert(r.isShard === true, 'still a shard by shape');
    assert(r.hasLifecycleScripts === true, 'postinstall must be detected — it is the attack vector');
  });

  test('NATIVE: null/garbage manifest is handled (treated as non-constrained)', () => {
    const r1 = classifyNativeShard('foo-linux-x64', 1, null);
    assert(r1.isShard === true, 'name match still works with null manifest');
    assert(r1.hasLifecycleScripts === false, 'null manifest → no lifecycle');
    const r2 = classifyNativeShard('foo', 1, { scripts: 'not-an-object', os: 'not-an-array' });
    assert(r2.isShard === false, 'malformed os (string, not array) must not count as a constraint');
  });

  // ─────────────────────────────────────────────────────────────────────────
  // shouldSkipSandbox — memory path
  // ─────────────────────────────────────────────────────────────────────────

  const base = {
    memorySuppress: false, lastSandboxAt: undefined, now: 1_000_000_000_000,
    revalidateMs: 7 * DAY, isNativeShard: false, hasLifecycleScripts: false,
    hasHighOrCritical: false, hasTemporal: false
  };

  test('MEM+: memory match + sandboxed 1d ago → skip-memory', () => {
    const r = shouldSkipSandbox({ ...base, memorySuppress: true, lastSandboxAt: base.now - 1 * DAY });
    assert(r && r.action === 'skip-memory', 'recent memory match must skip the sandbox');
  });

  test('MEM−: memory match but last sandbox 8d ago → run (revalidate canary)', () => {
    const r = shouldSkipSandbox({ ...base, memorySuppress: true, lastSandboxAt: base.now - 8 * DAY });
    assert(r === null, 'stale memory match must revalidate, not skip');
  });

  test('MEM−: memory match but never sandboxed (no lastSandboxAt) → run', () => {
    const r = shouldSkipSandbox({ ...base, memorySuppress: true, lastSandboxAt: undefined });
    assert(r === null, 'a memory entry with no sandbox timestamp must run once to establish coverage');
  });

  test('MEM−: NOT a memory match (new types / IOC) → never skip on memory', () => {
    const r = shouldSkipSandbox({ ...base, memorySuppress: false, lastSandboxAt: base.now });
    assert(r === null, 'memorySuppress=false means something changed → must run');
  });

  // ─────────────────────────────────────────────────────────────────────────
  // shouldSkipSandbox — native path + guard rails
  // ─────────────────────────────────────────────────────────────────────────

  test('NATIVE-SKIP+: shard, no lifecycle/HIGH/temporal → skip-native', () => {
    const r = shouldSkipSandbox({ ...base, isNativeShard: true });
    assert(r && r.action === 'skip-native', 'clean native shard should skip the sandbox');
  });

  test('NATIVE-SKIP−: shard WITH lifecycle script → run (attack vector)', () => {
    const r = shouldSkipSandbox({ ...base, isNativeShard: true, hasLifecycleScripts: true });
    assert(r === null, 'a shard with an install hook must still be sandboxed');
  });

  test('NATIVE-SKIP−: shard with HIGH/CRITICAL finding → run', () => {
    const r = shouldSkipSandbox({ ...base, isNativeShard: true, hasHighOrCritical: true });
    assert(r === null, 'HIGH/CRITICAL static finding must still be sandboxed');
  });

  test('NATIVE-SKIP−: shard with temporal signal → run', () => {
    const r = shouldSkipSandbox({ ...base, isNativeShard: true, hasTemporal: true });
    assert(r === null, 'temporal anomaly must still be sandboxed');
  });

  test('NATIVE-SKIP−: not a shard → run', () => {
    const r = shouldSkipSandbox({ ...base, isNativeShard: false });
    assert(r === null, 'non-shard with no memory match must run');
  });

  test('PRECEDENCE: recent memory match AND native shard → skips (memory wins)', () => {
    const r = shouldSkipSandbox({
      ...base, memorySuppress: true, lastSandboxAt: base.now - 1 * DAY, isNativeShard: true
    });
    assert(r && r.action === 'skip-memory', 'memory match is evaluated first');
  });

  test('CONFIG: SANDBOX_REVALIDATE_MS is a sane positive default', () => {
    assert(typeof SANDBOX_REVALIDATE_MS === 'number' && SANDBOX_REVALIDATE_MS > 0,
      'revalidation window must be a positive number');
  });

  // ─────────────────────────────────────────────────────────────────────────
  // state plumbing — markSandboxed + recordScanMemory read-modify-write
  // (hermetic: operate on an injected in-memory cache, restore afterward)
  // ─────────────────────────────────────────────────────────────────────────

  const savedCache = getScanMemoryCache();
  try {
    setScanMemoryCache(Object.create(null));

    test('STATE: markSandboxed stamps lastSandboxAt + a timestamp on a fresh entry', () => {
      markSandboxed('pkg-fresh', 1000);
      const e = loadScanMemory()['pkg-fresh'];
      assert(e && e.lastSandboxAt === 1000, 'lastSandboxAt should be set');
      assert(e.timestamp === 1000, 'a timestamp must exist so purge/eviction has a key');
    });

    test('STATE: recordScanMemory PRESERVES lastSandboxAt (read-modify-write)', () => {
      markSandboxed('pkg-rmw', 5000);
      recordScanMemory('pkg-rmw', 42, ['lifecycle_script'], []);
      const e = loadScanMemory()['pkg-rmw'];
      assert(e.lastSandboxAt === 5000, 'a later memory record must NOT clobber lastSandboxAt');
      assert(e.score === 42, 'score must be updated by recordScanMemory');
      assert(Array.isArray(e.types) && e.types[0] === 'lifecycle_script', 'types recorded');
    });

    test('STATE: recordScanMemory works with no prior entry (prev = {})', () => {
      recordScanMemory('pkg-new', 7, ['a', 'b'], ['b']);
      const e = loadScanMemory()['pkg-new'];
      assert(e && e.score === 7, 'fresh record without a prior sandbox stamp must still work');
      assert(e.lastSandboxAt === undefined, 'no sandbox run yet → no lastSandboxAt');
    });
  } finally {
    setScanMemoryCache(savedCache);
  }
}

module.exports = { runSandboxDecisionTests };
