'use strict';

const { test, asyncTest, assert } = require('../test-utils');
const be = require('../../src/monitor/burst-extras.js');

const T0 = 1_000_000_000_000;

// An ordinary extra above the threshold: established package, same install hooks.
function ctxAbove(over = {}) {
  return {
    parent: { name: 'bp-pkg', version: '2.0.3' },
    parentScripts: { postinstall: 'node setup.js' },
    isBurst: true,
    established: true,
    queueLength: 25_000,
    maxQueue: 20_000,
    getIocs: () => ({ packagesMap: new Map(), wildcardPackages: new Set() }),
    now: T0,
    log: () => {},
    ...over,
  };
}

function ordinaryExtra(over = {}) {
  return { version: '2.0.1', tarball: 'https://example.invalid/bp-pkg-2.0.1.tgz',
    scripts: { postinstall: 'node setup.js' }, ...over };
}

function admit(extra, ctx) {
  const ledger = [];
  const enqueue = be.admitBurstExtra(extra, { ledger: e => ledger.push(e), ...ctx });
  return { enqueue, ledger };
}

async function runBurstExtrasTests() {
  console.log('\n=== BURST EXTRAS BACKPRESSURE TESTS ===\n');

  test('BURST-EXTRAS: above the threshold an ordinary extra is dropped, counted and ledgered', () => {
    be._resetBurstExtraCounters(T0);
    const { enqueue, ledger } = admit(ordinaryExtra(), ctxAbove());
    assert(enqueue === false, 'ordinary extra above the threshold must not be queued');
    assert(be.getBurstExtraCounters().dropped === 1, `dropped counter must be 1, got ${be.getBurstExtraCounters().dropped}`);
    assert(ledger.length === 1, `one ledger entry expected, got ${ledger.length}`);
    const e = ledger[0];
    assert(e.name === 'bp-pkg' && e.version === '2.0.1' && e.ecosystem === 'npm' &&
      e.outcome === 'dropped' && e.source === 'burst_extra_backpressure' && e.isBurstExtra === true,
    `ledger entry mismatch: ${JSON.stringify(e)}`);
  });

  test('BURST-EXTRAS: below the threshold an ordinary extra is queued, not ledgered', () => {
    be._resetBurstExtraCounters(T0);
    const { enqueue, ledger } = admit(ordinaryExtra(), ctxAbove({ queueLength: 19_999 }));
    assert(enqueue === true, 'extra below the threshold must be queued');
    assert(ledger.length === 0, 'nothing ledgered below the threshold');
    assert(be.getBurstExtraCounters().enqueued.below_threshold === 1, 'counted as below_threshold');
  });

  const kept = [
    ['parent IOC match', ordinaryExtra(), { parent: { name: 'bp-pkg', isIOCMatch: true } }, 'ioc'],
    ['name in the IOC database (version entry)', ordinaryExtra(),
      { getIocs: () => ({ packagesMap: new Map([['bp-pkg', [{ version: '2.0.1' }]]]), wildcardPackages: new Set() }) }, 'ioc'],
    ['name in the IOC database (wildcard)', ordinaryExtra(),
      { getIocs: () => ({ packagesMap: new Map(), wildcardPackages: new Set(['bp-pkg']) }) }, 'ioc'],
    ['parent ATO signal', ordinaryExtra(), { parent: { name: 'bp-pkg', atoSignal: true } }, 'ato'],
    ['kept for an install-hook signal', ordinaryExtra({ keptForSignal: true }), {}, 'kept_for_signal'],
    ['adds an install hook', ordinaryExtra({ scripts: { postinstall: 'node setup.js', preinstall: 'curl x | sh' } }), {}, 'hook_delta'],
    ['changes an install hook', ordinaryExtra({ scripts: { postinstall: 'node other.js' } }), {}, 'hook_delta'],
    ['burst of a package that is not established', ordinaryExtra(), { established: false }, 'burst_new'],
  ];
  for (const [label, extra, over, reason] of kept) {
    test(`BURST-EXTRAS: above the threshold, ${label} is queued (${reason})`, () => {
      be._resetBurstExtraCounters(T0);
      const { enqueue, ledger } = admit(extra, ctxAbove(over));
      assert(enqueue === true, `${label}: must be queued above the threshold`);
      assert(ledger.length === 0, `${label}: must not be ledgered`);
      assert(be.getBurstExtraCounters().enqueued[reason] === 1,
        `${label}: counted as ${reason}, got ${JSON.stringify(be.getBurstExtraCounters())}`);
    });
  }

  const dropped = [
    ['removes an install hook', ordinaryExtra({ scripts: {} }), {}],
    ['burst of an established package', ordinaryExtra(), { established: true, isBurst: true }],
    ['no burst, package not established', ordinaryExtra(), { established: false, isBurst: false }],
  ];
  for (const [label, extra, over] of dropped) {
    test(`BURST-EXTRAS: above the threshold, ${label} is dropped`, () => {
      be._resetBurstExtraCounters(T0);
      const { enqueue } = admit(extra, ctxAbove(over));
      assert(enqueue === false, `${label}: must be dropped above the threshold`);
    });
  }

  test('BURST-EXTRAS: the IOC database is not loaded below the threshold', () => {
    let loads = 0;
    admit(ordinaryExtra(), ctxAbove({ queueLength: 10, getIocs: () => { loads++; return null; } }));
    assert(loads === 0, `getIocs must not be called below the threshold, called ${loads}x`);
  });

  test('BURST-EXTRAS: threshold defaults to 20000, MUADDIB_BURST_EXTRA_MAX_QUEUE overrides it', () => {
    const save = process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE;
    try {
      delete process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE;
      assert(be.burstExtraMaxQueue() === 20_000, `default must be 20000, got ${be.burstExtraMaxQueue()}`);
      process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE = '500';
      assert(be.burstExtraMaxQueue() === 500, 'override must apply');
      process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE = 'abc';
      assert(be.burstExtraMaxQueue() === 20_000, 'invalid value falls back to the default');
    } finally {
      if (save === undefined) delete process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE;
      else process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE = save;
    }
  });

  test('BURST-EXTRAS: established = older than 730 days and more than 100 versions', () => {
    assert(be.isEstablishedPackage({ age_days: 731, version_count: 101 }) === true, 'mature + many versions');
    assert(be.isEstablishedPackage({ age_days: 730, version_count: 500 }) === false, 'age 730 is not established');
    assert(be.isEstablishedPackage({ age_days: 3000, version_count: 100 }) === false, '100 versions is not established');
    assert(be.isEstablishedPackage(null) === false, 'unknown metadata is not established');
  });

  test('BURST-EXTRAS: counters are logged every 60 s with the reasons, then reset', () => {
    be._resetBurstExtraCounters(T0);
    const lines = [];
    const log = l => lines.push(l);
    admit(ordinaryExtra(), ctxAbove({ log, now: T0 + 1000 }));
    admit(ordinaryExtra(), ctxAbove({ log, now: T0 + 2000, queueLength: 5 }));
    assert(lines.length === 0, `no log before 60 s, got ${JSON.stringify(lines)}`);
    admit(ordinaryExtra(), ctxAbove({ log, now: T0 + 60_000, parent: { name: 'bp-pkg', atoSignal: true } }));
    assert(lines.length === 1, `one log line at 60 s, got ${lines.length}`);
    assert(lines[0].includes('BURST EXTRAS') && lines[0].includes('enqueued 2 (below_threshold 1, ato 1)') &&
      lines[0].includes('dropped 1 (backpressure)'), `log line mismatch: ${lines[0]}`);
    const c = be.getBurstExtraCounters();
    assert(c.dropped === 0 && c.enqueued.ato === 0, `counters reset after the log, got ${JSON.stringify(c)}`);
  });

  // Wiring: resolveTarballAndScan applies the decision with the live queue length.
  await asyncTest('BURST-EXTRAS: resolveTarballAndScan drops an ordinary extra when the queue is above the threshold', async () => {
    const queueMod = require('../../src/monitor/queue.js');
    const save = process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE;
    process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE = '2';
    const run = async (queueLen) => {
      const queue = Array.from({ length: queueLen }, (_, i) => ({ name: `filler-${i}`, version: '1.0.0', ecosystem: 'npm' }));
      const item = {
        name: 'bp-wire-pkg', version: '1.0.3', ecosystem: 'npm',
        tarballUrl: 'https://example.invalid/bp-wire-pkg-1.0.3.tgz',
        _npmInfo: {
          version: '1.0.3', latestTagVersion: '1.0.3', recentWindowCount: 1, scripts: {},
          recentVersions: [{ version: '1.0.2', tarball: 'https://example.invalid/bp-wire-pkg-1.0.2.tgz', scripts: {} }],
        },
      };
      const origLog = console.log;
      console.log = () => {};
      try {
        await queueMod.resolveTarballAndScan(item, {}, [], new Set(['npm/bp-wire-pkg@1.0.3']), new Map(), queue, false, null);
      } finally { console.log = origLog; }
      return queue.filter(q => q.name === 'bp-wire-pkg').length;
    };
    try {
      assert(await run(2) === 0, 'queue at the threshold: the ordinary extra must not be queued');
      assert(await run(1) === 1, 'queue below the threshold: the extra must be queued');
    } finally {
      if (save === undefined) delete process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE;
      else process.env.MUADDIB_BURST_EXTRA_MAX_QUEUE = save;
    }
  });
}

module.exports = { runBurstExtrasTests };
