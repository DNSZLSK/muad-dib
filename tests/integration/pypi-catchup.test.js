'use strict';

// Regression tests for the 2026-06-11 PyPI replay incident:
//  (1) a test-fixture serial leaked into prod state (data/pypi-serial.json)
//      because integration tests ran the real savePypiSerial — the state
//      files are now env-overridable and the harness points them at tmp;
//  (2) the catch-up protection measured the gap INSIDE one batch (bounded
//      ~50K) against PYPI_CATCHUP_MAX (100K), so a poller 37M serials behind
//      replayed years of history without ever tripping the skip — there is
//      now a global probe (changelog_last_serial) on full batches.

const fs = require('fs');
const path = require('path');
const { test, asyncTest, assert } = require('../test-utils');
const ingestion = require('../../src/monitor/ingestion.js');
const { savePypiSerial, loadPypiSerial, PYPI_SERIAL_FILE, NPM_SEQ_FILE } = require('../../src/monitor/state.js');

function changelogBatchXml(count, firstSerial) {
  const rows = [];
  for (let i = 0; i < count; i++) {
    rows.push(`<value><array><data>
      <value><string>replayed-pkg</string></value>
      <value><string>1.0.0</string></value>
      <value><int>1700000000</int></value>
      <value><string>new release</string></value>
      <value><int>${firstSerial + i}</int></value>
    </data></array></value>`);
  }
  return `<?xml version='1.0'?><methodResponse><params><param><value><array><data>
    ${rows.join('\n')}
  </data></array></value></param></params></methodResponse>`;
}

const lastSerialXml = n =>
  `<?xml version='1.0'?><methodResponse><params><param><value><int>${n}</int></value></param></params></methodResponse>`;

async function runPypiCatchupTests() {
  console.log('\n=== PYPI CATCH-UP / STATE-ISOLATION TESTS ===\n');

  test('STATE-ISOLATION: harness redirects pypi-serial and npm-seq away from prod data/', () => {
    const prodSerial = path.join(__dirname, '..', '..', 'data', 'pypi-serial.json');
    const prodSeq = path.join(__dirname, '..', '..', 'data', 'npm-seq.json');
    assert(process.env.MUADDIB_PYPI_SERIAL_FILE, 'harness must set MUADDIB_PYPI_SERIAL_FILE');
    assert(process.env.MUADDIB_NPM_SEQ_FILE, 'harness must set MUADDIB_NPM_SEQ_FILE');
    assert(PYPI_SERIAL_FILE === process.env.MUADDIB_PYPI_SERIAL_FILE,
      `state.js must honor the env override, got ${PYPI_SERIAL_FILE}`);
    assert(NPM_SEQ_FILE === process.env.MUADDIB_NPM_SEQ_FILE,
      `state.js must honor the env override, got ${NPM_SEQ_FILE}`);
    assert(PYPI_SERIAL_FILE !== prodSerial && NPM_SEQ_FILE !== prodSeq,
      'state files under test must NOT be the prod files');
  });

  test('STATE-ISOLATION: savePypiSerial round-trips through the overridden file only', () => {
    const prodSerial = path.join(__dirname, '..', '..', 'data', 'pypi-serial.json');
    const prodBefore = fs.existsSync(prodSerial) ? fs.readFileSync(prodSerial, 'utf8') : null;
    savePypiSerial(777);
    assert(loadPypiSerial() === 777, 'serial must round-trip via the overridden file');
    const written = JSON.parse(fs.readFileSync(PYPI_SERIAL_FILE, 'utf8'));
    assert(written.lastSerial === 777, 'overridden file must hold the saved serial');
    const prodAfter = fs.existsSync(prodSerial) ? fs.readFileSync(prodSerial, 'utf8') : null;
    assert(prodAfter === prodBefore, 'prod data/pypi-serial.json must be untouched by tests');
  });

  // The two XML-RPC tests below mutate the shared _deps.httpsPost seam — they
  // must be awaited (serialized), same as the pollPyPIChangelog tests in
  // monitor.test.js.
  await asyncTest('CATCHUP: full batch + huge global lag → probe changelog_last_serial and skip to current', async () => {
    const realPost = ingestion._deps.httpsPost;
    const realGet = ingestion._deps.httpsGet;
    const methods = [];
    // 10000 events spanning serials 1001..11000: the per-batch gap (10000) is
    // far below PYPI_CATCHUP_MAX, so only the GLOBAL probe can catch this.
    ingestion._deps.httpsPost = async (_url, body) => {
      const m = body.match(/<methodName>([^<]+)<\/methodName>/)[1];
      methods.push(m);
      if (m === 'changelog_last_serial') return lastSerialXml(37000000);
      return changelogBatchXml(10000, 1001);
    };
    ingestion._deps.httpsGet = async () => { throw new Error('test: no registry'); };

    const state = { pypiLastSerial: 1000 };
    const scanQueue = [];
    const stats = {};
    try {
      const count = await ingestion.pollPyPIChangelog(state, scanQueue, stats);
      assert(count === 0, `Global catch-up skip must queue nothing, got ${count}`);
      assert(scanQueue.length === 0, 'No ancient packages may be enqueued');
      assert(methods.includes('changelog_last_serial'), 'Full batch must trigger the global probe');
      assert(state.pypiLastSerial === 37000000,
        `Serial must jump to the registry current (37000000), got ${state.pypiLastSerial}`);
      assert(loadPypiSerial() === 37000000, 'Skip must be persisted (crash-safe resume)');
      assert(stats.pypiCatchupSkips === 1, `pypiCatchupSkips must be 1, got ${stats.pypiCatchupSkips}`);
      assert(stats.pypiCatchupSkippedEvents === 37000000 - 1000,
        `Skipped-events stat must reflect the global lag, got ${stats.pypiCatchupSkippedEvents}`);
    } finally {
      ingestion._deps.httpsPost = realPost;
      ingestion._deps.httpsGet = realGet;
    }
  });

  await asyncTest('CATCHUP: full batch but small global lag → no skip, batch processed normally', async () => {
    const realPost = ingestion._deps.httpsPost;
    const realGet = ingestion._deps.httpsGet;
    ingestion._deps.httpsPost = async (_url, body) => {
      const m = body.match(/<methodName>([^<]+)<\/methodName>/)[1];
      // Registry only slightly ahead of the batch tail: legit busy day, not a replay.
      if (m === 'changelog_last_serial') return lastSerialXml(11050);
      return changelogBatchXml(10000, 1001);
    };
    ingestion._deps.httpsGet = async () => { throw new Error('test: no registry'); };

    const state = { pypiLastSerial: 1000 };
    const scanQueue = [];
    const stats = {};
    try {
      const count = await ingestion.pollPyPIChangelog(state, scanQueue, stats);
      assert(!stats.pypiCatchupSkips, `No skip on a legit busy day, got ${stats.pypiCatchupSkips}`);
      assert(count === 1, `10000 events of one (name,version) must dedupe to 1 queued, got ${count}`);
      assert(scanQueue.length === 1 && scanQueue[0].name === 'replayed-pkg', 'the release must be queued');
      assert(state.pypiLastSerial === 11000, `Serial must advance to batch tail, got ${state.pypiLastSerial}`);
    } finally {
      ingestion._deps.httpsPost = realPost;
      ingestion._deps.httpsGet = realGet;
    }
  });
}

module.exports = { runPypiCatchupTests };
