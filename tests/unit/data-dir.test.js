'use strict';

/**
 * MUADDIB_DATA_DIR: one switch for every monitor / feed / ML state file, so that the test suite
 * never writes into a deployed checkout's data/ (it used to append test detections and alerts to
 * the real data/detections.jsonl and data/monitor-alerts.jsonl).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { test, assert } = require('../test-utils');

const ROOT = path.join(__dirname, '..', '..');
const REPO_DATA = path.join(ROOT, 'data');

function snapshot(dir) {
  const out = {};
  if (!fs.existsSync(dir)) return out;
  for (const name of fs.readdirSync(dir)) {
    try { const st = fs.statSync(path.join(dir, name)); if (st.isFile()) out[name] = st.size + ':' + st.mtimeMs; } catch { /* raced */ }
  }
  return out;
}

async function runDataDirTests() {
  console.log('\n=== DATA DIR ISOLATION TESTS ===\n');

  test('DATA-DIR: default is <repo>/data, MUADDIB_DATA_DIR moves it, an empty value keeps the default', () => {
    const { dataDir, dataPath, DEFAULT_DATA_DIR } = require('../../src/shared/data-dir.js');
    const prev = process.env.MUADDIB_DATA_DIR;
    try {
      delete process.env.MUADDIB_DATA_DIR;
      assert(dataDir() === DEFAULT_DATA_DIR && DEFAULT_DATA_DIR === REPO_DATA, 'default: ' + dataDir());
      process.env.MUADDIB_DATA_DIR = '  ';
      assert(dataDir() === DEFAULT_DATA_DIR, 'blank value must keep the default');
      process.env.MUADDIB_DATA_DIR = os.tmpdir();
      assert(dataPath('x.json') === path.join(path.resolve(os.tmpdir()), 'x.json'), 'override: ' + dataPath('x.json'));
    } finally {
      if (prev === undefined) delete process.env.MUADDIB_DATA_DIR; else process.env.MUADDIB_DATA_DIR = prev;
    }
  });

  test('DATA-DIR: the test harness points the data directory outside the repository', () => {
    const v = process.env.MUADDIB_DATA_DIR;
    assert(v && path.resolve(v) !== REPO_DATA && !path.resolve(v).startsWith(ROOT + path.sep),
      'tests/run-tests.js must set MUADDIB_DATA_DIR to a temporary directory, got ' + v);
  });

  test('DATA-DIR: monitor state writes land in MUADDIB_DATA_DIR, never in the repository data/', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-datadir-'));
    const before = snapshot(REPO_DATA);
    try {
      const script = "const s = require(process.argv[1]);" +
        "s.appendDetection('datadir-probe', '1.0.0', 'npm', ['probe'], 'HIGH');" +
        "s.appendAlert({ name: 'datadir-probe', version: '1.0.0', findings: [] });";
      const env = { ...process.env, MUADDIB_DATA_DIR: tmp };
      delete env.MUADDIB_DETECTIONS_FILE;
      const r = spawnSync(process.execPath, ['-e', script, path.join(ROOT, 'src', 'monitor', 'state.js')], { env, encoding: 'utf8' });
      assert(r.status === 0, 'probe failed: ' + r.stderr);
      const written = fs.readdirSync(tmp);
      assert(written.includes('detections.jsonl') && written.includes('monitor-alerts.jsonl'),
        'detections and alerts expected in the data dir, got ' + written.join(','));
      const after = snapshot(REPO_DATA);
      const changed = Object.keys(after).filter(k => after[k] !== before[k]);
      assert(changed.length === 0, 'repository data/ was written: ' + changed.join(','));
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  });
}

module.exports = { runDataDirTests };
