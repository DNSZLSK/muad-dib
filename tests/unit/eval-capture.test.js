'use strict';

// Evaluation capture (architecture lot 7): the random sample drawn over every scanned
// package (eval-sample.js), its ledger flag (state.js appendScanLedger), and the
// tarball capture of the random sample and of the near misses (tarball-archive.js
// captureForEvaluation, called at the end of queue.js scanPackage).

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync, execFileSync } = require('child_process');
const { test, asyncTest, assert } = require('../test-utils');

const SAMPLE = '../../src/monitor/eval-sample.js';
const ARCHIVE = '../../src/monitor/tarball-archive.js';

const AMPLE = { bavail: 1e9, bsize: 4096 }; // ~3.7 TB free
function withFreeSpace(stat, fn) {
  const real = fs.statfsSync;
  fs.statfsSync = () => stat;
  return Promise.resolve().then(fn).finally(() => { fs.statfsSync = real; });
}

// Save, set, run, restore a set of environment variables (undefined = unset).
async function withEnv(vars, fn) {
  const saved = {};
  for (const k of Object.keys(vars)) {
    saved[k] = process.env[k];
    if (vars[k] === undefined) delete process.env[k]; else process.env[k] = vars[k];
  }
  try { return await fn(); } finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    }
  }
}

function freshSample() {
  delete require.cache[require.resolve(SAMPLE)];
  return require(SAMPLE);
}

// tarball-archive.js reads MUADDIB_ARCHIVE_DIR at load: reload it inside the env.
function freshArchive() {
  delete require.cache[require.resolve(ARCHIVE)];
  delete require.cache[require.resolve(SAMPLE)];
  return require(ARCHIVE);
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function fakeTgz(dir, bytes = 4096) {
  const p = path.join(dir, 'package.tar.gz');
  fs.writeFileSync(p, crypto.randomBytes(bytes));
  return p;
}

function archivedFiles(archiveRoot) {
  if (!fs.existsSync(archiveRoot)) return [];
  const out = [];
  for (const day of fs.readdirSync(archiveRoot)) {
    for (const f of fs.readdirSync(path.join(archiveRoot, day))) out.push(path.join(archiveRoot, day, f));
  }
  return out;
}

async function runEvalCaptureTests() {
  console.log('\n=== Evaluation Capture Tests ===\n');

  // --- Random sample draw ---

  await asyncTest('EVAL-SAMPLE: rate 0 never draws, rate 1 always draws', async () => {
    await withEnv({ MUADDIB_EVAL_SAMPLE_SALT: 'k1', MUADDIB_EVAL_SAMPLE_RATE: '0' }, () => {
      const s = freshSample();
      for (let i = 0; i < 200; i++) assert(!s.isEvalRandomSample('npm', `p${i}`, '1.0.0'), 'rate 0 must never draw');
    });
    await withEnv({ MUADDIB_EVAL_SAMPLE_SALT: 'k1', MUADDIB_EVAL_SAMPLE_RATE: '1' }, () => {
      const s = freshSample();
      for (let i = 0; i < 200; i++) assert(s.isEvalRandomSample('npm', `p${i}`, '1.0.0'), 'rate 1 must always draw');
    });
  });

  await asyncTest('EVAL-SAMPLE: default rate is 1 %, drawn fraction close to it, invalid rate falls back', async () => {
    await withEnv({ MUADDIB_EVAL_SAMPLE_SALT: 'k2', MUADDIB_EVAL_SAMPLE_RATE: undefined }, () => {
      const s = freshSample();
      assert(s.getEvalSampleRate() === 0.01, `default rate 0.01, got ${s.getEvalSampleRate()}`);
      let n = 0;
      const N = 40000;
      for (let i = 0; i < N; i++) if (s.isEvalRandomSample('npm', `pkg-${i}`, '1.0.0')) n++;
      // Binomial(40000, 0.01): mean 400, sd ~19.9; [300, 500] is +-5 sd.
      assert(n >= 300 && n <= 500, `drawn ${n}/${N}, expected about 400`);
    });
    for (const bad of ['-0.1', '1.5', 'abc']) {
      await withEnv({ MUADDIB_EVAL_SAMPLE_RATE: bad }, () => {
        assert(freshSample().getEvalSampleRate() === 0.01, `rate "${bad}" must fall back to 0.01`);
      });
    }
  });

  await asyncTest('EVAL-SAMPLE: same key gives the same draw, another key another set (not predictable without it)', async () => {
    const keys = Array.from({ length: 5000 }, (_, i) => `pkg-${i}`);
    const drawn = async (salt) => withEnv({ MUADDIB_EVAL_SAMPLE_SALT: salt, MUADDIB_EVAL_SAMPLE_RATE: '0.05' }, () => {
      const s = freshSample();
      return keys.filter(k => s.isEvalRandomSample('npm', k, '1.0.0')).join(',');
    });
    const a1 = await drawn('alpha');
    const a2 = await drawn('alpha');
    const b = await drawn('beta');
    assert(a1 === a2, 'same key must give the same sample');
    assert(a1 !== b, 'a different key must give a different sample');
  });

  await asyncTest('EVAL-SAMPLE: ecosystem and version are part of the draw; missing name or version never draws', async () => {
    await withEnv({ MUADDIB_EVAL_SAMPLE_SALT: 'k3', MUADDIB_EVAL_SAMPLE_RATE: '0.5' }, () => {
      const s = freshSample();
      const keys = Array.from({ length: 400 }, (_, i) => `p${i}`);
      const npm = keys.map(k => s.isEvalRandomSample('npm', k, '1.0.0')).join('');
      const pypi = keys.map(k => s.isEvalRandomSample('pypi', k, '1.0.0')).join('');
      const v2 = keys.map(k => s.isEvalRandomSample('npm', k, '2.0.0')).join('');
      assert(npm !== pypi && npm !== v2, 'ecosystem and version must change the draw');
      assert(!s.isEvalRandomSample('npm', '', '1.0.0') && !s.isEvalRandomSample('npm', 'x', null), 'no name or version: never drawn');
    });
  });

  await asyncTest('EVAL-SAMPLE: without a salt, the key is created once in the data dir (0600) and reused', async () => {
    const data = tmpDir('evalkey-');
    try {
      await withEnv({ MUADDIB_EVAL_SAMPLE_SALT: undefined, MUADDIB_DATA_DIR: data, MUADDIB_EVAL_SAMPLE_RATE: '0.5' }, () => {
        const keys = Array.from({ length: 300 }, (_, i) => `p${i}`);
        const s1 = freshSample();
        const first = keys.map(k => s1.isEvalRandomSample('npm', k, '1.0.0')).join('');
        const keyFile = path.join(data, 'eval-sample.key');
        assert(fs.existsSync(keyFile), 'key file created');
        assert(/^[0-9a-f]{64}$/.test(fs.readFileSync(keyFile, 'utf8').trim()), 'key file holds 32 random bytes in hex');
        if (process.platform !== 'win32') {
          assert((fs.statSync(keyFile).mode & 0o077) === 0, 'key file not readable by group or others');
        }
        const s2 = freshSample(); // a restart: new module instance, same file
        const second = keys.map(k => s2.isEvalRandomSample('npm', k, '1.0.0')).join('');
        assert(first === second, 'the draw must survive a restart');
      });
    } finally { fs.rmSync(data, { recursive: true, force: true }); }
  });

  // --- Ledger flag ---

  await asyncTest('EVAL-SAMPLE: the scan ledger marks drawn packages evalSample: true, and only them', async () => {
    const f = path.join(os.tmpdir(), `ledger-eval-${process.pid}-${Date.now()}.jsonl`);
    try {
      for (const [rate, expected] of [['1', true], ['0', false]]) {
        await withEnv({ MUADDIB_SCAN_LEDGER_FILE: f, MUADDIB_EVAL_SAMPLE_SALT: 'k4', MUADDIB_EVAL_SAMPLE_RATE: rate }, () => {
          try { fs.unlinkSync(f); } catch { /* none */ }
          delete require.cache[require.resolve('../../src/monitor/state.js')];
          delete require.cache[require.resolve(SAMPLE)];
          const st = require('../../src/monitor/state.js');
          st.appendScanLedger({ name: 'drawn', version: '1.0.0', ecosystem: 'npm', outcome: 'clean', score: 0 });
          st.appendScanLedger({ name: 'killed', version: '1.0.0', ecosystem: 'npm', outcome: 'static_timeout', source: 'static_timeout' });
          const rows = st.loadScanLedger();
          assert(rows.length === 2, `2 ledger rows, got ${rows.length}`);
          for (const r of rows) {
            if (expected) assert(r.evalSample === true, `rate 1: ${r.name} must carry evalSample`);
            else assert(!('evalSample' in r), `rate 0: ${r.name} must not carry evalSample`);
          }
        });
      }
    } finally {
      try { fs.unlinkSync(f); } catch { /* none */ }
      delete require.cache[require.resolve('../../src/monitor/state.js')];
    }
  });

  // --- captureForEvaluation ---

  async function inArchive(env, fn) {
    const root = tmpDir('evalarch-');
    const work = tmpDir('evalwork-');
    try {
      // Near-miss rate 1 unless a test sets it: the other tests check what a kept near miss is.
      return await withEnv({ MUADDIB_ARCHIVE_DIR: root, MUADDIB_EVAL_SAMPLE_SALT: 'k5', MUADDIB_EVAL_NEAR_MISS_RATE: '1', ...env }, async () => {
        const mod = freshArchive();
        mod._resetNearMissBudgetForTests();
        return await fn(mod, root, work);
      });
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(work, { recursive: true, force: true });
      delete require.cache[require.resolve(ARCHIVE)];
    }
  }

  await asyncTest('EVAL-CAPTURE: a near miss (score 1-19) is kept: .tgz copied, JSON with reason and SHA-256', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '0' }, async (mod, root, work) => {
      const tgz = fakeTgz(work);
      const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: '@sc/near', version: '1.2.3', ecosystem: 'npm', tgzPath: tgz, score: 12, suspectKeepsTarball: false }));
      assert(Array.isArray(r) && r.join() === 'near_miss', `reasons near_miss, got ${JSON.stringify(r)}`);
      const files = archivedFiles(root).map(p => path.basename(p)).sort();
      assert(files.join() === 'sc__near-1.2.3.json,sc__near-1.2.3.tgz', `archived files: ${files.join()}`);
      const dayDir = path.dirname(archivedFiles(root)[0]);
      const meta = JSON.parse(fs.readFileSync(path.join(dayDir, 'sc__near-1.2.3.json'), 'utf8'));
      const sha = crypto.createHash('sha256').update(fs.readFileSync(tgz)).digest('hex');
      assert(meta.tarball_archived === true && meta.tarball_sha256 === sha, 'tarball_archived true with the copy SHA-256');
      assert(meta.score === 12 && meta.eval_sample === false && meta.capture_reasons.join() === 'near_miss', 'score, eval_sample, reasons');
      assert(meta.package === '@sc/near' && meta.version === '1.2.3' && meta.ecosystem === 'npm', 'identity fields');
      assert(fs.existsSync(tgz), 'the scan tarball itself is untouched (copy, not move)');
    });
  });

  await asyncTest('EVAL-CAPTURE: not drawn and score 0, or at/above the tgz floor, is not kept', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '0' }, async (mod, root, work) => {
      const tgz = fakeTgz(work);
      for (const score of [0, 20, 75, null]) {
        const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: `s${score}`, version: '1.0.0', ecosystem: 'npm', tgzPath: tgz, score, suspectKeepsTarball: false }));
        assert(r === null, `score ${score} not drawn: nothing kept, got ${JSON.stringify(r)}`);
      }
      assert(archivedFiles(root).length === 0, 'archive stays empty');
    });
  });

  await asyncTest('EVAL-CAPTURE: the random sample is kept at any score, even without one (timeout)', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '1' }, async (mod, root, work) => {
      const tgz = fakeTgz(work);
      for (const [name, score, reasons] of [['zero', 0, 'random'], ['high', 60, 'random'], ['near', 5, 'random,near_miss'], ['timeout', null, 'random']]) {
        const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name, version: '1.0.0', ecosystem: 'npm', tgzPath: tgz, score, suspectKeepsTarball: false }));
        assert(r && r.join() === reasons, `${name}: reasons ${reasons}, got ${JSON.stringify(r)}`);
      }
      const day = path.dirname(archivedFiles(root)[0]);
      const t = JSON.parse(fs.readFileSync(path.join(day, 'timeout-1.0.0.json'), 'utf8'));
      assert(t.score === null && t.eval_sample === true, 'timeout capture: score null, eval_sample true');
    });
  });

  await asyncTest('EVAL-CAPTURE: never duplicates what the suspect archive keeps, never overwrites a kept .tgz', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '1' }, async (mod, root, work) => {
      const tgz = fakeTgz(work);
      const r1 = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: 'sus', version: '1.0.0', ecosystem: 'npm', tgzPath: tgz, score: 45, suspectKeepsTarball: true }));
      assert(r1 === null && archivedFiles(root).length === 0, 'suspect archive owns it: no capture');
      const r2 = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: 'twice', version: '1.0.0', ecosystem: 'npm', tgzPath: tgz, score: 3, suspectKeepsTarball: false }));
      const kept = archivedFiles(root).find(p => p.endsWith('.tgz'));
      const before = fs.readFileSync(kept);
      const r3 = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: 'twice', version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work), score: 3, suspectKeepsTarball: false }));
      assert(r2 && r3 === null, 'second capture of the same version is a no-op');
      assert(Buffer.compare(before, fs.readFileSync(kept)) === 0, 'kept .tgz unchanged');
    });
  });

  await asyncTest('EVAL-CAPTURE: a JSON-only suspect record (score < 20) keeps its fields and gains the tarball', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '0' }, async (mod, root, work) => {
      // What archiveSuspectTarball writes synchronously for a T2 suspect under the tgz floor.
      await withFreeSpace(AMPLE, () => mod.archiveSuspectTarball('t2pkg', '1.0.0', 'http://127.0.0.1:1/t2pkg.tgz', { score: 15, priority: 'T2', rulesTriggered: ['AST-001'] }));
      const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: 't2pkg', version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work), score: 15, suspectKeepsTarball: false }));
      assert(r && r.join() === 'near_miss', 'near miss kept');
      const day = path.dirname(archivedFiles(root)[0]);
      const meta = JSON.parse(fs.readFileSync(path.join(day, 't2pkg-1.0.0.json'), 'utf8'));
      assert(meta.priority === 'T2' && meta.rules_triggered.join() === 'AST-001', 'suspect fields preserved');
      assert(meta.tarball_archived === true && typeof meta.tarball_sha256 === 'string', 'now marked archived with a hash');
    });
  });

  await asyncTest('EVAL-CAPTURE: near-miss daily budget stops near misses, not the random sample', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '0', MUADDIB_EVAL_NEAR_MISS_MAX_MB_PER_DAY: '0' }, async (mod, root, work) => {
      const origWarn = console.warn; console.warn = () => {};
      try {
        const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: 'nm', version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work), score: 9, suspectKeepsTarball: false }));
        assert(r === null && archivedFiles(root).length === 0, 'budget 0: near miss not kept');
      } finally { console.warn = origWarn; }
    });
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '1', MUADDIB_EVAL_NEAR_MISS_MAX_MB_PER_DAY: '0' }, async (mod, root, work) => {
      const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: 'rnd', version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work), score: 9, suspectKeepsTarball: false }));
      assert(r && r.includes('random'), 'random sample is not subject to the near-miss budget');
    });
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '0', MUADDIB_EVAL_NEAR_MISS_MAX_MB_PER_DAY: '1' }, async (mod, root, work) => {
      const origWarn = console.warn; console.warn = () => {};
      try {
        const kept = [];
        for (let i = 0; i < 5; i++) {
          const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: `b${i}`, version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work, 300 * 1024), score: 9, suspectKeepsTarball: false }));
          if (r) kept.push(i);
        }
        assert(kept.join() === '0,1,2', `1 MB budget holds three 300 KB near misses, kept ${kept.join()}`);
      } finally { console.warn = origWarn; }
    });
  });

  await asyncTest('EVAL-NEAR-MISS: default rate 20 %, drawn fraction close to it, independent of the random sample', async () => {
    await withEnv({ MUADDIB_EVAL_SAMPLE_SALT: 'k6', MUADDIB_EVAL_SAMPLE_RATE: '0.2', MUADDIB_EVAL_NEAR_MISS_RATE: undefined }, () => {
      const s = freshSample();
      assert(s.getEvalNearMissRate() === 0.2, `default near-miss rate 0.2, got ${s.getEvalNearMissRate()}`);
      const N = 20000;
      let nm = 0, both = 0;
      for (let i = 0; i < N; i++) {
        const a = s.isEvalNearMissSample('npm', `pkg-${i}`, '1.0.0');
        const b = s.isEvalRandomSample('npm', `pkg-${i}`, '1.0.0');
        if (a) nm++;
        if (a && b) both++;
      }
      // Binomial(20000, 0.2): mean 4000, sd ~56.6; [3700, 4300] is about +-5 sd.
      assert(nm >= 3700 && nm <= 4300, `near-miss drawn ${nm}/${N}, expected about 4000`);
      // Independent draws at 0.2 x 0.2: mean 800, sd ~27.7. The same draw would give ~4000.
      assert(both >= 650 && both <= 950, `overlap with the random sample ${both}, expected about 800 (independent draws)`);
    });
    for (const bad of ['-1', '2', 'x']) {
      await withEnv({ MUADDIB_EVAL_NEAR_MISS_RATE: bad }, () => {
        assert(freshSample().getEvalNearMissRate() === 0.2, `near-miss rate "${bad}" must fall back to 0.2`);
      });
    }
  });

  await asyncTest('EVAL-NEAR-MISS: rate 0 keeps no near miss, rate 0.2 keeps only the drawn ones', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '0', MUADDIB_EVAL_NEAR_MISS_RATE: '0' }, async (mod, root, work) => {
      const tgz = fakeTgz(work);
      for (let i = 0; i < 20; i++) {
        const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: `z${i}`, version: '1.0.0', ecosystem: 'npm', tgzPath: tgz, score: 7, suspectKeepsTarball: false }));
        assert(r === null, `rate 0: near miss z${i} not kept`);
      }
      assert(archivedFiles(root).length === 0, 'archive stays empty');
    });
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '0', MUADDIB_EVAL_NEAR_MISS_RATE: '0.2' }, async (mod, root, work) => {
      const tgz = fakeTgz(work, 256);
      const s = require(SAMPLE);
      let kept = 0, drawn = 0;
      for (let i = 0; i < 200; i++) {
        const name = `d${i}`;
        if (s.isEvalNearMissSample('npm', name, '1.0.0')) drawn++;
        const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name, version: '1.0.0', ecosystem: 'npm', tgzPath: tgz, score: 7, suspectKeepsTarball: false }));
        if (r) {
          kept++;
          assert(s.isEvalNearMissSample('npm', name, '1.0.0'), `${name} kept but not drawn`);
        }
      }
      assert(kept === drawn && kept > 0 && kept < 200, `kept ${kept}, drawn ${drawn}: exactly the drawn near misses`);
    });
  });

  await asyncTest('EVAL-NEAR-MISS: a restarted process rebuilds the day budget from disk', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '0', MUADDIB_EVAL_NEAR_MISS_MAX_MB_PER_DAY: '1' }, async (mod, root, work) => {
      const origWarn = console.warn; console.warn = () => {};
      try {
        for (let i = 0; i < 3; i++) {
          const r = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: `before${i}`, version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work, 300 * 1024), score: 9, suspectKeepsTarball: false }));
          assert(r, `before restart: near miss ${i} kept`);
        }
        mod._resetNearMissBudgetForTests(); // the restart: in-memory budget gone, files stay
        const fresh = freshArchive();
        fresh._resetNearMissBudgetForTests();
        const r = await withFreeSpace(AMPLE, () => fresh.captureForEvaluation({ name: 'after', version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work, 300 * 1024), score: 9, suspectKeepsTarball: false }));
        assert(r === null, `after restart: 900 KB already on disk, a 300 KB near miss exceeds 1 MB, got ${JSON.stringify(r)}`);
      } finally { console.warn = origWarn; }
    });
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '1', MUADDIB_EVAL_NEAR_MISS_MAX_MB_PER_DAY: '1' }, async (mod, root, work) => {
      // Random captures (even with a near-miss score) are outside the near-miss budget on disk too.
      for (let i = 0; i < 4; i++) {
        await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: `rnd${i}`, version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work, 300 * 1024), score: 9, suspectKeepsTarball: false }));
      }
      await withEnv({ MUADDIB_EVAL_SAMPLE_RATE: '0' }, async () => {
        const fresh = freshArchive();
        fresh._resetNearMissBudgetForTests();
        const r = await withFreeSpace(AMPLE, () => fresh.captureForEvaluation({ name: 'nm-after', version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work, 300 * 1024), score: 9, suspectKeepsTarball: false }));
        assert(r && r.join() === 'near_miss', `1.2 MB of random captures must not use the near-miss budget, got ${JSON.stringify(r)}`);
      });
    });
  });

  await asyncTest('EVAL-CAPTURE: stops at its own free-space floor, above the suspect floor', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '1' }, async (mod, root, work) => {
      // 10 GB free: above the 5 GB suspect floor, below the 25 GB evaluation floor.
      const tenGb = { bavail: (10 * 1024 * 1024 * 1024) / 4096, bsize: 4096 };
      const r = await withFreeSpace(tenGb, () => mod.captureForEvaluation({ name: 'low', version: '1.0.0', ecosystem: 'npm', tgzPath: fakeTgz(work), score: 0, suspectKeepsTarball: false }));
      assert(r === null && archivedFiles(root).length === 0, 'no capture below the evaluation floor');
      assert(await withFreeSpace(tenGb, () => mod.hasEnoughSpace(root)), 'the suspect archive still has room at 10 GB');
      assert(mod.getEvalMinFreeBytes() === 25 * 1024 * 1024 * 1024, 'default evaluation floor 25 GB');
    });
    await withEnv({ MUADDIB_EVAL_CAPTURE_MIN_FREE_GB: '1', MUADDIB_ARCHIVE_MIN_FREE_GB: '5' }, () => {
      const mod = freshArchive();
      assert(mod.getEvalMinFreeBytes() === 5 * 1024 * 1024 * 1024, 'evaluation floor is never below the suspect floor');
    });
  });

  await asyncTest('EVAL-CAPTURE: unsafe version or missing tarball never writes, never throws', async () => {
    await inArchive({ MUADDIB_EVAL_SAMPLE_RATE: '1' }, async (mod, root, work) => {
      const r1 = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: 'x', version: '1.0.0', ecosystem: 'npm', tgzPath: path.join(work, 'absent.tgz'), score: 0, suspectKeepsTarball: false }));
      const r2 = await withFreeSpace(AMPLE, () => mod.captureForEvaluation({ name: 'x', version: '../../../escape', ecosystem: 'npm', tgzPath: fakeTgz(work), score: 0, suspectKeepsTarball: false }));
      assert(r1 === null, 'missing tarball: nothing kept');
      assert(r2 && archivedFiles(root).every(p => path.dirname(path.dirname(p)) === root), 'sanitized name stays inside its day dir');
    });
  });

  // --- End to end: queue.js scanPackage keeps a drawn package, not an undrawn clean one ---

  test('EVAL-CAPTURE: scanPackage keeps the scanned tarball of a drawn package (rate 1) and nothing at rate 0', () => {
    const work = tmpDir('evale2e-');
    try {
      const pkgDir = path.join(work, 'package');
      fs.mkdirSync(pkgDir);
      fs.writeFileSync(path.join(pkgDir, 'package.json'), '{"name":"e2e-clean","version":"1.0.0"}');
      fs.writeFileSync(path.join(pkgDir, 'index.js'), 'module.exports = function add(a, b) { return a + b; };\n');
      const tgz = path.join(work, 'fixture.tgz');
      // Relative paths: GNU tar reads "C:\..." as a remote host (host:path) on Windows.
      execFileSync('tar', ['czf', 'fixture.tgz', 'package'], { cwd: work });
      const driver = `
        const fs = require('fs'), path = require('path');
        const state = require(${JSON.stringify(path.resolve(__dirname, '../../src/monitor/state.js'))});
        const queue = require(${JSON.stringify(path.resolve(__dirname, '../../src/monitor/queue.js'))});
        const cache = state.tarballCachePath(state.tarballCacheKey('e2e-clean', '1.0.0'));
        fs.mkdirSync(path.dirname(cache), { recursive: true });
        fs.copyFileSync(process.argv[1], cache);
        const stats = { scanned: 0, clean: 0, suspect: 0, errors: 0,
          suspectByTier: { t1: 0, t1a: 0, t1b: 0, t2: 0, t3: 0 },
          errorsByType: { too_large: 0, tar_failed: 0, archive_failed: 0, unsupported_format: 0, http_error: 0, timeout: 0, static_timeout: 0, other: 0 },
          totalTimeMs: 0, mlFiltered: 0, lastReportTime: Date.now() };
        queue.scanPackage('e2e-clean', '1.0.0', 'npm', 'http://127.0.0.1:1/e2e-clean-1.0.0.tgz', {}, stats, [], new Set(), new Map(), [], false)
          .then(() => { console.log('E2E_DONE scanned=' + stats.scanned + ' clean=' + stats.clean); process.exit(0); })
          .catch(e => { console.log('E2E_FAIL ' + e.message); process.exit(1); });`;
      for (const [rate, expectKept] of [['1', true], ['0', false]]) {
        const archive = path.join(work, `archive-${rate}`);
        const env = { ...process.env,
          MUADDIB_ARCHIVE_DIR: archive,
          MUADDIB_DATA_DIR: path.join(work, `data-${rate}`),
          MUADDIB_TARBALL_CACHE_DIR: path.join(work, `cache-${rate}`),
          MUADDIB_SCAN_LEDGER_FILE: path.join(work, `ledger-${rate}.jsonl`),
          MUADDIB_EVAL_SAMPLE_RATE: rate,
          MUADDIB_EVAL_SAMPLE_SALT: 'e2e',
          MUADDIB_EVAL_CAPTURE_MIN_FREE_GB: '1',
          MUADDIB_ARCHIVE_MIN_FREE_GB: '1',
          MUADDIB_NO_REGISTRY_FETCH: '1' };
        const out = spawnSync(process.execPath, ['-e', driver, tgz], { encoding: 'utf8', env, timeout: 90000 });
        assert(/E2E_DONE scanned=1 clean=1/.test(out.stdout), `rate ${rate}: scan must complete clean; stdout=${out.stdout.slice(-400)} stderr=${(out.stderr || '').slice(-400)}`);
        const kept = archivedFiles(archive).filter(p => p.endsWith('.tgz'));
        if (expectKept) {
          assert(kept.length === 1 && path.basename(kept[0]) === 'e2e-clean-1.0.0.tgz', `rate 1: tarball kept, got ${kept.map(p => path.basename(p)).join()}`);
          assert(Buffer.compare(fs.readFileSync(kept[0]), fs.readFileSync(tgz)) === 0, 'kept bytes are the scanned tarball');
          const meta = JSON.parse(fs.readFileSync(kept[0].replace(/\.tgz$/, '.json'), 'utf8'));
          assert(meta.eval_sample === true && meta.score === 0 && meta.capture_reasons.join() === 'random', `metadata ${JSON.stringify(meta)}`);
        } else {
          assert(kept.length === 0, `rate 0, clean: nothing kept, got ${kept.length}`);
        }
        const ledger = fs.readFileSync(path.join(work, `ledger-${rate}.jsonl`), 'utf8').trim().split('\n').map(l => JSON.parse(l));
        const row = ledger.find(r => r.name === 'e2e-clean');
        assert(row && row.outcome === 'clean', `ledger row for the scan, got ${JSON.stringify(ledger)}`);
        assert(expectKept ? row.evalSample === true : !('evalSample' in row), `rate ${rate}: ledger evalSample flag`);
      }
    } finally { fs.rmSync(work, { recursive: true, force: true }); }
  });
}

module.exports = { runEvalCaptureTests };
