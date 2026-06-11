'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { Worker } = require('worker_threads');
const { test, asyncTest, assert, spyOn } = require('../test-utils');
const shadow = require('../../src/shared/shadow.js');

// All env read at CALL time in shadow.js — point at a temp file per test.
function withShadowEnv(file, fn, { enabled = true, max } = {}) {
  const save = {
    on: process.env.MUADDIB_SHADOW,
    file: process.env.MUADDIB_SHADOW_FILE,
    max: process.env.MUADDIB_SHADOW_MAX
  };
  if (enabled) process.env.MUADDIB_SHADOW = '1'; else delete process.env.MUADDIB_SHADOW;
  process.env.MUADDIB_SHADOW_FILE = file;
  if (max !== undefined) process.env.MUADDIB_SHADOW_MAX = String(max);
  else delete process.env.MUADDIB_SHADOW_MAX;
  try { return fn(); }
  finally {
    for (const [k, env] of [['on', 'MUADDIB_SHADOW'], ['file', 'MUADDIB_SHADOW_FILE'], ['max', 'MUADDIB_SHADOW_MAX']]) {
      if (save[k] !== undefined) process.env[env] = save[k];
      else delete process.env[env];
    }
  }
}

async function runShadowTests() {
  console.log('\n=== SHADOW-MODE FRAMEWORK TESTS ===\n');

  test('SHADOW: divergence written with exact shape (round-trip)', () => {
    const f = path.join(os.tmpdir(), `shadow-${Date.now()}-a.jsonl`);
    try {
      withShadowEnv(f, () => {
        shadow.recordShadowDivergence({
          detector: 'compromised_email_domain', package: 'node-ipc', version: '9.2.3',
          ecosystem: 'npm', oldVerdict: true, newVerdict: false,
          evidence: { domain: 'atlantis-software.net', oldMarginDays: 30 }
        });
        const e = shadow.readShadowDivergences();
        assert(e.length === 1, `expected 1 entry, got ${e.length}`);
        const r = e[0];
        assert(r.detector === 'compromised_email_domain' && r.package === 'node-ipc' && r.version === '9.2.3', 'identity fields preserved');
        assert(r.oldVerdict === true && r.newVerdict === false, 'verdicts preserved');
        assert(r.evidence && r.evidence.domain === 'atlantis-software.net', 'evidence preserved');
        assert(typeof r.ts === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(r.ts), 'ts is ISO');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SHADOW: flag off → nothing written, no file created', () => {
    const f = path.join(os.tmpdir(), `shadow-${Date.now()}-off.jsonl`);
    withShadowEnv(f, () => {
      shadow.recordShadowDivergence({ detector: 'x', oldVerdict: 1, newVerdict: 2 });
      assert(!fs.existsSync(f), 'disabled shadow must not create the file');
      assert(shadow.isShadowEnabled() === false, 'isShadowEnabled false when env unset');
    }, { enabled: false });
  });

  test('SHADOW: oversized evidence is truncated, line stays parsable', () => {
    const f = path.join(os.tmpdir(), `shadow-${Date.now()}-big.jsonl`);
    try {
      withShadowEnv(f, () => {
        shadow.recordShadowDivergence({
          detector: 'x', oldVerdict: 'a', newVerdict: 'b',
          evidence: { blob: 'z'.repeat(10_000) }
        });
        const e = shadow.readShadowDivergences();
        assert(e.length === 1, 'entry parsable');
        assert(e[0].evidence && e[0].evidence._truncated === true, 'evidence marked truncated');
        assert(JSON.stringify(e[0].evidence).length < 3000, 'evidence capped near 2KB');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SHADOW: missing detector or malformed input → silent no-op (never throws)', () => {
    const f = path.join(os.tmpdir(), `shadow-${Date.now()}-noop.jsonl`);
    try {
      withShadowEnv(f, () => {
        shadow.recordShadowDivergence(null);
        shadow.recordShadowDivergence({});
        shadow.recordShadowDivergence({ oldVerdict: 1, newVerdict: 2 }); // no detector
        assert(!fs.existsSync(f), 'no entry without a detector');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SHADOW: write failure (EROFS) is swallowed — a shadow failure must never break a scan', () => {
    const f = path.join(os.tmpdir(), `shadow-${Date.now()}-rofs.jsonl`);
    withShadowEnv(f, () => {
      const spy = spyOn(fs, 'appendFileSync', () => { const e = new Error('read-only'); e.code = 'EROFS'; throw e; });
      try {
        shadow.recordShadowDivergence({ detector: 'x', oldVerdict: 1, newVerdict: 2 });
        assert(spy.callCount >= 1, 'append attempted');
      } finally { spy.restore(); }
      assert(true, 'no exception propagated');
    });
  });

  test('SHADOW: compaction keeps the most recent MAX entries (bounded log)', () => {
    const f = path.join(os.tmpdir(), `shadow-${Date.now()}-cap.jsonl`);
    try {
      withShadowEnv(f, () => {
        for (let i = 0; i < 25; i++) {
          shadow.recordShadowDivergence({ detector: 'd', package: `p${i}`, oldVerdict: 1, newVerdict: 2 });
        }
        shadow._compactShadowJsonl(f); // explicit (interval-triggered in prod)
        const e = shadow.readShadowDivergences();
        assert(e.length === 10, `cap=10 must keep 10, got ${e.length}`);
        assert(e[0].package === 'p15' && e[e.length - 1].package === 'p24', 'keeps the most recent (FIFO drop)');
      }, { max: 10 });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  test('SHADOW: reader skips corrupt lines and filters by detector + sinceTs', () => {
    const f = path.join(os.tmpdir(), `shadow-${Date.now()}-filter.jsonl`);
    try {
      withShadowEnv(f, () => {
        shadow.recordShadowDivergence({ detector: 'alpha', package: 'a', oldVerdict: 1, newVerdict: 2 });
        fs.appendFileSync(f, '{ truncated-mid-write\n');
        shadow.recordShadowDivergence({ detector: 'beta', package: 'b', oldVerdict: 1, newVerdict: 2 });
        const all = shadow.readShadowDivergences();
        assert(all.length === 2, `corrupt line skipped (got ${all.length})`);
        const onlyBeta = shadow.readShadowDivergences({ detector: 'beta' });
        assert(onlyBeta.length === 1 && onlyBeta[0].package === 'b', 'detector filter');
        const future = shadow.readShadowDivergences({ sinceTs: Date.now() + 60_000 });
        assert(future.length === 0, 'sinceTs filter excludes older entries');
      });
    } finally { try { fs.unlinkSync(f); } catch {} }
  });

  // THE key behavioral gate: a full CLI scan with shadow ON produces the SAME
  // verdict as with shadow OFF. The framework has no channel back into the
  // pipeline — this test pins that contract end-to-end (execSync directly, not
  // runScan, because runScan's cache would serve the first run's output twice).
  await asyncTest('SHADOW: full scan output identical with shadow ON vs OFF (zero-effect contract)', async () => {
    const { execSync } = require('child_process');
    const BIN = path.join(__dirname, '..', '..', 'bin', 'muaddib.js');
    const target = path.join(__dirname, '..', 'samples', 'entropy');
    const shadowFile = path.join(os.tmpdir(), `shadow-${Date.now()}-identity.jsonl`);
    const scanJson = (extraEnv) => {
      let out;
      try {
        out = execSync(`node "${BIN}" scan "${target}" --json`, {
          encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
          env: { ...process.env, MUADDIB_NO_REGISTRY_FETCH: '1', ...extraEnv }
        });
      } catch (e) { out = e.stdout || ''; }
      return JSON.parse(out);
    };
    try {
      const off = scanJson({});
      const on = scanJson({ MUADDIB_SHADOW: '1', MUADDIB_SHADOW_FILE: shadowFile });
      assert(on.riskScore === off.riskScore, `riskScore identical (off=${off.riskScore}, on=${on.riskScore})`);
      const types = r => JSON.stringify((r.threats || []).map(t => `${t.type}:${t.severity}`).sort());
      assert(types(on) === types(off), 'threat types+severities identical with shadow on');
    } finally { try { fs.unlinkSync(shadowFile); } catch {} }
  });

  // Concurrency: shadow.js is called from inside scan workers — N worker_threads
  // appending concurrently must produce only complete, parsable lines (single
  // appendFileSync per record under O_APPEND).
  await asyncTest('SHADOW: concurrent appends from N workers → every line complete and parsable', async () => {
    const f = path.join(os.tmpdir(), `shadow-${Date.now()}-conc.jsonl`);
    const N_WORKERS = 4, M_RECORDS = 50;
    const workerSrc = `
      const { workerData } = require('worker_threads');
      process.env.MUADDIB_SHADOW = '1';
      process.env.MUADDIB_SHADOW_FILE = workerData.file;
      const shadow = require(workerData.mod);
      for (let i = 0; i < workerData.m; i++) {
        shadow.recordShadowDivergence({
          detector: 'conc', package: 'w' + workerData.id + '-' + i,
          oldVerdict: true, newVerdict: false,
          evidence: { pad: 'x'.repeat(200) }
        });
      }
    `;
    try {
      await Promise.all(Array.from({ length: N_WORKERS }, (_, id) => new Promise((resolve, reject) => {
        const w = new Worker(workerSrc, {
          eval: true,
          workerData: { file: f, m: M_RECORDS, id, mod: require.resolve('../../src/shared/shadow.js') }
        });
        w.on('exit', c => c === 0 ? resolve() : reject(new Error('worker exit ' + c)));
        w.on('error', reject);
      })));
      const raw = fs.readFileSync(f, 'utf8').split('\n').filter(l => l.trim());
      assert(raw.length === N_WORKERS * M_RECORDS, `all ${N_WORKERS * M_RECORDS} lines present, got ${raw.length}`);
      let parsed = 0;
      for (const line of raw) { JSON.parse(line); parsed++; } // throws on interleaved/torn line
      assert(parsed === raw.length, 'every line parses (no interleaving under O_APPEND single-write)');
    } finally { try { fs.unlinkSync(f); } catch {} }
  });
}

module.exports = { runShadowTests };
