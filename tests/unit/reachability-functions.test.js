'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { test, assert } = require('../test-utils');
const reachability = require('../../src/scanner/reachability.js');
const { _internals, computeReachableFunctions } = reachability;

function _writePackage(files) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-fnreach-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(tmp, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return tmp;
}

function _cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

function runReachabilityFunctionsTests() {
  console.log('\n=== REACHABILITY FUNCTIONS TESTS (Chantier 2) ===\n');

  // ---------------------------------------------------------------------------
  // Dynamic resolution detection (fail-open guard)
  // ---------------------------------------------------------------------------

  test('hasDynamicResolution: eval triggers fail-open', () => {
    const ast = _internals._parseWithLocations('eval("1+1");');
    assert(_internals._hasDynamicResolution(ast) === true, 'eval should mark file dynamic');
  });

  test('hasDynamicResolution: new Function triggers fail-open', () => {
    const ast = _internals._parseWithLocations('const f = new Function("return 1");');
    assert(_internals._hasDynamicResolution(ast) === true, 'new Function should mark dynamic');
  });

  test('hasDynamicResolution: dynamic require triggers fail-open', () => {
    const ast = _internals._parseWithLocations('const x = "fs"; require(x);');
    assert(_internals._hasDynamicResolution(ast) === true, 'require(var) should mark dynamic');
  });

  test('hasDynamicResolution: globalThis[var] triggers fail-open', () => {
    const ast = _internals._parseWithLocations('const k = "process"; globalThis[k];');
    assert(_internals._hasDynamicResolution(ast) === true, 'globalThis[var] should mark dynamic');
  });

  test('hasDynamicResolution: static require does NOT trigger', () => {
    const ast = _internals._parseWithLocations('const fs = require("fs");');
    assert(_internals._hasDynamicResolution(ast) === false, 'literal require is static');
  });

  test('hasDynamicResolution: globalThis.process (static) does NOT trigger', () => {
    const ast = _internals._parseWithLocations('const p = globalThis.process;');
    assert(_internals._hasDynamicResolution(ast) === false, 'static MemberExpression is fine');
  });

  // ---------------------------------------------------------------------------
  // collectNamedFunctions
  // ---------------------------------------------------------------------------

  test('collectNamedFunctions: captures FunctionDeclaration with line range', () => {
    const code = 'function foo() {\n  return 1;\n}\n';
    const ast = _internals._parseWithLocations(code);
    const fns = _internals._collectNamedFunctions(ast);
    assert(fns.length === 1, 'expected 1 function, got ' + fns.length);
    assert(fns[0].name === 'foo', 'name=foo');
    assert(fns[0].startLine === 1 && fns[0].endLine === 3, 'lines 1-3 expected, got ' + fns[0].startLine + '-' + fns[0].endLine);
  });

  test('collectNamedFunctions: captures const arrow functions', () => {
    const code = 'const bar = () => {\n  return 2;\n};\n';
    const ast = _internals._parseWithLocations(code);
    const fns = _internals._collectNamedFunctions(ast);
    assert(fns.length === 1, 'expected 1 function');
    assert(fns[0].name === 'bar', 'name=bar');
    assert(fns[0].kind === 'fn_const', 'kind=fn_const');
  });

  test('collectNamedFunctions: captures class methods', () => {
    const code = 'class X {\n  foo() { return 1; }\n  bar() { return 2; }\n}\n';
    const ast = _internals._parseWithLocations(code);
    const fns = _internals._collectNamedFunctions(ast);
    const names = fns.map(f => f.name).sort();
    assert(names.length === 2, 'expected 2 methods, got ' + names.length);
    assert(names[0] === 'X.bar' && names[1] === 'X.foo', 'method names: ' + names.join(','));
  });

  // ---------------------------------------------------------------------------
  // collectSeedNames
  // ---------------------------------------------------------------------------

  test('collectSeedNames: module.exports.foo = foo => foo is seed', () => {
    const code = 'function foo() {} module.exports.foo = foo;';
    const ast = _internals._parseWithLocations(code);
    const { seeds } = _internals._collectSeedNames(ast);
    assert(seeds.has('foo'), 'foo should be a seed');
  });

  test('collectSeedNames: ESM export function => seed', () => {
    const code = 'export function bar() {}';
    const ast = _internals._parseWithLocations(code);
    const { seeds } = _internals._collectSeedNames(ast);
    assert(seeds.has('bar'), 'bar should be a seed');
  });

  test('collectSeedNames: top-level call => seed', () => {
    const code = 'function init() {} init();';
    const ast = _internals._parseWithLocations(code);
    const { seeds } = _internals._collectSeedNames(ast);
    assert(seeds.has('init'), 'init should be seeded by top-level call');
  });

  test('collectSeedNames: callback passed at top level => seed', () => {
    const code = 'function cleanup() {} process.on("exit", cleanup);';
    const ast = _internals._parseWithLocations(code);
    const { seeds } = _internals._collectSeedNames(ast);
    assert(seeds.has('cleanup'), 'cleanup should be seeded as callback reference');
  });

  test('collectSeedNames: never-referenced function is NOT seeded', () => {
    const code = 'function dead() {} function used() {} module.exports.used = used;';
    const ast = _internals._parseWithLocations(code);
    const { seeds } = _internals._collectSeedNames(ast);
    assert(!seeds.has('dead'), 'dead should not be seeded');
    assert(seeds.has('used'), 'used should be seeded');
  });

  // ---------------------------------------------------------------------------
  // analyzeFunctionReachability (full BFS)
  // ---------------------------------------------------------------------------

  test('analyzeFunctionReachability: dead helper produces dead range', () => {
    const code =
      'function alive() { return 1; }\n' +
      'function dead() { return 2; }\n' +
      'module.exports.alive = alive;\n';
    const ast = _internals._parseWithLocations(code);
    const result = _internals._analyzeFunctionReachability(ast);
    assert(result.dynamic === false, 'should not be dynamic');
    assert(result.deadRanges.length === 1, 'expected 1 dead range, got ' + result.deadRanges.length);
    assert(result.deadRanges[0].name === 'dead', 'dead range name=' + result.deadRanges[0].name);
  });

  test('analyzeFunctionReachability: indirect call keeps helper alive', () => {
    const code =
      'function helper() { return 1; }\n' +
      'function entry() { return helper() + 1; }\n' +
      'module.exports.entry = entry;\n';
    const ast = _internals._parseWithLocations(code);
    const result = _internals._analyzeFunctionReachability(ast);
    assert(result.deadRanges.length === 0, 'helper should be live, got ' + JSON.stringify(result.deadRanges));
  });

  test('analyzeFunctionReachability: top-level eval => fail-open whole file', () => {
    const code =
      'function dead() { return 1; }\n' +
      'eval("1+1");\n';
    const ast = _internals._parseWithLocations(code);
    const result = _internals._analyzeFunctionReachability(ast);
    assert(result.dynamic === true, 'should mark dynamic at file-level');
    assert(result.deadRanges.length === 0, 'no dead ranges when top-level dynamic');
  });

  test('analyzeFunctionReachability: dead function with eval stays dead (chantier 2 v2)', () => {
    // Granularity improvement: a webpack chunk loader with eval that is never
    // called from any export must still be flagged as dead code. Pre-v2 the
    // file would fail-open globally and lose this signal entirely.
    const code =
      'function chunkLoader() { eval("1"); }\n' + // dead: never referenced
      'function entry() { return 1; }\n' +
      'module.exports.entry = entry;\n';
    const ast = _internals._parseWithLocations(code);
    const result = _internals._analyzeFunctionReachability(ast);
    assert(result.dynamic === false, 'top-level is not dynamic');
    assert(result.dynamicFailOpen === false, 'dead dynamic function does not trigger fail-open');
    const deadNames = result.deadRanges.map(r => r.name);
    assert(deadNames.includes('chunkLoader'),
      'chunkLoader should be dead even though it contains eval, got ' + JSON.stringify(deadNames));
  });

  test('analyzeFunctionReachability: live function with eval triggers fail-open', () => {
    // If the dynamic function IS reached via the call graph, we cannot follow
    // into the eval and must fail-open the rest of the file.
    const code =
      'function helper() { return 2; }\n' + // would be dead, but...
      'function entry() { eval("helper()"); }\n' + // entry is dynamic and live
      'module.exports.entry = entry;\n';
    const ast = _internals._parseWithLocations(code);
    const result = _internals._analyzeFunctionReachability(ast);
    assert(result.dynamicFailOpen === true, 'live dynamic function should fail-open');
    assert(result.deadRanges.length === 0, 'no dead ranges after fail-open, got ' + JSON.stringify(result.deadRanges));
  });

  test('analyzeFunctionReachability: dynamic in nested helper is contained', () => {
    // Helper has eval but is not exported nor referenced - stays dead despite
    // the dynamic content. Other live functions remain analyzable.
    const code =
      'function activeHelper() { return 1; }\n' +
      'function deadDynamic() { eval("anything"); }\n' +
      'function entry() { return activeHelper(); }\n' +
      'module.exports.entry = entry;\n';
    const ast = _internals._parseWithLocations(code);
    const result = _internals._analyzeFunctionReachability(ast);
    assert(result.dynamicFailOpen === false, 'unreached dynamic does not fail-open');
    const deadNames = result.deadRanges.map(r => r.name);
    assert(deadNames.includes('deadDynamic'), 'deadDynamic still flagged dead, got ' + JSON.stringify(deadNames));
    assert(!deadNames.includes('activeHelper'), 'activeHelper kept live');
    assert(!deadNames.includes('entry'), 'entry kept live');
  });

  test('analyzeFunctionReachability: exported class => all methods live', () => {
    const code =
      'class Worker {\n' +
      '  init() { this.helper(); }\n' +
      '  helper() { return 1; }\n' +
      '  unused() { return 2; }\n' +
      '}\n' +
      'module.exports = Worker;\n';
    const ast = _internals._parseWithLocations(code);
    const result = _internals._analyzeFunctionReachability(ast);
    assert(result.deadRanges.length === 0, 'all methods of exported class should be live, got ' + JSON.stringify(result.deadRanges));
  });

  test('analyzeFunctionReachability: empty file produces no dead ranges', () => {
    const code = '// just a comment\nconst x = 1;\n';
    const ast = _internals._parseWithLocations(code);
    const result = _internals._analyzeFunctionReachability(ast);
    assert(result.deadRanges.length === 0, 'no functions => no dead ranges');
  });

  // ---------------------------------------------------------------------------
  // computeReachableFunctions (file IO + caps)
  // ---------------------------------------------------------------------------

  test('computeReachableFunctions: returns map keyed by relative path', () => {
    const dir = _writePackage({
      'index.js':
        'function alive() { return 1; }\n' +
        'function dead() { return 2; }\n' +
        'module.exports.alive = alive;\n'
    });
    try {
      const out = computeReachableFunctions(dir, new Set(['index.js']));
      assert(out.has('index.js'), 'should contain index.js');
      const info = out.get('index.js');
      assert(info.dynamic === false, 'not dynamic');
      assert(info.deadRanges.length === 1, 'dead range count');
      assert(info.deadRanges[0].name === 'dead', 'dead name=dead');
    } finally { _cleanup(dir); }
  });

  test('computeReachableFunctions: skips non-JS extensions', () => {
    const dir = _writePackage({
      'README.md': '# hello\nfunction looks_like_code() {}\n'
    });
    try {
      const out = computeReachableFunctions(dir, new Set(['README.md']));
      assert(out.size === 0, 'README should be skipped, size=' + out.size);
    } finally { _cleanup(dir); }
  });

  test('computeReachableFunctions: empty input returns empty map', () => {
    const out = computeReachableFunctions('/tmp/anything', null);
    assert(out instanceof Map && out.size === 0, 'empty input -> empty map');
  });

  test('computeReachableFunctions: caps at MAX_FN_REACH_FILES', () => {
    // Sanity check: the constant is reasonable to bound runtime
    assert(_internals.MAX_FN_REACH_FILES >= 100 && _internals.MAX_FN_REACH_FILES <= 10000,
      'MAX_FN_REACH_FILES sanity: ' + _internals.MAX_FN_REACH_FILES);
    assert(_internals.MAX_FN_REACH_BYTES >= 64 * 1024,
      'MAX_FN_REACH_BYTES sanity: ' + _internals.MAX_FN_REACH_BYTES);
  });

  // ---------------------------------------------------------------------------
  // Scoring integration: applyFPReductions consumes reachableFunctions
  // ---------------------------------------------------------------------------

  test('applyFPReductions: downgrades threat in dead function', () => {
    const { applyFPReductions } = require('../../src/scoring.js');
    const reachableFiles = new Set(['lib/utils.js']);
    const reachableFunctions = new Map();
    reachableFunctions.set('lib/utils.js', {
      dynamic: false,
      deadRanges: [{ startLine: 5, endLine: 10, name: 'deadHelper' }]
    });
    const threats = [{
      type: 'suspicious_dataflow',
      severity: 'HIGH',
      file: 'lib/utils.js',
      line: 7,
      message: 'env -> network'
    }];
    applyFPReductions(threats, reachableFiles, 'pkg-x', null, reachableFunctions);
    assert(threats[0].severity === 'LOW', 'HIGH should downgrade to LOW, got ' + threats[0].severity);
    const reasons = threats[0].reductions.map(r => r.rule);
    assert(reasons.includes('unreachable_function'),
      'reductions should include unreachable_function, got ' + JSON.stringify(reasons));
    assert(threats[0].unreachableFunction === 'deadHelper', 'unreachableFunction marker set');
  });

  test('applyFPReductions: does NOT downgrade threat in live function', () => {
    const { applyFPReductions } = require('../../src/scoring.js');
    const reachableFiles = new Set(['lib/utils.js']);
    const reachableFunctions = new Map();
    reachableFunctions.set('lib/utils.js', {
      dynamic: false,
      deadRanges: [{ startLine: 5, endLine: 10, name: 'deadHelper' }]
    });
    const threats = [{
      type: 'suspicious_dataflow',
      severity: 'HIGH',
      file: 'lib/utils.js',
      line: 20, // outside dead range
      message: 'env -> network'
    }];
    applyFPReductions(threats, reachableFiles, 'pkg-x', null, reachableFunctions);
    assert(threats[0].severity === 'HIGH', 'live function => no downgrade, got ' + threats[0].severity);
  });

  test('applyFPReductions: dynamic file fails open (no fn-level downgrade)', () => {
    const { applyFPReductions } = require('../../src/scoring.js');
    const reachableFiles = new Set(['lib/utils.js']);
    const reachableFunctions = new Map();
    reachableFunctions.set('lib/utils.js', {
      dynamic: true,
      deadRanges: []
    });
    const threats = [{
      type: 'suspicious_dataflow',
      severity: 'HIGH',
      file: 'lib/utils.js',
      line: 7
    }];
    applyFPReductions(threats, reachableFiles, 'pkg-x', null, reachableFunctions);
    assert(threats[0].severity === 'HIGH', 'dynamic file => fail-open, got ' + threats[0].severity);
  });

  test('applyFPReductions: threat without t.line is no-op for fn-level', () => {
    const { applyFPReductions } = require('../../src/scoring.js');
    const reachableFiles = new Set(['lib/utils.js']);
    const reachableFunctions = new Map();
    reachableFunctions.set('lib/utils.js', {
      dynamic: false,
      deadRanges: [{ startLine: 5, endLine: 10, name: 'deadHelper' }]
    });
    const threats = [{
      type: 'dangerous_exec',
      severity: 'CRITICAL',
      file: 'lib/utils.js'
      // no line
    }];
    applyFPReductions(threats, reachableFiles, 'pkg-x', null, reachableFunctions);
    assert(threats[0].severity === 'CRITICAL', 'no line => fn-level no-op, got ' + threats[0].severity);
  });

  test('applyFPReductions: REACHABILITY_EXEMPT_TYPES bypasses fn-level downgrade', () => {
    const { applyFPReductions } = require('../../src/scoring.js');
    const reachableFiles = new Set(['package.json']);
    const reachableFunctions = new Map();
    reachableFunctions.set('package.json', {
      dynamic: false,
      deadRanges: [{ startLine: 5, endLine: 10, name: 'whatever' }]
    });
    const threats = [{
      type: 'lifecycle_script', // exempt
      severity: 'CRITICAL',
      file: 'package.json',
      line: 7
    }];
    applyFPReductions(threats, reachableFiles, 'pkg-x', null, reachableFunctions);
    assert(threats[0].severity === 'CRITICAL', 'lifecycle is exempt, got ' + threats[0].severity);
  });

  test('applyFPReductions: missing reachableFunctions argument is harmless (back-compat)', () => {
    const { applyFPReductions } = require('../../src/scoring.js');
    const reachableFiles = new Set(['lib/utils.js']);
    const threats = [{
      type: 'suspicious_dataflow',
      severity: 'HIGH',
      file: 'lib/utils.js',
      line: 7
    }];
    // Call without 5th arg — must not throw, must not change severity.
    applyFPReductions(threats, reachableFiles, 'pkg-x', null);
    assert(threats[0].severity === 'HIGH', 'no fn data => no downgrade, got ' + threats[0].severity);
  });
}

module.exports = { runReachabilityFunctionsTests };

if (require.main === module) {
  runReachabilityFunctionsTests();
  const { getCounters } = require('../test-utils');
  console.log(JSON.stringify(getCounters()));
}
