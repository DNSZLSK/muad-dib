'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, assert, runScan } = require('../test-utils');
const {
  extractGypInvokedScripts,
  correlatePhantomGyp
} = require('../../src/scanner/phantom-gyp.js');

// Write a binding.gyp into a fresh temp dir and return the dir (caller cleans up).
function gypDir(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phantom-gyp-'));
  fs.writeFileSync(path.join(dir, 'binding.gyp'), content, 'utf8');
  return dir;
}

function scanJson(target) {
  const out = runScan(target, '--json');
  // runScan returns stdout even on non-zero exit (threats present). Extract the JSON object.
  const start = out.indexOf('{');
  const end = out.lastIndexOf('}');
  return JSON.parse(out.slice(start, end + 1));
}

function runPhantomGypTests() {
  console.log('\n=== Phantom-Gyp Compound Tests (Phase 1b) ===\n');

  // ── extraction (pure) ──

  test('extractGypInvokedScripts: extracts node/python script-file invocations', () => {
    const refs = extractGypInvokedScripts([
      '"sources": ["<!(node loader.js)"]',
      '"x": "<!@(python3 ./util/setup.py)"',
      '"y": "<!(node ./util/has_lib.js --verbose)"'
    ].join('\n'));
    const files = refs.map(r => r.file);
    assert(files.includes('loader.js'), 'should extract bare node script');
    assert(files.includes('./util/setup.py'), 'should extract python script (<!@ form)');
    assert(files.includes('./util/has_lib.js'), 'should extract node script even with trailing flag');
    assert(refs.find(r => r.file === './util/setup.py').interpreter === 'python3', 'interpreter captured');
  });

  test('extractGypInvokedScripts: skips inline-eval, <(var) expansion, and non-script interpreters', () => {
    const refs = extractGypInvokedScripts([
      '"a": "<!(node -e require(\'http\'))"',                       // inline -e → no file
      '"b": "<!(node -p \\"require(\'node-addon-api\').include\\")"', // inline -p → no file
      '"c": "<!(node --eval doEvil())"',                            // inline --eval → no file
      '"d": "<(module_root_dir)/build"',                            // variable expansion (no !) → ignored
      '"e": "<@(library_dirs)"',                                    // list-var expansion (no !) → ignored
      '"f": "<!(pkg-config --cflags glib-2.0)"'                     // non-script interpreter → no file
    ].join('\n'));
    assert(refs.length === 0, `expected no script refs, got ${JSON.stringify(refs)}`);
  });

  // ── correlator (synthetic threats + temp binding.gyp) ──

  test('correlatePhantomGyp: fires CRITICAL when the invoked file is independently malicious', () => {
    const dir = gypDir('"sources": ["<!(node loader.js)"]');
    try {
      const threats = [{ type: 'staged_payload', severity: 'CRITICAL', file: 'loader.js' }];
      const fired = correlatePhantomGyp(threats, dir);
      assert(fired && fired.type === 'gyp_phantom_exec', 'should push gyp_phantom_exec');
      assert(fired.severity === 'CRITICAL' && fired.file === 'binding.gyp', 'CRITICAL, attributed to binding.gyp');
      assert(threats.some(t => t.type === 'gyp_phantom_exec'), 'compound added to the array');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('correlatePhantomGyp: fires on a non-LOW HIGH_CONFIDENCE type on the invoked file (./path match)', () => {
    const dir = gypDir('"sources": ["<!(node ./src/payload.js)"]');
    try {
      // gyp_command_exec is in HIGH_CONFIDENCE_MALICE_TYPES; HIGH (non-LOW) on the invoked file.
      const threats = [{ type: 'gyp_command_exec', severity: 'HIGH', file: 'src/payload.js' }];
      assert(correlatePhantomGyp(threats, dir), 'HC non-LOW verdict on invoked file should fire');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('correlatePhantomGyp: does NOT fire on a benign invoked file (LOW heuristic only)', () => {
    const dir = gypDir('"sources": ["<!(node ./util/has_lib.js)"]');
    try {
      const threats = [{ type: 'env_access', severity: 'LOW', file: 'util/has_lib.js' }];
      assert(correlatePhantomGyp(threats, dir) === null, 'LOW heuristic must not trigger the compound');
      assert(!threats.some(t => t.type === 'gyp_phantom_exec'), 'no compound added');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('correlatePhantomGyp: does NOT fire when malice is in a DIFFERENT file than the invoked one', () => {
    const dir = gypDir('"sources": ["<!(node loader.js)"]');
    try {
      const threats = [{ type: 'staged_payload', severity: 'CRITICAL', file: 'index.js' }];
      assert(correlatePhantomGyp(threats, dir) === null, 'malice on index.js must not implicate loader.js');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('correlatePhantomGyp: does NOT fire for <(var) variable-expansion (no command execution)', () => {
    const dir = gypDir('"sources": ["<(module_root_dir)/loader.js"]');
    try {
      // Even with a CRITICAL on loader.js, plain variable-expansion is not a command-sub → no fire.
      const threats = [{ type: 'staged_payload', severity: 'CRITICAL', file: 'loader.js' }];
      assert(correlatePhantomGyp(threats, dir) === null, '<(...) must never trigger the compound');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  test('correlatePhantomGyp: no binding.gyp → no fire; idempotent on re-run', () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'phantom-gyp-none-'));
    try {
      assert(correlatePhantomGyp([{ type: 'staged_payload', severity: 'CRITICAL', file: 'loader.js' }], empty) === null,
        'no binding.gyp → no fire');
    } finally { fs.rmSync(empty, { recursive: true, force: true }); }

    const dir = gypDir('"sources": ["<!(node loader.js)"]');
    try {
      const threats = [{ type: 'staged_payload', severity: 'CRITICAL', file: 'loader.js' }];
      assert(correlatePhantomGyp(threats, dir), 'first run fires');
      assert(correlatePhantomGyp(threats, dir) === null, 'second run is a no-op (idempotent)');
      assert(threats.filter(t => t.type === 'gyp_phantom_exec').length === 1, 'exactly one compound');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  // ── end-to-end via the real CLI pipeline ──

  test('e2e: malicious <!(node loader.js) + malicious loader.js → gyp_phantom_exec CRITICAL, score≥20', () => {
    const r = scanJson('tests/samples/phantom-gyp/malicious');
    const types = new Set((r.threats || []).map(t => t.type));
    assert(types.has('gyp_phantom_exec'), 'malicious Phantom-Gyp fixture must raise gyp_phantom_exec');
    assert((r.summary.riskScore || 0) >= 20, `score should cross the alert threshold, got ${r.summary.riskScore}`);
    const p = (r.threats || []).find(t => t.type === 'gyp_phantom_exec');
    assert(p && (p.rule_id === 'MUADDIB-COMPOUND-017' || p.rule === 'MUADDIB-COMPOUND-017'), 'compound carries the rule id');
  });

  test('e2e (FPR guard): benign native addon <!(node ./util/has_lib.js) → NO gyp_phantom_exec', () => {
    const r = scanJson('tests/samples/phantom-gyp/benign');
    const types = new Set((r.threats || []).map(t => t.type));
    assert(!types.has('gyp_phantom_exec'), 'benign build-helper invocation must NOT trigger the compound');
  });
}

module.exports = { runPhantomGypTests };
