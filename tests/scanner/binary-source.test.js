'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, assert, runScan } = require('../test-utils');
const { scanBinarySource } = require('../../src/scanner/binary-source.js');
const { sniffBinaryBuffer, looksBinaryString } = require('../../src/shared/binary-sniff.js');

const _tmp = [];
function tmpDir() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'binsrc-'));
  _tmp.push(d);
  return d;
}
function write(dir, rel, bytesOrStr) {
  const fp = path.join(dir, rel);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, bytesOrStr);
  return fp;
}
function scanJson(target) {
  const out = runScan(target, '--json');
  const s = out.indexOf('{');
  const e = out.lastIndexOf('}');
  return JSON.parse(out.slice(s, e + 1));
}
const buf = (...b) => Buffer.from(b);

function runBinarySourceTests() {
  console.log('\n=== binary_masquerading_as_source Tests (BINSRC-001) ===\n');

  // ── sniffBinaryBuffer: BINARY (must detect) ──
  test('sniff: executable/archive/container magic bytes → binary', () => {
    assert(sniffBinaryBuffer(buf(0x7f, 0x45, 0x4c, 0x46, 1, 1)).binary, 'ELF');
    assert(sniffBinaryBuffer(buf(0x4d, 0x5a, 0x90, 0)).binary, 'PE/MZ');
    assert(sniffBinaryBuffer(buf(0xcf, 0xfa, 0xed, 0xfe, 0)).binary, 'Mach-O');
    assert(sniffBinaryBuffer(buf(0x1f, 0x8b, 0x08, 0)).binary, 'gzip');
    assert(sniffBinaryBuffer(buf(0x50, 0x4b, 0x03, 0x04)).binary, 'zip');
    assert(sniffBinaryBuffer(buf(0x00, 0x61, 0x73, 0x6d)).binary, 'wasm');
  });

  test('sniff: leading control byte (jscrambler \\x1bCSI custom container) → binary', () => {
    const v = sniffBinaryBuffer(buf(0x1b, 0x43, 0x53, 0x49, 0x01, 0x03));
    assert(v.binary && /control byte 0x1b/.test(v.reason), 'CSI header must be flagged, got ' + JSON.stringify(v));
  });

  test('sniff: lone/sparse NUL delimiter in valid source → NOT binary (BINSRC-001 FP fix)', () => {
    // `${a}\x00${b}` NUL-delimited dedup keys are a legit source idiom; one NUL among text must NOT flag.
    // Regression guard: rule #3 (NUL-anywhere) used to over-fire on gavio/baldart/turtle etc.
    const src = 'const sep = "\x00"; const key = (a, b) => a + sep + b;\n' + 'let pad = 0;\n'.repeat(20);
    const v = sniffBinaryBuffer(Buffer.from(src, 'latin1'));
    assert(!v.binary, 'lone NUL delimiter must NOT be flagged, got ' + JSON.stringify(v));
  });

  test('sniff: NUL-dense blob → binary (NUL still counts toward the density ratio)', () => {
    const b = Buffer.alloc(256); for (let i = 0; i < 256; i++) b[i] = i % 4 === 0 ? 0x41 : 0x00;
    assert(sniffBinaryBuffer(b).binary, 'a NUL-dense prefix must be binary via the density rule');
  });

  test('sniff: high ratio of control bytes → binary', () => {
    const b = Buffer.alloc(256); for (let i = 0; i < 256; i++) b[i] = i % 7 === 0 ? 0x41 : 0x03;
    assert(sniffBinaryBuffer(b).binary, 'mostly-control prefix must be binary');
  });

  // ── sniffBinaryBuffer: TEXT (must NOT flag — FPR guard) ──
  test('sniff: minified/normal/BOM/multibyte source text → NOT binary', () => {
    assert(!sniffBinaryBuffer(Buffer.from('!function(){var a=1;return a}();')).binary, 'minified text');
    assert(!sniffBinaryBuffer(Buffer.from('const x = require("fs");\n')).binary, 'normal JS');
    assert(!sniffBinaryBuffer(Buffer.concat([buf(0xef, 0xbb, 0xbf), Buffer.from('const y=1;')])).binary, 'UTF-8 BOM');
    assert(!sniffBinaryBuffer(Buffer.from('// 日本語\nconst z = "🎉";\n')).binary, 'multibyte UTF-8');
    assert(!sniffBinaryBuffer(buf(0xff, 0xfe, 0x63, 0x00, 0x6f, 0x00)).binary, 'UTF-16 BOM text (has NULs by design)');
    assert(!sniffBinaryBuffer(Buffer.from('')).binary, 'empty file');
    assert(!sniffBinaryBuffer(Buffer.from('#!/usr/bin/env node\nconsole.log(1)\n')).binary, 'shebang script');
  });

  // ── looksBinaryString (the parser ingestion guard) ──
  test('looksBinaryString: guard skips binary content, keeps real source', () => {
    assert(looksBinaryString('\x1bCSI\x01\x03'), 'leading control byte');
    assert(looksBinaryString('abc\x00def'), 'embedded NUL');
    assert(!looksBinaryString('const x = 1;\nmodule.exports = x;'), 'normal JS not skipped');
    assert(!looksBinaryString('﻿const y = 1;'), 'BOM+text not skipped');
  });

  // ── scanner: fires in dist/ (the blind spot), clean on text ──
  test('scanner: flags binaries in dist/ (which text scanners exclude), clean on bundles', () => {
    const d = tmpDir();
    write(d, 'dist/intro.js', Buffer.concat([buf(0x1b, 0x43, 0x53, 0x49, 0x01), Buffer.alloc(300)])); // CSI carrier
    write(d, 'dist/payload.cjs', Buffer.concat([buf(0x7f, 0x45, 0x4c, 0x46), Buffer.alloc(200, 9)]));  // ELF
    write(d, 'dist/bundle.min.js', '!function(){var a="' + 'x'.repeat(5000) + '"}();');                 // minified text
    write(d, 'lib/index.js', 'module.exports = 1;\n');
    const t = scanBinarySource(d);
    const fired = new Set(t.map(x => x.file));
    assert(fired.has('dist/intro.js'), 'must flag dist/intro.js (CSI) — the carrier text scanners skip');
    assert(fired.has('dist/payload.cjs'), 'must flag dist/payload.cjs (ELF)');
    assert(!fired.has('dist/bundle.min.js'), 'must NOT flag a minified text bundle');
    assert(!fired.has('lib/index.js'), 'must NOT flag normal source');
    assert(t.every(x => x.type === 'binary_masquerading_as_source' && x.severity === 'HIGH'), 'type+severity');
  });

  // ── end-to-end via the CLI ──
  test('e2e: binary .js in dist/ → binary_masquerading_as_source HIGH (BINSRC-001)', () => {
    const d = tmpDir();
    write(d, 'package.json', JSON.stringify({ name: 'binsrc-e2e', version: '1.0.0' }));
    write(d, 'dist/intro.js', Buffer.concat([buf(0x1b, 0x43, 0x53, 0x49, 0x01, 0x03), Buffer.alloc(4096)]));
    const r = scanJson(d);
    const c = (r.threats || []).find(t => t.type === 'binary_masquerading_as_source');
    assert(c, 'CLI must surface binary_masquerading_as_source');
    assert(c.severity === 'HIGH', 'HIGH severity');
    assert(c.rule_id === 'MUADDIB-BINSRC-001' || c.rule === 'MUADDIB-BINSRC-001', 'carries the rule id');
  });

  test('e2e (FPR guard): only a minified text bundle in dist/ → NO finding', () => {
    const d = tmpDir();
    write(d, 'package.json', JSON.stringify({ name: 'binsrc-benign', version: '1.0.0' }));
    write(d, 'dist/bundle.min.js', '!function(){var a="' + 'y'.repeat(20000) + '";return a}();');
    const r = scanJson(d);
    assert(!(r.threats || []).some(t => t.type === 'binary_masquerading_as_source'), 'minified bundle must NOT trip BINSRC');
  });

  for (const d of _tmp) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
}

module.exports = { runBinarySourceTests };
