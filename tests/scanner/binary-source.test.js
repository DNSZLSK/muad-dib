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

  // ══ text_payload_as_font_asset Tests (BINSRC-002 — PolinRider .woff2 carrier) ══
  console.log('\n=== text_payload_as_font_asset Tests (BINSRC-002) ===\n');

  // Real fonts: distinctive font magic bytes at offset 0 (a prefix match ⇒ genuine ⇒ skip).
  const realWoff2 = () => Buffer.concat([buf(0x77, 0x4f, 0x46, 0x32), Buffer.alloc(4096, 0x11)]); // 'wOF2'
  const realTtf = () => Buffer.concat([buf(0x00, 0x01, 0x00, 0x00), Buffer.alloc(4096, 0x22)]);   // TrueType
  // The PolinRider loader: plaintext JS shipped as a font. campaign marker + obfuscator + spawn.
  const fakeFontJs = 'global.i="A8-3292-1";const _0xb40cd9=0x4963;require("child_process").spawn("node",["-e","1"],{detached:true}).unref();\n';

  test('scanner: plaintext-JS .woff2 (no font magic + exec tokens) → text_payload_as_font_asset CRITICAL', () => {
    const d = tmpDir();
    write(d, 'public/fonts/fa-solid-400.woff2', fakeFontJs);
    const t = scanBinarySource(d);
    const hit = t.find(x => x.type === 'text_payload_as_font_asset');
    assert(hit, 'must flag the fake .woff2 loader (the PolinRider payload body)');
    assert(hit.severity === 'CRITICAL', 'CRITICAL severity, got ' + (hit && hit.severity));
    assert(hit.file === 'public/fonts/fa-solid-400.woff2', 'reports the carrier path');
  });

  test('scanner: fake payload in each font/asset extension → all flagged', () => {
    const d = tmpDir();
    for (const ext of ['woff', 'ttf', 'otf', 'eot']) write(d, `assets/x.${ext}`, fakeFontJs);
    const fired = new Set(scanBinarySource(d).filter(x => x.type === 'text_payload_as_font_asset').map(x => x.file));
    for (const ext of ['woff', 'ttf', 'otf', 'eot']) assert(fired.has(`assets/x.${ext}`), `must flag .${ext} carrier`);
  });

  // Variant-resistance (chantier 2026-08): the carrier is not tied to a font extension.
  test('scanner: same JS payload under a NON-font binary-asset extension (.png/.wasm/.node/.dat/.bin) → all flagged', () => {
    const d = tmpDir();
    for (const ext of ['png', 'wasm', 'node', 'dat', 'data', 'bin', 'jpg', 'gif', 'ico', 'webp']) {
      write(d, `public/assets/carrier.${ext}`, fakeFontJs);
    }
    const fired = new Set(scanBinarySource(d).filter(x => x.type === 'text_payload_as_font_asset').map(x => x.file));
    for (const ext of ['png', 'wasm', 'node', 'dat', 'data', 'bin', 'jpg', 'gif', 'ico', 'webp']) {
      assert(fired.has(`public/assets/carrier.${ext}`), `renaming the loader .${ext} must NOT evade BINSRC-002`);
    }
  });

  test('scanner (FPR guard): REAL binary assets under the new extensions (PNG/wasm magic) → NOT flagged', () => {
    const d = tmpDir();
    // PNG magic \x89PNG\r\n\x1a\n — leading high byte ⇒ sniffBinaryBuffer flags binary ⇒ skipped.
    write(d, 'img/logo.png', Buffer.concat([buf(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a), Buffer.alloc(4096, 0x42)]));
    // JPEG magic \xff\xd8\xff.
    write(d, 'img/photo.jpg', Buffer.concat([buf(0xff, 0xd8, 0xff, 0xe0), Buffer.alloc(4096, 0x33)]));
    // Real WebAssembly module: \0asm + version.
    write(d, 'wasm/mod.wasm', Buffer.concat([buf(0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00), Buffer.alloc(2048, 0x05)]));
    // Real native addon: an ELF .node.
    write(d, 'build/addon.node', Buffer.concat([buf(0x7f, 0x45, 0x4c, 0x46), Buffer.alloc(2048, 0x09)]));
    const t = scanBinarySource(d).filter(x => x.type === 'text_payload_as_font_asset');
    assert(t.length === 0, 'genuine binary assets must NOT trip BINSRC-002, got ' + JSON.stringify(t.map(x => x.file)));
  });

  test('scanner (FPR guard): a plain-text .dat/.bin config without exec tokens → NOT flagged', () => {
    const d = tmpDir();
    // Some tooling ships printable-text blobs under opaque extensions; without JS exec tokens
    // the exec-oriented JS_PAYLOAD_SIGNS gate keeps precision (FP≈0).
    write(d, 'data/params.dat', 'threshold=0.5\nmax_iter=100\nlabel=benign\n'.repeat(30));
    write(d, 'data/table.bin', 'col_a,col_b,col_c\n1,2,3\n4,5,6\n'.repeat(50));
    const t = scanBinarySource(d).filter(x => x.type === 'text_payload_as_font_asset');
    assert(t.length === 0, 'printable text under .dat/.bin without exec tokens must NOT flag, got ' + JSON.stringify(t.map(x => x.file)));
  });

  test('scanner (FPR guard): benign data with only WEAK tokens (=>, process.env, Buffer.from) → NOT flagged', () => {
    const d = tmpDir();
    // These substrings appear in benign config/data/docs. After the token tightening a single
    // weak hit must no longer fire CRITICAL (the pre-fix list tripped on a lone `=>`).
    write(d, 'data/mapping.dat', 'input => output\nkey => value\nsize => 42\n'.repeat(20));
    write(d, 'data/notes.data', 'Reads process.env.PATH then wraps Buffer.from(x) — see docs.\n'.repeat(20));
    const t = scanBinarySource(d).filter(x => x.type === 'text_payload_as_font_asset');
    assert(t.length === 0, 'weak-token-only benign data must NOT flag after tightening, got ' + JSON.stringify(t.map(x => x.file)));
  });

  test('scanner: uppercase carrier extension (.WOFF2 / .PNG) → still flagged (case-insensitive findFiles)', () => {
    const d = tmpDir();
    write(d, 'public/fonts/fa-solid-400.WOFF2', fakeFontJs);
    write(d, 'assets/icon.PNG', fakeFontJs);
    const fired = new Set(scanBinarySource(d).filter(x => x.type === 'text_payload_as_font_asset').map(x => x.file));
    assert(fired.has('public/fonts/fa-solid-400.WOFF2'), 'a one-char rename to uppercase .WOFF2 must not evade');
    assert(fired.has('assets/icon.PNG'), 'uppercase .PNG must not evade');
  });

  test('scanner (FPR guard): a REAL binary font → NOT flagged', () => {
    const d = tmpDir();
    write(d, 'public/fonts/real.woff2', realWoff2());       // wOF2 magic
    write(d, 'public/fonts/real.ttf', realTtf());           // TrueType magic
    write(d, 'public/fonts/real.eot', Buffer.alloc(4096, 0x03)); // magic-less but dense binary
    const t = scanBinarySource(d).filter(x => x.type === 'text_payload_as_font_asset');
    assert(t.length === 0, 'genuine fonts must NOT trip BINSRC-002, got ' + JSON.stringify(t.map(x => x.file)));
  });

  test('scanner (FPR guard): a font-extension file that is plain prose (no exec tokens) → NOT flagged', () => {
    const d = tmpDir();
    // e.g. a mis-extensioned license/readme placeholder — text, but no JS. Precision guard.
    write(d, 'fonts/notice.woff2', 'This font is licensed under the SIL Open Font License version 1.1.\n'.repeat(8));
    const t = scanBinarySource(d).filter(x => x.type === 'text_payload_as_font_asset');
    assert(t.length === 0, 'plain text without exec tokens must NOT flag, got ' + JSON.stringify(t.map(x => x.file)));
  });

  test('e2e: PolinRider shape (tasks.json folderOpen + JS .woff2) → CRITICAL alert', () => {
    const d = tmpDir();
    write(d, 'package.json', JSON.stringify({ name: 'zzz-polinrider-test', version: '1.2.10' }));
    write(d, '.vscode/tasks.json', JSON.stringify({
      version: '2.0.0',
      tasks: [{ label: 'eslint-check', type: 'shell', command: 'node ./public/fonts/fa-solid-400.woff2', runOptions: { runOn: 'folderOpen' } }]
    }));
    write(d, 'public/fonts/fa-solid-400.woff2', fakeFontJs);
    const r = scanJson(d);
    const font = (r.threats || []).find(t => t.type === 'text_payload_as_font_asset');
    assert(font, 'CLI must surface text_payload_as_font_asset (the payload body, not just the trigger)');
    assert(font.rule_id === 'MUADDIB-BINSRC-002' || font.rule === 'MUADDIB-BINSRC-002', 'carries the rule id');
    const score = r.riskScore ?? r.summary?.riskScore;
    assert(score >= 75, 'single-fire floor: a confirmed .woff2 loader must score ≥75, got ' + score);
  });

  for (const d of _tmp) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
}

module.exports = { runBinarySourceTests };
