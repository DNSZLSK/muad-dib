'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, assert, runScan } = require('../test-utils');
const {
  correlateInstallNativeDropExec,
  extractInvokedScriptFiles,
  analyzeScriptForDropExec
} = require('../../src/scanner/native-drop-exec.js');

const _tmpDirs = [];
// Build a throwaway package dir: pkg = package.json object, files = { relpath: content }.
function pkgDir(pkg, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ndx-'));
  _tmpDirs.push(dir);
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg, null, 2), 'utf8');
  for (const [rel, content] of Object.entries(files || {})) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content, 'utf8');
  }
  return dir;
}
// True when the compound fires on a built package dir.
function fires(dir) {
  return !!correlateInstallNativeDropExec([], dir);
}
function scanJson(target) {
  const out = runScan(target, '--json');
  const start = out.indexOf('{');
  const end = out.lastIndexOf('}');
  return JSON.parse(out.slice(start, end + 1));
}

// A jscrambler@8.14.0-shaped loader (ESM, local read + gunzip + write 0o755 + spawn detached).
const JSCRAMBLER_SHAPE = [
  'import { readFileSync, writeFileSync } from "fs";',
  'import { gunzipSync } from "zlib";',
  'import { spawn } from "child_process";',
  'import { tmpdir } from "os";',
  'const b = readFileSync(new URL("./intro.js", import.meta.url));',
  'const t = tmpdir() + "/." + Math.random().toString(36).slice(2);',
  'writeFileSync(t, gunzipSync(b), { mode: 0o755 });',
  'spawn(t, [], { detached: true, stdio: "ignore", windowsHide: true }).unref();'
].join('\n');

function runNativeDropExecTests() {
  console.log('\n=== install_native_drop_exec Compound Tests (COMPOUND-020) ===\n');

  // ── pure extraction ──

  test('extractInvokedScriptFiles: pulls `node x.js` from lifecycle commands, skips inline-eval', () => {
    assert(extractInvokedScriptFiles('node dist/setup.js').includes('dist/setup.js'), 'bare node script');
    assert(extractInvokedScriptFiles('node ./boot.js && echo ok').includes('./boot.js'), '&&-chained script');
    assert(extractInvokedScriptFiles('node --experimental-vm-modules loader.mjs').includes('loader.mjs'), 'flag then script');
    assert(extractInvokedScriptFiles('node -e "doThing()"').length === 0, 'inline -e has no file');
    assert(extractInvokedScriptFiles('node-gyp rebuild').length === 0, 'node-gyp is not a node script');
    assert(extractInvokedScriptFiles('tsc -p .').length === 0, 'non-node command');
  });

  test('analyzeScriptForDropExec: the three signals must co-occur (drop-only does not fire)', () => {
    const dir = pkgDir({ scripts: { preinstall: 'node s.js' } },
      { 's.js': 'const fs=require("fs");fs.writeFileSync("/tmp/x","hi",{mode:0o755});' });
    const a = analyzeScriptForDropExec(dir, 's.js');
    assert(a && a.fired === false, 'write-executable alone (no bundled source, no exec) must not fire');
  });

  // ── positives (must FIRE) — variant-robustness ──

  test('POSITIVE: jscrambler ESM shape (local read + gunzip + write 0o755 + spawn detached)', () => {
    const dir = pkgDir({ scripts: { preinstall: 'node dist/setup.js' } }, { 'dist/setup.js': JSCRAMBLER_SHAPE });
    assert(fires(dir), 'jscrambler@8.14.0 shape must fire');
  });

  test('POSITIVE: CJS variant (Buffer.from base64 + chmod +x + execFile), no readFileSync/gzip', () => {
    const dir = pkgDir({ scripts: { postinstall: 'node install.js' } }, {
      'install.js': [
        'const cp=require("child_process");const fs=require("fs");const os=require("os");',
        'const buf=Buffer.from("TVqQAAAA","base64");',
        'const t=os.tmpdir()+"/svc";',
        'fs.writeFileSync(t,buf);fs.chmodSync(t,0o755);cp.execFile(t,[]);'
      ].join('\n')
    });
    assert(fires(dir), 'base64 payload + chmod + execFile variant must fire');
  });

  test('POSITIVE: readFileSync local + write mode 0o700 + fork (install hook)', () => {
    const dir = pkgDir({ scripts: { install: 'node dist/boot.js' } }, {
      'dist/boot.js': [
        'const {readFileSync,writeFileSync}=require("fs");const {fork}=require("child_process");const p=require("path");',
        'const data=readFileSync(p.join(__dirname,"blob.bin"));',
        'const t="/tmp/.h"+Date.now();writeFileSync(t,data,{mode:0o700});fork(t);'
      ].join('\n')
    });
    assert(fires(dir), 'local read + exec-bit write + fork variant must fire');
  });

  // ── negatives (must NOT fire) — FPR guard against legitimate installers ──

  test('NEGATIVE: esbuild-style https download + chmod + spawn (network → download-exec, not ours)', () => {
    const dir = pkgDir({ scripts: { postinstall: 'node install.js' } }, {
      'install.js': [
        'const https=require("https");const fs=require("fs");const cp=require("child_process");',
        'const bin=require("path").join(__dirname,"bin","x");',
        'https.get("https://registry.npmjs.org/x.tgz",res=>{const w=fs.createWriteStream(bin);res.pipe(w);',
        'w.on("finish",()=>{fs.chmodSync(bin,0o755);cp.spawnSync(bin,["--version"]);});});'
      ].join('\n')
    });
    assert(!fires(dir), 'network download installer must NOT fire');
  });

  test('NEGATIVE: prebuild-install-style https + gunzip + write .node, then require (no spawn)', () => {
    const dir = pkgDir({ scripts: { postinstall: 'node install.js' } }, {
      'install.js': [
        'const https=require("https");const fs=require("fs");const zlib=require("zlib");',
        'https.get("https://github.com/x/y.tar.gz",res=>{const c=[];res.on("data",d=>c.push(d));',
        'res.on("end",()=>{const out=zlib.gunzipSync(Buffer.concat(c));fs.writeFileSync("build/Release/x.node",out,{mode:0o644});});});',
        'module.exports=require("./build/Release/x.node");'
      ].join('\n')
    });
    assert(!fires(dir), 'download+extract+require(.node) must NOT fire (network + no spawn)');
  });

  test('NEGATIVE: node-gyp build script spawns a literal command (not a written path)', () => {
    const dir = pkgDir({ scripts: { install: 'node scripts/build.js' } }, {
      'scripts/build.js': [
        'const {spawnSync}=require("child_process");const fs=require("fs");',
        'fs.readFileSync("package.json");spawnSync("node-gyp",["rebuild"],{stdio:"inherit"});'
      ].join('\n')
    });
    assert(!fires(dir), 'literal-command spawn must NOT fire');
  });

  test('NEGATIVE: writes a string-literal wrapper.sh 0o755 and spawns it (source not bundled bytes)', () => {
    const dir = pkgDir({ scripts: { postinstall: 'node setup.js' } }, {
      'setup.js': [
        'const fs=require("fs");const {spawn}=require("child_process");',
        'const w="/tmp/wrapper.sh";fs.writeFileSync(w,"#!/bin/sh\\necho building",{mode:0o755});spawn(w,[]);'
      ].join('\n')
    });
    assert(!fires(dir), 'writing an inline shell wrapper is not a bundled-binary drop');
  });

  test('NEGATIVE: plain babel build postinstall (no drop, no computed exec)', () => {
    const dir = pkgDir({ scripts: { postinstall: 'node build.js' } },
      { 'build.js': 'const {execSync}=require("child_process");execSync("babel src -d dist");' });
    assert(!fires(dir), 'ordinary build step must NOT fire');
  });

  test('NEGATIVE: drop-exec present but NOT reached from an install hook', () => {
    const dir = pkgDir({ scripts: { test: 'node t.js' } }, {
      'index.js': [
        'const {readFileSync,writeFileSync,chmodSync}=require("fs");const {spawn}=require("child_process");',
        'const d=readFileSync(__dirname+"/b.bin");const t="/tmp/x";writeFileSync(t,d);chmodSync(t,0o755);spawn(t);'
      ].join('\n')
    });
    assert(!fires(dir), 'no install hook invokes the loader → must NOT fire');
  });

  // ── end-to-end (pipeline) ──

  test('e2e: malicious fixture → install_native_drop_exec CRITICAL, crosses alert threshold', () => {
    const r = scanJson('tests/samples/native-drop-exec/malicious');
    const threats = r.threats || [];
    const types = new Set(threats.map(t => t.type));
    assert(types.has('install_native_drop_exec'), 'malicious fixture must raise install_native_drop_exec');
    assert((r.summary.riskScore || 0) >= 20, `score should cross the alert threshold, got ${r.summary.riskScore}`);
    const c = threats.find(t => t.type === 'install_native_drop_exec');
    assert(c && (c.rule_id === 'MUADDIB-COMPOUND-020' || c.rule === 'MUADDIB-COMPOUND-020'), 'compound carries the rule id');
    assert(c && c.severity === 'CRITICAL', 'compound is CRITICAL');
  });

  test('e2e (FPR guard): benign network-download installer → NO install_native_drop_exec', () => {
    const r = scanJson('tests/samples/native-drop-exec/benign');
    const types = new Set((r.threats || []).map(t => t.type));
    assert(!types.has('install_native_drop_exec'), 'legit URL-download installer must NOT trigger the compound');
  });

  // cleanup temp dirs
  for (const d of _tmpDirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
}

module.exports = { runNativeDropExecTests };
