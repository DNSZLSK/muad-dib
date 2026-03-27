#!/usr/bin/env node
'use strict';

/**
 * MUAD'DIB Performance Benchmark
 *
 * Generates synthetic projects of different sizes and measures:
 * - Scan time (wall-clock via process.hrtime.bigint())
 * - Peak memory usage (process.memoryUsage())
 * - Per-scanner breakdown (via _capture mode timing)
 *
 * Usage: node scripts/benchmark.js [--runs N] [--sizes small,medium,large]
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// ----- Config -----
const RUNS = parseInt(process.argv.find((a, i) => process.argv[i - 1] === '--runs') || '3', 10);
const SIZE_ARG = process.argv.find((a, i) => process.argv[i - 1] === '--sizes') || 'small,medium,large';
const SIZES = SIZE_ARG.split(',').map(s => s.trim());

const SIZE_CONFIGS = {
  small:  { files: 10,  label: '10 JS files' },
  medium: { files: 100, label: '100 JS files' },
  large:  { files: 500, label: '500 JS files (cap test)' }
};

// ----- Synthetic file templates -----
// Mix of benign-looking code with varied patterns to exercise all scanners
const TEMPLATES = [
  // Standard module
  (i) => `'use strict';
const path = require('path');
const fs = require('fs');

function process${i}(input) {
  const result = input.toString().trim();
  return path.resolve(result);
}

module.exports = { process${i} };
`,
  // HTTP client usage
  (i) => `'use strict';
const https = require('https');

function fetch${i}(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });
}

module.exports = { fetch${i} };
`,
  // Crypto usage
  (i) => `'use strict';
const crypto = require('crypto');

function hash${i}(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function verify${i}(data, expected) {
  const actual = hash${i}(data);
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

module.exports = { hash${i}, verify${i} };
`,
  // Config/util module
  (i) => `'use strict';
const os = require('os');

const CONFIG_${i} = {
  tmpDir: os.tmpdir(),
  cpus: os.cpus().length,
  platform: os.platform(),
  arch: os.arch()
};

function getConfig${i}() {
  return { ...CONFIG_${i} };
}

module.exports = { getConfig${i}, CONFIG_${i} };
`,
  // Event emitter pattern
  (i) => `'use strict';
const { EventEmitter } = require('events');

class Service${i} extends EventEmitter {
  constructor() {
    super();
    this.data = new Map();
  }

  add(key, value) {
    this.data.set(key, value);
    this.emit('added', { key, value });
  }

  remove(key) {
    this.data.delete(key);
    this.emit('removed', { key });
  }
}

module.exports = { Service${i} };
`
];

// ----- Generate synthetic project -----
function generateProject(tmpDir, fileCount) {
  fs.mkdirSync(tmpDir, { recursive: true });

  // Create package.json
  fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
    name: `bench-project-${fileCount}`,
    version: '1.0.0',
    description: 'Synthetic benchmark project',
    main: 'index.js'
  }, null, 2));

  // Create subdirectories for realism
  const dirs = ['', 'src', 'lib', 'utils', 'helpers'];
  for (const d of dirs) {
    if (d) fs.mkdirSync(path.join(tmpDir, d), { recursive: true });
  }

  // Create JS files
  for (let i = 0; i < fileCount; i++) {
    const template = TEMPLATES[i % TEMPLATES.length];
    const dir = dirs[i % dirs.length];
    const filePath = path.join(tmpDir, dir, `module-${i}.js`);
    fs.writeFileSync(filePath, template(i));
  }

  // Create index.js that references some modules
  const imports = Array.from({ length: Math.min(10, fileCount) }, (_, i) => {
    const dir = dirs[i % dirs.length];
    const rel = dir ? `./${dir}/module-${i}` : `./module-${i}`;
    return `const m${i} = require('${rel}');`;
  }).join('\n');
  fs.writeFileSync(path.join(tmpDir, 'index.js'), `'use strict';\n${imports}\n\nconsole.log('Loaded modules');\n`);

  return tmpDir;
}

// ----- Cleanup -----
function cleanup(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch { /* ignore */ }
}

// ----- Run benchmark -----
async function benchmark() {
  // Lazy-load the scanner
  const { run } = require('../src/index.js');
  const { clearFileListCache } = require('../src/utils.js');
  const { clearASTCache } = require('../src/shared/constants.js');

  console.log('='.repeat(70));
  console.log('  MUAD\'DIB Performance Benchmark');
  console.log(`  Runs per size: ${RUNS}  |  Sizes: ${SIZES.join(', ')}`);
  console.log(`  Node ${process.version}  |  ${os.cpus()[0]?.model || 'unknown CPU'}  |  ${os.platform()}`);
  console.log('='.repeat(70));
  console.log();

  const results = {};

  for (const sizeName of SIZES) {
    const config = SIZE_CONFIGS[sizeName];
    if (!config) {
      console.error(`Unknown size: ${sizeName}`);
      continue;
    }

    console.log(`--- ${sizeName.toUpperCase()}: ${config.label} ---`);

    const tmpDir = path.join(os.tmpdir(), `muaddib-bench-${sizeName}-${Date.now()}`);
    generateProject(tmpDir, config.files);

    const times = [];
    const memories = [];

    for (let r = 0; r < RUNS; r++) {
      // Clear caches between runs for fair measurement
      clearFileListCache();
      clearASTCache();

      // Force GC if available
      if (global.gc) global.gc();

      const memBefore = process.memoryUsage();
      const start = process.hrtime.bigint();

      try {
        await run(tmpDir, { _capture: true });
      } catch (err) {
        console.error(`  Run ${r + 1} error: ${err.message}`);
      }

      const end = process.hrtime.bigint();
      const memAfter = process.memoryUsage();

      const durationMs = Number(end - start) / 1e6;
      const heapDelta = memAfter.heapUsed - memBefore.heapUsed;
      const rssAfter = memAfter.rss;

      times.push(durationMs);
      memories.push({ heapDelta, rss: rssAfter, heapUsed: memAfter.heapUsed });

      console.log(`  Run ${r + 1}/${RUNS}: ${durationMs.toFixed(0)}ms  |  heap: ${(memAfter.heapUsed / 1024 / 1024).toFixed(1)}MB  |  RSS: ${(rssAfter / 1024 / 1024).toFixed(1)}MB`);
    }

    // Stats
    times.sort((a, b) => a - b);
    const median = times[Math.floor(times.length / 2)];
    const mean = times.reduce((a, b) => a + b, 0) / times.length;
    const min = times[0];
    const max = times[times.length - 1];
    const peakRss = Math.max(...memories.map(m => m.rss));
    const peakHeap = Math.max(...memories.map(m => m.heapUsed));

    results[sizeName] = { median, mean, min, max, peakRss, peakHeap, runs: RUNS, files: config.files };

    console.log(`  => median: ${median.toFixed(0)}ms  mean: ${mean.toFixed(0)}ms  min: ${min.toFixed(0)}ms  max: ${max.toFixed(0)}ms`);
    console.log(`  => peak heap: ${(peakHeap / 1024 / 1024).toFixed(1)}MB  peak RSS: ${(peakRss / 1024 / 1024).toFixed(1)}MB`);
    console.log();

    cleanup(tmpDir);
  }

  // ----- Per-scanner timing (single run on medium) -----
  console.log('--- SCANNER BREAKDOWN (medium, single run) ---');
  const scannerTmpDir = path.join(os.tmpdir(), `muaddib-bench-scanner-${Date.now()}`);
  const scannerFiles = SIZE_CONFIGS.medium?.files || 100;
  generateProject(scannerTmpDir, scannerFiles);
  clearFileListCache();
  clearASTCache();

  // Monkey-patch Promise.allSettled to measure per-scanner time
  const origAllSettled = Promise.allSettled.bind(Promise);
  const scannerTimings = [];

  // We'll measure by wrapping run() and parsing its internal flow
  // Simpler approach: time each scanner individually
  const scannerModules = [
    { name: 'PackageJson', mod: '../src/scanner/package.js', fn: 'scanPackageJson' },
    { name: 'ShellScripts', mod: '../src/scanner/shell.js', fn: 'scanShellScripts' },
    { name: 'AST', mod: '../src/scanner/ast.js', fn: 'analyzeAST' },
    { name: 'Obfuscation', mod: '../src/scanner/obfuscation.js', fn: 'detectObfuscation' },
    { name: 'Dependencies', mod: '../src/scanner/dependencies.js', fn: 'scanDependencies' },
    { name: 'Hashes', mod: '../src/scanner/hash.js', fn: 'scanHashes' },
    { name: 'DataFlow', mod: '../src/scanner/dataflow.js', fn: 'analyzeDataFlow' },
    { name: 'Typosquat', mod: '../src/scanner/typosquat.js', fn: 'scanTyposquatting' },
    { name: 'GitHubActions', mod: '../src/scanner/github-actions.js', fn: 'scanGitHubActions' },
    { name: 'Entropy', mod: '../src/scanner/entropy.js', fn: 'scanEntropy' },
    { name: 'AIConfig', mod: '../src/scanner/ai-config.js', fn: 'scanAIConfig' }
  ];

  for (const s of scannerModules) {
    try {
      const mod = require(s.mod);
      const fn = mod[s.fn];
      if (!fn) {
        scannerTimings.push({ name: s.name, ms: 0, note: 'not found' });
        continue;
      }

      clearFileListCache(); // each scanner gets fresh file list
      const start = process.hrtime.bigint();
      try {
        await fn(scannerTmpDir, {});
      } catch { /* some scanners may throw on benign input */ }
      const end = process.hrtime.bigint();
      const ms = Number(end - start) / 1e6;
      scannerTimings.push({ name: s.name, ms });
    } catch (err) {
      scannerTimings.push({ name: s.name, ms: 0, note: err.message });
    }
  }

  // Sort by time descending
  scannerTimings.sort((a, b) => b.ms - a.ms);
  const totalScannerMs = scannerTimings.reduce((sum, s) => sum + s.ms, 0);

  for (const s of scannerTimings) {
    const pct = totalScannerMs > 0 ? ((s.ms / totalScannerMs) * 100).toFixed(1) : '0.0';
    const bar = '#'.repeat(Math.max(1, Math.round(s.ms / totalScannerMs * 40)));
    console.log(`  ${s.name.padEnd(15)} ${s.ms.toFixed(0).padStart(6)}ms  ${pct.padStart(5)}%  ${bar}${s.note ? ` (${s.note})` : ''}`);
  }
  console.log(`  ${'TOTAL'.padEnd(15)} ${totalScannerMs.toFixed(0).padStart(6)}ms`);
  console.log();

  cleanup(scannerTmpDir);

  // ----- Summary table -----
  console.log('='.repeat(70));
  console.log('  SUMMARY');
  console.log('='.repeat(70));
  console.log(`  ${'Size'.padEnd(10)} ${'Files'.padStart(6)} ${'Median'.padStart(8)} ${'Mean'.padStart(8)} ${'Min'.padStart(8)} ${'Max'.padStart(8)} ${'Heap'.padStart(8)} ${'RSS'.padStart(8)}`);
  console.log(`  ${'-'.repeat(10)} ${'-'.repeat(6)} ${'-'.repeat(8)} ${'-'.repeat(8)} ${'-'.repeat(8)} ${'-'.repeat(8)} ${'-'.repeat(8)} ${'-'.repeat(8)}`);
  for (const [name, r] of Object.entries(results)) {
    console.log(`  ${name.padEnd(10)} ${String(r.files).padStart(6)} ${(r.median.toFixed(0) + 'ms').padStart(8)} ${(r.mean.toFixed(0) + 'ms').padStart(8)} ${(r.min.toFixed(0) + 'ms').padStart(8)} ${(r.max.toFixed(0) + 'ms').padStart(8)} ${((r.peakHeap / 1024 / 1024).toFixed(1) + 'MB').padStart(8)} ${((r.peakRss / 1024 / 1024).toFixed(1) + 'MB').padStart(8)}`);
  }
  console.log();

  // Slowest scanner
  if (scannerTimings.length > 0) {
    console.log(`  Slowest scanner: ${scannerTimings[0].name} (${scannerTimings[0].ms.toFixed(0)}ms, ${((scannerTimings[0].ms / totalScannerMs) * 100).toFixed(1)}% of total)`);
  }
  console.log();
}

benchmark().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
