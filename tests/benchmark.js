#!/usr/bin/env node
'use strict';

/**
 * MUAD'DIB Performance Benchmark Suite
 *
 * Measures scan performance across synthetic projects of varying sizes.
 * Outputs per-scanner timing, memory usage, and bottleneck analysis.
 *
 * Usage:
 *   node tests/benchmark.js                 # Full suite (small/medium/large/xlarge)
 *   node tests/benchmark.js --size small     # Single size only
 *   node tests/benchmark.js --size medium
 *   node tests/benchmark.js --size large
 *   node tests/benchmark.js --size xlarge
 *   node tests/benchmark.js --compare        # Run comparison benchmarks (cache/deobfuscate/paranoid)
 *   node tests/benchmark.js --json           # Output results as JSON
 *   node tests/benchmark.js --iterations 3   # Average over N runs (default: 1)
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

// ============================================
// PROJECT GENERATOR
// ============================================

const SIZES = {
  small:  { files: 10,    label: 'Small (10 files)' },
  medium: { files: 100,   label: 'Medium (100 files)' },
  large:  { files: 1000,  label: 'Large (1,000 files)' },
  xlarge: { files: 10000, label: 'XLarge (10,000 files)' }
};

// Realistic JS file templates exercising different scanners
const TEMPLATES = {
  // Normal module — no findings
  normal: (i) => `'use strict';
const path = require('path');
const EventEmitter = require('events');

class Service${i} extends EventEmitter {
  constructor(opts) {
    super();
    this.name = opts.name || 'service-${i}';
    this.config = Object.assign({}, opts);
  }

  async process(data) {
    const result = data.map(item => ({
      id: item.id,
      value: item.value * 2,
      timestamp: Date.now()
    }));
    this.emit('processed', result);
    return result;
  }

  toString() {
    return \`[\${this.name}]\`;
  }
}

module.exports = { Service${i} };
`,

  // Dynamic require — triggers AST scanner
  dynamicRequire: (i) => `'use strict';
const path = require('path');
const name = 'module-' + ${i};
const mod = require(name);
module.exports = mod;
`,

  // Env access — triggers dataflow scanner
  envAccess: (i) => `'use strict';
const http = require('http');
const token = process.env.API_TOKEN;
const secret = process.env.SECRET_KEY;
function send${i}() {
  http.request({ hostname: 'api.example.com', path: '/data', headers: { authorization: token } });
}
module.exports = { send${i} };
`,

  // Light obfuscation pattern — triggers obfuscation scanner
  obfuscated: (i) => `'use strict';
var _0x${i.toString(16).padStart(4, '0')} = [
  '\\x68\\x65\\x6c\\x6c\\x6f',
  '\\x77\\x6f\\x72\\x6c\\x64',
  '\\x66\\x6f\\x6f\\x62\\x61\\x72'
];
var a = _0x${i.toString(16).padStart(4, '0')}[0];
var b = _0x${i.toString(16).padStart(4, '0')}[1];
module.exports = { a: a, b: b };
`,

  // Filesystem access — triggers dataflow
  fsAccess: (i) => `'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');

function readConfig${i}() {
  const home = os.homedir();
  const configPath = path.join(home, '.config', 'app${i}', 'settings.json');
  if (fs.existsSync(configPath)) {
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
  }
  return {};
}

module.exports = { readConfig${i} };
`,

  // Complex module — exercises AST deeply
  complex: (i) => `'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const zlib = require('zlib');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

class DataProcessor${i} {
  constructor() {
    this.cache = new Map();
    this.stats = { hits: 0, misses: 0 };
  }

  hash(input) {
    return crypto.createHash('sha256').update(input).digest('hex');
  }

  async compress(data) {
    const buf = Buffer.from(JSON.stringify(data));
    return gzip(buf);
  }

  async decompress(buf) {
    const raw = await gunzip(buf);
    return JSON.parse(raw.toString());
  }

  get(key) {
    const h = this.hash(key);
    if (this.cache.has(h)) {
      this.stats.hits++;
      return this.cache.get(h);
    }
    this.stats.misses++;
    return null;
  }

  set(key, value) {
    const h = this.hash(key);
    this.cache.set(h, value);
  }
}

module.exports = { DataProcessor${i} };
`
};

// Distribution: 60% normal, 10% each for the suspicious patterns
function getTemplate(i) {
  const mod = i % 10;
  if (mod < 6) return TEMPLATES.normal;
  if (mod === 6) return TEMPLATES.dynamicRequire;
  if (mod === 7) return TEMPLATES.envAccess;
  if (mod === 8) return TEMPLATES.obfuscated;
  if (mod === 9) return TEMPLATES.fsAccess;
  return TEMPLATES.complex;
}

function generateProject(tmpDir, fileCount) {
  // Create directory structure
  const dirs = ['src', 'src/utils', 'src/services', 'src/models', 'lib', 'lib/helpers'];
  for (const d of dirs) {
    fs.mkdirSync(path.join(tmpDir, d), { recursive: true });
  }

  // Distribute files across directories
  for (let i = 0; i < fileCount; i++) {
    const dir = dirs[i % dirs.length];
    const template = getTemplate(i);
    const content = template(i);
    fs.writeFileSync(path.join(tmpDir, dir, `file-${i}.js`), content);
  }

  // package.json (exercises package scanner)
  fs.writeFileSync(path.join(tmpDir, 'package.json'), JSON.stringify({
    name: `bench-project-${fileCount}`,
    version: '1.0.0',
    scripts: {
      start: 'node src/index.js',
      test: 'node tests/run.js',
      build: 'webpack --mode production'
    },
    dependencies: {
      express: '^4.18.0',
      lodash: '^4.17.21'
    }
  }, null, 2));

  // An index.js entry point
  fs.writeFileSync(path.join(tmpDir, 'src', 'index.js'),
    `'use strict';\nconst app = require('express')();\napp.listen(3000);\n`
  );

  return tmpDir;
}

function rmrf(dir) {
  if (!fs.existsSync(dir)) return;
  fs.rmSync(dir, { recursive: true, force: true });
}

// ============================================
// SCANNER INSTRUMENTATION
// ============================================

// Import scanners directly for per-scanner timing
const { scanPackageJson } = require('../src/scanner/package.js');
const { scanShellScripts } = require('../src/scanner/shell.js');
const { analyzeAST } = require('../src/scanner/ast.js');
const { detectObfuscation } = require('../src/scanner/obfuscation.js');
const { scanDependencies } = require('../src/scanner/dependencies.js');
const { scanHashes } = require('../src/scanner/hash.js');
const { analyzeDataFlow } = require('../src/scanner/dataflow.js');
const { scanTyposquatting } = require('../src/scanner/typosquat.js');
const { scanGitHubActions } = require('../src/scanner/github-actions.js');
const { scanEntropy } = require('../src/scanner/entropy.js');
const { scanAIConfig } = require('../src/scanner/ai-config.js');
const { deobfuscate } = require('../src/scanner/deobfuscate.js');
const { buildModuleGraph, annotateTaintedExports, detectCrossFileFlows } = require('../src/scanner/module-graph');
const { clearFileListCache } = require('../src/utils.js');
const { loadCachedIOCs } = require('../src/ioc/updater.js');

// Pre-warm IOC cache so it doesn't skew per-scanner timings
// (IOC loading takes ~3s on first call due to JSON parsing of ~5MB compact file)
function warmupIOCs() {
  const start = process.hrtime.bigint();
  loadCachedIOCs();
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  return ms;
}

// Some scanners return promises (scanPackageJson), some are sync.
// Mark async scanners so the benchmark awaits them properly.
const SCANNERS = [
  { name: 'package',        fn: (t) => scanPackageJson(t), async: true },
  { name: 'shell',          fn: (t) => scanShellScripts(t) },
  { name: 'ast',            fn: (t) => analyzeAST(t, { deobfuscate }) },
  { name: 'obfuscation',    fn: (t) => detectObfuscation(t) },
  { name: 'dependencies',   fn: (t) => scanDependencies(t) },
  { name: 'hash',           fn: (t) => scanHashes(t) },
  { name: 'dataflow',       fn: (t) => analyzeDataFlow(t, { deobfuscate }) },
  { name: 'typosquat',      fn: (t) => scanTyposquatting(t) },
  { name: 'github-actions', fn: (t) => scanGitHubActions(t) },
  { name: 'entropy',        fn: (t) => scanEntropy(t, {}) },
  { name: 'ai-config',      fn: (t) => scanAIConfig(t) }
];

function timeSync(fn) {
  const start = process.hrtime.bigint();
  const result = fn();
  const end = process.hrtime.bigint();
  return { result, ms: Number(end - start) / 1e6 };
}

async function timeAsync(fn) {
  const start = process.hrtime.bigint();
  const result = await fn();
  const end = process.hrtime.bigint();
  return { result, ms: Number(end - start) / 1e6 };
}

function getMemoryMB() {
  const mem = process.memoryUsage();
  return {
    rss: Math.round(mem.rss / 1024 / 1024 * 10) / 10,
    heapUsed: Math.round(mem.heapUsed / 1024 / 1024 * 10) / 10,
    heapTotal: Math.round(mem.heapTotal / 1024 / 1024 * 10) / 10,
    external: Math.round(mem.external / 1024 / 1024 * 10) / 10
  };
}

// ============================================
// BENCHMARK RUNNER
// ============================================

async function benchmarkSize(sizeKey, iterations) {
  const size = SIZES[sizeKey];
  const tmpDir = path.join(os.tmpdir(), `muaddib-bench-${sizeKey}-${Date.now()}`);

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  ${size.label}`);
  console.log(`${'='.repeat(60)}`);

  // Generate project
  const { ms: genMs } = timeSync(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
    generateProject(tmpDir, size.files);
  });
  console.log(`  Project generated in ${genMs.toFixed(0)}ms`);

  const runs = [];

  for (let iter = 0; iter < iterations; iter++) {
    if (iterations > 1) console.log(`\n  --- Iteration ${iter + 1}/${iterations} ---`);

    // Force GC if available (run with --expose-gc)
    if (global.gc) global.gc();

    // Per-scanner timing (file list cache cleared between each to measure fair I/O per scanner)
    const scannerResults = {};
    let totalScannerMs = 0;

    for (const scanner of SCANNERS) {
      clearFileListCache();
      if (global.gc) global.gc();

      let ms, result;
      if (scanner.async) {
        ({ ms, result } = await timeAsync(() => scanner.fn(tmpDir)));
      } else {
        ({ ms, result } = timeSync(() => scanner.fn(tmpDir)));
      }
      scannerResults[scanner.name] = {
        ms: Math.round(ms * 100) / 100,
        threats: Array.isArray(result) ? result.length : 0
      };
      totalScannerMs += ms;
    }

    // Module graph timing (separate phase)
    clearFileListCache();
    const { ms: moduleGraphMs } = timeSync(() => {
      const graph = buildModuleGraph(tmpDir);
      const tainted = annotateTaintedExports(graph, tmpDir);
      detectCrossFileFlows(graph, tainted, tmpDir);
    });
    scannerResults['module-graph'] = { ms: Math.round(moduleGraphMs * 100) / 100, threats: 0 };
    totalScannerMs += moduleGraphMs;

    // Deobfuscation timing (standalone — measures pure deob cost separately)
    clearFileListCache();
    const { ms: deobMs } = timeSync(() => {
      const { findFiles } = require('../src/utils.js');
      const files = findFiles(tmpDir, { extensions: ['.js'] });
      for (const f of files) {
        try {
          const code = fs.readFileSync(f, 'utf8');
          deobfuscate(code, f);
        } catch { /* skip */ }
      }
    });
    scannerResults['deobfuscate'] = { ms: Math.round(deobMs * 100) / 100, threats: 0 };

    // Full end-to-end scan via run() with _capture
    clearFileListCache();
    if (global.gc) global.gc();
    const memBeforeFull = getMemoryMB();

    const { run } = require('../src/index.js');
    let e2eMs = 0;
    let e2eThreats = 0;
    {
      const start = process.hrtime.bigint();
      try {
        const result = await run(tmpDir, { _capture: true });
        e2eThreats = result.threats.length;
      } catch { /* scan may fail on synthetic data */ }
      const end = process.hrtime.bigint();
      e2eMs = Number(end - start) / 1e6;
    }

    const memAfter = getMemoryMB();

    // Overhead = E2E minus sum of individual scanners.
    // Note: individual scanners are timed with cache clears between each,
    // so totalScannerMs includes redundant file discovery.
    // E2E benefits from shared file list cache, so it's usually faster.
    // A negative overhead means the cache is saving that much time.
    const overhead = e2eMs - totalScannerMs;

    runs.push({
      scanners: scannerResults,
      totalScannerMs: Math.round(totalScannerMs * 100) / 100,
      e2eMs: Math.round(e2eMs * 100) / 100,
      e2eThreats,
      overhead: Math.round(overhead * 100) / 100,
      memBefore: memBeforeFull,
      memAfter,
      memDelta: {
        rss: Math.round((memAfter.rss - memBeforeFull.rss) * 10) / 10,
        heapUsed: Math.round((memAfter.heapUsed - memBeforeFull.heapUsed) * 10) / 10
      }
    });
  }

  // Average results across iterations
  const avg = averageRuns(runs);

  // Print results
  printResults(avg, size);

  // Cleanup
  rmrf(tmpDir);

  return { size: sizeKey, ...avg };
}

function averageRuns(runs) {
  if (runs.length === 1) return runs[0];

  const avg = {
    scanners: {},
    totalScannerMs: 0,
    e2eMs: 0,
    e2eThreats: runs[0].e2eThreats,
    overhead: 0,
    memAfter: { rss: 0, heapUsed: 0, heapTotal: 0, external: 0 },
    memDelta: { rss: 0, heapUsed: 0 }
  };

  const scannerNames = Object.keys(runs[0].scanners);
  for (const name of scannerNames) {
    avg.scanners[name] = {
      ms: Math.round(runs.reduce((s, r) => s + r.scanners[name].ms, 0) / runs.length * 100) / 100,
      threats: runs[0].scanners[name].threats
    };
  }

  avg.totalScannerMs = Math.round(runs.reduce((s, r) => s + r.totalScannerMs, 0) / runs.length * 100) / 100;
  avg.e2eMs = Math.round(runs.reduce((s, r) => s + r.e2eMs, 0) / runs.length * 100) / 100;
  avg.overhead = Math.round(runs.reduce((s, r) => s + r.overhead, 0) / runs.length * 100) / 100;
  avg.memAfter.rss = Math.round(runs.reduce((s, r) => s + r.memAfter.rss, 0) / runs.length * 10) / 10;
  avg.memAfter.heapUsed = Math.round(runs.reduce((s, r) => s + r.memAfter.heapUsed, 0) / runs.length * 10) / 10;
  avg.memDelta.rss = Math.round(runs.reduce((s, r) => s + r.memDelta.rss, 0) / runs.length * 10) / 10;
  avg.memDelta.heapUsed = Math.round(runs.reduce((s, r) => s + r.memDelta.heapUsed, 0) / runs.length * 10) / 10;

  return avg;
}

function printResults(data, size) {
  // Per-scanner table
  console.log(`\n  Per-scanner timing:`);
  console.log(`  ${'Scanner'.padEnd(18)} ${'Time (ms)'.padStart(12)} ${'%'.padStart(7)} ${'Threats'.padStart(8)}`);
  console.log(`  ${'-'.repeat(18)} ${'-'.repeat(12)} ${'-'.repeat(7)} ${'-'.repeat(8)}`);

  const entries = Object.entries(data.scanners).sort((a, b) => b[1].ms - a[1].ms);
  for (const [name, info] of entries) {
    const pct = data.totalScannerMs > 0 ? (info.ms / data.totalScannerMs * 100) : 0;
    console.log(
      `  ${name.padEnd(18)} ${info.ms.toFixed(1).padStart(12)} ${pct.toFixed(1).padStart(6)}% ${String(info.threats).padStart(8)}`
    );
  }

  console.log(`  ${'-'.repeat(18)} ${'-'.repeat(12)} ${'-'.repeat(7)} ${'-'.repeat(8)}`);
  console.log(`  ${'TOTAL scanners'.padEnd(18)} ${data.totalScannerMs.toFixed(1).padStart(12)} ${' 100.0%'.padStart(7)}`);

  // E2E
  console.log(`\n  End-to-end scan:  ${data.e2eMs.toFixed(1)} ms (${data.e2eThreats} threats)`);
  if (data.overhead < 0) {
    console.log(`  Cache savings:    ${Math.abs(data.overhead).toFixed(1)} ms (shared file list cache vs per-scanner I/O)`);
  } else {
    console.log(`  Orchestration overhead: ${data.overhead.toFixed(1)} ms (IOC load, scoring, dedup)`);
  }

  // Throughput
  const filesPerSec = size.files / (data.e2eMs / 1000);
  console.log(`  Throughput: ${filesPerSec.toFixed(0)} files/sec`);

  // Memory
  console.log(`\n  Memory:`);
  console.log(`    Peak RSS:        ${data.memAfter.rss} MB`);
  console.log(`    Peak heap used:  ${data.memAfter.heapUsed} MB`);
  console.log(`    Delta RSS:       ${data.memDelta.rss > 0 ? '+' : ''}${data.memDelta.rss} MB`);
  console.log(`    Delta heap:      ${data.memDelta.heapUsed > 0 ? '+' : ''}${data.memDelta.heapUsed} MB`);

  // Bottleneck
  const [topName, topInfo] = entries[0];
  const topPct = data.totalScannerMs > 0 ? (topInfo.ms / data.totalScannerMs * 100) : 0;
  console.log(`\n  Bottleneck: ${topName} (${topPct.toFixed(1)}% of scanner time)`);
}

// ============================================
// COMPARISON BENCHMARKS
// ============================================

async function benchmarkComparisons() {
  const fileCount = 200; // Moderate size for stable A/B comparisons (less GC noise)
  const tmpDir = path.join(os.tmpdir(), `muaddib-bench-compare-${Date.now()}`);
  fs.mkdirSync(tmpDir, { recursive: true });
  generateProject(tmpDir, fileCount);

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  COMPARISON BENCHMARKS (${fileCount} files)`);
  console.log(`${'='.repeat(60)}`);

  const { run } = require('../src/index.js');

  // Warmup: 2 full scans to stabilize JIT and OS file cache
  console.log('  Warming up JIT...');
  await run(tmpDir, { _capture: true });
  clearFileListCache();
  await run(tmpDir, { _capture: true });
  clearFileListCache();

  // Measure: run N times and take median to reduce variance
  const REPS = 3;

  async function timeRunMedian(label, options) {
    const times = [];
    let threats = 0;
    let memDelta = 0;
    for (let i = 0; i < REPS; i++) {
      clearFileListCache();
      if (global.gc) global.gc();
      const memBefore = getMemoryMB();
      const start = process.hrtime.bigint();
      try {
        const result = await run(tmpDir, { _capture: true, ...options });
        threats = result.threats.length;
      } catch { /* ignore */ }
      const end = process.hrtime.bigint();
      const ms = Number(end - start) / 1e6;
      const memAfter = getMemoryMB();
      memDelta = memAfter.heapUsed - memBefore.heapUsed;
      times.push(ms);
    }
    times.sort((a, b) => a - b);
    const median = times[Math.floor(times.length / 2)];
    return { label, ms: median, threats, memDelta, allTimes: times };
  }

  const results = [];

  // 1. Baseline E2E measurement
  console.log('\n  [1] Baseline E2E');
  const baseline = await timeRunMedian('Baseline (default options)', {});
  results.push(baseline);
  console.log(`    Default scan: ${baseline.ms.toFixed(1)} ms (${baseline.threats} threats)`);

  // 2. With vs without deobfuscation
  console.log('\n  [2] Deobfuscation impact');
  const withDeob = await timeRunMedian('With deobfuscation', {});
  const withoutDeob = await timeRunMedian('Without deobfuscation', { noDeobfuscate: true });
  results.push(withDeob, withoutDeob);

  const deobCost = withDeob.ms - withoutDeob.ms;
  console.log(`    With deobfuscation:    ${withDeob.ms.toFixed(1)} ms (${withDeob.threats} threats)`);
  console.log(`    Without deobfuscation: ${withoutDeob.ms.toFixed(1)} ms (${withoutDeob.threats} threats)`);
  console.log(`    Deobfuscation cost:    ${deobCost.toFixed(1)} ms (${deobCost > 0 ? '+' + ((deobCost / withoutDeob.ms) * 100).toFixed(1) + '%' : 'negligible'})`);

  // 3. With vs without module graph
  console.log('\n  [3] Module graph impact');
  const withMg = await timeRunMedian('With module graph', {});
  const withoutMg = await timeRunMedian('Without module graph', { noModuleGraph: true });
  results.push(withMg, withoutMg);

  const mgCost = withMg.ms - withoutMg.ms;
  console.log(`    With module graph:    ${withMg.ms.toFixed(1)} ms`);
  console.log(`    Without module graph: ${withoutMg.ms.toFixed(1)} ms`);
  console.log(`    Module graph cost:    ${mgCost.toFixed(1)} ms (${mgCost > 0 ? '+' + ((mgCost / withoutMg.ms) * 100).toFixed(1) + '%' : 'negligible'})`);

  // 4. Normal vs paranoid (suppress [PARANOID] output)
  console.log('\n  [4] Paranoid mode impact');
  const normalMode = await timeRunMedian('Normal mode', {});
  const origLog = console.log;
  console.log = (...args) => { if (!String(args[0]).includes('[PARANOID]')) origLog(...args); };
  const paranoidMode = await timeRunMedian('Paranoid mode', { paranoid: true });
  console.log = origLog;
  results.push(normalMode, paranoidMode);

  const paranoidCost = paranoidMode.ms - normalMode.ms;
  console.log(`    Normal mode:   ${normalMode.ms.toFixed(1)} ms (${normalMode.threats} threats)`);
  console.log(`    Paranoid mode: ${paranoidMode.ms.toFixed(1)} ms (${paranoidMode.threats} threats)`);
  console.log(`    Paranoid cost: ${paranoidCost.toFixed(1)} ms (${paranoidCost > 0 ? '+' + ((paranoidCost / normalMode.ms) * 100).toFixed(1) + '%' : 'negligible'})`);

  // 5. Minimal mode (no deob, no module graph)
  console.log('\n  [5] Minimal vs full');
  const fullMode = await timeRunMedian('Full (all features)', {});
  const minimalMode = await timeRunMedian('Minimal (no deob, no MG)', { noDeobfuscate: true, noModuleGraph: true });
  results.push(fullMode, minimalMode);

  const savings = fullMode.ms - minimalMode.ms;
  console.log(`    Full:    ${fullMode.ms.toFixed(1)} ms`);
  console.log(`    Minimal: ${minimalMode.ms.toFixed(1)} ms`);
  console.log(`    Savings: ${savings.toFixed(1)} ms (${savings > 0 ? '-' + ((savings / fullMode.ms) * 100).toFixed(1) + '%' : 'negligible'})`);

  rmrf(tmpDir);
  return results;
}

// ============================================
// SCALING ANALYSIS
// ============================================

async function benchmarkScaling() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  SCALING ANALYSIS`);
  console.log(`${'='.repeat(60)}`);

  const { run } = require('../src/index.js');
  const points = [10, 50, 100, 250, 500, 1000, 2500, 5000];
  const scalingData = [];

  for (const fileCount of points) {
    const tmpDir = path.join(os.tmpdir(), `muaddib-bench-scale-${fileCount}-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    generateProject(tmpDir, fileCount);

    clearFileListCache();
    if (global.gc) global.gc();
    const start = process.hrtime.bigint();
    try {
      await run(tmpDir, { _capture: true });
    } catch { /* ignore */ }
    const end = process.hrtime.bigint();
    const ms = Number(end - start) / 1e6;

    const mem = getMemoryMB();
    scalingData.push({ files: fileCount, ms: Math.round(ms), rss: mem.rss, heapUsed: mem.heapUsed });

    console.log(`  ${String(fileCount).padStart(6)} files: ${ms.toFixed(0).padStart(8)} ms  (RSS: ${mem.rss} MB, Heap: ${mem.heapUsed} MB)`);

    rmrf(tmpDir);
  }

  // Linearity analysis
  if (scalingData.length >= 2) {
    const first = scalingData[0];
    const last = scalingData[scalingData.length - 1];
    const fileRatio = last.files / first.files;
    const timeRatio = last.ms / first.ms;
    const complexity = Math.log(timeRatio) / Math.log(fileRatio);

    console.log(`\n  Scaling factor: O(n^${complexity.toFixed(2)})`);
    if (complexity <= 1.2) {
      console.log(`  --> Near-linear scaling`);
    } else if (complexity <= 1.5) {
      console.log(`  --> Slightly super-linear (acceptable)`);
    } else {
      console.log(`  --> Super-linear: potential bottleneck at scale`);
    }
  }

  return scalingData;
}

// ============================================
// MAIN
// ============================================

async function main() {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes('--json');
  const compareMode = args.includes('--compare');
  const scalingMode = args.includes('--scaling');

  let sizeFilter = null;
  const sizeIdx = args.indexOf('--size');
  if (sizeIdx !== -1 && args[sizeIdx + 1]) {
    sizeFilter = args[sizeIdx + 1];
    if (!SIZES[sizeFilter]) {
      console.error(`Unknown size: ${sizeFilter}. Valid: ${Object.keys(SIZES).join(', ')}`);
      process.exit(1);
    }
  }

  let iterations = 1;
  const iterIdx = args.indexOf('--iterations');
  if (iterIdx !== -1 && args[iterIdx + 1]) {
    iterations = parseInt(args[iterIdx + 1], 10) || 1;
  }

  console.log(`\nMUAD'DIB Performance Benchmark`);
  console.log(`Node ${process.version} | ${os.platform()} ${os.arch()} | ${os.cpus()[0].model}`);
  console.log(`${os.cpus().length} cores | ${Math.round(os.totalmem() / 1024 / 1024 / 1024)} GB RAM`);
  if (iterations > 1) console.log(`Averaging over ${iterations} iterations`);

  // Pre-warm IOC cache (loading iocs-compact.json takes ~3s on first call)
  const iocWarmupMs = warmupIOCs();
  console.log(`IOC cache warmed in ${iocWarmupMs.toFixed(0)}ms`);

  const allResults = { iocWarmupMs: Math.round(iocWarmupMs) };

  if (compareMode) {
    allResults.comparisons = await benchmarkComparisons();
  } else if (scalingMode) {
    allResults.scaling = await benchmarkScaling();
  } else {
    // Size benchmarks
    const sizes = sizeFilter ? [sizeFilter] : Object.keys(SIZES);
    allResults.sizes = [];
    for (const s of sizes) {
      const result = await benchmarkSize(s, iterations);
      allResults.sizes.push(result);
    }

    // Always run scaling analysis for the full suite
    if (!sizeFilter) {
      allResults.scaling = await benchmarkScaling();
    }
  }

  // Summary
  if (allResults.sizes && allResults.sizes.length > 1) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`  SUMMARY`);
    console.log(`${'='.repeat(60)}`);
    console.log(`  ${'Size'.padEnd(22)} ${'E2E (ms)'.padStart(10)} ${'files/sec'.padStart(10)} ${'RSS (MB)'.padStart(10)} ${'Bottleneck'.padStart(18)}`);
    console.log(`  ${'-'.repeat(22)} ${'-'.repeat(10)} ${'-'.repeat(10)} ${'-'.repeat(10)} ${'-'.repeat(18)}`);

    for (const r of allResults.sizes) {
      const sizeInfo = SIZES[r.size];
      const fps = sizeInfo.files / (r.e2eMs / 1000);
      const entries = Object.entries(r.scanners).sort((a, b) => b[1].ms - a[1].ms);
      const bottleneck = entries[0][0];
      console.log(
        `  ${sizeInfo.label.padEnd(22)} ${r.e2eMs.toFixed(0).padStart(10)} ${fps.toFixed(0).padStart(10)} ${r.memAfter.rss.toFixed(1).padStart(10)} ${bottleneck.padStart(18)}`
      );
    }
  }

  // JSON output
  if (jsonOutput) {
    const outPath = path.join(__dirname, '..', 'metrics', `benchmark-${new Date().toISOString().slice(0, 10)}.json`);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(allResults, null, 2));
    console.log(`\n  Results saved to ${outPath}`);
  }

  console.log(`\n${'='.repeat(60)}`);
  console.log(`  Benchmark complete.`);
  console.log(`${'='.repeat(60)}\n`);
}

main().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
