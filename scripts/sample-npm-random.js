#!/usr/bin/env node
/**
 * MUAD'DIB — npm Random Package Sampler
 *
 * Samples 200 packages from the npm registry by stratified random sampling.
 * Used to measure FPR on a representative npm sample (not curated).
 *
 * Strata (by dependency count):
 *   small  (<10 deps):   80 packages  (40%)
 *   medium (10-50 deps):  60 packages  (30%)
 *   large  (50-100 deps): 40 packages  (20%)
 *   vlarge (100+ deps):   20 packages  (10%)
 *
 * Exclusions: @types/*, deprecated, already in packages-npm.txt
 *
 * Usage:
 *   node scripts/sample-npm-random.js [--seed N] [--output path]
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CURATED_FILE = path.join(ROOT, 'datasets', 'benign', 'packages-npm.txt');
const DEFAULT_OUTPUT = path.join(ROOT, 'datasets', 'benign', 'packages-npm-random.txt');

const STRATA = {
  small:  { min: 0,   max: 9,   quota: 80 },
  medium: { min: 10,  max: 50,  quota: 60 },
  large:  { min: 51,  max: 100, quota: 40 },
  vlarge: { min: 101, max: Infinity, quota: 20 }
};

// Search keywords — diverse enough to sample across npm
const SEARCH_KEYWORDS = [
  'util', 'helper', 'config', 'server', 'client', 'api', 'data',
  'file', 'string', 'array', 'json', 'http', 'url', 'path', 'stream',
  'log', 'debug', 'test', 'mock', 'format', 'parse', 'transform',
  'crypto', 'hash', 'encode', 'decode', 'compress', 'cache', 'queue',
  'event', 'promise', 'async', 'callback', 'middleware', 'router',
  'database', 'mongo', 'redis', 'sql', 'orm', 'schema', 'validate',
  'cli', 'terminal', 'color', 'progress', 'spinner', 'prompt',
  'image', 'pdf', 'csv', 'xml', 'yaml', 'markdown', 'html',
  'email', 'auth', 'token', 'session', 'cookie', 'proxy',
  'date', 'time', 'math', 'random', 'uuid', 'id', 'slug',
  'webpack', 'babel', 'eslint', 'prettier', 'rollup', 'vite',
  'react', 'vue', 'angular', 'svelte', 'solid', 'preact',
  'express', 'koa', 'fastify', 'socket', 'graphql', 'rest',
  'aws', 'azure', 'gcp', 'docker', 'kubernetes', 'ci',
  'i18n', 'locale', 'charset', 'buffer', 'binary', 'hex',
  'retry', 'timeout', 'rate', 'limit', 'throttle', 'debounce',
  'merge', 'deep', 'clone', 'diff', 'patch', 'compare',
  'glob', 'pattern', 'regex', 'match', 'search', 'filter',
  'tree', 'graph', 'list', 'map', 'set', 'stack',
  'plugin', 'loader', 'adapter', 'wrapper', 'bridge', 'connector'
];

// Seeded PRNG (mulberry32) for reproducibility
function mulberry32(seed) {
  return function() {
    seed |= 0; seed = seed + 0x6D2B79F5 | 0;
    let t = Math.imul(seed ^ seed >>> 15, 1 | seed);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}

function shuffleArray(arr, rng) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 15000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        httpsGet(res.headers.location).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`JSON parse error: ${e.message}`)); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

/**
 * Search npm registry for packages matching a keyword.
 * Returns array of { name, version } objects.
 */
async function searchNpm(keyword, from = 0, size = 250) {
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(keyword)}&size=${size}&from=${from}`;
  try {
    const data = await httpsGet(url);
    return (data.objects || []).map(o => ({
      name: o.package.name,
      version: o.package.version,
      description: o.package.description || '',
      deprecated: o.package.deprecated || false
    }));
  } catch (err) {
    console.error(`  [WARN] npm search "${keyword}" failed: ${err.message}`);
    return [];
  }
}

/**
 * Get dependency count for a package via npm view.
 * Returns { deps, devDeps } or null on failure.
 */
async function getDepCount(pkgName) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}/latest`;
  try {
    const data = await httpsGet(url);
    const deps = data.dependencies ? Object.keys(data.dependencies).length : 0;
    const devDeps = data.devDependencies ? Object.keys(data.devDependencies).length : 0;
    return { deps, devDeps, totalDeps: deps + devDeps };
  } catch {
    return null;
  }
}

function classifyStratum(depCount) {
  for (const [name, { min, max }] of Object.entries(STRATA)) {
    if (depCount >= min && depCount <= max) return name;
  }
  return 'small';
}

function loadCuratedPackages() {
  try {
    return new Set(
      fs.readFileSync(CURATED_FILE, 'utf8')
        .split(/\r?\n/)
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'))
    );
  } catch {
    return new Set();
  }
}

async function main() {
  const args = process.argv.slice(2);
  let seed = 42;
  let outputPath = DEFAULT_OUTPUT;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--seed' && args[i + 1]) { seed = parseInt(args[i + 1], 10); i++; }
    if (args[i] === '--output' && args[i + 1]) { outputPath = args[i + 1]; i++; }
  }

  const rng = mulberry32(seed);
  const curated = loadCuratedPackages();
  console.log(`  Loaded ${curated.size} curated packages to exclude`);
  console.log(`  Seed: ${seed}`);

  // Phase 1: Collect candidate packages from npm search
  console.log(`\n  [1/3] Collecting candidates from npm search...`);
  const candidates = new Map(); // name -> { name, version, description }
  const shuffledKeywords = shuffleArray([...SEARCH_KEYWORDS], rng);

  for (let i = 0; i < shuffledKeywords.length; i++) {
    const keyword = shuffledKeywords[i];
    if (process.stdout.isTTY) {
      process.stdout.write(`\r  Searching "${keyword}" (${i + 1}/${shuffledKeywords.length})...          `);
    }

    // Search with random offset for diversity
    const offset = Math.floor(rng() * 200);
    const results = await searchNpm(keyword, offset, 250);

    for (const pkg of results) {
      // Exclusion filters
      if (candidates.has(pkg.name)) continue;
      if (curated.has(pkg.name)) continue;
      if (pkg.name.startsWith('@types/')) continue;
      if (pkg.deprecated) continue;
      if (pkg.name.startsWith('_')) continue;

      candidates.set(pkg.name, pkg);
    }

    // Stop early if we have enough candidates
    if (candidates.size >= 2000) break;

    // Rate limiting: ~100ms between requests
    await new Promise(r => setTimeout(r, 100));
  }

  if (process.stdout.isTTY) {
    process.stdout.write('\r' + ''.padEnd(80) + '\r');
  }
  console.log(`  Collected ${candidates.size} unique candidates`);

  // Phase 2: Classify by dependency count
  // Over-collect: allow 2x quota per stratum to enable backfill
  console.log(`\n  [2/3] Classifying by dependency count...`);
  const buckets = { small: [], medium: [], large: [], vlarge: [] };
  const candidateList = shuffleArray([...candidates.keys()], rng);

  const totalQuota = Object.values(STRATA).reduce((s, v) => s + v.quota, 0);
  let classified = 0;
  let processed = 0;
  // Over-collect limit: 2x quota per stratum to provide backfill pool
  const OVER_COLLECT = 2;

  for (const pkgName of candidateList) {
    // Check if all buckets have enough for backfill
    const allOverCollected = Object.entries(STRATA).every(
      ([name, { quota }]) => buckets[name].length >= quota * OVER_COLLECT
    );
    if (allOverCollected) break;

    processed++;
    if (process.stdout.isTTY && processed % 10 === 0) {
      const bucketStatus = Object.entries(buckets).map(([k, v]) => `${k}:${v.length}/${STRATA[k].quota}`).join(' ');
      process.stdout.write(`\r  Classifying [${processed}/${candidateList.length}] ${bucketStatus}          `);
    }

    const info = await getDepCount(pkgName);
    if (!info) continue;

    const stratum = classifyStratum(info.totalDeps);
    if (buckets[stratum].length < STRATA[stratum].quota * OVER_COLLECT) {
      buckets[stratum].push({ name: pkgName, deps: info.totalDeps, stratum });
      classified++;
    }

    // Rate limiting
    await new Promise(r => setTimeout(r, 50));
  }

  if (process.stdout.isTTY) {
    process.stdout.write('\r' + ''.padEnd(80) + '\r');
  }

  // Phase 3: Output with backfill
  // If large/vlarge strata can't meet quota, redistribute remaining slots
  // to small/medium proportionally (reflects real npm distribution).
  console.log(`\n  [3/3] Writing results...`);
  const selected = [];
  let deficit = 0;
  for (const [name, { quota }] of Object.entries(STRATA)) {
    const actual = Math.min(buckets[name].length, quota);
    console.log(`    ${name}: ${actual}/${quota} packages`);
    selected.push(...buckets[name].slice(0, actual));
    deficit += quota - actual;
  }

  // Backfill deficit from small/medium overflow (proportional)
  if (deficit > 0) {
    console.log(`    Backfilling ${deficit} slots from small/medium overflow...`);
    const backfillSources = ['small', 'medium']; // priority order
    for (const src of backfillSources) {
      if (deficit <= 0) break;
      const overflow = buckets[src].slice(STRATA[src].quota);
      const take = Math.min(overflow.length, deficit);
      if (take > 0) {
        selected.push(...overflow.slice(0, take));
        deficit -= take;
        console.log(`      +${take} from ${src} overflow`);
      }
    }
  }

  const totalSelected = selected.length;
  console.log(`\n  Total: ${totalSelected}/200 packages`);

  if (totalSelected < 200) {
    console.warn(`\n  [WARN] Only ${totalSelected} packages found. Re-run with different --seed or add more search keywords.`);
  }

  // Write output file
  // Use a Set to track already-written packages (avoid duplication from backfill)
  const writtenNames = new Set();
  const header = [
    '# MUAD\'DIB Benign Random Dataset — npm stratified random sample',
    `# Generated: ${new Date().toISOString()}`,
    `# Seed: ${seed}`,
    `# Total: ${totalSelected} packages`,
    '# Strata: small (<10 deps): 80, medium (10-50): 60, large (51-100): 40, vlarge (100+): 20',
    '# Backfill: unfilled large/vlarge slots redistributed to small/medium',
    '# Used by `muaddib evaluate` to measure FPR on representative npm sample',
    ''
  ];

  const lines = [];
  for (const [name, { quota }] of Object.entries(STRATA)) {
    const actual = Math.min(buckets[name].length, quota);
    lines.push(`# === ${name} (${actual}/${quota}) ===`);
    for (const pkg of buckets[name].slice(0, actual)) {
      lines.push(pkg.name);
      writtenNames.add(pkg.name);
    }
    lines.push('');
  }

  // Backfill section (additional packages from overflow)
  const backfillPkgs = selected.filter(p => !writtenNames.has(p.name));
  if (backfillPkgs.length > 0) {
    lines.push(`# === backfill (${backfillPkgs.length}) ===`);
    for (const pkg of backfillPkgs) {
      lines.push(pkg.name);
    }
    lines.push('');
  }

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, header.join('\n') + lines.join('\n'));
  console.log(`  Written to: ${path.relative(ROOT, outputPath)}`);

  // Verify no overlap with curated
  const overlap = selected.filter(p => curated.has(p.name));
  if (overlap.length > 0) {
    console.error(`\n  [ERROR] ${overlap.length} packages overlap with curated corpus: ${overlap.map(p => p.name).join(', ')}`);
  } else {
    console.log('  No overlap with curated corpus');
  }
}

main().catch(err => {
  console.error(`[ERROR] ${err.message}`);
  process.exit(1);
});
