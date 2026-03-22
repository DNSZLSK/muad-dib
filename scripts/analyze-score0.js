#!/usr/bin/env node
'use strict';

/**
 * analyze-score0.js — Diagnostic script for score-0 malware investigation.
 *
 * Analyzes packages from the Datadog benchmark that scored 0 (zero threats detected).
 * Categorizes each package to identify blind spots vs expected non-detections.
 *
 * Categories:
 *   - empty_package: no code files at all
 *   - ts_only: only .ts files (no .js)
 *   - binary_only: only .wasm/.node/.dll/.so
 *   - non_code_assets: CSS/images/fonts/markdown only
 *   - minimum_viable: package.json + README only
 *   - python_in_npm: .py files in an npm package
 *   - unknown: has .js but 0 detections — TRUE BLIND SPOT
 *
 * Usage:
 *   node scripts/analyze-score0.js --benchmark data/datadog-benchmark.jsonl
 *   node scripts/analyze-score0.js --benchmark data/datadog-benchmark.jsonl --csv report.csv
 *   node scripts/analyze-score0.js --dir .muaddib-cache/datadog-tarballs/
 */

const fs = require('fs');
const path = require('path');

const CODE_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.jsx']);
const TS_EXTENSIONS = new Set(['.ts', '.tsx', '.cts', '.mts']);
const BINARY_EXTENSIONS = new Set(['.wasm', '.node', '.dll', '.so', '.dylib', '.exe']);
const ASSET_EXTENSIONS = new Set(['.css', '.scss', '.less', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
  '.woff', '.woff2', '.ttf', '.eot', '.otf', '.md', '.txt', '.html', '.htm', '.map']);
const PY_EXTENSIONS = new Set(['.py', '.pyx', '.pyi']);

function categorizePackage(packageDir) {
  if (!fs.existsSync(packageDir)) return 'missing';

  const files = [];
  function walk(dir, depth) {
    if (depth > 5) return; // Limit depth
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git') continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full, depth + 1);
        } else if (entry.isFile()) {
          files.push(entry.name);
        }
      }
    } catch { /* skip permission errors */ }
  }
  walk(packageDir, 0);

  if (files.length === 0) return 'empty_package';

  const extensions = files.map(f => path.extname(f).toLowerCase());
  const hasCode = extensions.some(e => CODE_EXTENSIONS.has(e));
  const hasTs = extensions.some(e => TS_EXTENSIONS.has(e));
  const hasBinary = extensions.some(e => BINARY_EXTENSIONS.has(e));
  const hasPython = extensions.some(e => PY_EXTENSIONS.has(e));
  const hasAssets = extensions.some(e => ASSET_EXTENSIONS.has(e));

  // Only package.json + README
  const nonMeta = files.filter(f => !['package.json', 'readme.md', 'readme', 'license', 'license.md', 'changelog.md'].includes(f.toLowerCase()));
  if (nonMeta.length === 0) return 'minimum_viable';

  if (hasCode) return 'unknown'; // TRUE BLIND SPOT: has JS but 0 detections

  if (hasTs && !hasCode) return 'ts_only';
  if (hasBinary && !hasCode && !hasTs) return 'binary_only';
  if (hasPython && !hasCode) return 'python_in_npm';
  if (hasAssets && !hasCode && !hasTs && !hasBinary) return 'non_code_assets';

  return 'unknown'; // Fallback
}

function loadBenchmarkResults(filepath) {
  if (!fs.existsSync(filepath)) {
    console.error(`[SCORE0] File not found: ${filepath}`);
    process.exit(1);
  }

  const content = fs.readFileSync(filepath, 'utf8');
  const records = [];
  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    try {
      const record = JSON.parse(line);
      if (record.score === 0 && record.threat_count === 0) {
        records.push(record);
      }
    } catch { /* skip malformed */ }
  }
  return records;
}

function main() {
  const args = process.argv.slice(2);
  const benchmarkIdx = args.indexOf('--benchmark');
  const dirIdx = args.indexOf('--dir');
  const csvIdx = args.indexOf('--csv');

  const benchmarkFile = benchmarkIdx >= 0 ? args[benchmarkIdx + 1] : null;
  const tarballDir = dirIdx >= 0 ? args[dirIdx + 1] : null;
  const csvFile = csvIdx >= 0 ? args[csvIdx + 1] : null;

  if (!benchmarkFile && !tarballDir) {
    console.log('Usage:');
    console.log('  node scripts/analyze-score0.js --benchmark data/datadog-benchmark.jsonl');
    console.log('  node scripts/analyze-score0.js --dir .muaddib-cache/datadog-tarballs/');
    console.log('  node scripts/analyze-score0.js --benchmark data/datadog-benchmark.jsonl --csv report.csv');
    process.exit(0);
  }

  let packages = [];

  if (benchmarkFile) {
    const records = loadBenchmarkResults(benchmarkFile);
    console.log(`[SCORE0] Loaded ${records.length} score-0 packages from benchmark`);
    packages = records.map(r => ({
      name: r.name || r.package || 'unknown',
      version: r.version || '',
      dir: tarballDir ? path.join(tarballDir, r.name || r.package || 'unknown') : null
    }));
  } else if (tarballDir) {
    // Direct directory scan mode
    if (!fs.existsSync(tarballDir)) {
      console.error(`[SCORE0] Directory not found: ${tarballDir}`);
      process.exit(1);
    }
    const entries = fs.readdirSync(tarballDir, { withFileTypes: true });
    packages = entries
      .filter(e => e.isDirectory())
      .map(e => ({ name: e.name, version: '', dir: path.join(tarballDir, e.name) }));
    console.log(`[SCORE0] Found ${packages.length} package directories`);
  }

  // Categorize
  const categories = {};
  const results = [];

  for (const pkg of packages) {
    let category = 'no_dir';
    if (pkg.dir && fs.existsSync(pkg.dir)) {
      category = categorizePackage(pkg.dir);
    }
    categories[category] = (categories[category] || 0) + 1;
    results.push({ name: pkg.name, version: pkg.version, category });
  }

  // Summary
  console.log('\n=== SCORE 0 INVESTIGATION REPORT ===\n');
  console.log(`Total score-0 packages: ${packages.length}\n`);

  const sortedCategories = Object.entries(categories).sort((a, b) => b[1] - a[1]);
  for (const [cat, count] of sortedCategories) {
    const pct = ((count / packages.length) * 100).toFixed(1);
    const label = cat === 'unknown' ? `${cat} *** BLIND SPOT ***` : cat;
    console.log(`  ${label}: ${count} (${pct}%)`);
  }

  const unknownCount = categories.unknown || 0;
  console.log(`\n  Actionable blind spots: ${unknownCount} packages with JS code but 0 detections`);

  // CSV output
  if (csvFile) {
    const csvLines = ['name,version,category'];
    for (const r of results) {
      csvLines.push(`${r.name},${r.version},${r.category}`);
    }
    fs.writeFileSync(csvFile, csvLines.join('\n'), 'utf8');
    console.log(`\n  CSV report written to: ${csvFile}`);
  }

  // List unknown packages (first 20)
  const unknowns = results.filter(r => r.category === 'unknown');
  if (unknowns.length > 0) {
    console.log('\n  First 20 "unknown" (blind spot) packages:');
    for (const u of unknowns.slice(0, 20)) {
      console.log(`    - ${u.name}@${u.version}`);
    }
    if (unknowns.length > 20) {
      console.log(`    ... and ${unknowns.length - 20} more`);
    }
  }
}

main();
