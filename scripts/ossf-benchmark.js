#!/usr/bin/env node
'use strict';

/**
 * MUAD'DIB OpenSSF Benchmark
 *
 * Fetches the OpenSSF malicious-packages dataset (via OSV.dev API),
 * downloads available npm packages, scans them with MUAD'DIB, and
 * produces a benchmark results file consumed by `muaddib evaluate`.
 *
 * Usage:
 *   node scripts/ossf-benchmark.js [--sample N] [--seed N] [--refresh]
 *   node scripts/ossf-benchmark.js --prefetch [--concurrency N]
 *
 * Options:
 *   --sample N       Number of packages to sample (default: 5000)
 *   --seed N         Random seed for reproducibility (default: 42)
 *   --refresh        Force re-download of cached tarballs
 *   --prefetch       Download-only mode: cache tarballs for ALL entries, no scan.
 *                    Run daily to capture packages before npm unpublishes them.
 *   --concurrency N  Concurrent downloads in prefetch mode (default: 5)
 *
 * Output:
 *   datasets/real-world/ossf-benchmark-results.json
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const RESULTS_FILE = path.join(ROOT, 'datasets', 'real-world', 'ossf-benchmark-results.json');
const CACHE_DIR = path.join(ROOT, '.muaddib-cache', 'ossf-tarballs');
const PACK_TIMEOUT_MS = 30000;
const SCAN_TIMEOUT_MS = 30000;
const SAFE_PKG_RE = /^(@[\w._-]+\/)?[\w._-]+$/;

// --- CLI args ---
const SAMPLE_SIZE = parseInt(process.argv.find((a, i) => process.argv[i - 1] === '--sample') || '5000', 10);
const SEED = parseInt(process.argv.find((a, i) => process.argv[i - 1] === '--seed') || '42', 10);
const REFRESH = process.argv.includes('--refresh');
const PREFETCH_MODE = process.argv.includes('--prefetch');
const PREFETCH_CONCURRENCY = parseInt(process.argv.find((a, i) => process.argv[i - 1] === '--concurrency') || '5', 10);

// --- Seeded PRNG (Mulberry32) ---
function mulberry32(seed) {
  let s = seed | 0;
  return function() {
    s = (s + 0x6D2B79F5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// --- Native tgz extraction (same as evaluate.js) ---
function extractTgz(tgzPath, destDir) {
  const compressed = fs.readFileSync(tgzPath);
  const tarData = zlib.gunzipSync(compressed);

  let offset = 0;
  while (offset + 512 <= tarData.length) {
    const header = tarData.subarray(offset, offset + 512);
    if (header.every(b => b === 0)) break;

    const name = header.subarray(0, 100).toString('utf8').replace(/\0+$/, '');
    const sizeOctal = header.subarray(124, 136).toString('utf8').replace(/\0+$/, '').trim();
    const size = parseInt(sizeOctal, 8) || 0;
    const typeFlag = String.fromCharCode(header[156]);

    offset += 512;

    if (name && (typeFlag === '0' || typeFlag === '\0') && size > 0) {
      const resolved = path.resolve(destDir, name);
      const rel = path.relative(path.resolve(destDir), resolved);
      if (rel.startsWith('..') || path.isAbsolute(rel)) {
        offset += Math.ceil(size / 512) * 512;
        continue;
      }
      fs.mkdirSync(path.dirname(resolved), { recursive: true });
      fs.writeFileSync(resolved, tarData.subarray(offset, offset + size));
    }

    offset += Math.ceil(size / 512) * 512;
  }
}

function pkgToCacheName(name, version) {
  return (name + '@' + version).replace(/\//g, '_').replace(/@/g, '_');
}

// --- Step 1: Fetch OSV npm MAL-* index via zip dump ---
async function fetchOSSFIndex() {
  console.log('\n[1/5] Fetching OSV npm malware index...');

  // Use the OSV zip dump (same as scrapeOSVDataDump) for the full index
  // This is more complete than the query API which has pagination limits
  const https = require('https');
  const AdmZip = require('adm-zip');

  const zipUrl = 'https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip';

  console.log('  Downloading npm OSV zip...');
  const zipBuffer = await new Promise(function(resolve, reject) {
    const chunks = [];
    let totalBytes = 0;

    https.get(zipUrl, { headers: { 'User-Agent': 'MUADDIB-Scanner/3.0' } }, function(res) {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location) {
        https.get(res.headers.location, { headers: { 'User-Agent': 'MUADDIB-Scanner/3.0' } }, function(res2) {
          res2.on('data', function(chunk) {
            chunks.push(chunk);
            totalBytes += chunk.length;
            if (totalBytes % (10 * 1024 * 1024) < chunk.length) {
              process.stdout.write('\r  Downloaded: ' + (totalBytes / 1024 / 1024).toFixed(1) + ' MB');
            }
          });
          res2.on('end', function() {
            process.stdout.write('\r  Downloaded: ' + (totalBytes / 1024 / 1024).toFixed(1) + ' MB\n');
            resolve(Buffer.concat(chunks));
          });
          res2.on('error', reject);
        }).on('error', reject);
        return;
      }

      res.on('data', function(chunk) {
        chunks.push(chunk);
        totalBytes += chunk.length;
        if (totalBytes % (10 * 1024 * 1024) < chunk.length) {
          process.stdout.write('\r  Downloaded: ' + (totalBytes / 1024 / 1024).toFixed(1) + ' MB');
        }
      });
      res.on('end', function() {
        process.stdout.write('\r  Downloaded: ' + (totalBytes / 1024 / 1024).toFixed(1) + ' MB\n');
        resolve(Buffer.concat(chunks));
      });
      res.on('error', reject);
    }).on('error', reject);
  });

  console.log('  Parsing MAL-* entries...');
  const zip = new AdmZip(zipBuffer);
  const entries = zip.getEntries();

  // Deduplicate by name@version, keep first MAL-* ID encountered
  const dedupMap = new Map(); // key: "name@version" -> entry
  let malCount = 0;

  for (const entry of entries) {
    const entryName = entry.entryName;
    if (!entryName.startsWith('MAL-') || !entryName.endsWith('.json')) continue;

    // Size guard
    const entrySize = entry.header ? entry.header.size : 0;
    if (entrySize > 10 * 1024 * 1024) continue; // skip >10MB entries

    try {
      const vuln = JSON.parse(entry.getData().toString('utf8'));
      if (!vuln.affected) continue;

      for (const affected of vuln.affected) {
        if (!affected.package || affected.package.ecosystem !== 'npm') continue;

        const pkgName = affected.package.name;
        const versions = [];

        // Extract versions from ranges or explicit list
        if (affected.versions && affected.versions.length > 0) {
          for (const v of affected.versions) versions.push(v);
        } else if (affected.ranges) {
          for (const range of affected.ranges) {
            if (range.events) {
              for (const evt of range.events) {
                if (evt.introduced && evt.introduced !== '0') versions.push(evt.introduced);
              }
            }
          }
        }

        // If no specific version, use wildcard marker
        if (versions.length === 0) versions.push('*');

        // Determine source from database_specific
        let source = 'unknown';
        if (vuln.database_specific && vuln.database_specific['malicious-packages-origins']) {
          const origins = vuln.database_specific['malicious-packages-origins'];
          if (origins.length > 0 && origins[0].source) {
            source = origins[0].source;
          }
        }

        for (const ver of versions) {
          const key = pkgName + '@' + ver;
          if (!dedupMap.has(key)) {
            dedupMap.set(key, {
              name: pkgName,
              version: ver,
              osv_id: vuln.id,
              source: source,
              summary: (vuln.summary || '').slice(0, 200),
              published: vuln.published || null
            });
          }
        }
      }

      malCount++;
    } catch { /* skip unparseable */ }
  }

  const index = Array.from(dedupMap.values());
  console.log('  Parsed ' + malCount + ' MAL-* reports -> ' + index.length + ' unique name@version entries');

  return index;
}

// --- Step 2: Stratified sampling ---
function stratifySample(index, sampleSize, seed) {
  console.log('\n[2/5] Stratified sampling (' + sampleSize + ' packages, seed=' + seed + ')...');

  const rng = mulberry32(seed);

  // Filter out wildcard versions (can't download *)
  const downloadable = index.filter(e => e.version !== '*' && SAFE_PKG_RE.test(e.name));
  console.log('  Downloadable (non-wildcard, valid name): ' + downloadable.length);

  // Filter out spam packages (SEO junk uploaded to npm — never available, waste time)
  const SPAM_WORDS = /\b(watch|movie|free|generator|download|stream|online|full|episode|subtitle)\b/i;
  const filtered = downloadable.filter(function(e) {
    if (e.name.length > 100) return false;
    if (/\s/.test(e.name)) return false;
    if (SPAM_WORDS.test(e.name)) return false;
    return true;
  });
  const spamRemoved = downloadable.length - filtered.length;
  if (spamRemoved > 0) console.log('  Spam filtered: ' + spamRemoved + ' entries removed');
  console.log('  After spam filter: ' + filtered.length);

  // Group by source
  const bySource = {};
  for (const entry of filtered) {
    const src = entry.source || 'unknown';
    if (!bySource[src]) bySource[src] = [];
    bySource[src].push(entry);
  }

  console.log('  Sources: ' + Object.entries(bySource).map(([k, v]) => k + '=' + v.length).join(', '));

  // Shuffle each source group with seeded RNG
  for (const src of Object.keys(bySource)) {
    const arr = bySource[src];
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      const tmp = arr[i];
      arr[i] = arr[j];
      arr[j] = tmp;
    }
  }

  // Proportional allocation per source
  const sources = Object.keys(bySource);
  const totalDownloadable = filtered.length;
  const sample = [];

  for (const src of sources) {
    const proportion = bySource[src].length / totalDownloadable;
    const count = Math.max(1, Math.round(proportion * sampleSize));
    const take = bySource[src].slice(0, count);
    sample.push(...take);
  }

  // Trim to exact sample size
  while (sample.length > sampleSize) sample.pop();

  console.log('  Sampled: ' + sample.length + ' packages');
  return sample;
}

// --- Step 3: Check npm availability ---
async function checkAvailability(sample) {
  console.log('\n[3/5] Checking npm availability...');

  let available = 0;
  let unavailable = 0;
  let errors = 0;

  const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm';

  for (let i = 0; i < sample.length; i++) {
    const entry = sample[i];

    if (process.stdout.isTTY) {
      process.stdout.write('\r  Checking [' + (i + 1) + '/' + sample.length + '] ' + entry.name + '@' + entry.version + '          ');
    }

    try {
      execSync(npmCmd + ' view ' + entry.name + '@' + entry.version + ' version --json', {
        encoding: 'utf8',
        timeout: 10000,
        stdio: ['pipe', 'pipe', 'pipe']
      });
      entry.status = 'available';
      available++;
    } catch (err) {
      const stderr = (err.stderr || '').toLowerCase();
      if (stderr.includes('404') || stderr.includes('not found') || stderr.includes('not in this registry')) {
        entry.status = 'unavailable';
        unavailable++;
      } else {
        entry.status = 'error';
        entry.error = (err.message || '').slice(0, 100);
        errors++;
      }
    }
  }

  if (process.stdout.isTTY) {
    process.stdout.write('\r' + ''.padEnd(80) + '\r');
  }

  console.log('  Available: ' + available + ', Unavailable: ' + unavailable + ', Errors: ' + errors);
  return sample;
}

// --- Step 4: Download and scan ---
async function downloadAndScan(sample) {
  console.log('\n[4/5] Downloading and scanning available packages...');

  const { run } = require('../src/index.js');
  const { clearFileListCache } = require('../src/utils.js');

  fs.mkdirSync(CACHE_DIR, { recursive: true });

  const scannable = sample.filter(e => e.status === 'available');
  console.log('  Scannable: ' + scannable.length + ' packages');

  let scanned = 0;
  let detected = 0;
  let scanErrors = 0;
  let scanCount = 0;

  for (let i = 0; i < scannable.length; i++) {
    const entry = scannable[i];
    const progress = '[' + (i + 1) + '/' + scannable.length + ']';

    if (process.stdout.isTTY) {
      process.stdout.write('\r  Scanning ' + progress + ' ' + entry.name + '@' + entry.version + '          ');
    }

    // Download
    const cacheName = pkgToCacheName(entry.name, entry.version);
    const pkgCacheDir = path.join(CACHE_DIR, cacheName);
    let extractedDir = null;

    if (!REFRESH && fs.existsSync(path.join(pkgCacheDir, 'package'))) {
      extractedDir = path.join(pkgCacheDir, 'package');
    } else {
      fs.mkdirSync(pkgCacheDir, { recursive: true });
      try {
        const output = execSync('npm pack ' + entry.name + '@' + entry.version, {
          cwd: pkgCacheDir,
          encoding: 'utf8',
          timeout: PACK_TIMEOUT_MS,
          stdio: ['pipe', 'pipe', 'pipe']
        });
        const tgzFilename = output.trim().split(/\r?\n/).pop().trim();
        const tgzPath = path.join(pkgCacheDir, tgzFilename);

        if (fs.existsSync(tgzPath)) {
          extractTgz(tgzPath, pkgCacheDir);
          try { fs.unlinkSync(tgzPath); } catch { /* ignore */ }
          if (fs.existsSync(path.join(pkgCacheDir, 'package'))) {
            extractedDir = path.join(pkgCacheDir, 'package');
          }
        }
      } catch {
        // Download failed — mark as unavailable (possibly removed between check and download)
        entry.status = 'unavailable';
        entry.error = 'npm pack failed';
        fs.rmSync(pkgCacheDir, { recursive: true, force: true });
      }
    }

    if (!extractedDir) {
      if (entry.status === 'available') {
        entry.status = 'error';
        entry.error = 'extraction failed';
        scanErrors++;
      }
      continue;
    }

    // Scan
    try {
      const result = await Promise.race([
        run(extractedDir, { _capture: true }),
        new Promise(function(_, reject) {
          setTimeout(function() { reject(new Error('scan timeout')); }, SCAN_TIMEOUT_MS);
        })
      ]);

      const score = result.summary.riskScore || 0;
      entry.score = score;
      entry.detected = score >= 20;
      entry.threat_count = result.summary.total || 0;
      entry.threats = (result.threats || []).slice(0, 20).map(function(t) {
        return { type: t.type, severity: t.severity, file: t.file };
      });
      entry.status = 'scanned';

      scanned++;
      if (entry.detected) detected++;
    } catch (err) {
      entry.status = 'error';
      entry.error = (err.message || '').slice(0, 100);
      entry.score = 0;
      entry.detected = false;
      scanErrors++;
    }

    // Memory management
    clearFileListCache();
    scanCount++;
    if (scanCount % 20 === 0 && global.gc) {
      global.gc();
      const used = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
      console.log('\n  [Memory] ' + used + ' MB after ' + scanCount + ' scans');
    }
  }

  if (process.stdout.isTTY) {
    process.stdout.write('\r' + ''.padEnd(80) + '\r');
  }

  console.log('  Scanned: ' + scanned + ', Detected: ' + detected + ', Errors: ' + scanErrors);
  return { scanned, detected, scanErrors };
}

// --- Step 5: Save results ---
function saveResults(sample, index, stats) {
  console.log('\n[5/5] Saving results...');

  // Compute per-source breakdown
  const bySource = {};
  for (const entry of sample) {
    const src = entry.source || 'unknown';
    if (!bySource[src]) bySource[src] = { total: 0, scanned: 0, detected: 0, unavailable: 0 };
    bySource[src].total++;
    if (entry.status === 'scanned') {
      bySource[src].scanned++;
      if (entry.detected) bySource[src].detected++;
    } else if (entry.status === 'unavailable') {
      bySource[src].unavailable++;
    }
  }

  // Compute TPR per source
  for (const src of Object.keys(bySource)) {
    const d = bySource[src];
    d.tpr = d.scanned > 0 ? d.detected / d.scanned : 0;
  }

  // Score distribution
  const scannedEntries = sample.filter(e => e.status === 'scanned');
  const scoreDistribution = { '0': 0, '1-9': 0, '10-19': 0, '20-49': 0, '50-74': 0, '75-100': 0 };
  for (const e of scannedEntries) {
    const s = e.score || 0;
    if (s === 0) scoreDistribution['0']++;
    else if (s <= 9) scoreDistribution['1-9']++;
    else if (s <= 19) scoreDistribution['10-19']++;
    else if (s <= 49) scoreDistribution['20-49']++;
    else if (s <= 74) scoreDistribution['50-74']++;
    else scoreDistribution['75-100']++;
  }

  const results = {
    metadata: {
      benchmark: 'OpenSSF Malicious Packages',
      version: 'v1',
      repo: 'https://github.com/ossf/malicious-packages',
      scanned_at: new Date().toISOString(),
      seed: SEED,
      total_osv_npm_unique: index.length,
      sampled: sample.length,
      available_on_npm: sample.filter(e => e.status === 'scanned' || e.status === 'available').length,
      scanned: stats.scanned,
      detected: stats.detected,
      missed: stats.scanned - stats.detected,
      errors: stats.scanErrors,
      unavailable: sample.filter(e => e.status === 'unavailable').length,
      threshold: 20,
      tpr: stats.scanned > 0 ? ((stats.detected / stats.scanned * 100).toFixed(1) + '%') : 'N/A',
      coverage: ((stats.scanned / sample.length * 100).toFixed(1) + '%'),
      by_source: bySource,
      score_distribution: scoreDistribution
    },
    results: sample.map(function(e) {
      return {
        name: e.name,
        version: e.version,
        osv_id: e.osv_id,
        source: e.source,
        status: e.status,
        score: e.score || 0,
        detected: e.detected || false,
        threat_count: e.threat_count || 0,
        threats: e.threats || [],
        error: e.error || undefined
      };
    })
  };

  fs.mkdirSync(path.dirname(RESULTS_FILE), { recursive: true });
  fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2));
  console.log('  Saved to: ' + RESULTS_FILE);

  return results;
}

// --- Prefetch mode: download tarballs for ALL entries, no scan ---
// Captures packages before npm unpublishes them (~hours after OSSF report).
// Skips already-cached packages. No sampling, no availability check, no scan.
// Run daily: node scripts/ossf-benchmark.js --prefetch
async function prefetchTarballs(index) {
  console.log('\n[PREFETCH] Downloading tarballs for ' + index.length + ' entries (concurrency: ' + PREFETCH_CONCURRENCY + ')...');

  fs.mkdirSync(CACHE_DIR, { recursive: true });

  // Filter to entries with valid name+version that aren't already cached
  const eligible = index.filter(function(entry) {
    if (!entry.name || !entry.version || entry.version === '*') return false;
    if (!SAFE_PKG_RE.test(entry.name)) return false;
    const cacheName = pkgToCacheName(entry.name, entry.version);
    const pkgDir = path.join(CACHE_DIR, cacheName, 'package');
    if (!REFRESH && fs.existsSync(pkgDir)) return false; // already cached
    return true;
  });

  const alreadyCached = index.length - eligible.length;
  console.log('  Already cached: ' + alreadyCached + ', To fetch: ' + eligible.length);

  let fetched = 0;
  let failed = 0;
  let i = 0;

  // Process in batches of PREFETCH_CONCURRENCY
  while (i < eligible.length) {
    const batch = eligible.slice(i, i + PREFETCH_CONCURRENCY);
    const promises = batch.map(function(entry) {
      return new Promise(function(resolve) {
        const cacheName = pkgToCacheName(entry.name, entry.version);
        const pkgCacheDir = path.join(CACHE_DIR, cacheName);
        fs.mkdirSync(pkgCacheDir, { recursive: true });
        try {
          const output = execSync('npm pack ' + entry.name + '@' + entry.version, {
            cwd: pkgCacheDir,
            encoding: 'utf8',
            timeout: PACK_TIMEOUT_MS,
            stdio: ['pipe', 'pipe', 'pipe']
          });
          const tgzFilename = output.trim().split(/\r?\n/).pop().trim();
          const tgzPath = path.join(pkgCacheDir, tgzFilename);
          if (fs.existsSync(tgzPath)) {
            extractTgz(tgzPath, pkgCacheDir);
            try { fs.unlinkSync(tgzPath); } catch { /* ignore */ }
            if (fs.existsSync(path.join(pkgCacheDir, 'package'))) {
              fetched++;
              resolve('ok');
              return;
            }
          }
          fs.rmSync(pkgCacheDir, { recursive: true, force: true });
          failed++;
          resolve('fail');
        } catch {
          fs.rmSync(pkgCacheDir, { recursive: true, force: true });
          failed++;
          resolve('fail');
        }
      });
    });

    await Promise.all(promises);
    i += batch.length;

    if (process.stdout.isTTY) {
      process.stdout.write('\r  Progress: ' + i + '/' + eligible.length +
        '  fetched=' + fetched + '  failed=' + failed + '          ');
    }
  }

  if (process.stdout.isTTY) process.stdout.write('\n');
  console.log('  Done. Fetched: ' + fetched + ', Failed (unavailable): ' + failed +
    ', Already cached: ' + alreadyCached + ', Total cached: ' + (alreadyCached + fetched));
  return { fetched, failed, alreadyCached };
}

// --- Main ---
async function main() {
  const startTime = Date.now();

  console.log('='.repeat(60));
  console.log('  MUAD\'DIB OpenSSF Benchmark' + (PREFETCH_MODE ? ' (PREFETCH)' : ''));
  if (!PREFETCH_MODE) console.log('  Sample: ' + SAMPLE_SIZE + ', Seed: ' + SEED);
  console.log('='.repeat(60));

  // 1. Fetch full OSV npm index
  const index = await fetchOSSFIndex();

  // --- Prefetch mode: just download tarballs, no scan ---
  if (PREFETCH_MODE) {
    const stats = await prefetchTarballs(index);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log('\n' + '='.repeat(60));
    console.log('  PREFETCH COMPLETE');
    console.log('='.repeat(60));
    console.log('  OSV index size:    ' + index.length);
    console.log('  Already cached:    ' + stats.alreadyCached);
    console.log('  Newly fetched:     ' + stats.fetched);
    console.log('  Unavailable:       ' + stats.failed);
    console.log('  Total cached:      ' + (stats.alreadyCached + stats.fetched));
    console.log('  Elapsed:           ' + elapsed + 's');
    console.log('='.repeat(60) + '\n');
    return;
  }

  // --- Normal mode: sample, check, scan, report ---

  // 2. Stratified sample
  const sample = stratifySample(index, SAMPLE_SIZE, SEED);

  // 3. Check npm availability
  await checkAvailability(sample);

  // 4. Download + scan
  const stats = await downloadAndScan(sample);

  // 5. Save results
  const results = saveResults(sample, index, stats);

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  console.log('\n' + '='.repeat(60));
  console.log('  RESULTS');
  console.log('='.repeat(60));
  console.log('  Total OSV npm unique:  ' + index.length);
  console.log('  Sampled:               ' + sample.length);
  console.log('  Available on npm:      ' + results.metadata.available_on_npm);
  console.log('  Scanned:               ' + stats.scanned);
  console.log('  Detected (score>=20):  ' + stats.detected);
  console.log('  TPR:                   ' + results.metadata.tpr);
  console.log('  Coverage:              ' + results.metadata.coverage);
  console.log('  Elapsed:               ' + elapsed + 's');
  console.log('='.repeat(60) + '\n');
}

main().catch(function(err) {
  console.error('[FATAL] ' + err.message);
  console.error(err.stack);
  process.exit(1);
});
