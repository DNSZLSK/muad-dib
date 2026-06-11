#!/usr/bin/env node
'use strict';

/**
 * Backtest — mcp_config_injection 3-tier classification replay.
 *
 * Re-scans every package that historically fired `mcp_config_injection`
 * (data/detections.jsonl) with MUADDIB_SHADOW=1, so the shadow classifier
 * (src/scanner/ast-detectors/mcp-write-classifier.js) labels each emission:
 *   template               → divergence logged (candidate CRITICAL→MEDIUM)
 *   shell_exec / injection → no divergence (stays CRITICAL)
 * Output = the a/b/c distribution + the template-class package list that a
 * human adjudicates before flipping the severity. No live wait.
 *
 * Tarball sources, in order:
 *   1. archive/<date>/<name with / → __>-<version>.tgz (≈7 days retained)
 *   2. https://registry.npmjs.org/... direct tarball fetch (no npm CLI, no
 *      script execution). 404 = unpublished since the alert (often a TP) →
 *      counted skipped.
 *
 * Idempotent: per-package results append to the checkpoint as they complete;
 * re-runs skip resolved packages.
 *
 * Usage: node scripts/backtest-mcp-3tier.js [--limit N] [--checkpoint path]
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, execSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'muaddib.js');
const DETECTIONS = path.join(ROOT, 'data', 'detections.jsonl');
const ARCHIVE_DIR = path.join(ROOT, 'archive');
const DEFAULT_CHECKPOINT = path.join(ROOT, 'data', 'backtest-mcp-3tier.jsonl');
const DETECTOR = 'mcp_config_injection';

function parseArgs(argv) {
  const opts = { checkpoint: DEFAULT_CHECKPOINT, limit: Infinity };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--limit' && argv[i + 1]) opts.limit = parseInt(argv[++i], 10) || Infinity;
    else if (argv[i] === '--checkpoint' && argv[i + 1]) opts.checkpoint = argv[++i];
  }
  return opts;
}

function readJsonl(file) {
  const out = [];
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch { return out; }
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line)); } catch { /* skip corrupt */ }
  }
  return out;
}

/** archive filename convention: @scope/name → @scope__name (slash → __). */
function archiveBase(name, version) {
  return `${name.replace(/\//g, '__')}-${version}.tgz`;
}

function findArchivedTarball(name, versions) {
  let days = [];
  try { days = fs.readdirSync(ARCHIVE_DIR).filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort().reverse(); } catch { return null; }
  for (const day of days) {
    for (const v of versions) {
      const p = path.join(ARCHIVE_DIR, day, archiveBase(name, v));
      if (fs.existsSync(p)) return { tarball: p, version: v, source: 'archive' };
    }
  }
  return null;
}

async function downloadTarball(name, version, destDir) {
  // registry tarball: basename excludes the scope
  const base = name.startsWith('@') ? name.split('/')[1] : name;
  const url = `https://registry.npmjs.org/${name}/-/${base}-${version}.tgz`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);
  try {
    const res = await fetch(url, { signal: controller.signal, redirect: 'follow' });
    if (!res.ok) { try { await res.text(); } catch {} return null; }
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > 100 * 1024 * 1024) return null; // 100MB sanity cap
    const out = path.join(destDir, archiveBase(name, version));
    fs.writeFileSync(out, buf);
    return { tarball: out, version, source: 'registry' };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function scanWithShadow(extractedDir, shadowFile) {
  let out;
  try {
    out = execFileSync('node', [BIN, 'scan', extractedDir, '--json'], {
      encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], timeout: 120_000,
      env: {
        ...process.env,
        MUADDIB_NO_REGISTRY_FETCH: '1',
        MUADDIB_SHADOW: '1',
        MUADDIB_SHADOW_FILE: shadowFile
      }
    });
  } catch (e) {
    out = e.stdout || '';
  }
  try { return JSON.parse(out); } catch { return null; }
}

async function main() {
  const opts = parseArgs(process.argv);

  // Population: distinct packages (+ their alerted versions) that fired the detector.
  const targets = new Map();
  for (const e of readJsonl(DETECTIONS)) {
    if (!e || !Array.isArray(e.findings) || !e.findings.includes(DETECTOR)) continue;
    let t = targets.get(e.package);
    if (!t) { t = new Set(); targets.set(e.package, t); }
    if (e.version && e.version !== 'N/A') t.add(e.version);
  }
  const resolved = new Map(readJsonl(opts.checkpoint).filter(e => e.name).map(e => [e.name, e]));
  console.log(`[MCP-BACKTEST] ${targets.size} distinct packages with ${DETECTOR} alerts; ${resolved.size} resolved in checkpoint`);

  const work = path.join(os.tmpdir(), `mcp-backtest-${process.pid}`);
  fs.mkdirSync(work, { recursive: true });

  let processed = 0;
  for (const [name, versionSet] of targets) {
    if (resolved.has(name)) continue;
    if (processed >= opts.limit) { console.log(`[MCP-BACKTEST] --limit reached (re-run to continue)`); break; }
    processed++;
    const versions = Array.from(versionSet);
    const record = { name, ts: new Date().toISOString() };
    const pkgWork = path.join(work, String(processed));
    fs.mkdirSync(pkgWork, { recursive: true });
    try {
      let got = findArchivedTarball(name, versions);
      if (!got && versions.length > 0) got = await downloadTarball(name, versions[0], pkgWork);
      if (!got) {
        record.skipped = 'tarball_unavailable (unpublished or archive-expired)';
      } else {
        record.version = got.version;
        record.tarballSource = got.source;
        const extractDir = path.join(pkgWork, 'x');
        fs.mkdirSync(extractDir, { recursive: true });
        execSync(`tar -xzf "${got.tarball}" -C "${extractDir}"`, { stdio: 'pipe', timeout: 60_000 });
        const shadowFile = path.join(pkgWork, 'shadow.jsonl');
        const result = scanWithShadow(extractDir, shadowFile);
        if (!result) {
          record.skipped = 'scan_failed';
        } else {
          const mcpThreats = (result.threats || []).filter(t => t.type === DETECTOR);
          record.fires = mcpThreats.length > 0;
          record.reasons = mcpThreats.map(t => t.message.replace(/^MCP config injection: /, '').slice(0, 160));
          let div = [];
          try {
            div = fs.readFileSync(shadowFile, 'utf8').split('\n').filter(l => l.trim())
              .map(l => JSON.parse(l)).filter(e => e.detector === 'mcp_config_injection_3tier');
          } catch { /* no divergence file = no template-class write */ }
          record.templateDivergences = div.length;
          record.cls = !record.fires ? 'no_longer_fires'
            : (div.length > 0 ? 'template' : 'kept_critical');
          if (div.length > 0) record.divergenceEvidence = div.slice(0, 3).map(d => d.evidence);
        }
      }
    } catch (err) {
      record.skipped = 'error: ' + String(err.message).slice(0, 200);
    } finally {
      try { fs.rmSync(pkgWork, { recursive: true, force: true }); } catch { /* best-effort */ }
    }
    fs.appendFileSync(opts.checkpoint, JSON.stringify(record) + '\n', 'utf8');
    console.log(`[MCP-BACKTEST] ${name}@${record.version || '?'}: ${record.cls || record.skipped}`);
  }
  try { fs.rmSync(work, { recursive: true, force: true }); } catch { /* best-effort */ }

  // Summary from the full checkpoint.
  const all = new Map(readJsonl(opts.checkpoint).filter(e => e.name).map(e => [e.name, e]));
  const sum = { template: 0, kept_critical: 0, no_longer_fires: 0, skipped: 0 };
  const templateList = [];
  for (const e of all.values()) {
    if (e.skipped) { sum.skipped++; continue; }
    sum[e.cls] = (sum[e.cls] || 0) + 1;
    if (e.cls === 'template') templateList.push(e.name);
  }
  const summary = {
    generatedAt: new Date().toISOString(),
    detector: DETECTOR,
    population: targets.size,
    resolved: all.size,
    ...sum,
    templatePackages: templateList,
    caveats: [
      'kept_critical = shell_exec or instruction_injection class (reasons field distinguishes them per package).',
      'no_longer_fires = detector changed since the alert OR alert came from a different file than the published tarball.',
      'skipped/unpublished packages are often TPs (malware gets removed) — the FN side is gated by fixtures/GT, not this replay.'
    ]
  };
  const summaryFile = opts.checkpoint.replace(/\.jsonl$/, '') + '-summary.json';
  fs.writeFileSync(summaryFile, JSON.stringify(summary, null, 2));
  console.log('\n========== MCP 3-TIER BACKTEST SUMMARY ==========');
  console.log(`population:          ${summary.population}`);
  console.log(`resolved:            ${summary.resolved}`);
  console.log(`template (→MEDIUM):  ${sum.template}${templateList.length ? ' → ' + templateList.slice(0, 10).join(', ') + (templateList.length > 10 ? '…' : '') : ''}`);
  console.log(`kept CRITICAL (b/c): ${sum.kept_critical}`);
  console.log(`no longer fires:     ${sum.no_longer_fires}`);
  console.log(`skipped:             ${sum.skipped}`);
  console.log(`summary:             ${summaryFile}`);
}

main().catch(err => { console.error('[MCP-BACKTEST] fatal:', err); process.exit(1); });
