#!/usr/bin/env node
'use strict';

/**
 * Backtest — compromised_email_domain V1 vs V2 replay.
 *
 * Replays every package that historically fired `compromised_email_domain`
 * (from data/detections.jsonl) through BOTH semantics:
 *   V1 (live):     RDAP creation > first_publish - 30d   (the 850+ FP source)
 *   V2 (candidate): RDAP creation > first_publish strictly, public email
 *                   providers excluded (node-ipc May-2026 validated shape)
 * and prints the divergence table that adjudicates the flip — no live wait.
 *
 * Honest caveats (annotated in the summary):
 *  - RDAP is queried TODAY: a domain re-registered since the alert can differ
 *    from alert-time state. This biases toward MORE flags (conservative).
 *  - Packages unpublished since their alert are skipped and counted.
 *
 * Crash-resilient + idempotent:
 *  - every resolved package is appended to the checkpoint JSONL as it
 *    completes; a re-run loads the checkpoint and skips resolved packages;
 *  - RDAP results are persisted PER DOMAIN in the same checkpoint (453
 *    packages collapse to a few hundred domains; the in-process 30d cache
 *    does not survive a crash, the checkpoint does).
 *
 * Usage:
 *   node scripts/backtest-email-domain.js [--detections path] [--checkpoint path]
 *       [--limit N]           # stop after N unresolved packages (smoke run)
 *       [--delay-ms N]        # inter-package delay (default 300)
 */

const fs = require('fs');
const path = require('path');

const { getPackageMetadata } = require('../src/scanner/npm-registry.js');
const {
  fetchRdap,
  isCompromisedDomain,
  isCompromisedDomainV2,
  uniqueDomains
} = require('../src/scanner/email-domain.js');

const ROOT = path.join(__dirname, '..');
const DEFAULT_DETECTIONS = path.join(ROOT, 'data', 'detections.jsonl');
const DEFAULT_CHECKPOINT = path.join(ROOT, 'data', 'backtest-email-domain.jsonl');
const DETECTOR = 'compromised_email_domain';

function parseArgs(argv) {
  const opts = { detections: DEFAULT_DETECTIONS, checkpoint: DEFAULT_CHECKPOINT, limit: Infinity, delayMs: 300 };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--detections' && argv[i + 1]) opts.detections = argv[++i];
    else if (argv[i] === '--checkpoint' && argv[i + 1]) opts.checkpoint = argv[++i];
    else if (argv[i] === '--limit' && argv[i + 1]) opts.limit = parseInt(argv[++i], 10) || Infinity;
    else if (argv[i] === '--delay-ms' && argv[i + 1]) opts.delayMs = parseInt(argv[++i], 10) || 300;
  }
  return opts;
}

function readJsonl(file) {
  const out = [];
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); } catch { return out; }
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line)); } catch { /* tolerant: skip corrupt line */ }
  }
  return out;
}

function appendCheckpoint(file, obj) {
  fs.appendFileSync(file, JSON.stringify(obj) + '\n', 'utf8');
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function main() {
  const opts = parseArgs(process.argv);

  // 1. Historical alert population: distinct packages that fired the detector.
  const targets = new Map(); // name -> { versions:Set }
  for (const e of readJsonl(opts.detections)) {
    if (!e || !Array.isArray(e.findings) || !e.findings.includes(DETECTOR)) continue;
    if ((e.ecosystem || 'npm') !== 'npm') continue; // npm-only population today
    let t = targets.get(e.package);
    if (!t) { t = { versions: new Set() }; targets.set(e.package, t); }
    if (e.version) t.versions.add(e.version);
  }
  if (targets.size === 0) {
    console.error(`No ${DETECTOR} alerts found in ${opts.detections}`);
    process.exit(1);
  }

  // 2. Checkpoint: skip already-resolved packages, preload per-domain RDAP.
  const resolved = new Map();   // name -> checkpoint record
  const rdapByDomain = new Map(); // domain -> creationDate|null
  for (const e of readJsonl(opts.checkpoint)) {
    if (e.type === 'pkg' && e.name) resolved.set(e.name, e);
    else if (e.type === 'rdap' && e.domain) rdapByDomain.set(e.domain, e.creationDate ?? null);
  }
  console.log(`[BACKTEST] ${targets.size} distinct packages with ${DETECTOR} alerts; ` +
    `${resolved.size} already resolved in checkpoint; ${rdapByDomain.size} cached RDAP domains`);

  // 3. Replay.
  let processed = 0;
  for (const [name] of targets) {
    if (resolved.has(name)) continue;
    if (processed >= opts.limit) { console.log(`[BACKTEST] --limit ${opts.limit} reached, stopping (re-run to continue)`); break; }
    processed++;

    let record = { type: 'pkg', name, ts: new Date().toISOString() };
    try {
      const meta = await getPackageMetadata(name);
      if (!meta || !Array.isArray(meta.maintainer_emails) || meta.maintainer_emails.length === 0 || !meta.created_at) {
        record.skipped = !meta ? 'metadata_unavailable' : (!meta.created_at ? 'no_created_at' : 'no_maintainer_emails');
        appendCheckpoint(opts.checkpoint, record);
        console.log(`[BACKTEST] ${processed}/${Math.min(opts.limit, targets.size - resolved.size)} ${name}: SKIP (${record.skipped})`);
        continue;
      }

      const domains = uniqueDomains(meta.maintainer_emails);
      const domainResults = [];
      let v1 = false, v2 = false;
      for (const domain of domains) {
        let creationDate;
        if (rdapByDomain.has(domain)) {
          creationDate = rdapByDomain.get(domain);
        } else {
          const r = await fetchRdap(domain);
          creationDate = r && r.creationDate ? r.creationDate : null;
          rdapByDomain.set(domain, creationDate);
          appendCheckpoint(opts.checkpoint, { type: 'rdap', domain, creationDate });
          await sleep(500); // be gentle with rdap.org
        }
        const dv1 = creationDate ? isCompromisedDomain(creationDate, meta.created_at) : false;
        const dv2 = creationDate ? isCompromisedDomainV2(creationDate, meta.created_at, domain) : false;
        v1 = v1 || dv1;
        v2 = v2 || dv2;
        domainResults.push({ domain, creationDate, v1: dv1, v2: dv2 });
      }

      record = { ...record, created_at: meta.created_at, domains: domainResults, v1, v2 };
      appendCheckpoint(opts.checkpoint, record);
      const tag = v1 === v2 ? (v1 ? 'BOTH' : 'NEITHER') : (v1 ? 'V1-ONLY (FP killed)' : 'V2-ONLY (new flag)');
      console.log(`[BACKTEST] ${name}: ${tag}`);
    } catch (err) {
      record.skipped = 'error: ' + err.message;
      appendCheckpoint(opts.checkpoint, record);
      console.log(`[BACKTEST] ${name}: ERROR ${err.message}`);
    }
    await sleep(opts.delayMs);
  }

  // 4. Summary from the (full) checkpoint — works on partial runs too.
  const all = readJsonl(opts.checkpoint).filter(e => e.type === 'pkg');
  const dedup = new Map(all.map(e => [e.name, e])); // last record wins
  let v1Only = 0, v2Only = 0, both = 0, neither = 0, skipped = 0;
  const v1OnlyList = [], v2OnlyList = [];
  for (const e of dedup.values()) {
    if (e.skipped) { skipped++; continue; }
    if (e.v1 && !e.v2) { v1Only++; v1OnlyList.push(e.name); }
    else if (!e.v1 && e.v2) { v2Only++; v2OnlyList.push(e.name); }
    else if (e.v1 && e.v2) both++;
    else neither++;
  }
  const summary = {
    generatedAt: new Date().toISOString(),
    detector: DETECTOR,
    population: targets.size,
    resolved: dedup.size,
    v1Only, v2Only, both, neither, skipped,
    v1OnlyExamples: v1OnlyList.slice(0, 30),
    v2OnlyPackages: v2OnlyList, // every new flag must be human-reviewed
    caveats: [
      'RDAP queried today, not at alert time — a domain re-registered since biases toward MORE flags (conservative).',
      'Packages unpublished since their alert are skipped and counted in `skipped`.',
      'V1/V2 are package-level ORs over maintainer domains.'
    ]
  };
  const summaryFile = opts.checkpoint.replace(/\.jsonl$/, '') + '-summary.json';
  fs.writeFileSync(summaryFile, JSON.stringify(summary, null, 2));
  console.log('\n========== BACKTEST SUMMARY ==========');
  console.log(`population (distinct pkgs): ${summary.population}`);
  console.log(`resolved:                   ${summary.resolved}`);
  console.log(`V1-only (FP killed by V2):  ${v1Only}`);
  console.log(`V2-only (NEW flags — review!): ${v2Only}${v2OnlyList.length ? ' → ' + v2OnlyList.slice(0, 10).join(', ') : ''}`);
  console.log(`both (still flagged):       ${both}`);
  console.log(`neither (RDAP null today):  ${neither}`);
  console.log(`skipped:                    ${skipped}`);
  console.log(`summary written to:         ${summaryFile}`);
}

main().catch(err => { console.error('[BACKTEST] fatal:', err); process.exit(1); });
