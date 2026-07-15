#!/usr/bin/env node
'use strict';

// ---------------------------------------------------------------------------
// Rule robustness audit — READ-ONLY map (chantier 2026-07-15). No src/ change.
//
// Merges THREE substrates into one per-rule table so we can triage 272 rules by
// data instead of by hand:
//   1. Registry spine  — src/rules (key = threat `type`; getRule → id/sev/conf/domain)
//   2. Ledger (suspicion, FULL population, NO ground truth) — data/scan-ledger.jsonl
//      types[] = "rule fired" (post-dedup, cap 12); score/outcome = monitor self-class.
//   3. Corpus (GROUND TRUTH, reviewed sample) — data/corpus/confirmed-corpus.jsonl
//      rules_triggered × human verdict (FP/MALWARE). This is the only TP/FP truth.
//
// Adapts fpr-live.js `_ledgerDetail` (minus its suspect/confirmed filter) + the
// coherence-mine.js fp_sole/mw_sole loop (generalised from HC types to ALL types).
//
// CAVEATS (surfaced in output): corpus = TYPE-PRESENCE vs verdict = addressability,
// NOT gate precision; MALWARE n≈42 is small; ledger types[] capped at 12; mode-gated
// (paranoid/sandbox_/temporal) absence ≠ dead. This maps; it does not adjudicate.
// ---------------------------------------------------------------------------

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const { RULES, PARANOID_RULES } = require('../src/rules');
const classify = require('../src/monitor/classify.js');
const IOC_MATCH_TYPES = new Set(classify.IOC_MATCH_TYPES || []);

const LEDGER = process.env.MUADDIB_SCAN_LEDGER_FILE || path.resolve(__dirname, '..', 'data', 'scan-ledger.jsonl');
const CORPUS = path.resolve(__dirname, '..', 'data', 'corpus', 'confirmed-corpus.jsonl');
const OUT = path.resolve(__dirname, '..', 'data', 'corpus', 'rule-audit.json');

// F1–F16 cap values (scoring.js:1740-1854) — a type present with score pinned here
// was suppressed by a contextual cap, not scored on merit.
const CAP_VALUES = new Set([20, 25, 30, 35]);
// Outcomes that were actually scanned & scored (carry types[]/score). Others
// (dropped/spilled/interrupted/error/size_skip/static_timeout) never scored.
const SCANNED_OUTCOMES = new Set(['clean', 'clean_low_signal', 'clean_tooling', 'ml_clean', 'llm_benign', 'suspect', 'confirmed']);
// Temporal-only types (--temporal* flags); paranoid + sandbox_ handled below.
const TEMPORAL_TYPES = new Set(['dangerous_api_added', 'lifecycle_added', 'lifecycle_modified', 'lifecycle_removed']);

// --- Spine ---
const spine = {};
for (const [type, r] of Object.entries(RULES)) {
  spine[type] = {
    type, rule_id: r.id, severity: r.severity, confidence: r.confidence, domain: r.domain || '',
    isCompound: /COMPOUND/i.test(r.id || ''), isParanoid: false
  };
}
for (const [type, r] of Object.entries(PARANOID_RULES || {})) {
  if (!spine[type]) spine[type] = { type, rule_id: r.id, severity: r.severity, confidence: r.confidence || '', domain: 'paranoid', isCompound: false, isParanoid: true };
}
const strongTypes = new Set(Object.keys(spine).filter(t => spine[t].severity === 'HIGH' || spine[t].severity === 'CRITICAL'));
// Not part of the normal static tarball-scan path: paranoid (flag), sandbox_ (sandbox
// gate), temporal (--temporal), and monitor publish/maintainer telemetry (author-domain,
// not code scan). Their absence from a scan-ledger types[] is expected, NOT "dead".
const MODE_GATED_ID_RE = /MUADDIB-(TEMPORAL|MAINTAINER|PUBLISH|PARANOID)/;
const isModeGated = t => (spine[t] && (spine[t].isParanoid || MODE_GATED_ID_RE.test(spine[t].rule_id))) || t.startsWith('sandbox_') || TEMPORAL_TYPES.has(t);

const median = arr => (arr.length ? arr.slice().sort((a, b) => a - b)[Math.floor(arr.length / 2)] : null);

(async () => {
  // --- Ledger pass (suspicion, full population; NO suspect-only filter) ---
  const L = {};
  const ensureL = t => (L[t] || (L[t] = { fires: 0, solo: 0, combo: 0, suspect: 0, clean: 0, capped: 0, scoresSolo: [], scoresCombo: [] }));
  let ledgerScored = 0;
  const unregLedger = {};
  if (fs.existsSync(LEDGER)) {
    const rl = readline.createInterface({ input: fs.createReadStream(LEDGER, { encoding: 'utf8' }), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line) continue;
      let e; try { e = JSON.parse(line); } catch { continue; }
      if (!e || !Array.isArray(e.types) || !e.types.length) continue;
      if (!SCANNED_OUTCOMES.has(e.outcome)) continue;
      ledgerScored++;
      const solo = e.types.length === 1;
      const isSuspect = e.outcome === 'suspect' || e.outcome === 'confirmed';
      const score = typeof e.score === 'number' ? e.score : null;
      const capped = score !== null && CAP_VALUES.has(score);
      for (const t of e.types) {
        if (!spine[t]) { unregLedger[t] = (unregLedger[t] || 0) + 1; continue; }
        const a = ensureL(t);
        a.fires++; solo ? a.solo++ : a.combo++;
        isSuspect ? a.suspect++ : a.clean++;
        if (capped) a.capped++;
        if (score !== null) (solo ? a.scoresSolo : a.scoresCombo).push(score);
      }
    }
  }

  // --- Corpus pass (ground truth) ---
  const C = {};
  const ensureC = t => (C[t] || (C[t] = { fp_any: 0, mw_any: 0, fp_sole: 0, mw_sole: 0 }));
  let nFP = 0, nMW = 0;
  if (fs.existsSync(CORPUS)) {
    for (const line of fs.readFileSync(CORPUS, 'utf8').trim().split('\n')) {
      let r; try { r = JSON.parse(line); } catch { continue; }
      const isFP = r.verdict === 'FP', isMW = r.verdict === 'MALWARE';
      if (!isFP && !isMW) continue;
      isFP ? nFP++ : nMW++;
      const present = new Set(Array.isArray(r.rules_triggered) ? r.rules_triggered : []);
      const strongPresent = [...present].filter(t => strongTypes.has(t));
      const iocPresent = [...present].some(t => IOC_MATCH_TYPES.has(t));
      for (const t of present) {
        if (!spine[t]) continue;
        const a = ensureC(t);
        isFP ? a.fp_any++ : a.mw_any++;
        // sole = this is the ONLY HIGH/CRITICAL signal AND no IOC → gating it de-alerts exactly this row
        if (strongTypes.has(t) && strongPresent.length === 1 && strongPresent[0] === t && !iocPresent) {
          isFP ? a.fp_sole++ : a.mw_sole++;
        }
      }
    }
  }

  // --- Merge + auto-bucket ---
  const firedTypes = new Set([...Object.keys(L), ...Object.keys(C)]);
  const rows = [];
  for (const type of Object.keys(spine)) {
    const l = L[type] || { fires: 0, solo: 0, combo: 0, suspect: 0, clean: 0, capped: 0, scoresSolo: [], scoresCombo: [] };
    const c = C[type] || { fp_any: 0, mw_any: 0, fp_sole: 0, mw_sole: 0 };
    const fired = firedTypes.has(type);
    const mode_gated = isModeGated(type);
    const never_fired = !fired && !mode_gated;
    const pctCapped = l.fires ? l.capped / l.fires : 0;
    const fp_sole_rate = (c.fp_sole + c.mw_sole) ? c.fp_sole / (c.fp_sole + c.mw_sole) : null;

    let bucket;
    if (!fired) bucket = mode_gated ? 'MODE_GATED' : 'DEAD';
    else if (c.mw_sole > 0 && c.fp_sole > 0) bucket = 'MIXED';
    else if (c.mw_sole > 0) bucket = 'GOLD';
    else if (c.fp_sole >= 10) bucket = 'NOISE';
    else if (l.fires >= 1000 && pctCapped >= 0.5) bucket = 'CAPPED';
    else if (l.fires >= 20 && l.solo === 0) bucket = 'REDUNDANT';
    else if (c.fp_any > 0) bucket = 'FP_LEAN';
    else bucket = 'QUIET';

    rows.push({
      type, rule_id: spine[type].rule_id, severity: spine[type].severity, confidence: spine[type].confidence,
      domain: spine[type].domain, isCompound: spine[type].isCompound,
      ledger: {
        fires: l.fires, solo: l.solo, combo: l.combo,
        pctSuspect: l.fires ? +(l.suspect / l.fires).toFixed(3) : 0,
        pctClean: l.fires ? +(l.clean / l.fires).toFixed(3) : 0,
        scoreP50solo: median(l.scoresSolo), scoreP50combo: median(l.scoresCombo),
        pctCapped: +pctCapped.toFixed(3)
      },
      corpus: { fp_any: c.fp_any, mw_any: c.mw_any, fp_sole: c.fp_sole, mw_sole: c.mw_sole, fp_sole_rate: fp_sole_rate !== null ? +fp_sole_rate.toFixed(3) : null },
      flags: { never_fired, mode_gated, capped: pctCapped >= 0.5 },
      bucket
    });
  }

  // --- Output ---
  const byBucket = {};
  for (const r of rows) (byBucket[r.bucket] = byBucket[r.bucket] || []).push(r);
  fs.writeFileSync(OUT, JSON.stringify({
    generatedFrom: { ledger: path.basename(LEDGER), corpus: path.basename(CORPUS) },
    totals: { rules: rows.length, ledgerScored, corpusFP: nFP, corpusMW: nMW, unregisteredLedgerTypes: Object.keys(unregLedger).length },
    bucketCounts: Object.fromEntries(Object.entries(byBucket).map(([k, v]) => [k, v.length])),
    rows
  }, null, 2));

  const H = s => `\n${'═'.repeat(84)}\n${s}\n${'═'.repeat(84)}`;
  console.log(H(`RULE AUDIT — ${rows.length} rules · ledger scored=${ledgerScored} · corpus FP=${nFP}/MW=${nMW}`));
  console.log('Buckets: ' + Object.entries(byBucket).sort((a, b) => b[1].length - a[1].length).map(([k, v]) => `${k} ${v.length}`).join(' · '));
  console.log(`Unregistered types seen in ledger (fall through to MUADDIB-UNK): ${Object.keys(unregLedger).length}` +
    (Object.keys(unregLedger).length ? ' → ' + Object.entries(unregLedger).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([t, n]) => `${t}(${n})`).join(', ') : ''));

  const tbl = (title, list, cols) => {
    console.log(H(title + `  (${list.length})`));
    console.log(cols.header);
    for (const r of list.slice(0, cols.limit || 25)) console.log(cols.row(r));
    if (list.length > (cols.limit || 25)) console.log(`  … +${list.length - (cols.limit || 25)} more (see rule-audit.json)`);
  };
  const pad = (s, n) => String(s).padEnd(n);
  const padL = (s, n) => String(s).padStart(n);

  // NOISE — safe-gate FP-creator candidates, ranked by fp_sole
  tbl('NOISE — FP-creators: high fp_sole, mw_sole=0 (gating de-alerts fp_sole, loses 0 malware)',
    (byBucket.NOISE || []).sort((a, b) => b.corpus.fp_sole - a.corpus.fp_sole),
    { limit: 20, header: '  ' + pad('type', 34) + pad('sev', 9) + padL('fp_sole', 8) + padL('fp_any', 8) + padL('L.fires', 9) + padL('L.solo', 8) + padL('%cap', 6),
      row: r => '  ' + pad(r.type, 34) + pad(r.severity, 9) + padL(r.corpus.fp_sole, 8) + padL(r.corpus.fp_any, 8) + padL(r.ledger.fires, 9) + padL(r.ledger.solo, 8) + padL((r.ledger.pctCapped * 100).toFixed(0), 6) });

  // MIXED — fires on both FP and malware sole → needs a discriminant, not a blunt gate
  tbl('MIXED — fires SOLE on BOTH malware and FP (needs discriminant, not retire)',
    (byBucket.MIXED || []).sort((a, b) => b.corpus.fp_sole - a.corpus.fp_sole),
    { limit: 20, header: '  ' + pad('type', 34) + pad('sev', 9) + padL('fp_sole', 8) + padL('mw_sole', 8) + padL('fp_rate', 8) + padL('L.fires', 9),
      row: r => '  ' + pad(r.type, 34) + pad(r.severity, 9) + padL(r.corpus.fp_sole, 8) + padL(r.corpus.mw_sole, 8) + padL(r.corpus.fp_sole_rate ?? '—', 8) + padL(r.ledger.fires, 9) });

  // DEAD — never fired, not mode-gated
  tbl('DEAD — never fired in ledger OR corpus, not mode-gated (verify before retiring)',
    (byBucket.DEAD || []).sort((a, b) => a.type.localeCompare(b.type)),
    { limit: 60, header: '  ' + pad('type', 40) + pad('rule_id', 26) + pad('sev', 9) + 'domain',
      row: r => '  ' + pad(r.type, 40) + pad(r.rule_id, 26) + pad(r.severity, 9) + r.domain });

  // REDUNDANT — always combo, never solo
  tbl('REDUNDANT — always fires in combo, never solo (compound-fold candidates)',
    (byBucket.REDUNDANT || []).sort((a, b) => b.ledger.fires - a.ledger.fires),
    { limit: 25, header: '  ' + pad('type', 34) + pad('sev', 9) + padL('L.fires', 9) + padL('%susp', 7) + padL('mw_any', 8) + padL('fp_any', 8),
      row: r => '  ' + pad(r.type, 34) + pad(r.severity, 9) + padL(r.ledger.fires, 9) + padL((r.ledger.pctSuspect * 100).toFixed(0), 7) + padL(r.corpus.mw_any, 8) + padL(r.corpus.fp_any, 8) });

  // SCORING-watch — HIGH/CRITICAL but mostly FP when sole
  const scoringWatch = rows.filter(r => (r.severity === 'HIGH' || r.severity === 'CRITICAL') && r.corpus.fp_sole >= 5 && r.corpus.fp_sole_rate !== null && r.corpus.fp_sole_rate >= 0.9)
    .sort((a, b) => b.corpus.fp_sole - a.corpus.fp_sole);
  tbl('SCORING-watch — HIGH/CRITICAL severity but ≥90% FP when it is the sole strong signal',
    scoringWatch,
    { limit: 25, header: '  ' + pad('type', 34) + pad('sev', 9) + pad('conf', 8) + padL('fp_sole', 8) + padL('mw_sole', 8) + padL('fp_rate', 8),
      row: r => '  ' + pad(r.type, 34) + pad(r.severity, 9) + pad(r.confidence, 8) + padL(r.corpus.fp_sole, 8) + padL(r.corpus.mw_sole, 8) + padL(r.corpus.fp_sole_rate, 8) });

  console.log(H('CAVEATS'));
  console.log('  • corpus fp_sole/mw_sole = TYPE-PRESENCE vs human verdict = ADDRESSABILITY, not gate precision.');
  console.log(`  • MALWARE ground truth n=${nMW} is small → GOLD/MIXED malware counts are low-confidence.`);
  console.log('  • ledger types[] capped at 12 (state.js:1121) → combo/solo undercount on >12-type packages.');
  console.log('  • ledger has NO ground truth: pctSuspect/pctClean = monitor self-classification, not TP/FP.');
  console.log('  • MODE_GATED (paranoid/sandbox_/temporal) absence ≠ dead. DEAD list still needs per-rule verify.');
  console.log(`\nwrote ${path.relative(path.resolve(__dirname, '..'), OUT)}`);
})();
