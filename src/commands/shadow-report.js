'use strict';

// muaddib shadow-report — read the shadow-mode divergence log and print the
// V1-vs-V2 adjudication split per detector. This is the read side of
// src/shared/shadow.js: detectors compute a candidate semantics alongside the
// live one and log disagreements; this command turns the log into the table a
// human adjudicates before flipping the semantics.
//
// The log only contains DIVERGENCES (agreements are not recorded), so:
//   old-only  = oldVerdict truthy, newVerdict falsy → alerts V2 would drop (FP killed)
//   new-only  = newVerdict truthy, oldVerdict falsy → NEW flags (review every one)
//   changed   = both truthy but different (e.g. severity reclassification)

const { readShadowDivergences } = require('../shared/shadow.js');

const DAY_MS = 24 * 60 * 60 * 1000;

/** Parse `--since 7d` / `--since 12h` / ISO string → ms epoch (null = all). */
function parseSince(s) {
  if (!s) return null;
  const m = /^(\d+)([dh])$/.exec(s);
  if (m) {
    const n = parseInt(m[1], 10);
    return Date.now() - n * (m[2] === 'd' ? DAY_MS : 3600 * 1000);
  }
  const p = Date.parse(s);
  return Number.isNaN(p) ? null : p;
}

function classify(e) {
  const oldT = !!e.oldVerdict, newT = !!e.newVerdict;
  if (oldT && !newT) return 'oldOnly';
  if (!oldT && newT) return 'newOnly';
  return 'changed';
}

async function runShadowReport(opts = {}) {
  const sinceMs = parseSince(opts.since);
  const entries = readShadowDivergences({
    detector: opts.detector || undefined,
    sinceTs: sinceMs !== null ? sinceMs : undefined
  });

  if (entries.length === 0) {
    console.log('\n  No shadow divergences recorded' +
      (opts.detector ? ` for detector "${opts.detector}"` : '') +
      (opts.since ? ` since ${opts.since}` : '') +
      '.\n  (Shadow mode logs only V1≠V2 disagreements; enable with MUADDIB_SHADOW=1.)\n');
    return;
  }

  // Group by detector, dedup by package@version (a package rescanned N times
  // diverges N times — the adjudication unit is the package, not the event).
  const byDetector = new Map();
  for (const e of entries) {
    let d = byDetector.get(e.detector);
    if (!d) { d = { events: 0, byKey: new Map() }; byDetector.set(e.detector, d); }
    d.events++;
    const key = `${e.package || '?'}@${e.version || ''}`;
    if (!d.byKey.has(key)) d.byKey.set(key, e); // first divergence wins for the listing
  }

  if (opts.json) {
    const out = {};
    for (const [det, d] of byDetector) {
      const split = { oldOnly: [], newOnly: [], changed: [] };
      for (const [key, e] of d.byKey) split[classify(e)].push({ key, evidence: e.evidence });
      out[det] = {
        events: d.events, distinct: d.byKey.size,
        oldOnly: split.oldOnly.length, newOnly: split.newOnly.length, changed: split.changed.length,
        newOnlyList: split.newOnly, oldOnlyExamples: split.oldOnly.slice(0, 20)
      };
    }
    console.log(JSON.stringify(out, null, 2));
    return;
  }

  console.log('\n  MUAD\'DIB Shadow Divergence Report' + (opts.since ? ` (since ${opts.since})` : '') + '\n');
  for (const [det, d] of byDetector) {
    const split = { oldOnly: [], newOnly: [], changed: [] };
    for (const [key, e] of d.byKey) split[classify(e)].push({ key, e });
    console.log(`  ${det}`);
    console.log(`    divergence events: ${d.events} | distinct pkg@version: ${d.byKey.size}`);
    console.log(`    old-only (V2 drops the alert — FP killed): ${split.oldOnly.length}`);
    console.log(`    new-only (V2 adds a flag — REVIEW):        ${split.newOnly.length}`);
    if (split.changed.length) {
      console.log(`    changed (both fire, different verdict):   ${split.changed.length}`);
    }
    const show = (label, list, max) => {
      if (!list.length) return;
      console.log(`    ${label}:`);
      for (const { key, e } of list.slice(0, max)) {
        const ev = e.evidence ? JSON.stringify(e.evidence) : '';
        console.log(`      - ${key}  old=${JSON.stringify(e.oldVerdict)} new=${JSON.stringify(e.newVerdict)} ${ev.slice(0, 140)}`);
      }
      if (list.length > max) console.log(`      ... and ${list.length - max} more`);
    };
    // Every NEW flag must be human-reviewed (possible FN risk if wrong) — show all.
    show('new-only detail', split.newOnly, 50);
    show('old-only examples', split.oldOnly, 20);
    show('changed detail', split.changed, 20);
    console.log('');
  }
}

module.exports = { runShadowReport, parseSince };
