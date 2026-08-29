#!/usr/bin/env node
/**
 * GitHub Action reporter for MUAD'DIB.
 *
 * Reads a `muaddib scan --json` result file and:
 *   1. writes machine outputs to $GITHUB_OUTPUT (risk_score, threats_count,
 *      critical_count, high_count, risk_level), and
 *   2. prints a compact human-readable summary to the Action log.
 *
 * This replaces the fragile `grep -o '"threats":\['` parsing in action.yml
 * (which always reported 1) and removes the second full scan the composite
 * action previously ran only to produce human output — a real cost on a
 * CPU-bound scanner. The JSON scan is now authoritative for BOTH metrics and
 * the pass/fail exit code.
 *
 * Usage: node action-report.cjs <path-to-result.json>
 * Never throws on a malformed/missing file — a scanner crash must not be
 * masked as a reporter crash; it degrades to zeros and a clear log line.
 */
'use strict';

const fs = require('fs');

const jsonPath = process.argv[2];

function setOutput(key, value) {
  const file = process.env.GITHUB_OUTPUT;
  const line = `${key}=${value}\n`;
  if (file) {
    try {
      fs.appendFileSync(file, line);
      return;
    } catch (e) {
      // Fall through to stdout so the value is at least visible in the log.
      console.error(`[action-report] could not write $GITHUB_OUTPUT: ${e.message}`);
    }
  }
  process.stdout.write(line);
}

let result = null;
try {
  result = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
} catch (e) {
  console.error(`[action-report] could not read scan JSON (${jsonPath}): ${e.message}`);
}

const summary = (result && result.summary) || {};
const threats = (result && Array.isArray(result.threats)) ? result.threats : [];

const riskScore = Number.isFinite(summary.riskScore) ? summary.riskScore : 0;
const riskLevel = summary.riskLevel || 'UNKNOWN';
const critical = Number.isFinite(summary.critical) ? summary.critical : 0;
const high = Number.isFinite(summary.high) ? summary.high : 0;
const medium = Number.isFinite(summary.medium) ? summary.medium : 0;
const low = Number.isFinite(summary.low) ? summary.low : 0;
const threatsCount = threats.length;

setOutput('risk_score', riskScore);
setOutput('risk_level', riskLevel);
setOutput('threats_count', threatsCount);
setOutput('critical_count', critical);
setOutput('high_count', high);

// --- Human-readable summary -------------------------------------------------
const bar = '='.repeat(52);
console.log('');
console.log(bar);
console.log(`  MUAD'DIB supply-chain scan`);
console.log(bar);
console.log(`  Risk score : ${riskScore}/100  (${riskLevel})`);
console.log(`  Threats    : ${threatsCount}  (critical ${critical}, high ${high}, medium ${medium}, low ${low})`);
console.log(bar);

if (threatsCount > 0) {
  // Rank by severity so the log leads with what matters. Cap the list so a
  // 500-threat result does not flood the Action log.
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const ranked = threats
    .slice()
    .sort((a, b) => (order[a && a.severity] ?? 9) - (order[b && b.severity] ?? 9));
  const MAX = 25;
  for (const t of ranked.slice(0, MAX)) {
    const sev = String((t && t.severity) || '?').toUpperCase().padEnd(8);
    const type = (t && t.type) || (t && t.id) || 'unknown';
    const file = (t && (t.file || t.path)) || '';
    const line = (t && t.line != null) ? `:${t.line}` : '';
    console.log(`  [${sev}] ${type}  ${file}${line}`);
  }
  if (ranked.length > MAX) {
    console.log(`  … and ${ranked.length - MAX} more (see SARIF / --json artifact)`);
  }
  console.log(bar);

  // Community feedback loop: a prefilled GitHub issue on the scanner's repo so
  // a maintainer who believes a finding is wrong can report it in one click.
  // Advisory only — it opens an issue for manual triage, it never changes a
  // verdict, which is what keeps a bad actor from "voting" their own package
  // clean. Every FP confirmed here hardens the FP caps.
  console.log(`  Think a finding is a false positive? Report it:`);
  console.log(`  ${buildFpReportUrl(result, ranked)}`);
  console.log(bar);
}

// Build a prefilled "false positive" issue URL for github.com/DNSZLSK/muad-dib.
// Kept compact (top findings only) so the URL stays well under practical limits.
function buildFpReportUrl(res, ranked) {
  const target = (res && res.target) || '.';
  const pkg = String(target).split(/[\\/]/).filter(Boolean).pop() || target;
  const types = [...new Set(ranked.map((t) => (t && t.type) || (t && t.id)).filter(Boolean))].slice(0, 8);
  const title = `[FP] ${pkg}: ${types[0] || 'finding'}`;
  const body = [
    "Suspected false positive from the MUAD'DIB GitHub Action.",
    '',
    `- Scanned target: \`${target}\``,
    `- Risk score: ${riskScore}/100 (${riskLevel})`,
    `- Rules that fired: ${types.join(', ')}`,
    '',
    '### Why I believe this is a false positive',
    '<!-- Is this your package? What does the flagged code legitimately do? -->',
    '',
    '### Flagged findings',
    ...ranked.slice(0, 10).map((t) => {
      const ln = (t && t.line != null) ? `:${t.line}` : '';
      return `- \`${(t && t.severity) || '?'}\` ${(t && t.type) || 'unknown'} — ${(t && (t.file || t.path)) || ''}${ln}`;
    })
  ].join('\n');
  const q = `labels=false-positive&title=${encodeURIComponent(title)}&body=${encodeURIComponent(body)}`;
  return `https://github.com/DNSZLSK/muad-dib/issues/new?${q}`;
}

// The reporter never sets the exit code — action.yml owns pass/fail from the
// authoritative --json scan exit code.
