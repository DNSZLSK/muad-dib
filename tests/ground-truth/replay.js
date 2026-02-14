#!/usr/bin/env node
/**
 * MUAD'DIB Ground Truth Replay
 *
 * Loads attacks.json, scans each sample with muaddib, and compares
 * actual findings against expected detections.
 *
 * Usage:
 *   node tests/ground-truth/replay.js              # replay all
 *   node tests/ground-truth/replay.js GT-001       # replay single
 *   node tests/ground-truth/replay.js --verbose    # detailed output
 *   node tests/ground-truth/replay.js --json       # machine-readable
 */

const fs = require('fs');
const path = require('path');
const { run } = require('../../src/index.js');

const GT_DIR = path.join(__dirname);
const ATTACKS_FILE = path.join(GT_DIR, 'attacks.json');

function loadAttacks() {
  const raw = fs.readFileSync(ATTACKS_FILE, 'utf8');
  return JSON.parse(raw);
}

async function scanSample(sampleDir) {
  const result = await run(sampleDir, { _capture: true });
  return result;
}

function checkExpected(attack, result) {
  const expected = attack.expected;
  const threats = result.threats || [];
  const total = result.summary ? result.summary.total : threats.length;

  const status = {
    id: attack.id,
    name: attack.name,
    version: attack.version,
    passed: true,
    total,
    details: [],
    matchedRules: [],
    matchedSeverities: [],
    gaps: attack.gaps || null
  };

  // Check min_threats
  if (total < expected.min_threats) {
    status.passed = false;
    status.details.push(`Expected >= ${expected.min_threats} threats, got ${total}`);
  }

  // Check required rules
  const foundRules = new Set(threats.map(t => t.rule_id));
  for (const rule of expected.rules) {
    if (foundRules.has(rule)) {
      status.matchedRules.push(rule);
    } else {
      status.passed = false;
      status.details.push(`Missing expected rule: ${rule}`);
    }
  }

  // Check severities (at least one match)
  const foundSeverities = new Set(threats.map(t => t.severity));
  for (const sev of expected.severities) {
    if (foundSeverities.has(sev)) {
      status.matchedSeverities.push(sev);
    }
  }
  if (expected.severities.length > 0 && status.matchedSeverities.length === 0) {
    status.passed = false;
    status.details.push(`No matching severities. Expected: ${expected.severities.join(', ')}, got: ${[...foundSeverities].join(', ') || 'none'}`);
  }

  return status;
}

function formatSeveritySummary(threats) {
  const counts = {};
  for (const t of threats) {
    counts[t.severity] = (counts[t.severity] || 0) + 1;
  }
  const parts = [];
  if (counts.CRITICAL) parts.push(`${counts.CRITICAL} CRITICAL`);
  if (counts.HIGH) parts.push(`${counts.HIGH} HIGH`);
  if (counts.MEDIUM) parts.push(`${counts.MEDIUM} MEDIUM`);
  if (counts.LOW) parts.push(`${counts.LOW} LOW`);
  return parts.join(' + ') || '0 findings';
}

function formatDetectionHint(attack, threats) {
  if (threats.length === 0) {
    if (attack.expected.min_threats === 0) return 'expected: out of scope';
    return 'MISS';
  }
  const types = [...new Set(threats.map(t => t.type))];
  return types.map(t => t.replace(/_/g, ' ')).join(' + ');
}

async function replay(options = {}) {
  const data = loadAttacks();
  const attacks = data.attacks;
  const filterId = options.filterId || null;
  const verbose = options.verbose || false;
  const jsonMode = options.json || false;

  const results = [];
  let detected = 0;
  let missed = 0;
  let outOfScope = 0;

  for (const attack of attacks) {
    if (filterId && attack.id !== filterId) continue;

    const sampleDir = path.join(GT_DIR, attack.sample_dir);
    if (!fs.existsSync(sampleDir)) {
      results.push({
        id: attack.id,
        name: attack.name,
        passed: false,
        error: `Sample directory not found: ${sampleDir}`,
        total: 0,
        threats: []
      });
      missed++;
      continue;
    }

    let scanResult;
    try {
      scanResult = await scanSample(sampleDir);
    } catch (err) {
      results.push({
        id: attack.id,
        name: attack.name,
        passed: false,
        error: `Scan error: ${err.message}`,
        total: 0,
        threats: []
      });
      missed++;
      continue;
    }

    const status = checkExpected(attack, scanResult);
    status.threats = scanResult.threats || [];

    if (status.passed) {
      if (attack.expected.min_threats === 0) {
        outOfScope++;
      } else {
        detected++;
      }
    } else {
      missed++;
    }

    results.push(status);
  }

  const totalRun = results.length;
  const rate = totalRun > 0 ? Math.round(((detected + outOfScope) / totalRun) * 100) : 0;

  if (jsonMode) {
    const report = {
      timestamp: new Date().toISOString(),
      version: data.version,
      total: totalRun,
      detected,
      missed,
      outOfScope,
      rate,
      results: results.map(r => ({
        id: r.id,
        name: r.name,
        version: r.version,
        passed: r.passed,
        total: r.total,
        matchedRules: r.matchedRules || [],
        matchedSeverities: r.matchedSeverities || [],
        details: r.details || [],
        gaps: r.gaps || null,
        error: r.error || null
      }))
    };
    console.log(JSON.stringify(report, null, 2));
    return report;
  }

  // Console formatted output
  console.log('');
  console.log('=== MUAD\'DIB Ground Truth Replay ===');
  console.log(`Attacks: ${totalRun} | Detected: ${detected} | Missed: ${missed} | Out of scope: ${outOfScope} | Rate: ${rate}%`);
  console.log('');

  for (const r of results) {
    const attack = attacks.find(a => a.id === r.id);
    if (!attack) continue;

    if (r.error) {
      const icon = '\u2717';
      console.log(`  ${icon} ${r.name.padEnd(16)} ERROR: ${r.error}`);
      continue;
    }

    const sevSummary = formatSeveritySummary(r.threats);
    const hint = formatDetectionHint(attack, r.threats);

    if (r.passed && attack.expected.min_threats === 0) {
      // Out of scope — expected 0 findings
      const icon = '\u26AA';
      console.log(`  ${icon} ${attack.name.padEnd(16)} ${sevSummary.padEnd(20)} (${hint})`);
    } else if (r.passed) {
      const icon = '\u2713';
      console.log(`  ${icon} ${attack.name.padEnd(16)} ${sevSummary.padEnd(20)} (${hint})`);
    } else {
      const icon = '\u2717';
      console.log(`  ${icon} ${attack.name.padEnd(16)} ${sevSummary.padEnd(20)} FAIL: ${r.details.join('; ')}`);
    }

    if (verbose) {
      if (r.threats.length > 0) {
        for (const t of r.threats) {
          console.log(`      [${t.severity}] ${t.rule_id} — ${t.message}`);
        }
      }
      if (r.gaps) {
        console.log(`      GAP: ${r.gaps}`);
      }
      console.log('');
    }
  }

  console.log('');
  return { total: totalRun, detected, missed, outOfScope, rate, results };
}

// Parse CLI args when run standalone
if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {};

  for (const arg of args) {
    if (arg === '--verbose' || arg === '-v') {
      options.verbose = true;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg.startsWith('GT-')) {
      options.filterId = arg;
    }
  }

  replay(options)
    .then(result => {
      if (!options.json) {
        process.exit(result.missed > 0 ? 1 : 0);
      }
    })
    .catch(err => {
      console.error('[ERROR]', err.message);
      process.exit(1);
    });
}

module.exports = { replay, loadAttacks, checkExpected, scanSample };
