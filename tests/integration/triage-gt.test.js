'use strict';

const fs = require('fs');
const path = require('path');
const { test, assert } = require('../test-utils');

async function runTriageGtTests() {
  console.log('\n=== TRIAGE GT COVERAGE TESTS ===\n');

  // The REAL allowlist, imported from the executor. The previous local replica
  // had already drifted (14 entries vs 16 in executor.js — scanAntiScannerInjection
  // and scanBinarySource were missing) while its comment claimed "the test fails
  // if either side drifts". Coverage below is computed against the true set.
  const { QUICK_SCAN_ALLOWLIST, SCANNER_NAMES } = require('../../src/pipeline/executor.js');

  // Maps the short scanner names used in attacks.json's `expected.scanners`
  // to the module-level names used in executor.js's SCANNER_NAMES.
  const SCANNER_NAME_MAP = {
    package: 'scanPackageJson',
    shell: 'scanShellScripts',
    ast: 'analyzeAST',
    dataflow: 'analyzeDataFlow',
    obfuscation: 'detectObfuscation',
    entropy: 'scanEntropy',
    dependencies: 'scanDependencies',
    typosquat: 'scanTyposquatting',
    'ioc-strings': 'scanIocStrings',
    'github-actions': 'scanGitHubActions',
    hash: 'scanHashes',
    'python-source': 'scanPythonSource',
    'python-ast': 'scanPythonAST',
    'ai-config': 'scanAIConfig',
    python: 'matchPythonIOCs',
    'anti-forensic': 'scanAntiForensic',
    'stub-package': 'scanStubPackage',
    monorepo: 'scanMonorepo',
    'trusted-dep-diff': 'scanTrustedDepDiff',
    'pypi-typosquat': 'checkPyPITyposquatting',
    // Post-processing / module-graph not in SCANNER_NAMES; they always run
    // even in quick_scan because they're outside the gated Promise.allSettled.
    'intent-coherence': null,
    'module-graph': null,
    reachability: null,
  };

  const attacksPath = path.join(__dirname, '..', 'ground-truth', 'attacks.json');
  if (!fs.existsSync(attacksPath)) {
    console.warn('[TRIAGE-GT] attacks.json not found — skipping coverage test');
    return;
  }
  const attacksJson = JSON.parse(fs.readFileSync(attacksPath, 'utf8'));
  const attacks = (attacksJson && attacksJson.attacks) || [];

  // ── Coverage analysis ──────────────────────────────────────────────────

  test('TRIAGE-GT: quick allowlist keeps the non-negotiable GT anchors and stays inside SCANNER_NAMES', () => {
    // TPR anchors (analyzeAST covers 70/96 GT, analyzeDataFlow 31/96) plus the
    // cheap high-signal scanners quick mode cannot lose. Membership assertions
    // on the REAL set — additions to the allowlist are allowed, removals of
    // these anchors are not.
    const anchors = [
      'scanPackageJson', 'scanShellScripts', 'analyzeAST', 'detectObfuscation',
      'scanDependencies', 'analyzeDataFlow', 'scanTyposquatting', 'scanGitHubActions',
      'matchPythonIOCs', 'scanEntropy', 'scanIocStrings', 'scanPythonSource', 'scanPythonAST',
      'scanAIConfig'
    ];
    for (const s of anchors) assert(QUICK_SCAN_ALLOWLIST.has(s), `${s} missing from allowlist`);
    // Every allowlist entry must be a real scanner name — a typo here would
    // silently disable the scanner in quick mode (ifEnabled would never match).
    for (const s of QUICK_SCAN_ALLOWLIST) {
      assert(SCANNER_NAMES.includes(s), `allowlist entry ${s} is not in SCANNER_NAMES — typo would silently drop it in quick mode`);
    }
    // Deliberate exclusions (documented in executor.js) must stay excluded —
    // re-adding scanAntiForensic would reintroduce its 45s timeout in quick mode.
    assert(!QUICK_SCAN_ALLOWLIST.has('scanAntiForensic'), 'scanAntiForensic is excluded by design (45s timeout)');
    assert(!QUICK_SCAN_ALLOWLIST.has('scanTrustedDepDiff'), 'scanTrustedDepDiff is opt-in only');
  });

  test('TRIAGE-GT: every GT attack with declared scanners has AT LEAST ONE in quick allowlist', () => {
    // Soft contract: if any GT attack's declared scanners are *entirely* outside the
    // quick allowlist, that attack would only be detected in full mode. Such an attack
    // must therefore have a triage-flipping signal (lifecycle, ATO, no_metadata, suspect
    // reputation factor). We can't verify the triage signal without registry metadata,
    // so we surface the gap as an assertion: at least one expected scanner must be in
    // the allowlist (so quick mode still has SOMETHING to fire on).
    const gaps = [];
    let totalWithScanners = 0;
    for (const a of attacks) {
      const declared = (a.expected && a.expected.scanners) || [];
      if (declared.length === 0) continue; // no contract → no claim to verify
      totalWithScanners++;
      const mapped = declared
        .map(s => SCANNER_NAME_MAP[s] || s)
        .filter(s => s !== null); // drop post-processors (always run in both modes)
      if (mapped.length === 0) continue; // entirely post-processing → covered by both modes
      const anyInAllowlist = mapped.some(s => QUICK_SCAN_ALLOWLIST.has(s));
      if (!anyInAllowlist) {
        gaps.push({ id: a.id, name: a.name, scanners: declared, mapped });
      }
    }
    if (gaps.length > 0) {
      const summary = gaps.map(g => `${g.id}(${g.name}): scanners=[${g.scanners.join(',')}]`).join('\n  ');
      assert(false,
        `${gaps.length}/${totalWithScanners} GT attacks have NO scanner in QUICK_SCAN_ALLOWLIST:\n  ${summary}\n` +
        `→ Either add the relevant scanner to the allowlist, or document that triage MUST flip these to full.`);
    }
  });

  test('TRIAGE-GT: coverage report — how many attacks are fully covered by quick vs need full', () => {
    let fullCoverage = 0;        // every declared scanner in quick allowlist
    let partialCoverage = 0;     // at least one in allowlist, some outside
    let needsFullMode = 0;       // declared scanners but none in allowlist (would fail above)
    let noScanners = 0;          // no expected.scanners declared
    for (const a of attacks) {
      const declared = (a.expected && a.expected.scanners) || [];
      if (declared.length === 0) { noScanners++; continue; }
      const mapped = declared.map(s => SCANNER_NAME_MAP[s] || s).filter(s => s !== null);
      if (mapped.length === 0) { fullCoverage++; continue; }
      const inAllowlist = mapped.filter(s => QUICK_SCAN_ALLOWLIST.has(s));
      if (inAllowlist.length === mapped.length) fullCoverage++;
      else if (inAllowlist.length > 0) partialCoverage++;
      else needsFullMode++;
    }
    const total = attacks.length;
    console.log(`[TRIAGE-GT] coverage on ${total} attacks:`);
    console.log(`  fully covered by quick : ${fullCoverage}`);
    console.log(`  partial (one+ in quick): ${partialCoverage}`);
    console.log(`  needs full mode only  : ${needsFullMode}`);
    console.log(`  no scanners declared  : ${noScanners}`);
    // Sanity: total accounted for
    assert(fullCoverage + partialCoverage + needsFullMode + noScanners === total,
      `accounting mismatch: ${fullCoverage + partialCoverage + needsFullMode + noScanners} vs ${total}`);
    // Hard floor: at least 70% of attacks with declared scanners must be fully
    // covered by quick mode. Below that, queue saturation gain is too small to
    // justify the regression risk and we should expand the allowlist.
    const withScanners = total - noScanners;
    if (withScanners > 0) {
      const pct = (fullCoverage / withScanners) * 100;
      assert(pct >= 70,
        `quick coverage = ${pct.toFixed(1)}% of declared-scanner GT — below 70% floor. Expand allowlist or downgrade Stage 2 scope.`);
    }
  });
}

module.exports = { runTriageGtTests };
