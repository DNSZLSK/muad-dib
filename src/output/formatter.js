const { saveReport } = require('../report.js');
const { saveSARIF } = require('../sarif.js');
const { saveCycloneDX } = require('./cyclonedx.js');
const { getPlaybook } = require('../response/playbooks.js');
const { DOMAIN_CODES, getRuleDomain } = require('../rules/index.js');

// P0a — domain tag formatter for CLI text output.
// Returns a bracketed 3-letter code like "[MAL]" / "[AUT]" / "[ENG]" / "[VUL]"
// to display next to the severity prefix. Resolves the domain from the threat
// type if not already set on the threat object (defense in depth).
function domainTag(threat) {
  const d = (threat && threat.domain) || (threat && threat.type ? getRuleDomain(threat.type) : 'malware');
  const code = DOMAIN_CODES[d] || 'UNK';
  return '[' + code + ']';
}

/**
 * Format and print scan output in the requested format.
 * Handles JSON, HTML, SARIF, explain, and normal (default) modes.
 * @param {Object} result - scan result object
 * @param {Object} options - scan options (json, html, sarif, explain, breakdown)
 * @param {Object} ctx - context object with shared state
 * @param {Object|null} ctx.spinner - TTY spinner instance
 * @param {Object|null} ctx.sandboxData - sandbox analysis results
 * @param {string|null} ctx.mostSuspiciousFile - file with highest score
 * @param {number} ctx.maxFileScore - highest per-file score
 * @param {number} ctx.packageScore - package-level score
 * @param {number} ctx.globalRiskScore - global sum score
 * @param {Array} ctx.deduped - deduplicated threats
 * @param {Array} ctx.enrichedThreats - enriched threats with rules/playbooks
 * @param {Object|null} ctx.pythonInfo - Python scan metadata
 * @param {Array} ctx.breakdown - score breakdown sorted by impact
 * @param {string} ctx.targetPath - scan target path
 */
function formatOutput(result, options, ctx) {
  const {
    spinner, sandboxData, mostSuspiciousFile, maxFileScore,
    packageScore, globalRiskScore, deduped, enrichedThreats,
    pythonInfo, breakdown, targetPath
  } = ctx;

  // JSON output
  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  }
  // HTML output
  else if (options.html) {
    saveReport(result, options.html);
    console.log(`[OK] HTML report generated: ${options.html}`);
  }
  // SARIF output
  else if (options.sarif) {
    saveSARIF(result, options.sarif);
    console.log(`[OK] SARIF report generated: ${options.sarif}`);
  }
  // P1b — CycloneDX 1.5 SBOM output
  else if (options.cyclonedx) {
    saveCycloneDX(result, options.cyclonedx);
    console.log(`[OK] CycloneDX BOM generated: ${options.cyclonedx}`);
  }
  // Explain output
  else if (options.explain) {
    if (!spinner) console.log(`\n[MUADDIB] Scanning ${targetPath}\n`);
    else console.log('');

    const explainScoreBar = '█'.repeat(Math.floor(result.summary.riskScore / 5)) + '░'.repeat(20 - Math.floor(result.summary.riskScore / 5));
    console.log(`[SCORE] ${result.summary.riskScore}/100 [${explainScoreBar}] ${result.summary.riskLevel}`);
    if (mostSuspiciousFile) {
      console.log(`        Max file: ${mostSuspiciousFile} (${maxFileScore} pts)`);
      if (packageScore > 0) {
        console.log(`        Package-level: +${packageScore} pts`);
      }
    }
    console.log('');

    if (options.breakdown && breakdown.length > 0) {
      console.log('[BREAKDOWN] Score contributors:');
      for (const entry of breakdown) {
        const pts = String(entry.points).padStart(2);
        console.log(`  +${pts}  ${entry.reason} (${entry.rule})`);
      }
      if (globalRiskScore !== result.summary.riskScore) {
        console.log('  ----');
        console.log(`  Global sum: ${globalRiskScore}, Per-file max: ${result.summary.riskScore}`);
      }
      console.log('');
    }

    if (pythonInfo) {
      console.log(`[PYTHON] ${pythonInfo.dependencies} dependencies detected (${pythonInfo.files.join(', ')})`);
      if (pythonInfo.threats > 0) {
        console.log(`[PYTHON] ${pythonInfo.threats} malicious PyPI package(s) found!\n`);
      } else {
        console.log(`[PYTHON] No known malicious PyPI packages.\n`);
      }
    }

    if (enrichedThreats.length === 0) {
      console.log('[OK] No threats detected.\n');
    } else {
      console.log(`[ALERT] ${enrichedThreats.length} threat(s) detected:\n`);
      enrichedThreats.forEach((t, i) => {
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        const countStr = t.count > 1 ? ` (x${t.count})` : '';
        console.log(`  ${i + 1}. [${t.severity}] ${domainTag(t)} ${t.rule_name}${countStr}`);
        console.log(`     Rule ID:    ${t.rule_id}`);
        console.log(`     Domain:     ${t.domain || getRuleDomain(t.type)}`);
        console.log(`     File:       ${t.file}`);
        if (t.line) console.log(`     Line:       ${t.line}`);
        console.log(`     Confidence: ${t.confidence}`);
        console.log(`     Message:    ${t.message}`);
        if (t.mitre) console.log(`     MITRE:      ${t.mitre} (https://attack.mitre.org/techniques/${t.mitre.replace('.', '/')})`);
        if (t.references && t.references.length > 0) {
          console.log(`     References:`);
          t.references.forEach(ref => console.log(`       - ${ref}`));
        }
        console.log(`     Playbook:   ${t.playbook}`);
        console.log('');
      });
    }

    // Sandbox section (explain)
    if (sandboxData) {
      console.log(`\n[SANDBOX] Dynamic analysis — ${sandboxData.package}`);
      console.log(`  Score:    ${sandboxData.score}/100`);
      console.log(`  Severity: ${sandboxData.severity}`);
      if (sandboxData.findings.length === 0) {
        console.log('  No suspicious behavior detected.\n');
      } else {
        console.log(`  ${sandboxData.findings.length} finding(s):`);
        sandboxData.findings.forEach(f => {
          console.log(`    [${f.severity}] ${f.type}: ${f.detail}`);
        });
        console.log('');
      }
    }
  }
  // Normal output
  else {
    if (!spinner) console.log(`\n[MUADDIB] Scanning ${targetPath}\n`);
    else console.log('');

    const scoreBar = '█'.repeat(Math.floor(result.summary.riskScore / 5)) + '░'.repeat(20 - Math.floor(result.summary.riskScore / 5));
    console.log(`[SCORE] ${result.summary.riskScore}/100 [${scoreBar}] ${result.summary.riskLevel}`);
    if (mostSuspiciousFile) {
      console.log(`        Max file: ${mostSuspiciousFile} (${maxFileScore} pts)`);
      if (packageScore > 0) {
        console.log(`        Package-level: +${packageScore} pts`);
      }
    }
    console.log('');

    if (options.breakdown && breakdown.length > 0) {
      console.log('[BREAKDOWN] Score contributors:');
      for (const entry of breakdown) {
        const pts = String(entry.points).padStart(2);
        console.log(`  +${pts}  ${entry.reason} (${entry.rule})`);
      }
      if (globalRiskScore !== result.summary.riskScore) {
        console.log('  ----');
        console.log(`  Global sum: ${globalRiskScore}, Per-file max: ${result.summary.riskScore}`);
      }
      console.log('');
    }

    if (pythonInfo) {
      console.log(`[PYTHON] ${pythonInfo.dependencies} dependencies detected (${pythonInfo.files.join(', ')})`);
      if (pythonInfo.threats > 0) {
        console.log(`[PYTHON] ${pythonInfo.threats} malicious PyPI package(s) found!\n`);
      } else {
        console.log(`[PYTHON] No known malicious PyPI packages.\n`);
      }
    }

    if (deduped.length === 0) {
      console.log('[OK] No threats detected.\n');
    } else {
      // v2.11.11: Filter degraded LOW quick-scan signals from default output.
      // These are regex-only detections in overflow files (no AST context) and
      // clutter the output on monorepos. Show with --verbose. Scoring, JSON,
      // SARIF, and HTML output are unaffected — this is display-only.
      const hiddenCount = options.verbose ? 0 : deduped.filter(t => t.degraded && t.severity === 'LOW').length;
      let displayThreats = options.verbose ? deduped : deduped.filter(t => !(t.degraded && t.severity === 'LOW'));
      // P0a — --domain filter is DISPLAY ONLY. Score/exit code are computed
      // from the full set; this only narrows the printed threats. Allows
      // workflows like "show me only author-risk threats" without changing
      // the underlying alert level.
      let domainFilteredOut = 0;
      if (Array.isArray(options.domainFilter) && options.domainFilter.length > 0) {
        const allowed = new Set(options.domainFilter);
        const before = displayThreats.length;
        displayThreats = displayThreats.filter(t => {
          const d = t.domain || getRuleDomain(t.type);
          return allowed.has(d);
        });
        domainFilteredOut = before - displayThreats.length;
      }
      if (displayThreats.length === 0 && hiddenCount > 0) {
        console.log(`[OK] No high-confidence threats detected (${hiddenCount} low-confidence signal(s) hidden, use --verbose to show).\n`);
      } else {
        console.log(`[ALERT] ${displayThreats.length} threat(s) detected:\n`);
        displayThreats.forEach((t, i) => {
          const countStr = t.count > 1 ? ` (x${t.count})` : '';
          console.log(`  ${i + 1}. [${t.severity}] ${domainTag(t)} ${t.type}${countStr}`);
          console.log(`     ${t.message}`);
          console.log(`     File: ${t.file}`);
          const playbook = getPlaybook(t.type);
          if (playbook) {
            console.log(`     \u2192 ${playbook}`);
          }
          console.log('');
        });
        if (hiddenCount > 0) {
          console.log(`  + ${hiddenCount} low-confidence signal(s) hidden (use --verbose to show)\n`);
        }
        if (domainFilteredOut > 0) {
          console.log(`  + ${domainFilteredOut} threat(s) hidden by --domain filter (score unchanged)\n`);
        }
      }
    }

    // Sandbox section (normal)
    if (sandboxData) {
      console.log(`[SANDBOX] Dynamic analysis — ${sandboxData.package}`);
      console.log(`  Score:    ${sandboxData.score}/100`);
      console.log(`  Severity: ${sandboxData.severity}`);
      if (sandboxData.findings.length === 0) {
        console.log('  No suspicious behavior detected.\n');
      } else {
        console.log(`  ${sandboxData.findings.length} finding(s):`);
        sandboxData.findings.forEach(f => {
          console.log(`    [${f.severity}] ${f.type}: ${f.detail}`);
        });
        console.log('');
      }
    }
  }
}

module.exports = { formatOutput };
