const { detectSuddenLifecycleChange } = require('../temporal-analysis.js');
const { detectSuddenAstChanges } = require('../temporal-ast-diff.js');
const { detectPublishAnomaly } = require('../publish-anomaly.js');
const { detectMaintainerChange } = require('../maintainer-change.js');

/**
 * Run all temporal analyses (lifecycle, AST diff, publish anomaly, maintainer change).
 * Each analysis is gated by its own option flag.
 * @param {string} targetPath - scan target
 * @param {Object} options - scan options (temporal, temporalAst, temporalPublish, temporalMaintainer, _capture, json)
 * @param {string[]} pkgNames - installed package names from listInstalledPackages()
 * @returns {Promise<Array>} array of threat objects
 */
async function runTemporalAnalyses(targetPath, options, pkgNames) {
  const threats = [];

  // Temporal analysis (--temporal flag, off by default)
  if (options.temporal) {
    if (!options._capture && !options.json) {
      console.log('[TEMPORAL] Analyzing lifecycle script changes (this makes network requests)...\n');
    }
    {
      const TEMPORAL_CONCURRENCY = 5;
      for (let i = 0; i < pkgNames.length; i += TEMPORAL_CONCURRENCY) {
        const batch = pkgNames.slice(i, i + TEMPORAL_CONCURRENCY);
        const results = await Promise.allSettled(
          batch.map(name => detectSuddenLifecycleChange(name))
        );
        for (const r of results) {
          if (r.status !== 'fulfilled' || !r.value.suspicious) continue;
          const det = r.value;
          for (const f of det.findings) {
            const isCriticalScript = ['preinstall', 'install', 'postinstall'].includes(f.script);
            const threatType = f.type === 'lifecycle_added'
              ? (isCriticalScript ? 'lifecycle_added_critical' : 'lifecycle_added_high')
              : 'lifecycle_modified';
            threats.push({
              type: threatType,
              severity: f.severity,
              message: `Package "${det.packageName}" v${det.latestVersion} ${f.type === 'lifecycle_added' ? 'added' : 'modified'} ${f.script} script (not in v${det.previousVersion}). Script: "${f.type === 'lifecycle_modified' ? f.newValue : f.value}"`,
              file: `node_modules/${det.packageName}/package.json`
            });
          }
        }
      }
    }
  }

  // Temporal AST analysis (--temporal-ast or --temporal-full flag, off by default)
  if (options.temporalAst) {
    if (!options._capture && !options.json) {
      console.log('[TEMPORAL-AST] Analyzing dangerous API changes (this downloads tarballs)...\n');
    }
    {
      const AST_CONCURRENCY = 3;
      for (let i = 0; i < pkgNames.length; i += AST_CONCURRENCY) {
        const batch = pkgNames.slice(i, i + AST_CONCURRENCY);
        const results = await Promise.allSettled(
          batch.map(name => detectSuddenAstChanges(name))
        );
        for (const r of results) {
          if (r.status !== 'fulfilled' || !r.value.suspicious) continue;
          const det = r.value;
          for (const f of det.findings) {
            const threatType = f.severity === 'CRITICAL' ? 'dangerous_api_added_critical'
              : f.severity === 'HIGH' ? 'dangerous_api_added_high'
              : 'dangerous_api_added_medium';
            threats.push({
              type: threatType,
              severity: f.severity,
              message: `Package "${det.packageName}" v${det.latestVersion} now uses ${f.pattern} (not in v${det.previousVersion})`,
              file: `node_modules/${det.packageName}/package.json`
            });
          }
        }
      }
    }
  }

  // Temporal publish frequency analysis (--temporal-publish or --temporal-full flag, off by default)
  if (options.temporalPublish) {
    if (!options._capture && !options.json) {
      console.log('[TEMPORAL-PUBLISH] Analyzing publish frequency anomalies (this makes network requests)...\n');
    }
    {
      const PUBLISH_CONCURRENCY = 5;
      const publishThreats = [];
      for (let i = 0; i < pkgNames.length; i += PUBLISH_CONCURRENCY) {
        const batch = pkgNames.slice(i, i + PUBLISH_CONCURRENCY);
        const results = await Promise.allSettled(
          batch.map(name => detectPublishAnomaly(name))
        );
        for (const r of results) {
          if (r.status !== 'fulfilled' || !r.value.suspicious) continue;
          const det = r.value;
          for (const a of det.anomalies) {
            publishThreats.push({
              type: a.type,
              severity: a.severity,
              message: a.description,
              file: `node_modules/${det.packageName}/package.json`,
              _scope: det.packageName.startsWith('@') ? det.packageName.split('/')[0] : null
            });
          }
        }
      }

      // P7: Scope-aware deduplication for monorepo releases.
      // When 3+ packages from the same @scope trigger publish_burst or rapid_succession,
      // it's a coordinated monorepo release (lerna, nx, turbo), not an attack.
      // Downgrade all findings for that scope to LOW severity.
      const MONOREPO_SCOPE_THRESHOLD = 3;
      const scopeTypeCounts = new Map(); // key: `${scope}:${type}` → count
      for (const t of publishThreats) {
        if (!t._scope) continue;
        const key = `${t._scope}:${t.type}`;
        scopeTypeCounts.set(key, (scopeTypeCounts.get(key) || 0) + 1);
      }
      for (const t of publishThreats) {
        if (t._scope) {
          const key = `${t._scope}:${t.type}`;
          if ((scopeTypeCounts.get(key) || 0) >= MONOREPO_SCOPE_THRESHOLD) {
            t.severity = 'LOW';
          }
        }
        delete t._scope; // clean up internal field
        threats.push(t);
      }
    }
  }

  // Temporal maintainer change analysis (--temporal-maintainer or --temporal-full flag, off by default)
  if (options.temporalMaintainer) {
    if (!options._capture && !options.json) {
      console.log('[TEMPORAL-MAINTAINER] Analyzing maintainer changes (this makes network requests)...\n');
    }
    {
      const MAINTAINER_CONCURRENCY = 5;
      for (let i = 0; i < pkgNames.length; i += MAINTAINER_CONCURRENCY) {
        const batch = pkgNames.slice(i, i + MAINTAINER_CONCURRENCY);
        const results = await Promise.allSettled(
          batch.map(name => detectMaintainerChange(name))
        );
        for (const r of results) {
          if (r.status !== 'fulfilled' || !r.value.suspicious) continue;
          const det = r.value;
          for (const f of det.findings) {
            threats.push({
              type: f.type,
              severity: f.severity,
              message: f.description,
              file: `node_modules/${det.packageName}/package.json`
            });
          }
        }
      }
    }
  }

  return threats;
}

module.exports = { runTemporalAnalyses };
