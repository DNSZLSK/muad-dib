const { test, asyncTest, assert } = require('../test-utils');

async function runTemporalRunnerTests() {
  console.log('\n=== TEMPORAL RUNNER TESTS ===\n');

  const { runTemporalAnalyses } = require('../../src/temporal-runner.js');

  // --- No flags enabled ---

  await asyncTest('TEMPORAL-RUNNER: No flags returns empty threats', async () => {
    const threats = await runTemporalAnalyses('/fake', {}, []);
    assert(Array.isArray(threats), 'Should return array');
    assert(threats.length === 0, 'No flags = no threats');
  });

  // --- temporal flag with empty pkgNames ---

  await asyncTest('TEMPORAL-RUNNER: temporal flag with empty pkgNames', async () => {
    const threats = await runTemporalAnalyses('/fake', { temporal: true, _capture: true }, []);
    assert(Array.isArray(threats), 'Should return array');
    assert(threats.length === 0, 'Empty pkgNames = no threats');
  });

  // --- temporalAst flag with empty pkgNames ---

  await asyncTest('TEMPORAL-RUNNER: temporalAst flag with empty pkgNames', async () => {
    const threats = await runTemporalAnalyses('/fake', { temporalAst: true, _capture: true }, []);
    assert(Array.isArray(threats), 'Should return array');
    assert(threats.length === 0, 'Empty pkgNames = no threats');
  });

  // --- temporalPublish flag with empty pkgNames ---

  await asyncTest('TEMPORAL-RUNNER: temporalPublish flag with empty pkgNames', async () => {
    const threats = await runTemporalAnalyses('/fake', { temporalPublish: true, _capture: true }, []);
    assert(Array.isArray(threats), 'Should return array');
    assert(threats.length === 0, 'Empty pkgNames = no threats');
  });

  // --- temporalMaintainer flag with empty pkgNames ---

  await asyncTest('TEMPORAL-RUNNER: temporalMaintainer flag with empty pkgNames', async () => {
    const threats = await runTemporalAnalyses('/fake', { temporalMaintainer: true, _capture: true }, []);
    assert(Array.isArray(threats), 'Should return array');
    assert(threats.length === 0, 'Empty pkgNames = no threats');
  });

  // --- All four flags combined ---

  await asyncTest('TEMPORAL-RUNNER: All four flags combined with empty pkgNames', async () => {
    const threats = await runTemporalAnalyses('/fake', {
      temporal: true, temporalAst: true, temporalPublish: true, temporalMaintainer: true,
      _capture: true
    }, []);
    assert(Array.isArray(threats), 'Should return array');
    assert(threats.length === 0, 'Empty pkgNames = no threats even with all flags');
  });

  // --- Mock detector results to cover loop bodies ---
  // Note: temporal-runner.js destructures imports at load time, so we need
  // to clear the require cache and re-require after patching detector modules.

  const path = require('path');
  const runnerPath = require.resolve('../../src/scanner/temporal-runner.js');

  function patchAndRequireRunner(modulePath, patchFn) {
    // Patch the detector module
    const mod = require(modulePath);
    const orig = Object.assign({}, mod);
    patchFn(mod);
    // Clear temporal-runner cache so it re-imports the patched module
    delete require.cache[runnerPath];
    const { runTemporalAnalyses: patched } = require(runnerPath);
    return { patched, restore: () => { Object.assign(mod, orig); delete require.cache[runnerPath]; } };
  }

  // Monkey-patch detectSuddenLifecycleChange to return suspicious result
  await asyncTest('TEMPORAL-RUNNER: temporal flag with suspicious lifecycle result', async () => {
    const { patched, restore } = patchAndRequireRunner('../../src/temporal-analysis.js', (mod) => {
      mod.detectSuddenLifecycleChange = async () => ({
        suspicious: true,
        packageName: 'mock-pkg',
        latestVersion: '2.0.0',
        previousVersion: '1.0.0',
        findings: [
          { type: 'lifecycle_added', script: 'postinstall', severity: 'CRITICAL', value: 'node evil.js' },
          { type: 'lifecycle_added', script: 'prepare', severity: 'HIGH', value: 'node setup.js' },
          { type: 'lifecycle_modified', script: 'test', severity: 'MEDIUM', newValue: 'node test.js' }
        ]
      });
    });
    try {
      const threats = await patched('/fake', { temporal: true, _capture: true }, ['mock-pkg']);
      assert(threats.length === 3, 'Should have 3 threats, got ' + threats.length);
      assert(threats[0].type === 'lifecycle_added_critical', 'postinstall should be lifecycle_added_critical');
      assert(threats[0].severity === 'CRITICAL', 'postinstall should be CRITICAL');
      assert(threats[1].type === 'lifecycle_added_high', 'prepare should be lifecycle_added_high');
      assert(threats[2].type === 'lifecycle_modified', 'test should be lifecycle_modified');
      assert(threats[0].file.includes('mock-pkg'), 'File should reference mock-pkg');
      assert(threats[0].message.includes('mock-pkg'), 'Message should include package name');
      assert(threats[0].message.includes('postinstall'), 'Message should include script name');
    } finally {
      restore();
    }
  });

  // Monkey-patch detectSuddenAstChanges to return suspicious result
  await asyncTest('TEMPORAL-RUNNER: temporalAst flag with suspicious AST changes', async () => {
    const { patched, restore } = patchAndRequireRunner('../../src/temporal-ast-diff.js', (mod) => {
      mod.detectSuddenAstChanges = async () => ({
        suspicious: true,
        packageName: 'ast-pkg',
        latestVersion: '3.0.0',
        previousVersion: '2.0.0',
        findings: [
          { pattern: 'child_process', severity: 'CRITICAL' },
          { pattern: 'fetch', severity: 'HIGH' },
          { pattern: 'dns.lookup', severity: 'MEDIUM' }
        ]
      });
    });
    try {
      const threats = await patched('/fake', { temporalAst: true, _capture: true }, ['ast-pkg']);
      assert(threats.length === 3, 'Should have 3 threats, got ' + threats.length);
      assert(threats[0].type === 'dangerous_api_added_critical', 'CRITICAL finding should map to _critical type');
      assert(threats[1].type === 'dangerous_api_added_high', 'HIGH finding should map to _high type');
      assert(threats[2].type === 'dangerous_api_added_medium', 'MEDIUM finding should map to _medium type');
      assert(threats[0].message.includes('child_process'), 'Message should include pattern name');
    } finally {
      restore();
    }
  });

  // Monkey-patch detectPublishAnomaly to return suspicious result
  await asyncTest('TEMPORAL-RUNNER: temporalPublish flag with suspicious publish', async () => {
    const { patched, restore } = patchAndRequireRunner('../../src/publish-anomaly.js', (mod) => {
      mod.detectPublishAnomaly = async () => ({
        suspicious: true,
        packageName: 'pub-pkg',
        anomalies: [
          { type: 'publish_burst', severity: 'HIGH', description: '5 versions in 1 hour' },
          { type: 'dormant_spike', severity: 'CRITICAL', description: 'No releases for 8 months' }
        ]
      });
    });
    try {
      const threats = await patched('/fake', { temporalPublish: true, _capture: true }, ['pub-pkg']);
      assert(threats.length === 2, 'Should have 2 threats, got ' + threats.length);
      assert(threats[0].type === 'publish_burst', 'Should be publish_burst');
      assert(threats[1].type === 'dormant_spike', 'Should be dormant_spike');
      assert(threats[0].file.includes('pub-pkg'), 'File should reference pub-pkg');
    } finally {
      restore();
    }
  });

  // Monkey-patch detectMaintainerChange to return suspicious result
  await asyncTest('TEMPORAL-RUNNER: temporalMaintainer flag with suspicious maintainer', async () => {
    const { patched, restore } = patchAndRequireRunner('../../src/maintainer-change.js', (mod) => {
      mod.detectMaintainerChange = async () => ({
        suspicious: true,
        packageName: 'maint-pkg',
        findings: [
          { type: 'sole_maintainer_change', severity: 'CRITICAL', description: 'Sole maintainer changed' },
          { type: 'new_maintainer', severity: 'HIGH', description: 'New maintainer added' }
        ]
      });
    });
    try {
      const threats = await patched('/fake', { temporalMaintainer: true, _capture: true }, ['maint-pkg']);
      assert(threats.length === 2, 'Should have 2 threats, got ' + threats.length);
      assert(threats[0].type === 'sole_maintainer_change', 'Should be sole_maintainer_change');
      assert(threats[1].type === 'new_maintainer', 'Should be new_maintainer');
    } finally {
      restore();
    }
  });

  // Test rejected promise handling (non-suspicious result)
  await asyncTest('TEMPORAL-RUNNER: temporal skips non-suspicious results', async () => {
    const { patched, restore } = patchAndRequireRunner('../../src/temporal-analysis.js', (mod) => {
      mod.detectSuddenLifecycleChange = async () => ({ suspicious: false, packageName: 'safe-pkg' });
    });
    try {
      const threats = await patched('/fake', { temporal: true, _capture: true }, ['safe-pkg']);
      assert(threats.length === 0, 'Non-suspicious result should produce 0 threats');
    } finally {
      restore();
    }
  });

  // Test rejected promise handling (error)
  await asyncTest('TEMPORAL-RUNNER: temporal handles rejected promise gracefully', async () => {
    const { patched, restore } = patchAndRequireRunner('../../src/temporal-analysis.js', (mod) => {
      mod.detectSuddenLifecycleChange = async () => { throw new Error('Network failure'); };
    });
    try {
      const threats = await patched('/fake', { temporal: true, _capture: true }, ['fail-pkg']);
      assert(threats.length === 0, 'Rejected promise should not produce threats');
    } finally {
      restore();
    }
  });

  // Test console logging when _capture is false and json is false
  await asyncTest('TEMPORAL-RUNNER: temporal logs when _capture and json are false', async () => {
    const { patched, restore } = patchAndRequireRunner('../../src/temporal-analysis.js', (mod) => {
      mod.detectSuddenLifecycleChange = async () => ({ suspicious: false });
    });
    const origLog = console.log;
    const logs = [];
    console.log = (msg) => logs.push(msg);
    try {
      await patched('/fake', { temporal: true }, ['pkg']);
      assert(logs.some(l => l.includes('[TEMPORAL]')), 'Should log TEMPORAL header');
    } finally {
      console.log = origLog;
      restore();
    }
  });

  // Test batch processing with multiple packages
  await asyncTest('TEMPORAL-RUNNER: temporal batches multiple packages', async () => {
    let callCount = 0;
    const { patched, restore } = patchAndRequireRunner('../../src/temporal-analysis.js', (mod) => {
      mod.detectSuddenLifecycleChange = async (name) => {
        callCount++;
        if (name === 'evil-pkg') {
          return {
            suspicious: true,
            packageName: name,
            latestVersion: '2.0.0',
            previousVersion: '1.0.0',
            findings: [{ type: 'lifecycle_added', script: 'postinstall', severity: 'CRITICAL', value: 'node evil.js' }]
          };
        }
        return { suspicious: false };
      };
    });
    try {
      const pkgs = ['pkg-a', 'pkg-b', 'pkg-c', 'evil-pkg', 'pkg-d', 'pkg-e', 'pkg-f'];
      const threats = await patched('/fake', { temporal: true, _capture: true }, pkgs);
      assert(callCount === 7, 'Should call detector for all 7 packages, got ' + callCount);
      assert(threats.length === 1, 'Should have 1 threat from evil-pkg, got ' + threats.length);
    } finally {
      restore();
    }
  });
}

module.exports = { runTemporalRunnerTests };
