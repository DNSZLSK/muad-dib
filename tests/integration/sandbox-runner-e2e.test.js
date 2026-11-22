'use strict';
// End-to-end check of docker/sandbox-runner.sh in a real container: builds an image from the
// working tree's docker/ under a test tag, runs it with the exact production arguments
// (buildDockerArgs) on a small benign local package, and reads the report. Catches what a
// shape-only test cannot: an install that fails before anything is analyzed, and a mock
// network that is not in the DNS path. Needs Docker; skipped in CI unless MUADDIB_TEST_DOCKER=1.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { asyncTest, assert, addSkipped } = require('../test-utils');

const DOCKER_DIR = path.join(__dirname, '..', '..', 'docker');
const TEST_IMAGE = 'muaddib-sandbox:runner-e2e-test';

function dockerUp() {
  const r = spawnSync('docker', ['info', '--format', '{{.ServerVersion}}'], { encoding: 'utf8', timeout: 20000 });
  return r.status === 0 && (r.stdout || '').trim().length > 0;
}

async function runSandboxRunnerE2ETests() {
  console.log('\n=== SANDBOX RUNNER E2E (Docker) ===\n');
  if (process.env.CI && !process.env.MUADDIB_TEST_DOCKER) { addSkipped(1, 'CI - sandbox runner e2e needs MUADDIB_TEST_DOCKER=1'); return; }
  if (!dockerUp()) { addSkipped(1, 'Docker not available - sandbox runner e2e skipped'); return; }
  const build = spawnSync('docker', ['build', '-q', '-t', TEST_IMAGE, DOCKER_DIR], { encoding: 'utf8', timeout: 600000 });
  if (build.status !== 0) { addSkipped(1, 'sandbox image build failed (network?) - e2e skipped: ' + String(build.stderr).slice(0, 200)); return; }
  try {
    await runAgainstTestImage();
  } finally {
    // Never leave the test image behind (layers shared with other images are kept by Docker).
    spawnSync('docker', ['image', 'rm', '-f', TEST_IMAGE], { encoding: 'utf8', timeout: 60000 });
  }
}

async function runAgainstTestImage() {
  const { buildDockerArgs } = require('../../src/sandbox/index.js');
  const { generateCanaryTokens } = require('../../src/integrations/canary-tokens.js');
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-runner-e2e-'));
  fs.writeFileSync(path.join(fixture, 'package.json'), JSON.stringify({
    name: 'runner-e2e-fixture', version: '1.0.0', main: 'index.js',
    // Looks up a safe domain, then writes and runs a small executable in the install
    // directory (as packages that ship a binary do): fails with EACCES on a noexec mount.
    // It also leaves a marker the entry point reports: npm 12 skips dependency install
    // scripts unless allowed (--dangerously-allow-all-scripts in the runner), silently.
    scripts: { postinstall: "node -e \"require('dns').lookup('github.com',()=>{});const f=require('fs');f.writeFileSync('/sandbox/install/postinstall-ran','1');f.writeFileSync('/sandbox/install/probe.sh','#!/bin/sh\\nexit 0\\n',{mode:0o755});require('child_process').execFileSync('/sandbox/install/probe.sh')\"" }
  }));
  fs.writeFileSync(path.join(fixture, 'index.js'), "if (require('fs').existsSync('/sandbox/install/postinstall-ran')) console.log('POSTINSTALL_RAN');\nmodule.exports = 1;\n");

  try {
    const args = buildDockerArgs({
      canaryTokens: generateCanaryTokens().tokens, containerName: 'runner-e2e-' + Date.now(), fakeHostname: 'dev-laptop-0000',
      local: true, localAbsPath: fixture, packageName: fixture, mode: 'permissive', upstreamDns: '8.8.8.8'
    });
    args[args.indexOf('muaddib-sandbox')] = TEST_IMAGE;
    const run = spawnSync('docker', args, { encoding: 'utf8', timeout: 180000 });
    const out = run.stdout || '';
    const i = out.lastIndexOf('---MUADDIB-REPORT-START---');
    let report = null;
    try { report = JSON.parse(out.slice(i + '---MUADDIB-REPORT-START---'.length).trim()); } catch { /* asserted below */ }

    await asyncTest('SANDBOX-E2E: a local package installs and its entry point loads', async () => {
      assert(report, 'the runner must print a parsable report, stderr tail: ' + String(run.stderr).slice(-300));
      assert(report.exit_code === 0, `npm install must succeed, exit_code=${report.exit_code}, install_output=${String(report.install_output).slice(-300)}`);
      assert(!/\[ENTRY_ERROR\]/.test(report.entrypoint_output || ''), 'the entry point must load: ' + String(report.entrypoint_output).slice(0, 300));
    });

    await asyncTest('SANDBOX-E2E: the dependency install script runs (not skipped by an npm allowScripts policy)', async () => {
      assert(report && /POSTINSTALL_RAN/.test(report.entrypoint_output || ''), 'the postinstall must have run before the entry point, entrypoint_output=' + JSON.stringify(report && report.entrypoint_output));
    });

    // Registry install, as the monitor does it (by name and exact version): this one needs
    // the npm cache, which the runner could not create in the root-owned home tmpfs (EACCES,
    // nothing installed, nothing analyzed). Needs network access to the npm registry.
    const regArgs = buildDockerArgs({
      canaryTokens: generateCanaryTokens().tokens, containerName: 'runner-e2e-reg-' + Date.now(), fakeHostname: 'dev-laptop-0000',
      packageName: 'is-number', version: '7.0.0', mode: 'permissive', upstreamDns: '8.8.8.8'
    });
    regArgs[regArgs.indexOf('muaddib-sandbox')] = TEST_IMAGE;
    const reg = spawnSync('docker', regArgs, { encoding: 'utf8', timeout: 180000 });
    const rOut = reg.stdout || '';
    let regReport = null;
    try { regReport = JSON.parse(rOut.slice(rOut.lastIndexOf('---MUADDIB-REPORT-START---') + '---MUADDIB-REPORT-START---'.length).trim()); } catch { /* asserted below */ }

    await asyncTest('SANDBOX-E2E: a registry package installs (no EACCES on the npm cache) and its entry point loads', async () => {
      assert(regReport, 'the runner must print a parsable report, stderr tail: ' + String(reg.stderr).slice(-300));
      assert(!/EACCES/.test(regReport.install_output || ''), 'no EACCES in the install output: ' + String(regReport.install_output).slice(-400));
      assert(regReport.exit_code === 0, `npm install must succeed, exit_code=${regReport.exit_code}, install_output=${String(regReport.install_output).slice(-300)}`);
      assert(!/\[ENTRY_ERROR\]/.test(regReport.entrypoint_output || ''), 'the entry point must load: ' + String(regReport.entrypoint_output).slice(0, 300));
      assert(/Installing is-number@7\.0\.0/.test(reg.stderr || ''), 'the runner must install the exact version passed by the host');
    });

    // An ESM-only package that declares only "exports" (no "main"): loading it by absolute
    // path ignored "exports" (MODULE_NOT_FOUND), so its code never ran.
    const esmArgs = buildDockerArgs({
      canaryTokens: generateCanaryTokens().tokens, containerName: 'runner-e2e-esm-' + Date.now(), fakeHostname: 'dev-laptop-0000',
      packageName: 'chalk', version: '6.0.1', mode: 'permissive', upstreamDns: '8.8.8.8'
    });
    esmArgs[esmArgs.indexOf('muaddib-sandbox')] = TEST_IMAGE;
    const esm = spawnSync('docker', esmArgs, { encoding: 'utf8', timeout: 180000 });
    const eOut = esm.stdout || '';
    let esmReport = null;
    try { esmReport = JSON.parse(eOut.slice(eOut.lastIndexOf('---MUADDIB-REPORT-START---') + '---MUADDIB-REPORT-START---'.length).trim()); } catch { /* asserted below */ }

    await asyncTest('SANDBOX-E2E: an ESM-only package declaring only "exports" is loaded at the entry point step', async () => {
      assert(esmReport && esmReport.exit_code === 0, 'install must succeed, got ' + JSON.stringify(esmReport && esmReport.install_output).slice(-300));
      assert(!/\[ENTRY_ERROR\]/.test(esmReport.entrypoint_output || ''), 'the entry point must load: ' + String(esmReport.entrypoint_output).slice(0, 300));
    });

    await asyncTest('SANDBOX-E2E: DNS goes through the mock network and safe-domain lookups are reported', async () => {
      assert(report && report.mock_network && report.mock_network.dns_in_path === true,
        'mock_network.dns_in_path must be true, got ' + JSON.stringify(report && report.mock_network));
      const safe = (report.network && report.network.safe_dns_queries) || [];
      assert(safe.includes('github.com'), 'the install-time lookup of github.com must be in network.safe_dns_queries, got ' + JSON.stringify(safe));
    });
  } finally {
    try { fs.rmSync(fixture, { recursive: true, force: true }); } catch { /* ignore */ }
  }

  // Time-offset run (run 2: +72 h through libfaketime): the entry point must really execute.
  // libfaketime also accelerated `timeout 30`, which killed node in about 30 ms, so those
  // runs reported CLEAN without having run the package.
  const probe = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-runner-e2e-entry-'));
  fs.writeFileSync(path.join(probe, 'package.json'), JSON.stringify({ name: 'entry-probe', version: '1.0.0', main: 'index.js' }));
  fs.writeFileSync(path.join(probe, 'index.js'), 'console.log("ENTRY_RAN"); module.exports = 1;\n');
  try {
    const offArgs = buildDockerArgs({
      canaryTokens: generateCanaryTokens().tokens, containerName: 'runner-e2e-off-' + Date.now(), fakeHostname: 'dev-laptop-0000',
      local: true, localAbsPath: probe, packageName: probe, mode: 'permissive', upstreamDns: '8.8.8.8', timeOffset: 259200000
    });
    offArgs[offArgs.indexOf('muaddib-sandbox')] = TEST_IMAGE;
    const off = spawnSync('docker', offArgs, { encoding: 'utf8', timeout: 180000 });
    const oOut = off.stdout || '';
    let offReport = null;
    try { offReport = JSON.parse(oOut.slice(oOut.lastIndexOf('---MUADDIB-REPORT-START---') + '---MUADDIB-REPORT-START---'.length).trim()); } catch { /* asserted below */ }

    await asyncTest('SANDBOX-E2E: under the +72 h time offset (libfaketime) the entry point still executes', async () => {
      assert(offReport, 'the runner must print a parsable report, stderr tail: ' + String(off.stderr).slice(-300));
      assert(/libfaketime active/.test(off.stderr || ''), 'this run must use libfaketime');
      assert(/ENTRY_RAN/.test(offReport.entrypoint_output || ''), 'the entry point must run, entrypoint_output=' + JSON.stringify(offReport.entrypoint_output));
    });
  } finally {
    try { fs.rmSync(probe, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

module.exports = { runSandboxRunnerE2ETests };
