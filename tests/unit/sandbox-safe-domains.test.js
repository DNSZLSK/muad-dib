'use strict';
// The sandbox "safe domain" list exists in four copies:
//   - docker/mock-network.js  SAFE_DOMAINS          container DNS: forwarded to the real resolver
//   - docker/preload.js       MOCK_SAFE_DOMAINS     container http/https/net: real network
//   - src/sandbox/network-allowlist.js  SAFE_INSTALL_DOMAINS  host scoring: not scored
//   - src/sandbox/index.js    SAFE_DOMAINS          host network report display ([OK]/[!!])
// A domain added to one copy and not to the others silently changes what reaches the real
// network or what is scored. This characterization test freezes the current relationship,
// including its known differences: any change to a copy must update this test explicitly.
// The two docker/ scripts cannot be loaded in a test (mock-network.js binds its servers at
// load time; the preload list lives inside a closure), so their array literals are
// evaluated from the AST, not searched as text.
const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');
const { test, assert } = require('../test-utils');

const ROOT = path.join(__dirname, '..', '..');

function arrayLiteral(relFile, name) {
  const ast = acorn.parse(fs.readFileSync(path.join(ROOT, relFile), 'utf8'),
    { ecmaVersion: 'latest', allowReturnOutsideFunction: true });
  const found = [];
  walk.simple(ast, {
    VariableDeclarator(n) {
      if (n.id && n.id.name === name && n.init && n.init.type === 'ArrayExpression') {
        found.push(n.init.elements.map(e => (e && e.type === 'Literal' ? e.value : null)));
      }
    }
  });
  if (found.length !== 1) throw new Error(`${relFile}: expected one array literal ${name}, found ${found.length}`);
  if (found[0].some(v => typeof v !== 'string')) throw new Error(`${relFile}: ${name} must hold string literals only`);
  return found[0];
}

const minus = (a, b) => a.filter(x => !b.includes(x)).sort();
const same = (a, b) => JSON.stringify(a) === JSON.stringify([...b].sort());

function runSandboxSafeDomainsTests() {
  console.log('\n=== SANDBOX SAFE DOMAIN LISTS ===\n');

  const mock = arrayLiteral('docker/mock-network.js', 'SAFE_DOMAINS');
  const preload = arrayLiteral('docker/preload.js', 'MOCK_SAFE_DOMAINS');
  const hostScoring = require('../../src/sandbox/network-allowlist').SAFE_INSTALL_DOMAINS;
  const hostReport = require('../../src/sandbox/index').SAFE_DOMAINS;

  test('SAFE-DOMAINS: no copy holds a duplicate entry', () => {
    for (const [label, list] of [['mock-network', mock], ['preload', preload],
      ['network-allowlist', hostScoring], ['index', hostReport]]) {
      assert(new Set(list).size === list.length, `${label} list has a duplicate entry`);
    }
  });

  test('SAFE-DOMAINS: the preload and the mock DNS let the same domains reach the real network', () => {
    assert(same(minus(mock, preload), []) && same(minus(preload, mock), []),
      `preload and mock-network lists differ: only in mock [${minus(mock, preload)}], only in preload [${minus(preload, mock)}]`);
  });

  test('SAFE-DOMAINS: host scoring treats as safe only domains the container forwards (frozen: fastly.* forwarded but scored)', () => {
    assert(same(minus(hostScoring, mock), []),
      `network-allowlist has domains the container does not forward: [${minus(hostScoring, mock)}]`);
    assert(same(minus(mock, hostScoring), ['fastly.com', 'fastly.net']),
      `forwarded but scored domains changed: [${minus(mock, hostScoring)}] (frozen: fastly.com, fastly.net)`);
  });

  test('SAFE-DOMAINS: the network report list is a frozen subset of the host scoring list', () => {
    assert(same(minus(hostReport, hostScoring), []),
      `index.js SAFE_DOMAINS has domains not in network-allowlist: [${minus(hostReport, hostScoring)}]`);
    const frozen = ['amazonaws.com', 'bitbucket.org', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
      'github.githubassets.com', 'gitlab.com', 'nodejs.org', 'registry.yarnpkg.com',
      'storage.googleapis.com', 'unpkg.com'];
    assert(same(minus(hostScoring, hostReport), frozen),
      `scoring-only domains changed: [${minus(hostScoring, hostReport)}]`);
  });
}

module.exports = { runSandboxSafeDomainsTests };
