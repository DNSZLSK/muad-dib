'use strict';

const path = require('path');
const { asyncTest, assert, runScanDirect } = require('../test-utils');
const { initPythonParser } = require('../../src/scanner/python-ast.js');

const FIXTURES = path.join(__dirname, '..', 'samples', 'python-ast');

async function findCryptoExfil(fixture) {
  const result = await runScanDirect(path.join(FIXTURES, fixture));
  return {
    found: (result.threats || []).find(t => t.type === 'crypto_exfil'),
    all: (result.threats || []).map(t => t.type),
    riskScore: (result.summary && result.summary.riskScore) || 0
  };
}

async function runCryptoExfilPythonTests() {
  console.log('\n=== CRYPTO-EXFIL PYTHON TESTS (COMPOUND-019, PyPI mirror) ===\n');

  // Ensure the tree-sitter Python parser is loaded (pre-analysis bootstrap).
  await initPythonParser();

  // ── Positive ─────────────────────────────────────────────────────────────
  await asyncTest('COMPOUND-019 (py): env secret + RSA/AES + POST to non-provider fires crypto_exfil', async () => {
    const { found, all, riskScore } = await findCryptoExfil('crypto-exfil-py');
    assert(found, `expected crypto_exfil, got: ${all.join(', ')}`);
    assert(found.severity === 'CRITICAL', `expected CRITICAL, got ${found.severity}`);
    // Lock the single-fire floor (the whole point of the scoring.js change): a lone
    // crypto_exfil CRITICAL on PyPI must reach 75 via SINGLE_FIRE_CRITICAL_TYPES, NOT be
    // buried at 25-35 by the PyPI cap. Presence+severity alone are silent on the floor —
    // if crypto_exfil were dropped from the set, the score would fall back to ~25-35 while
    // the CRITICAL still fires, and only this assertion would catch the regression.
    assert(riskScore >= 75, `single-fire floor expected riskScore >= 75, got ${riskScore}`);
  });

  // ── Negatives (each isolates one gate) ─────────────────────────────────────
  await asyncTest('COMPOUND-019 (py) negative: encrypt + POST to first-party provider does not fire (destAllBenign)', async () => {
    const { found } = await findCryptoExfil('crypto-exfil-benign-dest');
    assert(!found, 'crypto_exfil must NOT fire when every destination is a curated provider (api.stripe.com)');
  });

  await asyncTest('COMPOUND-019 (py) negative: encrypt + POST without credential harvest does not fire (E2E lib)', async () => {
    const { found } = await findCryptoExfil('crypto-exfil-no-harvest');
    assert(!found, 'crypto_exfil must NOT fire without a secret-harvest signal (encrypts caller data, not stolen creds)');
  });

  await asyncTest('COMPOUND-019 (py) negative: transport wrapper loading its OWN crypto key from env does not fire (CRYPTO_CONFIG_ENV exclusion)', async () => {
    const { found } = await findCryptoExfil('crypto-exfil-keyconfig');
    assert(!found, 'crypto_exfil must NOT fire when the env var is a crypto KEY (ENCRYPTION_KEY) read to encrypt — that is transport config, not credential harvesting');
  });

  await asyncTest('COMPOUND-019 (py) negative: harvest + POST without encryption does not fire', async () => {
    const { found } = await findCryptoExfil('crypto-exfil-no-crypto');
    assert(!found, 'crypto_exfil must NOT fire without an encryption primitive (plain env->network is pyast_env_to_network_write, not this compound)');
  });
}

module.exports = { runCryptoExfilPythonTests };
