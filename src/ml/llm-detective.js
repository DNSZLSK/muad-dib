'use strict';

/**
 * LLM Detective — Claude Haiku-based package analysis for FP reduction.
 *
 * Reads ALL source code from a suspect package and asks Haiku to determine
 * if it's real malware or a false positive. Operates in two modes:
 *   - shadow (default): log verdict, don't affect webhook flow
 *   - active: suppress webhook for high-confidence benign, enrich for malicious
 *
 * No external dependency — uses native fetch() against the Anthropic Messages API.
 *
 * Security: NEVER sends sandboxResult (contains honey tokens).
 */

const fs = require('fs');
const path = require('path');
const { findFiles } = require('../utils.js');

// ── Constants ──

const API_URL = 'https://api.anthropic.com/v1/messages';
const MODEL_ID = 'claude-haiku-4-5-20251001';
const MAX_CONTEXT_BYTES = 100 * 1024; // 100KB cap for source code in prompt
const LLM_TIMEOUT_MS = 60000; // 60s timeout per API call
const LLM_CONCURRENCY_MAX = 2; // max simultaneous API calls
const LLM_DAILY_LIMIT_DEFAULT = 100;
const MAX_SINGLE_FILE_BYTES = 512 * 1024; // skip individual files > 512KB

// Extensions to collect from packages
const SOURCE_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.json', '.py'];

// ── Semaphore (pattern: src/shared/http-limiter.js) ──

const _semaphore = { active: 0, queue: [] };

function acquireLlmSlot() {
  if (_semaphore.active < LLM_CONCURRENCY_MAX) {
    _semaphore.active++;
    return Promise.resolve();
  }
  return new Promise(resolve => {
    _semaphore.queue.push(resolve);
  });
}

function releaseLlmSlot() {
  if (_semaphore.queue.length > 0) {
    const next = _semaphore.queue.shift();
    next();
  } else {
    _semaphore.active--;
  }
}

// ── Daily quota counter (in-memory, resets at midnight UTC) ──

const _dailyCounter = { count: 0, resetDate: null };

function getTodayUTC() {
  return new Date().toISOString().slice(0, 10);
}

function isDailyQuotaAvailable() {
  const today = getTodayUTC();
  if (_dailyCounter.resetDate !== today) {
    _dailyCounter.count = 0;
    _dailyCounter.resetDate = today;
  }
  return _dailyCounter.count < getDailyLimit();
}

function incrementDailyCounter() {
  const today = getTodayUTC();
  if (_dailyCounter.resetDate !== today) {
    _dailyCounter.count = 0;
    _dailyCounter.resetDate = today;
  }
  _dailyCounter.count++;
}

function getDailyLimit() {
  return Math.max(1, parseInt(process.env.MUADDIB_LLM_DAILY_LIMIT, 10) || LLM_DAILY_LIMIT_DEFAULT);
}

function getDailyCount() {
  return _dailyCounter.count;
}

function resetDailyCounter() {
  _dailyCounter.count = 0;
  _dailyCounter.resetDate = null;
}

// ── Feature flags ──

function isLlmEnabled() {
  if (!process.env.ANTHROPIC_API_KEY) return false;
  const env = process.env.MUADDIB_LLM_ENABLED;
  if (env !== undefined && env.toLowerCase() === 'false') return false;
  return true;
}

function getLlmMode() {
  const env = process.env.MUADDIB_LLM_MODE;
  if (env && env.toLowerCase() === 'active') return 'active';
  return 'shadow';
}

// ── Stats ──

const _stats = { analyzed: 0, malicious: 0, benign: 0, uncertain: 0, errors: 0, skipped: 0 };

function getStats() {
  return { ..._stats };
}

function resetStats() {
  _stats.analyzed = 0;
  _stats.malicious = 0;
  _stats.benign = 0;
  _stats.uncertain = 0;
  _stats.errors = 0;
  _stats.skipped = 0;
}

// ── Source context collection ──

/**
 * Collect source files from an extracted package directory.
 * Respects MAX_CONTEXT_BYTES cap. If over, falls back to priority files.
 *
 * @param {string} extractedDir - path to extracted package
 * @param {Object} scanResult - scan result with threats[].file for priority
 * @returns {{ files: Array<{path: string, content: string}>, truncated: boolean, totalBytes: number }}
 */
function collectSourceContext(extractedDir, scanResult) {
  const allFiles = findFiles(extractedDir, {
    extensions: SOURCE_EXTENSIONS,
    maxFiles: 200
  });

  const fileEntries = [];
  let totalBytes = 0;
  let truncated = false;

  // Try to include all files
  for (const filePath of allFiles) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > MAX_SINGLE_FILE_BYTES) continue;
      if (totalBytes + stat.size > MAX_CONTEXT_BYTES) {
        truncated = true;
        break;
      }
      const content = fs.readFileSync(filePath, 'utf8');
      const relPath = path.relative(extractedDir, filePath).replace(/\\/g, '/');
      totalBytes += Buffer.byteLength(content, 'utf8');
      fileEntries.push({ path: relPath, content });
    } catch {
      // Skip unreadable files
    }
  }

  // If truncated, restart with priority files only
  if (truncated) {
    fileEntries.length = 0;
    totalBytes = 0;
    truncated = true;

    const flaggedFiles = new Set(
      ((scanResult && scanResult.threats) || [])
        .map(t => t.file)
        .filter(Boolean)
    );

    // Priority order: package.json, flagged files, entry point, README
    const priorityRelPaths = new Set();
    priorityRelPaths.add('package.json');
    for (const f of flaggedFiles) priorityRelPaths.add(f);

    // Read package.json to find entry point
    try {
      const pkgJsonPath = path.join(extractedDir, 'package.json');
      const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      if (pkgJson.main) priorityRelPaths.add(pkgJson.main);
      if (pkgJson.bin) {
        const bins = typeof pkgJson.bin === 'string' ? [pkgJson.bin] : Object.values(pkgJson.bin || {});
        for (const b of bins) if (b) priorityRelPaths.add(b);
      }
    } catch {}

    priorityRelPaths.add('README.md');
    priorityRelPaths.add('readme.md');

    for (const relPath of priorityRelPaths) {
      const absPath = path.join(extractedDir, relPath);
      try {
        if (!fs.existsSync(absPath)) continue;
        const stat = fs.statSync(absPath);
        if (stat.size > MAX_SINGLE_FILE_BYTES) continue;
        if (totalBytes + stat.size > MAX_CONTEXT_BYTES) continue;
        const content = fs.readFileSync(absPath, 'utf8');
        totalBytes += Buffer.byteLength(content, 'utf8');
        fileEntries.push({ path: relPath.replace(/\\/g, '/'), content });
      } catch {}
    }
  }

  return { files: fileEntries, truncated, totalBytes };
}

// ── Prompt construction ──

const SYSTEM_PROMPT = `You are a senior supply-chain security analyst performing the SAME investigation a human would do manually. You receive source code of a suspect package and static scanner results.

CRITICAL: The scanner findings are SIGNALS, not truth. Your job is to INDEPENDENTLY determine if this package is malicious by reading the code yourself. Many scanner findings are false positives — a CLI tool using child_process is not malware.

## YOUR INVESTIGATION METHOD

Do exactly what a human analyst would:

Step 1 — DECLARED PURPOSE: Read package.json. What does this package claim to do? Is the name/description/repo coherent?

Step 2 — CODE REALITY: Read ALL the code. Does it actually do what the description says? A "color picker" with child_process.exec is suspicious. A "CLI wrapper" with child_process.exec is normal.

Step 3 — DATA FLOW INTENT: When code accesses process.env or credentials:
- Is it CONFIGURING itself (reading DATABASE_URL, API_KEY for its own backend)? → BENIGN
- Is it COLLECTING and SENDING data to a third-party domain? → MALICIOUS
Follow the data: where does it GO?

Step 4 — DESTINATION CHECK: If data is sent somewhere:
- To the package's own documented API/backend? → BENIGN
- To a raw IP, ngrok/serveo tunnel, or unrelated domain? → MALICIOUS
- To nowhere (data is only read, never exfiltrated)? → BENIGN

Step 5 — COHERENCE: Does the complexity match the purpose?
- 3-file package with postinstall downloading binaries? → SUSPICIOUS
- Build tool with postinstall compiling native addon? → NORMAL
- Obfuscated code in a 10-line utility? → SUSPICIOUS
- Minified dist/ in a large framework? → NORMAL

## GOLDEN RULE

If sensitive data (env vars, credentials, keys) is only READ for self-configuration and never SENT to an external third-party, the package is BENIGN regardless of what the scanner says.

If sensitive data is COLLECTED and EXFILTRATED to a domain unrelated to the package's stated purpose, it is MALICIOUS.

## REFERENCE EXAMPLES

EXAMPLE 1 — TRUE MALWARE:
Package "slopex-cli" claims to be a "continuity patcher for OpenAI Codex". Postinstall downloads a binary from a personal GitHub repo and REPLACES the real Codex binary. The binary is not part of the described functionality — it's a trojan replacing a trusted tool.
→ Verdict: MALICIOUS (backdoor, confidence 0.97)

EXAMPLE 2 — FALSE POSITIVE:
Package "@yeaft/webchat-agent" is a "remote agent for WebChat connecting worker machines". Code uses execSync to locate the Claude CLI binary, process.env to read PATH configuration. Scanner flags "detached_credential_exfil" (CRITICAL) — but the code is just spawning a documented CLI tool and reading PATH. No data is sent to any external domain. The functionality matches the description.
→ Verdict: BENIGN (confidence 0.92)

EXAMPLE 3 — TRUE MALWARE:
Package "event-stream" (compromised via flatmap-stream dependency). Obfuscated code hidden in a nested dependency decrypts a payload targeting Bitcoin wallet data from Copay. The obfuscation has no legitimate reason — the parent package is a simple stream utility. The decrypted code specifically targets cryptocurrency credentials.
→ Verdict: MALICIOUS (credential_exfil, confidence 0.98)

EXAMPLE 4 — FALSE POSITIVE:
A web framework reads process.env.DATABASE_URL, process.env.API_KEY for configuration. It uses fetch() to call its own documented API endpoint. It uses dynamic require() to load user-configured plugins. Scanner flags env_access, dynamic_require, network_require — but all these are standard framework patterns. No data leaves the application boundary.
→ Verdict: BENIGN (confidence 0.95)

## KEY QUESTIONS TO ANSWER

1. "Do sensitive data (env vars, credentials) LEAVE the package to a third party?"
2. "Does the code do something HIDDEN that the description doesn't mention?"
3. "Is obfuscation justified (build tool output) or suspicious (tiny package, no build step)?"
4. "Does the postinstall relate to the declared functionality?"
5. "Could a reasonable developer have written this code for the stated purpose?"

## COMMON FALSE POSITIVE PATTERNS (do NOT flag these)

- CLI tools/wrappers using exec/spawn to run other CLI tools (their stated purpose)
- SDK packages reading API keys from env vars (standard configuration)
- Build tools with postinstall that compile native addons (node-gyp, prebuild)
- Packages reading process.env for feature flags, logging config, or database URLs
- Monorepo tooling with dynamic require for loading workspace packages
- Test frameworks that use eval() or vm.runInContext for sandboxed test execution

RESPOND IN STRICT JSON ONLY (nothing else):
{
  "verdict": "malicious" | "benign" | "uncertain",
  "confidence": 0.0-1.0,
  "investigation_steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
  "reasoning": "Final summary of your analysis",
  "iocs_found": ["domain.com", "1.2.3.4"],
  "attack_type": "credential_exfil" | "reverse_shell" | "crypto_miner" | "backdoor" | "typosquat" | "protestware" | null,
  "recommendation": "block" | "monitor" | "safe"
}`;

/**
 * Build the messages array for the Anthropic API call.
 *
 * @param {string} name - package name
 * @param {string} version - package version
 * @param {string} ecosystem - 'npm' or 'pypi'
 * @param {{ files: Array, truncated: boolean, totalBytes: number }} sourceContext
 * @param {Array} threats - scan findings
 * @param {Object} npmRegistryMeta - registry metadata (optional)
 * @returns {{ system: string, messages: Array }}
 */
function buildPrompt(name, version, ecosystem, sourceContext, threats, npmRegistryMeta) {
  let userContent = `## Package: ${name}@${version} (${ecosystem})\n\n`;

  // Registry metadata
  if (npmRegistryMeta) {
    userContent += `## Registry Metadata\n`;
    if (npmRegistryMeta.age_days !== undefined) userContent += `- Age: ${npmRegistryMeta.age_days} days\n`;
    if (npmRegistryMeta.weekly_downloads !== undefined) userContent += `- Weekly downloads: ${npmRegistryMeta.weekly_downloads}\n`;
    if (npmRegistryMeta.version_count !== undefined) userContent += `- Version count: ${npmRegistryMeta.version_count}\n`;
    if (npmRegistryMeta.author_package_count !== undefined) userContent += `- Author package count: ${npmRegistryMeta.author_package_count}\n`;
    if (npmRegistryMeta.has_repository !== undefined) userContent += `- Has repository: ${npmRegistryMeta.has_repository}\n`;
    userContent += '\n';
  }

  // Static scanner findings — framed as signals to challenge
  if (threats && threats.length > 0) {
    userContent += `## Static Scanner Signals (${threats.length} total — these are SIGNALS to investigate, not confirmed threats)\n`;
    for (const t of threats.slice(0, 30)) {
      const loc = t.file ? ` in ${t.file}${t.line ? ':' + t.line : ''}` : '';
      userContent += `- [${t.severity}] ${t.type}${loc}: ${t.message || ''}\n`;
    }
    if (threats.length > 30) {
      userContent += `... and ${threats.length - 30} more signals\n`;
    }
    userContent += '\n';
  }

  // Source code
  userContent += `## Source Code (${sourceContext.files.length} files, ${sourceContext.totalBytes} bytes${sourceContext.truncated ? ', TRUNCATED — only priority files shown' : ''})\n\n`;
  for (const file of sourceContext.files) {
    userContent += `### ${file.path}\n\`\`\`\n${file.content}\n\`\`\`\n\n`;
  }

  return {
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: userContent }]
  };
}

// ── Anthropic API call ──

/**
 * Call the Anthropic Messages API with retry on 429/5xx.
 *
 * @param {string} system - system prompt
 * @param {Array} messages - conversation messages
 * @returns {Promise<string>} response text content
 */
async function callAnthropicAPI(system, messages) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY not set');

  const body = JSON.stringify({
    model: MODEL_ID,
    max_tokens: 2048,
    system,
    messages
  });

  const maxAttempts = 2;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);

    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body,
        signal: controller.signal
      });

      clearTimeout(timeout);

      if (response.ok) {
        const data = await response.json();
        if (data.content && data.content[0] && data.content[0].text) {
          return data.content[0].text;
        }
        throw new Error('Unexpected response format');
      }

      // Retry on 429 or 5xx
      if ((response.status === 429 || response.status >= 500) && attempt < maxAttempts - 1) {
        const delay = 2000 * (attempt + 1);
        console.log(`[LLM] API ${response.status}, retrying in ${delay}ms...`);
        await new Promise(r => setTimeout(r, delay));
        continue;
      }

      const errorText = await response.text().catch(() => '');
      throw new Error(`API ${response.status}: ${errorText.slice(0, 200)}`);
    } catch (err) {
      clearTimeout(timeout);
      if (err.name === 'AbortError') {
        throw new Error(`API timeout (${LLM_TIMEOUT_MS}ms)`);
      }
      if (attempt < maxAttempts - 1 && err.message && /ECONNRESET|ETIMEDOUT|ENOTFOUND/.test(err.message)) {
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }
      throw err;
    }
  }
}

// ── Response parsing ──

/**
 * Parse LLM response text into structured verdict object.
 * Handles raw JSON and markdown-fenced JSON.
 *
 * @param {string} text - raw response text
 * @returns {{ verdict: string, confidence: number, reasoning: string, iocs_found: string[], attack_type: string|null, recommendation: string }}
 */
function parseResponse(text) {
  const fallback = {
    verdict: 'uncertain',
    confidence: 0,
    investigation_steps: [],
    reasoning: 'Failed to parse LLM response',
    iocs_found: [],
    attack_type: null,
    recommendation: 'monitor'
  };

  if (!text || typeof text !== 'string') return fallback;

  let parsed;
  try {
    parsed = JSON.parse(text.trim());
  } catch {
    // Try extracting JSON from markdown fence
    const fenceMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceMatch) {
      try {
        parsed = JSON.parse(fenceMatch[1].trim());
      } catch {
        return fallback;
      }
    } else {
      // Try finding first { ... } block
      const start = text.indexOf('{');
      const end = text.lastIndexOf('}');
      if (start !== -1 && end > start) {
        try {
          parsed = JSON.parse(text.substring(start, end + 1));
        } catch {
          return fallback;
        }
      } else {
        return fallback;
      }
    }
  }

  // Validate and normalize
  const validVerdicts = ['malicious', 'benign', 'uncertain'];
  const verdict = validVerdicts.includes(parsed.verdict) ? parsed.verdict : 'uncertain';

  let confidence = parseFloat(parsed.confidence);
  if (isNaN(confidence)) confidence = 0;
  confidence = Math.max(0, Math.min(1, confidence));

  const validRecommendations = ['block', 'monitor', 'safe'];
  const recommendation = validRecommendations.includes(parsed.recommendation) ? parsed.recommendation : 'monitor';

  return {
    verdict,
    confidence: Math.round(confidence * 1000) / 1000,
    investigation_steps: Array.isArray(parsed.investigation_steps) ? parsed.investigation_steps.filter(x => typeof x === 'string').slice(0, 10) : [],
    reasoning: typeof parsed.reasoning === 'string' ? parsed.reasoning : '',
    iocs_found: Array.isArray(parsed.iocs_found) ? parsed.iocs_found.filter(x => typeof x === 'string').slice(0, 20) : [],
    attack_type: typeof parsed.attack_type === 'string' ? parsed.attack_type : null,
    recommendation
  };
}

// ── Main entry point ──

/**
 * Investigate a suspect package with Claude Haiku.
 *
 * @param {string} extractedDir - path to extracted package source
 * @param {Object} scanResult - static scan result with threats[] and summary
 * @param {Object} options - { name, version, ecosystem, registryMeta, npmRegistryMeta, tier }
 * @returns {Promise<Object|null>} verdict object or null on skip/error
 */
async function investigatePackage(extractedDir, scanResult, options = {}) {
  const { name, version, ecosystem, npmRegistryMeta, tier } = options;

  // Guard rails
  if (!isLlmEnabled()) {
    _stats.skipped++;
    return null;
  }

  if (!isDailyQuotaAvailable()) {
    _stats.skipped++;
    console.log(`[LLM] Daily quota exhausted (${_dailyCounter.count}/${getDailyLimit()}) — skipping ${name}@${version}`);
    return null;
  }

  await acquireLlmSlot();
  try {
    incrementDailyCounter();

    // Collect source files
    const sourceContext = collectSourceContext(extractedDir, scanResult);
    if (sourceContext.files.length === 0) {
      _stats.skipped++;
      console.log(`[LLM] No source files found in ${name}@${version} — skipping`);
      return null;
    }

    // Build prompt
    const threats = (scanResult && scanResult.threats) || [];
    const { system, messages } = buildPrompt(
      name || 'unknown', version || '0.0.0', ecosystem || 'npm',
      sourceContext, threats, npmRegistryMeta
    );

    // Call API
    const responseText = await callAnthropicAPI(system, messages);

    // Parse response
    const result = parseResponse(responseText);
    result.mode = getLlmMode();

    // Update stats
    _stats.analyzed++;
    if (result.verdict === 'malicious') _stats.malicious++;
    else if (result.verdict === 'benign') _stats.benign++;
    else _stats.uncertain++;

    return result;
  } catch (err) {
    _stats.errors++;
    console.error(`[LLM] Investigation error for ${name}@${version}: ${err.message}`);
    return null;
  } finally {
    releaseLlmSlot();
  }
}

// ── Reset for testing ──

function resetLlmLimiter() {
  _semaphore.active = 0;
  _semaphore.queue.length = 0;
}

module.exports = {
  investigatePackage,
  isLlmEnabled,
  getLlmMode,
  getDailyLimit,
  getDailyCount,
  isDailyQuotaAvailable,
  incrementDailyCounter,
  getStats,
  resetStats,
  resetDailyCounter,
  resetLlmLimiter,
  // Exported for testing
  collectSourceContext,
  buildPrompt,
  parseResponse,
  // Constants for testing
  MAX_CONTEXT_BYTES,
  LLM_CONCURRENCY_MAX,
  LLM_DAILY_LIMIT_DEFAULT
};
