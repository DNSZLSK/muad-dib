# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Security mindset

Tu es un ingénieur sécurité senior spécialisé en supply chain attack detection (npm/PyPI).
Chaque règle de détection, chaque modification du scoring, chaque décision d'architecture
doit être justifiée par un threat model concret. Pense comme un attaquant : si tu ajoutes
une détection, demande-toi comment un adversaire la contournerait. Si tu modifies le scoring,
demande-toi comment un attaquant pourrait le manipuler.

Priorités :
- Zéro régression sur les détections existantes
- FPR ne doit jamais augmenter après un changement
- Chaque nouveau pattern doit avoir un test positif ET un test négatif
- Les compound detections ne doivent se déclencher que sur des combinaisons réellement malveillantes

## Commands

```bash
npm test          # Run all tests (custom framework, 2093 tests across 49 files)
npm run lint      # ESLint with security plugin
npm run scan      # Self-scan: node bin/muaddib.js scan .
npm run update    # Download latest IOCs
```

Scan a specific scanner's test fixtures:
```bash
node bin/muaddib.js scan tests/samples/ast --explain
node bin/muaddib.js scan tests/samples/entropy
```

Tests use a custom framework in `tests/run-tests.js` (no Jest). Test helpers:
- `test(name, fn)` / `asyncTest(name, fn)` — sync/async test registration
- `runScan(target, options)` — executes CLI and captures stdout
- `assert(cond, msg)` / `assertIncludes(str, substr, msg)`

**Important:** `execSync` throws on non-zero exit codes. When scanning test fixtures that contain threats, wrap in try/catch and read `e.stdout`.

## Architecture

**CLI entry:** `bin/muaddib.js` — yargs-based dispatcher, delegates to `src/index.js`.

**Core orchestration:** `src/index.js` — `run(targetPath, options)` runs cross-file module graph analysis first, then launches 13 individual scanners in parallel via `Promise.all` (14 scanner modules total), then deduplicates, applies FP reductions, scores using per-file max (v2.2.11: `riskScore = min(100, max(file_scores) + package_level_score)`, severity weights: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1), applies intent coherence analysis (intra-file source-sink pairing), enriches with rules/playbooks (134 rules), and outputs (CLI/JSON/HTML/SARIF). Result includes `warnings: []` array (v2.6.5) for incomplete scan notifications (module graph timeout/skip, deobfuscation failures). Exports `isPackageLevelThreat` and `computeGroupScore` for testing.

**Scanner pattern:** Each of the 13 individual scanners in `src/scanner/` returns `Array<{type, severity, message, file}>`:
- `file` must use `path.relative(targetPath, absolutePath)` for Windows compatibility
- Sync scanners are wrapped in `Promise.resolve()` in the Promise.all
- Use `findFiles(dir, { extensions, excludedDirs })` from `src/utils.js` for file walking
- Size guard: skip files > 10MB via `fs.statSync`

**PyPI support:** `src/scanner/python.js` detects Python projects by scanning `requirements.txt`, `setup.py`, and `pyproject.toml`. Dependencies are matched against PyPI IOCs (14K+ from OSV dump) and checked for typosquatting via Levenshtein distance with PEP 503 normalization.

**Supply Chain Anomaly Detection (v2.0):** 5 behavioral detection features that detect attacks before IOCs exist:
- `src/temporal-analysis.js` — Sudden lifecycle script detection (`--temporal`): detects `preinstall`/`install`/`postinstall` added in latest version
- `src/temporal-ast-diff.js` — Temporal AST diff (`--temporal-ast`): compares ASTs between versions to detect newly added dangerous APIs
- `src/publish-anomaly.js` — Publish frequency anomaly (`--temporal-publish`): detects publish bursts, dormant spikes, rapid succession
- `src/maintainer-change.js` — Maintainer change detection (`--temporal-maintainer`): detects new/suspicious maintainers, sole maintainer change
- `src/canary-tokens.js` — Canary tokens (sandbox): injects fake credentials and detects exfiltration attempts
- `--temporal-full` enables all 4 temporal features at once

**Sandbox Enhancements (v2.1.2):**
- CI-aware environment: `sandbox-runner.sh` sets CI=true, GITHUB_ACTIONS, GITLAB_CI, TRAVIS, CIRCLECI, JENKINS_URL to trigger CI-aware malware
- Enriched canary tokens: 6 static honeypots (GITHUB_TOKEN, NPM_TOKEN, AWS keys, SLACK/DISCORD webhooks) as fallback to dynamic tokens
- `detectStaticCanaryExfiltration()` in `src/sandbox/index.js` searches all report fields for static canary values
- Strict webhook filtering: monitor alerts only for IOC match, sandbox confirm, or canary exfiltration

**Sandbox Monkey-Patching Preload (v2.4.9):** `docker/preload.js` is a runtime monkey-patching script injected via `NODE_OPTIONS=--require /opt/preload.js` in the Docker sandbox. Detects time-bomb malware (MITRE T1497.003) that delays exfiltration past sandbox timeout.
- **Architecture**: `src/sandbox/index.js` (migrated from `src/sandbox.js`) orchestrates 3 sequential Docker runs at time offsets [0ms, 72h, 7d]. `runSandbox()` calls `runSingleSandbox()` with `MUADDIB_TIME_OFFSET_MS` env var. Early exit on score >= 80.
- **Preload patches** (IIFE, closure-scoped originals): Time APIs (Date.now, constructor, performance.now, process.hrtime/bigint, process.uptime), timers (setTimeout→0, setInterval→immediate first exec), network (http/https.request, fetch, dns, net.connect), filesystem (sensitive path detection via regex), process (child_process.* with dangerous command detection), environment (Proxy on process.env for sensitive key access).
- **Analyzer**: `src/sandbox/analyzer.js` parses `[PRELOAD]` log lines with 6 scoring rules: timer delay suspicious (>1h, MEDIUM +15), timer delay critical (>24h, CRITICAL +30, supersedes suspicious), sensitive file read (HIGH +20), network after sensitive read (CRITICAL +40, compound), exec suspicious (HIGH +25), env token access (MEDIUM +10).
- **Docker changes**: `docker/Dockerfile` copies `preload.js` to `/opt/preload.js`. `docker/sandbox-runner.sh` sets `NODE_OPTIONS`, captures `/tmp/preload.log`, includes `preload_log` in JSON report.

**Security Hardening (v2.1.2):**
- `src/shared/download.js` — SSRF-safe downloadToFile (domain allowlist + private IP blocking), injection-safe extractTarGz (execFileSync), sanitizePackageName (path traversal prevention)
- `src/shared/constants.js` — Centralized NPM_PACKAGE_REGEX, MAX_TARBALL_SIZE, DOWNLOAD_TIMEOUT

**Validation & Observability (v2.1):** Features for measuring and validating scanner effectiveness:
- `src/ground-truth.js` — Ground truth dataset: 51 real-world attacks (49 active) replayed against scanner. 93.9% TPR (46/49).
- `--breakdown` flag — Explainable score decomposition showing per-finding contribution

**AI Config Scanner (v2.2):** `src/scanner/ai-config.js` scans AI agent configuration files (`.cursorrules`, `.cursorignore`, `.windsurfrules`, `CLAUDE.md`, `AGENT.md`, `.github/copilot-instructions.md`, `copilot-setup-steps.yml`) for prompt injection patterns. Detects shell commands, exfiltration, credential access, and injection instructions. Compound detection (shell + exfil/credentials) escalates to CRITICAL.

**Deobfuscation Pre-processing (v2.2.5):** `src/scanner/deobfuscate.js` applies static AST-based deobfuscation before AST and dataflow scanners. 4 transformations: string concat folding, charcode reconstruction, base64 decode, hex array resolution. Phase 2 const propagation resolves `const x = 'literal'` references. Additive approach: original code scanned first (preserves obfuscation signals), then deobfuscated code adds new findings. Disable with `--no-deobfuscate`.

**Inter-module Dataflow (v2.2.6, bounded path v2.6.1):** `src/scanner/module-graph.js` builds a dependency graph of local modules, annotates tainted exports (fs.readFileSync, process.env, os.homedir, os.hostname, os.userInfo, os.networkInterfaces, child_process, dns), and detects when credentials read in one module reach a network/exec sink in another module. Features: 3-hop re-export chain propagation, class method analysis, named export destructuring, inline require re-export, function-wrapped taint propagation. v2.6.1 additions: bounded path (MAX_GRAPH_NODES=50, MAX_GRAPH_EDGES=200, MAX_FLOWS=20, 5s timeout), imported sink method detection, class `this.X` instance taint, stream pipeline `.pipe()` chain following, EventEmitter cross-module detection, pipe chain cross-file flows. Runs before individual scanners. Disable with `--no-module-graph`.

**Evaluation Framework (v2.2, corrected v2.2.7, FP reduction v2.2.8–v2.2.9, size analysis v2.2.10, per-file scoring v2.2.11, GT expansion v2.2.12, FP reduction P2 v2.3.0, P3 v2.3.1, Vague 4 v2.4.7, sandbox preload v2.4.9, FP reduction P4 v2.5.7–v2.5.8):** `src/commands/evaluate.js` measures TPR (Ground Truth, 49 real attacks from 51 samples), FPR (Benign, 529 npm packages — real source code via `npm pack` + native tar extraction), and ADR (Adversarial + Holdout, 83 evasive samples — 43 adversarial + 40 holdout). Benign tarballs cached in `.muaddib-cache/benign-tarballs/`. Flags: `--benign-limit N`, `--refresh-benign`. Results saved to `metrics/v{version}.json`. FPR progression: 0% (invalid, v2.2.0–v2.2.6) → 38% (v2.2.7) → 19.4% (v2.2.8) → 17.5% (v2.2.9) → ~13% (69/527, v2.2.11) → 8.9% (47/527, v2.3.0) → 7.4% (39/525, v2.3.1) → 6.0% (32/529, v2.5.8, included BENIGN_PACKAGE_WHITELIST bias) → ~13.6% (72/529, v2.5.14, audit hardening + whitelist removed in v2.5.10) → **12.3% (65/529, v2.5.16, P5+P6, honest measurement without whitelisting)** → **12.3% (65/532, v2.6.0, intent graph v2, zero FP added)** → **12.1% (64/529, v2.6.2, FP reduction P7)**. Adversarial samples in `datasets/adversarial/` (53 samples), holdout samples in `datasets/holdout-v2/` through `datasets/holdout-v5/` (40 samples), benign package lists in `datasets/benign/packages-npm.txt` (532 packages) and `datasets/benign/packages-pypi.txt` (132 packages), ground truth attacks in `tests/ground-truth/attacks.json` (51 entries), ground truth malware database in `datasets/ground-truth/known-malware.json` (65 entries).

**FP Reduction Post-processing (v2.2.8–v2.2.9, v2.3.0–v2.3.1):** `applyFPReductions()` in `src/scoring.js` applies count-based severity downgrades between deduplication and scoring. Thresholds: `dynamic_require` >10 HIGH→LOW, `dangerous_call_function` >5 MEDIUM→LOW, `require_cache_poison` >3 CRITICAL→LOW (single hit CRITICAL→HIGH), `suspicious_dataflow` >5 any→LOW, `obfuscation_detected` >3 any→LOW, `module_compile` >3 HIGH→LOW, `module_compile_dynamic` >3 HIGH→LOW, `zlib_inflate_eval` >2 CRITICAL→LOW, `credential_regex_harvest` >4 HIGH→LOW. Framework prototype hooks (Request/Response/App/Router.prototype) downgraded HIGH→MEDIUM (CRITICAL core prototypes untouched). HTTP client prototype whitelist: packages with >20 prototype_hook hits targeting HTTP methods → MEDIUM. Prototype hook MEDIUM scoring capped at 15 points max. Dist/build/minified file downgrade (one severity notch). Reachability-based downgrade (unreachable files → LOW). Typosquat whitelist expanded with 10 packages (chai, pino, ioredis, bcryptjs, recast, asyncdi, redux, args, oxlint, vasync). Scanner-level: expanded `SAFE_ENV_VARS` (+13 vars) and added `SAFE_ENV_PREFIXES` (npm_config_*, npm_lifecycle_*, npm_package_*, lc_*) in `src/scanner/ast.js`. Obfuscation in dist/build/*.bundle.js and .cjs/.mjs >100KB → LOW. Entropy: encoding table paths → LOW. Dataflow: os.platform/arch categorized as `telemetry_read` (capped at HIGH, not CRITICAL). Package scanner: `DEP_FP_WHITELIST` (es5-ext, bootstrap-sass), npm alias skip (`npm:` prefix).

**Per-File Max Scoring (v2.2.11):** Replaces global score accumulation with per-file max scoring. Formula: `riskScore = min(100, max(file_scores) + package_level_score)`. Threats are split into package-level (lifecycle scripts, typosquat, IOC matches, sandbox findings — classified by `PACKAGE_LEVEL_TYPES` Set + file heuristics) and file-level (AST, dataflow, obfuscation). File-level threats grouped by `threat.file`, each group scored independently via `computeGroupScore()`. Package-level threats scored separately. Result includes `globalRiskScore` (old sum), `maxFileScore`, `packageScore`, `mostSuspiciousFile`, `fileScores` map.

**Ground Truth Expansion (v2.2.12):** 51 real-world attack samples in `tests/ground-truth/` (49 active, 2 with min_threats=0). TPR: **93.9% (46/49)** as of v2.5.16. 3 out-of-scope misses: lottie-player, polyfill-io, trojanized-jquery (browser-only). 3 new detection rules: `crypto_decipher` (MUADDIB-AST-022, T1140), `module_compile` (MUADDIB-AST-023, T1059), `.secretKey`/`.privateKey` credential source in dataflow. ADR consolidated: 120 samples (53 adversarial + 40 holdout, 75 available on disk). ADR: **94.8% (73/77 available)** as of v2.6.2. 2 misses: `require-cache-poison` (P3 trade-off), `getter-defineProperty-exfil`.

**Scan Freeze Fix (v2.2.22):** Module graph scanner's `EXCLUDED_DIRS` aligned with main scanner to prevent infinite loops on `dist/`, `build/`, `.next/` directories.

**npm Package Fix (v2.2.23):** `.npmignore` updated to exclude ground-truth malware samples and adversarial datasets from the published npm package.

**Coverage Expansion (v2.2.24):** Tests expanded from 862 to 1317 (+455). Coverage 72% → 86% (c8 line coverage). All scanner, infrastructure, and utility modules covered.

**FP Reduction P2 (v2.3.0):** FPR ~13% → 8.9% (47/527). Dataflow scanner: os.* methods split into `fingerprint_read` (hostname, networkInterfaces, userInfo, homedir) and `telemetry_read` (platform, arch); telemetry-only findings capped at HIGH. Scoring: `module_compile` added to FP_COUNT_THRESHOLDS (>3 CRITICAL→LOW). Package scanner: `DEP_FP_WHITELIST` (es5-ext, bootstrap-sass), npm alias skip.

**FP Reduction P3 (v2.3.1):** FPR 8.2% → 7.4% (39/525). Scoring: `require_cache_poison` single hit CRITICAL→HIGH; HTTP client prototype whitelist (>20 hits → MEDIUM); obfuscation: .cjs/.mjs >100KB → LOW; entropy: encoding table paths → LOW. ADR: 100% → 98.7% (77/78, 1 documented miss: require-cache-poison). 8 new rules (AST-024 to AST-031), rule count 94 → 102. Tests 1317 → 1387. Current rule count: **134** (129 RULES + 5 PARANOID) as of v2.7.5.

**Security Audit (v2.5.0–v2.5.6):** Comprehensive security audit with 41 issues remediated across 5 versions: 10 initial remediations (14 CRITICAL, 18 HIGH) in v2.5.0, sandbox fixes (npm install timeout, preload timing, Docker caps, /proc/uptime) in v2.5.1–v2.5.3, 3 CRITICAL remediations (#10 native addon, #15 atomic writes, #18 AST bypasses) in v2.5.4, 14 HIGH remediations in v2.5.5, 5 MEDIUM remediations completing 41/41 in v2.5.6.

**FP Reduction P4 (v2.5.7–v2.5.8):** FPR 7.4% → **6.0% (32/529)**. Webhook noise reduction + `/usr/bin/timeout` whitelist. IOC wildcard audit: removed false IOC entries causing spurious matches. Tests: 1522 → **1656** (+134). Test files: 22 → **42**.

**Vague 4 Blue Team (v2.4.7):** 5 new adversarial samples (43 total). Pre-fix score 0/5 (0%). 5 bypass corrections: `resolveStringConcat()` for BinaryExpression string concat resolution, enhanced AST-027/AST-028 with deep string resolution + variable path tracking, fixed `new Function()` not setting `ctx.hasDynamicExec`, content-level compound detection for MCP/IDE/binary patterns. 3 new rules: `fetch_decrypt_exec` (AST-033, CRITICAL), `download_exec_binary` (AST-034, CRITICAL), `ide_persistence` (AST-035, HIGH). Post-fix: 5/5 (100%). ADR: 98.8% (82/83). Rule count: 107 (102 RULES + 5 PARANOID).

**Sandbox Preload (v2.4.9):** Multi-run sandbox with monkey-patching preload for time-bomb detection. 3 runs at [0h, 72h, 7d] offsets. 6 new sandbox preload rules (SANDBOX-009 to 014). Rule count: 121 (116 RULES + 5 PARANOID).

**Audit Hardening (v2.5.13):** 5 batches of hardening fixes: (1) Scoring: per-file plugin loader threshold (prevents cross-file dilution), lifecycle CRITICAL floor (packageScore >= 50 when CRITICAL present), percentage guard tightened 50%→40%. (2) IOC integrity: HMAC race condition fix (write before rename), `.hmac-initialized` marker enforcement, scraper HMAC consistency. (3) Sandbox: NODE_OPTIONS locked via Object.defineProperty to prevent preload bypass in child processes. (4) Dataflow: Promise `.then()` callback tainting for `fs.promises.readFile`, `fs.readFile` callback second-param tainting. (5) Deobfuscation: TemplateLiteral support in `tryFoldConcat`, ArrayPattern destructuring in Phase 2 const propagation. Tests: 1656 → **1790** (+134). Test files: 42 → **43**.

**Audit Hardening (v2.5.14):** 5 batches of hardening fixes targeting 14 remaining audit findings: (1) AST: eval alias bypass detection (`const E = eval; E(code)`), globalThis indirect assignment via aliases, require(obj.prop) object property resolution, variable reassignment tracking (`let x = 'child_'; x += 'process'; require(x)`). (2) Dataflow: JSON.stringify/parse/toString/String() taint propagation, removed fetchOnlySafeDomains guard from download_exec_binary compound (fetch+chmod+exec is never legitimate). (3) Shell: 3 new patterns — mkfifo+nc reverse shell, base64 decode pipe to bash, wget+base64 two-stage. (4) Entropy: fragment cluster detection (many short high-entropy strings), windowed analysis for strings > MAX_STRING_LENGTH. (5) Typosquat: pair-aware whitelist (whitelisted packages only skip the specific popular package they resemble, checked against all others). 4 new rules (SHELL-013 to SHELL-015, ENTROPY-004). Tests: 1790 → **1815** (+25). Rule count: 117 → **121** (116 RULES + 5 PARANOID).

**FP Reduction P5 (v2.5.15):** 7 heuristic precision fixes improving detection accuracy without reducing coverage. FPR: ~13.6% (72/529).

**FP Reduction P6 (v2.5.16):** Compound detection precision — 6 fixes: (1) `credential_regex_harvest` count-based downgrade (>4 hits HIGH→LOW — HTTP client libraries). (2) Remove `remote_code_load` and `proxy_data_intercept` from DIST_EXEMPT_TYPES — bundled dist/ files get standard downgrade. (3) Obfuscation large-file heuristic — `.js` >100KB → LOW. (4) Remove `discord`/`leveldb` from SENSITIVE_PATH_PATTERNS — data dirs, not creds. (5) `module_compile`/`module_compile_dynamic` baseline CRITICAL→HIGH — single call is framework behavior. (6) `DATAFLOW_SAFE_ENV_VARS` — exclude Node.js runtime config from credential sources. Tests: 1815 → **1869** (+54). TPR: 91.8% → **93.9%** (46/49). FPR: 13.6% → **12.3%** (65/529). ADR: **94.0%** (63/67 available).

**FP Reduction P7 (v2.6.2):** 7 heuristic fixes: (1) LOW-severity alert filtering in monitor. (2) Monorepo scope grouping for publish anomaly. (3) `env_access` count threshold (>10 → LOW). (4) `suspicious_dataflow` full bypass (removed 80% ratio guard). (5) `high_entropy_string` count threshold (>5 → LOW). (6) Extended DIST_FILE_RE (`out|output`) + `env_access` added to DIST_BUNDLER_ARTIFACT_TYPES. (7) `credential_regex_harvest` threshold lowered (>2 → LOW). Tests: 1869 → **1940** (+71). FPR: 12.3% → **12.1%** (64/529). ADR denominator fixed: counts only available samples. ADR: **94.8%** (73/77 available).

**Audit Remediation (v2.6.5):** Post-audit ANSSI hardening — 6 categories of fixes: (1) Critical safety: removed self-dependency in package.json, recursion depth guard (MAX_TAINT_DEPTH=50) in module-graph.js, redirect limit (MAX_REDIRECTS=5) in download.js, `warnings[]` array in scan results for incomplete scan notifications. (2) Detection bypasses: `env_access` conditional classification in intent-graph.js (sensitive env vars only), percentage guard count-based fix in scoring.js, array destructuring + object alias taint propagation in dataflow.js. (3) Evaluation methodology: global ADR_THRESHOLD=20 (replaces per-sample thresholds), scoped TPR reporting (Node.js vs all), stratified FPR by package size, CI smoke tests. (4) IOC input validation: package name + version format validation in scraper.js. (5) Paranoid mode: eval/Function/require alias tracking in scanParanoid. (6) Documentation: methodology caveats, honest metrics. Tests: 1940 → **1974** (+34).

**Audit Remediation (v2.6.9):** Post-audit technical fixes — 4 phases: (1) Critical: SSRF IPv6 bypass fix (safeDnsResolve resolves IPv4+IPv6), monitor scoring weight alignment (HIGH=10, MEDIUM=3), package.json overrides typo fix, CI version validation. (2) Documentation: rule count, test count, version alignment across README/SECURITY/CHANGELOG/CLAUDE.md. (3) Evaluation methodology: per-sample thresholds replaced with flat sample arrays, FPR operator consistency (>= not >), evaluation smoke tests. (4) Code hardening: Object.create(null) for prototype pollution prevention in module-graph.js, 3 new shell IFS evasion patterns (SHELL-016 to SHELL-018), charcode range validation in deobfuscator. Tests: 2009 → **2042** (+33). Rules: 130 → **133** (128 RULES + 5 PARANOID). Test files: 46 → **49**.

**Webhook Noise Reduction (v2.7.5):** Monitor webhook volume reduction — 4 chantiers: (1) Self-exclude: `SELF_PACKAGE_NAME` constant skips `muaddib-scanner` in pollNpm(). (2) WASM standalone: new rule `wasm_standalone` (AST-046, MEDIUM) for WebAssembly without network sinks, mutually exclusive with `wasm_host_sink` (CRITICAL). (3) Reputation scoring: `computeReputationFactor()` adjusts webhook score based on age/versions/downloads (floor 0.3, ceiling 1.5), IOC matches bypass. (4) Scope dedup: `bufferScopedWebhook()` groups scoped npm packages within 5min window into single grouped Discord webhook. Tests: 2042 → **2093** (+51). Rules: 133 → **134** (129 RULES + 5 PARANOID).

**New AST detection rules (v2.2):**
- MUADDIB-AST-008 to AST-012: Dynamic require with decode patterns, sandbox evasion, detached process, binary dropper patterns
- MUADDIB-AST-013: AI agent abuse (s1ngularity/Nx pattern — `--dangerously-skip-permissions`, `--yolo` flags)
- MUADDIB-AST-014: Credential CLI theft (`gh auth token`, `gcloud auth print-access-token`, `aws sts get-session-token`)
- MUADDIB-AST-015: Workflow write (fs.writeFileSync to `.github/workflows`, with variable propagation + regex fallback)
- MUADDIB-AST-016: Binary dropper (fs.chmodSync 0o755 + exec of temp file)
- MUADDIB-AST-017: Prototype hooking (globalThis.fetch, XMLHttpRequest.prototype, Node.js core module prototypes)
- MUADDIB-AST-018: Env charcode reconstruction (String.fromCharCode to build env var names)
- MUADDIB-AICONF-001: AI config prompt injection (HIGH)
- MUADDIB-AICONF-002: AI config compound injection — shell + exfil/credentials (CRITICAL)
- MUADDIB-PKG-010: Lifecycle shell pipe (curl|sh or wget|sh in preinstall/install/postinstall)
- MUADDIB-FLOW-003: Credential tampering / cache poisoning (sensitive read + write to cache paths)
- MUADDIB-AST-019: Require cache poisoning (require.cache access to hijack loaded modules)
- MUADDIB-AST-020: Staged binary payload (binary file .png/.jpg/.wasm + eval in same file — steganographic execution)
- MUADDIB-AST-021: Staged eval decode (eval/Function with atob or Buffer.from base64 argument — CRITICAL)
- MUADDIB-FLOW-004: Cross-file dataflow (credential read in one module, network exfil in another — CRITICAL)
- MUADDIB-AST-022: Encrypted payload decryption (crypto.createDecipher/createDecipheriv — flatmap-stream pattern, HIGH, T1140)
- MUADDIB-AST-023: Module compile execution (module._compile() — in-memory code execution, HIGH, T1059)
- MUADDIB-AST-024: Obfuscated payload via zlib inflate (zlib.inflateSync + eval — CRITICAL, T1140)
- MUADDIB-AST-025: Dynamic module compile execution (new Module() + _compile — HIGH, T1059)
- MUADDIB-AST-026: Anti-forensics write-execute-delete (write + exec + unlink — HIGH, T1070)
- MUADDIB-AST-027: MCP config injection (MCP server config manipulation — CRITICAL, T1059)
- MUADDIB-AST-028: Git hooks injection (write to .git/hooks — HIGH, T1195.002)
- MUADDIB-AST-029: Dynamic env var harvesting (Object.keys(process.env) — HIGH, T1552)
- MUADDIB-AST-030: DNS chunk exfiltration (dns.resolve with data in subdomain — HIGH, T1048)
- MUADDIB-AST-031: LLM API key harvesting (OPENAI_API_KEY, ANTHROPIC_API_KEY — MEDIUM, T1552)
- MUADDIB-AST-033: Steganographic payload chain (fetch + crypto decrypt + eval/Function — CRITICAL, T1027.003)
- MUADDIB-AST-034: Download-execute binary (download + chmod + execSync — CRITICAL, T1105)
- MUADDIB-AST-035: IDE task persistence (tasks.json + runOn:folderOpen + writeFileSync — HIGH, T1546)
- MUADDIB-SANDBOX-009: Suspicious timer delay (setTimeout/setInterval > 1h — MEDIUM, T1497.003)
- MUADDIB-SANDBOX-010: Critical timer delay / time-bomb (setTimeout/setInterval > 24h — CRITICAL, T1497.003)
- MUADDIB-SANDBOX-011: Preload sensitive file read (.npmrc/.ssh/.aws/.env via runtime monkey-patching — HIGH, T1552.001)
- MUADDIB-SANDBOX-012: Network after sensitive read (compound: file read + network — CRITICAL, T1041)
- MUADDIB-SANDBOX-013: Suspicious command execution (curl/wget/bash/sh/powershell via runtime monkey-patching — HIGH, T1059)
- MUADDIB-SANDBOX-014: Sensitive env var access (TOKEN/SECRET/KEY/PASSWORD via runtime monkey-patching — MEDIUM, T1552.001)
- MUADDIB-SHELL-013: FIFO + netcat reverse shell (mkfifo + nc sans /dev/tcp — CRITICAL, T1059.004)
- MUADDIB-SHELL-014: Base64 decode pipe to shell (base64 -d | bash — CRITICAL, T1140)
- MUADDIB-SHELL-015: Wget + base64 decode two-stage (wget + base64 -d — HIGH, T1105)
- MUADDIB-ENTROPY-004: Fragmented high entropy cluster (many short high-entropy strings — MEDIUM, T1027)
- MUADDIB-INTENT-001: Intent credential exfiltration (intra-file credential_read + exec/network sink — CRITICAL, T1041)
- MUADDIB-INTENT-002: Intent command output exfiltration (intra-file command_output + network sink — HIGH, T1041)
- MUADDIB-AST-046: WASM standalone module load (WebAssembly without network sinks — MEDIUM, T1027)

**Intent Graph Analysis (v2.6.0):** `src/intent-graph.js` performs intra-file source-sink coherence analysis. When a single file contains both a high-confidence credential source (sensitive_string, env_harvesting_dynamic, credential_regex_harvest) AND a dangerous sink (eval, exec, network), the intent graph boosts the score via a coherence matrix. Design principles: (1) INTRA-FILE pairing only — cross-file co-occurrence without proven data flow causes FP explosion on SDKs. (2) Cross-file detection delegated to module-graph.js (proven taint paths). (3) LOW severity threats excluded from pairing (respects FP reductions). (4) env_access and suspicious_dataflow excluded (standard config / double-counting). Intent bonus capped at 30 in scoring.js. Pipeline: deduplication → applyFPReductions → buildIntentPairs → enrichWithRules → calculateRiskScore.

**Red Team DPRK (v2.6.0):** 10 new adversarial samples in `datasets/adversarial/`. Group A (5 pure-API, multi-file): locale-config-sync, metrics-aggregator-lite, env-config-validator, stream-transform-kit, cache-warmup-utils. Group B (5 eval evasion): fn-return-eval, call-chain-eval, regex-source-require, charcode-arithmetic, object-method-alias. Scanner fixes: eval factory detection (`() => eval`), `.call.call(eval)` deep MemberExpression, `require(/regex/.source)` resolution, charcode arithmetic evaluation, object-method-alias taint tracking.

**Other key features (not scanners):**
- `src/sandbox/index.js` — Docker-based dynamic analysis: installs a package in an isolated container, captures filesystem changes, network traffic (tcpdump), and process spawns (strace). Injects canary tokens by default. Multi-run mode (v2.4.9) with monkey-patching preload for time-bomb detection.
- `src/diff.js` — Compares scan results between two git refs to surface only new threats (useful in CI). Exports `getThreatId`, `compareThreats`, `resolveRef` for testing.

**Internal (not user-facing):**
The following commands are internal infrastructure/dev tools. They work when called directly but are intentionally hidden from `--help` and the interactive menu. Do not expose them in user-facing documentation or CLI help.
- `src/monitor.js` — `muaddib monitor` runs on VPS via systemd, polls npm/PyPI every 60s. Exports `loadDetections`, `getDetectionStats`, `loadScanStats`.
- `src/threat-feed.js` — `muaddib feed` (JSON stdout) and `muaddib serve` (HTTP server with `/feed` and `/health`). SIEM integration for VPS infrastructure.
- `muaddib detections` — Detection history with lead time metrics. Uses monitor exports.
- `muaddib stats` — Daily scan statistics and FP rate. Uses monitor exports.
- `src/commands/evaluate.js` — `muaddib evaluate` measures TPR/FPR/ADR. Dev-only evaluation command.

**Rules & playbooks:** Threat types map to rules in `src/rules/index.js` (134 rules: 129 RULES + 5 PARANOID, MITRE ATT&CK mapped) and remediation text in `src/response/playbooks.js`. Both keyed by threat `type` string.

**IOC system (3-tier):**
1. `src/ioc/data/iocs-compact.json` (~5MB, ships with npm) — wildcards[] + versioned{} Maps for O(1) lookup
2. YAML files in `iocs/` — builtin rules
3. External sources (downloaded by `muaddib update`) — Shai-Hulud, DataDog, OSV dump

`loadCachedIOCs()` from `src/ioc/updater.js` merges all tiers and returns optimized Maps/Sets.

## Adding a New Scanner

1. Create `src/scanner/my-scanner.js` exporting a function that takes `targetPath` and returns threats array
2. Import in `src/index.js`, add to the Promise.all destructuring and the threats spread
3. Add rule entry in `src/rules/index.js` with id, name, severity, confidence, description, mitre
4. Add playbook entry in `src/response/playbooks.js`
5. Add tests in the appropriate test file under `tests/` (49 modular test files)
6. Create test fixtures in `tests/samples/my-scanner/`

## Key Constraints

- **No external runtime deps** beyond what's in package.json (acorn, acorn-walk, chalk, yargs, js-yaml, adm-zip, @inquirer/prompts)
- **Windows paths:** Always use `path.relative()` for file references in threats; never shell `!` in scripts
- **Symlink protection:** `findFiles` uses `lstatSync` + inode tracking (maxDepth fallback on Windows where ino=0)
- **Python typosquat false positives:** Typosquat check must skip packages that ARE in the popular list to avoid false positives (flask↔black)
- **Compact IOC format:** 87% of packages are wildcards (all versions malicious); `iocs.json` (112MB) is gitignored, `iocs-compact.json` (~5MB) is committed

## Post-Release Documentation Checklist
After every version bump / npm publish, update these files:
- README.md: scanner count, test count, version number, feature list, badges
- SECURITY.md: scanner/rule ID list, severity levels, any added/removed rules
- CHANGELOG.md: new version entry with all changes
- package.json version must match npm published version
Never skip documentation updates when publishing a new version.

## Git Workflow

- Always create a branch: `git checkout -b type/name` (e.g. `feat/entropy-scanner`, `fix/false-positive`)
- Open a PR and wait for CI to pass before merging
- Never commit directly to master
- Do not create commits automatically — the user handles commits manually
