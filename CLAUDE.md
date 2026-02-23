# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm test          # Run all tests (custom framework, 1317 tests across 20 files)
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

**Core orchestration:** `src/index.js` — `run(targetPath, options)` runs cross-file module graph analysis first, then launches 13 individual scanners in parallel via `Promise.all`, then deduplicates, applies FP reductions, scores using per-file max (v2.2.11: `riskScore = min(100, max(file_scores) + package_level_score)`, severity weights: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1), enriches with rules/playbooks (94 rules), and outputs (CLI/JSON/HTML/SARIF). Exports `isPackageLevelThreat` and `computeGroupScore` for testing.

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
- `detectStaticCanaryExfiltration()` in `src/sandbox.js` searches all report fields for static canary values
- Strict webhook filtering: monitor alerts only for IOC match, sandbox confirm, or canary exfiltration

**Security Hardening (v2.1.2):**
- `src/shared/download.js` — SSRF-safe downloadToFile (domain allowlist + private IP blocking), injection-safe extractTarGz (execFileSync), sanitizePackageName (path traversal prevention)
- `src/shared/constants.js` — Centralized NPM_PACKAGE_REGEX, MAX_TARBALL_SIZE, DOWNLOAD_TIMEOUT

**Validation & Observability (v2.1):** Features for measuring and validating scanner effectiveness:
- `src/ground-truth.js` — Ground truth dataset: 51 real-world attacks (49 active) replayed against scanner. 91.8% TPR (45/49).
- `--breakdown` flag — Explainable score decomposition showing per-finding contribution

**AI Config Scanner (v2.2):** `src/scanner/ai-config.js` scans AI agent configuration files (`.cursorrules`, `.cursorignore`, `.windsurfrules`, `CLAUDE.md`, `AGENT.md`, `.github/copilot-instructions.md`, `copilot-setup-steps.yml`) for prompt injection patterns. Detects shell commands, exfiltration, credential access, and injection instructions. Compound detection (shell + exfil/credentials) escalates to CRITICAL.

**Deobfuscation Pre-processing (v2.2.5):** `src/scanner/deobfuscate.js` applies static AST-based deobfuscation before AST and dataflow scanners. 4 transformations: string concat folding, charcode reconstruction, base64 decode, hex array resolution. Phase 2 const propagation resolves `const x = 'literal'` references. Additive approach: original code scanned first (preserves obfuscation signals), then deobfuscated code adds new findings. Disable with `--no-deobfuscate`.

**Inter-module Dataflow (v2.2.6):** `src/scanner/module-graph.js` builds a dependency graph of local modules, annotates tainted exports (fs.readFileSync, process.env, os.homedir, child_process, dns), and detects when credentials read in one module reach a network/exec sink in another module. Features: 3-hop re-export chain propagation, class method analysis, named export destructuring, inline require re-export, function-wrapped taint propagation. Runs before individual scanners. Disable with `--no-module-graph`.

**Evaluation Framework (v2.2, corrected v2.2.7, FP reduction v2.2.8–v2.2.9, size analysis v2.2.10, per-file scoring v2.2.11, GT expansion v2.2.12):** `src/commands/evaluate.js` measures TPR (Ground Truth, 49 real attacks from 51 samples), FPR (Benign, 529 npm packages — real source code via `npm pack` + native tar extraction), and ADR (Adversarial + Holdout, 78 evasive samples — 38 adversarial + 40 holdout). Benign tarballs cached in `.muaddib-cache/benign-tarballs/`. Flags: `--benign-limit N`, `--refresh-benign`. Results saved to `metrics/v{version}.json`. FPR reported in v2.2.0–v2.2.6 was invalid (0% on empty dirs); real FPR was 38% (19/50) in v2.2.7, reduced to 19.4% (102/527) in v2.2.8, 17.5% (92/527) in v2.2.9, then to **~13% (69/527)** in v2.2.11 via per-file max scoring. FPR by package size: **6.2%** on standard packages (<10 JS files, 290 packages), 11.9% medium (10-50), 25.0% large (50-100), 40.3% very large (100+). Adversarial samples in `datasets/adversarial/`, holdout samples in `datasets/holdout-v2/` through `datasets/holdout-v5/`, benign package lists in `datasets/benign/packages-npm.txt` (529 packages) and `datasets/benign/packages-pypi.txt` (132 packages), ground truth attacks in `tests/ground-truth/attacks.json` (51 entries), ground truth malware database in `datasets/ground-truth/known-malware.json` (65 entries).

**FP Reduction Post-processing (v2.2.8–v2.2.9):** `applyFPReductions()` in `src/index.js` applies count-based severity downgrades between deduplication and scoring. Thresholds: `dynamic_require` >10 HIGH→LOW, `dangerous_call_function` >5 MEDIUM→LOW, `require_cache_poison` >3 CRITICAL→LOW, `suspicious_dataflow` >5 any→LOW, `obfuscation_detected` >3 any→LOW. Framework prototype hooks (Request/Response/App/Router.prototype) downgraded HIGH→MEDIUM (CRITICAL core prototypes untouched). Prototype hook MEDIUM scoring capped at 15 points max. Typosquat whitelist expanded with 10 packages (chai, pino, ioredis, bcryptjs, recast, asyncdi, redux, args, oxlint, vasync). Scanner-level: expanded `SAFE_ENV_VARS` (+13 vars) and added `SAFE_ENV_PREFIXES` (npm_config_*, npm_lifecycle_*, npm_package_*, lc_*) in `src/scanner/ast.js`. Obfuscation in dist/build/*.bundle.js → LOW in `src/scanner/obfuscation.js`.

**Per-File Max Scoring (v2.2.11):** Replaces global score accumulation with per-file max scoring. Formula: `riskScore = min(100, max(file_scores) + package_level_score)`. Threats are split into package-level (lifecycle scripts, typosquat, IOC matches, sandbox findings — classified by `PACKAGE_LEVEL_TYPES` Set + file heuristics) and file-level (AST, dataflow, obfuscation). File-level threats grouped by `threat.file`, each group scored independently via `computeGroupScore()`. Package-level threats scored separately. Result includes `globalRiskScore` (old sum), `maxFileScore`, `packageScore`, `mostSuspiciousFile`, `fileScores` map. FPR: 17.5% → **~13%** (69/527). FPR on standard packages: **6.2%** (18/290).

**Ground Truth Expansion (v2.2.12):** 51 real-world attack samples in `tests/ground-truth/` (49 active, 2 with min_threats=0). TPR: **91.8% (45/49)**. 4 out-of-scope misses: lottie-player, polyfill-io, trojanized-jquery (browser-only), websocket-rat (FP-risky). 3 new detection rules: `crypto_decipher` (MUADDIB-AST-022, T1140), `module_compile` (MUADDIB-AST-023, T1059), `.secretKey`/`.privateKey` credential source in dataflow. ADR consolidated: 78 samples (38 adversarial + 40 holdout) = **100% (78/78)** (3 bypass samples added in v2.2.13).

**Scan Freeze Fix (v2.2.22):** Module graph scanner's `EXCLUDED_DIRS` aligned with main scanner to prevent infinite loops on `dist/`, `build/`, `.next/` directories.

**npm Package Fix (v2.2.23):** `.npmignore` updated to exclude ground-truth malware samples and adversarial datasets from the published npm package.

**Coverage Expansion (v2.2.24):** Tests expanded from 862 to 1317 (+455). Coverage 72% → 86% (c8 line coverage). All scanner, infrastructure, and utility modules covered.

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
- MUADDIB-AST-023: Module compile execution (module._compile() — in-memory code execution, CRITICAL, T1059)

**Other key features (not scanners):**
- `src/sandbox.js` — Docker-based dynamic analysis: installs a package in an isolated container, captures filesystem changes, network traffic (tcpdump), and process spawns (strace). Injects canary tokens by default.
- `src/diff.js` — Compares scan results between two git refs to surface only new threats (useful in CI). Exports `getThreatId`, `compareThreats`, `resolveRef` for testing.

**Internal (not user-facing):**
The following commands are internal infrastructure/dev tools. They work when called directly but are intentionally hidden from `--help` and the interactive menu. Do not expose them in user-facing documentation or CLI help.
- `src/monitor.js` — `muaddib monitor` runs on VPS via systemd, polls npm/PyPI every 60s. Exports `loadDetections`, `getDetectionStats`, `loadScanStats`.
- `src/threat-feed.js` — `muaddib feed` (JSON stdout) and `muaddib serve` (HTTP server with `/feed` and `/health`). SIEM integration for VPS infrastructure.
- `muaddib detections` — Detection history with lead time metrics. Uses monitor exports.
- `muaddib stats` — Daily scan statistics and FP rate. Uses monitor exports.
- `src/commands/evaluate.js` — `muaddib evaluate` measures TPR/FPR/ADR. Dev-only evaluation command.

**Rules & playbooks:** Threat types map to rules in `src/rules/index.js` (94 rules, MITRE ATT&CK mapped) and remediation text in `src/response/playbooks.js`. Both keyed by threat `type` string.

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
5. Add tests in the appropriate test file under `tests/` (20 modular test files)
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
