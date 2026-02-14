# Changelog

All notable changes to MUAD'DIB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- **Detection Time Logging** (`muaddib detections`): tracks `first_seen_at` timestamp for every detection, computes lead time vs. public advisory. Supports `--stats` for aggregate metrics and `--json` for machine-readable output.
- **FP Rate Tracking** (`muaddib stats`): daily scan statistics with total/clean/suspect/false_positive/confirmed counts and automatic FP rate computation. Supports `--daily` for per-day breakdown and `--json` for export.
- **Score Breakdown** (`muaddib scan --breakdown`): explainable score decomposition showing per-finding contribution with severity weights (CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1).
- **Threat Feed API** (`muaddib feed` / `muaddib serve`): JSON threat feed for SIEM integration. `feed` outputs to stdout with `--limit`, `--severity`, `--since` filters. `serve` starts an HTTP server (default port 3000) with `GET /feed` and `GET /health` endpoints.
- 709 tests (was 541 in v2.0.0), +168 new tests
- 74% code coverage (was ~65% in v2.0.0)
- New test files: `tests/integration/diff.test.js` (35 tests), `tests/integration/ground-truth.test.js`
- Expanded coverage for `src/diff.js`, `src/temporal-ast-diff.js`, `src/monitor.js`

### Changed
- Test count: 541 → 709 (+31% increase)
- Code coverage: ~65% → 74%
- Architecture diagram updated to include v2.1 validation & observability layer

### Breaking Changes
- None. All new features are additive CLI commands (`feed`, `serve`, `stats`, `detections`, `replay`, `ground-truth`) and a new scan flag (`--breakdown`).

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
- **Zero-day monitor** (`muaddib monitor`): continuous polling of npm and PyPI registries via RSS (60s interval), automatic download/extract/scan of every new package
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

[Unreleased]: https://github.com/DNSZLSK/muad-dib/compare/v2.1.2...HEAD
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
