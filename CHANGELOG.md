# Changelog

All notable changes to MUAD'DIB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/DNSZLSK/muad-dib/compare/v1.2.7...HEAD
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
