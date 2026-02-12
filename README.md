<p align="center">
  <img src="assets/logo2removebg.png" alt="MUAD'DIB Logo" width="700">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/muaddib-scanner"><img src="https://img.shields.io/npm/v/muaddib-scanner" alt="npm version"></a>
  <a href="https://github.com/DNSZLSK/muad-dib/actions/workflows/scan.yml"><img src="https://github.com/DNSZLSK/muad-dib/actions/workflows/scan.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/DNSZLSK/muad-dib"><img src="https://codecov.io/gh/DNSZLSK/muad-dib/branch/master/graph/badge.svg" alt="Coverage"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/DNSZLSK/muad-dib"><img src="https://api.scorecard.dev/projects/github.com/DNSZLSK/muad-dib/badge" alt="OpenSSF Scorecard"></a>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="Node">
  <img src="https://img.shields.io/badge/IOCs-225%2C000%2B-red" alt="IOCs">
</p>

<p align="center">
  <a href="#installation">Installation</a> |
  <a href="#usage">Usage</a> |
  <a href="#features">Features</a> |
  <a href="#vs-code">VS Code</a> |
  <a href="#ci-cd">CI/CD</a>
</p>

<p align="center">
  <a href="README.fr.md">Version francaise</a>
</p>

---

## Why MUAD'DIB?

npm and PyPI supply-chain attacks are exploding. Shai-Hulud compromised 25K+ repos in 2025. Existing tools detect threats but don't help you respond.

MUAD'DIB combines static analysis + dynamic analysis (Docker sandbox) to detect threats AND guide your response.

---

## Positioning

MUAD'DIB is an educational tool and a free first line of defense. It detects **known** npm and PyPI threats (225,000+ IOCs) and basic suspicious patterns.

**For enterprise protection**, use:
- [Socket.dev](https://socket.dev) - ML behavioral analysis, cloud sandboxing
- [Snyk](https://snyk.io) - Massive vulnerability database, CI/CD integrations
- [Opengrep](https://opengrep.dev) - Advanced dataflow analysis, Semgrep rules

MUAD'DIB does not replace these tools. It complements them for devs who want a quick, free check before installing an unknown package.

---

## Installation

### npm (recommended)

```bash
npm install -g muaddib-scanner
```

### From source

```bash
git clone https://github.com/DNSZLSK/muad-dib
cd muad-dib
npm install
npm link
```

---

## Usage

### Basic scan

```bash
muaddib scan .
muaddib scan /path/to/project
```

Scans both npm (package.json, node_modules) and Python (requirements.txt, setup.py, pyproject.toml) dependencies.

### Interactive mode

```bash
muaddib
```

Launches an interactive menu to guide you through all features.

### Safe install

```bash
muaddib install <package>
muaddib install lodash axios --save-dev
muaddib i express -g
muaddib install suspicious-pkg --force    # Force install despite threats
```

Scans packages for threats BEFORE installing. Blocks known malicious packages.

### Risk score

Each scan displays a 0-100 risk score:

```
[SCORE] 58/100 [***********---------] HIGH
```

### Explain mode (full details)

```bash
muaddib scan . --explain
```

Shows for each detection:
- Rule ID
- MITRE ATT&CK technique
- References (articles, CVEs)
- Response playbook

### Export

```bash
muaddib scan . --json > results.json     # JSON
muaddib scan . --html report.html        # HTML
muaddib scan . --sarif results.sarif     # SARIF (GitHub Security)
```

### Severity threshold

```bash
muaddib scan . --fail-on critical  # Fail only on CRITICAL
muaddib scan . --fail-on high      # Fail on HIGH and CRITICAL (default)
muaddib scan . --fail-on medium    # Fail on MEDIUM, HIGH, CRITICAL
```

### Paranoid mode

```bash
muaddib scan . --paranoid
```

Ultra-strict detection with lower tolerance. Useful for critical projects. Detects any network access, subprocess execution, dynamic code evaluation, and sensitive file access.

### Discord/Slack webhook

```bash
muaddib scan . --webhook "https://discord.com/api/webhooks/..."
```

Sends an alert with score and threats to Discord or Slack.

### Real-time monitoring

```bash
muaddib watch .
```

### Daemon mode

```bash
muaddib daemon
muaddib daemon --webhook "https://discord.com/api/webhooks/..."
```

Automatically monitors all `npm install` commands and scans new packages.

### Update IOCs (fast, ~5 seconds)

```bash
muaddib update
```

Loads the 225,000+ IOCs shipped in the package, merges YAML IOCs and additional GitHub sources (GenSecAI, DataDog). Run this after `npm install` for an instant IOC refresh.

### Scrape IOCs (full, ~5 minutes)

```bash
muaddib scrape
```

Full refresh from all primary sources. Downloads OSV bulk dumps for npm and PyPI (~100-200MB), OSSF, and all other sources. Run this when you want the absolute latest data.

Sources:
- **OSV.dev npm dump** - Bulk download of all MAL-* entries
- **OSV.dev PyPI dump** - Bulk download of all PyPI MAL-* entries
- **GenSecAI Shai-Hulud 2.0 Detector** - Consolidated list of 700+ Shai-Hulud packages
- **DataDog Security Labs** - Consolidated IOCs from multiple vendors
- **OSSF Malicious Packages** - OpenSSF database (8000+ reports via OSV.dev)
- **GitHub Advisory Database** - Malware-tagged advisories
- **Snyk Known Malware** - Historical malware packages
- **Static IOCs** - Socket.dev, Phylum, npm-removed packages

### Docker Sandbox

```bash
muaddib sandbox <package-name>
muaddib sandbox <package-name> --strict
```

Dynamic analysis: installs the package in an isolated Docker container and monitors runtime behavior via strace, tcpdump, and filesystem diffing.

Multi-layer monitoring:
- **System tracing** (strace): file access, process spawns, syscall monitoring
- **Network capture** (tcpdump): DNS resolutions with resolved IPs, HTTP requests (method, host, path, body), TLS SNI detection
- **Filesystem diff**: snapshot before/after install, detects files created in suspicious locations
- **Data exfiltration detection**: 16 sensitive patterns (tokens, credentials, SSH keys, private keys, .env)
- **Scoring engine**: 0-100 risk score based on behavioral severity

Use `--strict` to block all non-essential outbound network traffic via iptables.

Requires Docker Desktop installed.

```bash
muaddib sandbox lodash          # Safe package
muaddib sandbox suspicious-pkg  # Analyze unknown package
```

### Sandbox network report

```bash
muaddib sandbox-report <package-name>
muaddib sandbox-report <package-name> --strict
```

Same as `sandbox` but displays a detailed network report: DNS resolutions, HTTP requests, TLS connections, blocked connections (strict mode), and data exfiltration alerts.

### Diff (compare versions)

```bash
muaddib diff <ref> [path]
```

Compare threats between the current version and a previous commit/tag. Shows only **NEW** threats introduced since the reference point.

```bash
muaddib diff HEAD~1             # Compare with previous commit
muaddib diff v1.2.0             # Compare with tag
muaddib diff main               # Compare with branch
muaddib diff abc1234            # Compare with specific commit
```

Example output:
```
[MUADDIB DIFF] Comparing abc1234 -> def5678

  Risk Score: 25 -> 45 (+20 worse)
  Threats:    3 -> 5

  NEW threats:     2
  REMOVED threats: 0
  Unchanged:       3

  NEW THREATS (introduced since v1.2.0)
  ------------------------------------
  1. [HIGH] suspicious_dependency
     Known malicious package detected
     File: package.json
```

Use in CI to only fail on **new** threats, not existing technical debt:
```yaml
- run: muaddib diff ${{ github.event.pull_request.base.sha }} --fail-on high
```

### Pre-commit hooks

```bash
muaddib init-hooks [options]
```

Automatically scan before each commit. Supports multiple hook systems:

```bash
muaddib init-hooks                        # Auto-detect (husky/pre-commit/git)
muaddib init-hooks --type husky           # Force husky
muaddib init-hooks --type pre-commit      # Force pre-commit framework
muaddib init-hooks --type git             # Force native git hooks
muaddib init-hooks --mode diff            # Only block NEW threats
```

#### With pre-commit framework

Add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/DNSZLSK/muad-dib
    rev: v1.6.18
    hooks:
      - id: muaddib-scan        # Scan all threats
      # - id: muaddib-diff      # Or: only new threats
      # - id: muaddib-paranoid  # Or: ultra-strict mode
```

#### With husky

```bash
npx husky add .husky/pre-commit "npx muaddib scan . --fail-on high"
# Or for diff mode:
npx husky add .husky/pre-commit "npx muaddib diff HEAD --fail-on high"
```

#### Remove hooks

```bash
muaddib remove-hooks [path]
```

Removes all MUAD'DIB hooks (husky and git native).

#### Native git hooks

```bash
muaddib init-hooks --type git
# Creates .git/hooks/pre-commit
```

### Version check

MUAD'DIB automatically checks for new versions on startup and notifies you if an update is available.

---

## Features

### Python / PyPI support

MUAD'DIB automatically detects and scans Python projects:

- **requirements.txt** - All formats including `-r` recursive includes, extras, environment markers
- **setup.py** - Extracts `install_requires` and `setup_requires`
- **pyproject.toml** - PEP 621 dependencies and Poetry dependencies

Python packages are checked against 14,000+ known malicious PyPI packages (from OSV.dev) and tested for typosquatting against popular PyPI packages (requests, numpy, flask, django, pandas, etc.) using PEP 503 name normalization.

```
[PYTHON] Detected Python project (3 dependency files)
  requirements.txt: 12 packages
  setup.py: 3 packages
  pyproject.toml: 8 packages

[CRITICAL] PyPI IOC match: malicious-pkg (all versions)
[HIGH] PyPI typosquat: "reqeusts" looks like "requests"
```

### Typosquatting detection

MUAD'DIB detects packages with names similar to popular packages (npm and PyPI):

```
[HIGH] Package "lodahs" looks like "lodash" (swapped_chars). Possible typosquatting.
```

### Dataflow analysis

Detects when code reads credentials AND sends them over the network:

```
[CRITICAL] Suspicious flow: credential read (readFileSync, GITHUB_TOKEN) + network send (fetch)
```

### GitHub Actions scanning

Detects malicious patterns in `.github/workflows/` YAML files, including Shai-Hulud 2.0 backdoor indicators.

### Detected attacks

| Campaign | Packages | Status |
|----------|----------|--------|
| Shai-Hulud v1 (Sept 2025) | @ctrl/tinycolor, ng2-file-upload | Detected |
| Shai-Hulud v2 (Nov 2025) | @asyncapi/specs, posthog-node, kill-port | Detected |
| Shai-Hulud v3 (Dec 2025) | @vietmoney/react-big-calendar | Detected |
| event-stream (2018) | flatmap-stream, event-stream | Detected |
| eslint-scope (2018) | eslint-scope | Detected |
| Protestware | node-ipc, colors, faker | Detected |
| Typosquats | crossenv, mongose, babelcli | Detected |

### Detected techniques

| Technique | MITRE | Detection |
|-----------|-------|-----------|
| Credential theft (.npmrc, .ssh) | T1552.001 | AST |
| Env var exfiltration | T1552.001 | AST |
| Remote code execution | T1105 | Pattern |
| Reverse shell | T1059.004 | Pattern |
| Dead man's switch | T1485 | Pattern |
| Obfuscated code | T1027 | Heuristics |
| JS obfuscation patterns | T1027.002 | Pattern detection |
| Shannon entropy (strings) | T1027 | Entropy calculation |
| Typosquatting (npm + PyPI) | T1195.002 | Levenshtein |
| Supply chain compromise | T1195.002 | IOC matching |
| PyPI malicious package | T1195.002 | IOC matching |
| Sandbox dynamic analysis | Multiple | Docker + strace + tcpdump |

---

## IOC Sources

MUAD'DIB aggregates threat intelligence from verified sources only:

| Source | Type | Coverage |
|--------|------|----------|
| [OSV.dev npm dump](https://osv.dev) | Bulk zip | 200,000+ npm MAL-* entries |
| [OSV.dev PyPI dump](https://osv.dev) | Bulk zip | 14,000+ PyPI MAL-* entries |
| [GenSecAI Shai-Hulud Detector](https://github.com/gensecaihq/Shai-Hulud-2.0-Detector) | GitHub | 700+ Shai-Hulud packages |
| [DataDog Security Labs](https://github.com/DataDog/indicators-of-compromise) | GitHub | Consolidated IOCs from 7 vendors |
| [OSSF Malicious Packages](https://github.com/ossf/malicious-packages) | OSV API | 8000+ malware reports |
| [GitHub Advisory](https://github.com/advisories?query=type%3Amalware) | OSV API | Malware-tagged advisories |
| Snyk Known Malware | Static | Historical attacks |
| Socket.dev / Phylum | Static | Manual additions |

---

## VS Code

The VS Code extension automatically scans your npm projects.

### Installation

Search "MUAD'DIB" in VS Code Extensions, or:

```bash
code --install-extension dnszlsk.muaddib-vscode
```

### Commands

- `MUAD'DIB: Scan Project` - Scan entire project
- `MUAD'DIB: Scan Current File` - Scan current file

### Settings

- `muaddib.autoScan` - Auto-scan on project open (default: true)
- `muaddib.webhookUrl` - Discord/Slack webhook URL
- `muaddib.failLevel` - Alert level (critical/high/medium/low)

---

## CI/CD

### GitHub Actions (Marketplace)

Use the official MUAD'DIB action from the GitHub Marketplace:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: DNSZLSK/muad-dib@v1
        with:
          path: '.'
          fail-on: 'high'
          sarif: 'results.sarif'
```

#### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `fail-on` | Minimum severity to fail (critical/high/medium/low) | `high` |
| `sarif` | Path for SARIF output file | `` |
| `paranoid` | Enable ultra-strict detection | `false` |

#### Action Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to generated SARIF file |
| `risk-score` | Risk score (0-100) |
| `threats-count` | Number of threats detected |
| `exit-code` | Exit code (0 = clean) |

Alerts appear in Security > Code scanning alerts.

---

## Architecture

```
MUAD'DIB Scanner
|
+-- IOC Match (225,000+ packages, JSON DB)
|   +-- OSV.dev npm dump (200K+ MAL-* entries)
|   +-- OSV.dev PyPI dump (14K+ MAL-* entries)
|   +-- GenSecAI Shai-Hulud Detector
|   +-- DataDog Consolidated IOCs
|   +-- OSSF Malicious Packages (via OSV)
|   +-- GitHub Advisory (malware)
|   +-- Snyk Known Malware
|   +-- Static IOCs (Socket, Phylum)
|
+-- 12 Parallel Scanners
|   +-- AST Parse (acorn) — eval/Function severity by argument type
|   +-- Pattern Matching (shell, scripts)
|   +-- Obfuscation Detection (skip .min.js, ignore hex/unicode alone)
|   +-- Typosquat Detection (npm + PyPI, Levenshtein)
|   +-- Python Scanner (requirements.txt, setup.py, pyproject.toml)
|   +-- Shannon Entropy (string-level, 5.5 bits + 50 chars min)
|   +-- JS Obfuscation Patterns (_0x* vars, encoded arrays, eval+entropy)
|   +-- GitHub Actions Scanner
|   +-- Package, Dependencies, Hash, npm-registry, Dataflow scanners
|
+-- Paranoid Mode (ultra-strict)
+-- Docker Sandbox (behavioral analysis, network capture)
|
v
Dataflow Analysis (credential read -> network send)
|
v
Threat Enrichment (rules, MITRE ATT&CK, playbooks)
|
v
Output (CLI, JSON, HTML, SARIF, Webhook)
```

---

## Contributing

### Add IOCs

Edit YAML files in `iocs/`:

```yaml
- id: NEW-MALWARE-001
  name: "malicious-package"
  version: "*"
  severity: critical
  confidence: high
  source: community
  description: "Threat description"
  references:
    - https://example.com/article
  mitre: T1195.002
```

### Development

```bash
git clone https://github.com/DNSZLSK/muad-dib
cd muad-dib
npm install
npm test
```

### Testing

- **316 unit/integration tests** - 80% code coverage via [Codecov](https://codecov.io/gh/DNSZLSK/muad-dib)
- **56 fuzz tests** - Malformed YAML, invalid JSON, binary files, ReDoS, unicode, 10MB inputs
- **15 adversarial tests** - Simulated malicious packages, 15/15 detection rate
- **False positive validation** - 0 false positives on express, lodash, axios, react
- **ESLint security audit** - `eslint-plugin-security` with 14 rules enabled

---

## Community

- Discord: https://discord.gg/y8zxSmue

---

## Documentation

- [Threat Model](docs/threat-model.md) - What MUAD'DIB detects and doesn't detect
- [Security Audit Report v1.4.1](docs/MUADDIB_Security_Audit_Report_v1.4.1.pdf) - Full security audit (58 issues fixed)
- [IOCs YAML](iocs/) - Threat database

---

## License

MIT

---

<p align="center">
  <strong>The spice must flow. The worms must die.</strong>
</p>
