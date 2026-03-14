<p align="center">
  <img src="assets/muaddibLogo.png" alt="MUAD'DIB Logo" width="700">
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
  <a href="#cicd">CI/CD</a>
</p>

<p align="center">
  <a href="docs/README.fr.md">Version francaise</a>
</p>

---

## Why MUAD'DIB?

npm and PyPI supply-chain attacks are exploding. Shai-Hulud compromised 25K+ repos in 2025. Existing tools detect threats but don't help you respond.

MUAD'DIB combines **14 parallel scanners** (133 detection rules), a **deobfuscation engine**, **inter-module dataflow analysis**, **per-file max scoring**, Docker sandbox with **monkey-patching preload** for time-bomb detection, **behavioral anomaly detection**, and **ground truth validation** to detect threats AND guide your response — even before they appear in any IOC database.

---

## Positioning

MUAD'DIB is an educational tool and a free first line of defense. It detects **known** npm and PyPI threats (225,000+ IOCs) and suspicious behavioral patterns.

**For enterprise protection**, use:
- [Socket.dev](https://socket.dev) - ML behavioral analysis, cloud sandboxing
- [Snyk](https://snyk.io) - Massive vulnerability database, CI/CD integrations
- [Opengrep](https://opengrep.dev) - Advanced dataflow analysis, Semgrep rules

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

### Safe install

```bash
muaddib install <package>
muaddib install lodash axios --save-dev
muaddib install suspicious-pkg --force    # Force install despite threats
```

Scans packages for threats BEFORE installing. Blocks known malicious packages.

### Risk score

Each scan displays a 0-100 risk score:

```
[SCORE] 58/100 [***********---------] HIGH
```

### Explain mode

```bash
muaddib scan . --explain
```

Shows rule ID, MITRE ATT&CK technique, references, and response playbook for each detection.

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
```

### Paranoid mode

```bash
muaddib scan . --paranoid
```

Ultra-strict detection with lower tolerance. Detects any network access, subprocess execution, dynamic code evaluation, and sensitive file access.

### Webhook alerts

```bash
muaddib scan . --webhook "https://discord.com/api/webhooks/..."
```

Strict filtering (v2.1.2): alerts only for IOC matches, sandbox-confirmed threats, or canary token exfiltration.

### Behavioral anomaly detection (v2.0)

```bash
muaddib scan . --temporal-full     # All 4 temporal features
muaddib scan . --temporal          # Sudden lifecycle script detection
muaddib scan . --temporal-ast      # AST diff between versions
muaddib scan . --temporal-publish  # Publish frequency anomaly
muaddib scan . --temporal-maintainer # Maintainer change detection
```

Detects supply-chain attacks **before** they appear in IOC databases by analyzing changes between package versions. See [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md) for details.

### Docker sandbox

```bash
muaddib sandbox <package-name>
muaddib sandbox <package-name> --strict
```

Dynamic analysis in an isolated Docker container: strace, tcpdump, filesystem diff, canary tokens, CI-aware environment, and monkey-patching preload for time-bomb detection (multi-run at [0h, 72h, 7d] offsets).

### Other commands

```bash
muaddib watch .                    # Real-time monitoring
muaddib daemon                     # Daemon mode (auto-scan npm install)
muaddib update                     # Update IOCs (fast, ~5s)
muaddib scrape                     # Full IOC refresh (~5min)
muaddib diff HEAD~1                # Compare threats with previous commit
muaddib init-hooks                 # Pre-commit hooks (husky/pre-commit/git)
muaddib scan . --breakdown         # Explainable score decomposition
muaddib replay                     # Ground truth validation (46/49 TPR)
```

---

## Features

### 14 parallel scanners

| Scanner | Detection |
|---------|-----------|
| AST Parse (acorn) | eval, Function, credential theft, binary droppers, prototype hooks |
| Pattern Matching | Shell commands, reverse shells, dead man's switch |
| Dataflow Analysis | Credential read + network send (intra-file and cross-file) |
| Obfuscation Detection | JS obfuscation patterns (skip .min.js) |
| Deobfuscation Pre-processing | String concat, charcode, base64, hex array, const propagation |
| Inter-module Dataflow | Cross-file taint propagation (3-hop chains, class methods) |
| Intent Coherence | Intra-file source-sink pairing (credential + eval/network) |
| Typosquatting | npm + PyPI (Levenshtein distance) |
| Python Scanner | requirements.txt, setup.py, pyproject.toml, 14K+ PyPI IOCs |
| Shannon Entropy | High-entropy strings (5.5 bits + 50 chars min) |
| AI Config Scanner | .cursorrules, CLAUDE.md, copilot-instructions.md injection |
| Package/Dependencies | Lifecycle scripts, IOC matching (225K+ packages) |
| GitHub Actions | Shai-Hulud backdoor detection |
| Hash Scanner | Known malicious file hashes |

### 133 detection rules

All rules are mapped to MITRE ATT&CK techniques. See [SECURITY.md](SECURITY.md#detection-rules-v262) for the complete rules reference.

### Detected campaigns

| Campaign | Status |
|----------|--------|
| Shai-Hulud v1/v2/v3 (2025) | Detected |
| event-stream (2018) | Detected |
| eslint-scope (2018) | Detected |
| Protestware (node-ipc, colors, faker) | Detected |
| Typosquats (crossenv, mongose, babelcli) | Detected |

---

## VS Code

The VS Code extension automatically scans your npm projects.

```bash
code --install-extension dnszlsk.muaddib-vscode
```

- `MUAD'DIB: Scan Project` - Scan entire project
- `MUAD'DIB: Scan Current File` - Scan current file
- Settings: `muaddib.autoScan`, `muaddib.webhookUrl`, `muaddib.failLevel`

See [vscode-extension/README.md](vscode-extension/README.md) for full documentation.

---

## CI/CD

### GitHub Actions (Marketplace)

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

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `fail-on` | Minimum severity to fail | `high` |
| `sarif` | SARIF output file path | |
| `paranoid` | Ultra-strict detection | `false` |

### Pre-commit hooks

```bash
muaddib init-hooks                        # Auto-detect (husky/pre-commit/git)
muaddib init-hooks --type husky           # Force husky
muaddib init-hooks --mode diff            # Only block NEW threats
```

With pre-commit framework:
```yaml
repos:
  - repo: https://github.com/DNSZLSK/muad-dib
    rev: v2.6.6
    hooks:
      - id: muaddib-scan
```

---

## Evaluation Metrics

| Metric | Result | Details |
|--------|--------|---------|
| **Wild TPR** (Datadog 17K) | **88.2%** raw / **~100%** adjusted | 17,922 real malware. 2,077 out-of-scope (phishing, binaries, corrected) |
| **TPR** (Ground Truth) | **93.9%** (46/49) | 51 real attacks. 3 out-of-scope: browser-only |
| **FPR** (Benign) | **12.1%** (64/529) | 529 npm packages, real source via `npm pack` |
| **ADR** (Adversarial + Holdout) | **92.2%** (71/77) | 53 adversarial + 40 holdout (77 available on disk), global threshold=20 |

**2093 tests** across 49 files. **134 rules** (129 RULES + 5 PARANOID).

> **Methodology caveats:**
> - TPR measured on 49 Node.js attack samples (3 browser-only excluded from 51 total)
> - FPR measured on 529 curated popular npm packages (not a random sample)
> - ADR measured with global threshold (score >= 20) as of v2.6.5

See [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md) for the full experimental protocol, holdout history, and Datadog benchmark details.

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

- **2093 tests** across 49 modular test files
- **56 fuzz tests** - Malformed inputs, ReDoS, unicode, binary
- **Datadog 17K benchmark** - 17,922 real malware samples
- **Ground truth validation** - 51 real-world attacks (93.9% TPR)
- **False positive validation** - 12.1% FPR on 529 real npm packages

---

## Community

- Discord: https://discord.gg/y8zxSmue

---

## Documentation

- [Documentation Index](docs/INDEX.md) - All documentation in one place
- [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md) - Experimental protocol, holdout scores
- [Threat Model](docs/threat-model.md) - What MUAD'DIB detects and doesn't detect
- [Adversarial Evaluation](ADVERSARIAL.md) - Red team samples and ADR results
- [Security Policy](SECURITY.md) - Detection rules reference (134 rules)
- [Security Audit](docs/SECURITY_AUDIT.md) - Bypass validation report
- [FP Analysis](docs/EVALUATION.md) - Historical false positive analysis

---

## License

MIT

---

<p align="center">
  <strong>The spice must flow. The worms must die.</strong>
</p>
