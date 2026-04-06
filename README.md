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

MUAD'DIB combines **14 parallel scanners** (200 detection rules), a **deobfuscation engine**, **inter-module dataflow analysis**, **compound scoring**, **ML classifiers** (XGBoost), and gVisor/Docker sandbox to detect known threats and suspicious behavioral patterns in npm and PyPI packages.

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

Strict filtering (v2.1.2): alerts only for IOC matches, sandbox-confirmed threats, or canary token exfiltration. Priority triage (v2.10.21): P1 (red, IOC/sandbox/canary), P2 (orange, high-score/compounds), P3 (yellow, rest).

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
muaddib replay                     # Ground truth validation (60/64 TPR@3)
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

### 200 detection rules

All rules are mapped to MITRE ATT&CK techniques. See [SECURITY.md](SECURITY.md#detection-rules-v21021) for the complete rules reference.

### Detected campaigns

| Campaign | Status |
|----------|--------|
| GlassWorm (2026, 433+ packages) | Detected |
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
    rev: v2.10.57
    hooks:
      - id: muaddib-scan
```

---

## Evaluation Metrics

| Metric | Result | Details |
|--------|--------|---------|
| **ML FPR** | **2.85%** (239/8,393 holdout) | XGBoost retrained on 56,564 samples, 64 features, threshold=0.710 |
| **ML TPR** | **99.93%** (2,918/2,920 holdout) | 377 confirmed_malicious via OSSF/GHSA/npm correlation |
| **Wild TPR** (Datadog 17K) | **92.8%** (13,538/14,587 in-scope) | 17,922 packages. 3,335 skipped (no JS). By category: compromised_lib 97.8%, malicious_intent 92.1% |
| **TPR@3** (detection rate) | **93.75%** (60/64) | 66 real attacks (64 active, 2 out-of-scope). Threshold=3: any signal |
| **TPR@20** (alert rate) | **85.9%** (55/64) | Operational alert threshold=20, aligned with ADR/FPR |
| **FPR rules** (Benign curated) | **14.0%** (74/532) | 532 npm packages, real source via `npm pack` |
| **FPR after ML** | **8.3%** (44/529) | ML filters 30/31 T1 benign, 0 GT/ADR suppressed |
| **FPR** (Benign random) | **7.5%** (15/200) | 200 random npm packages, stratified sampling |
| **ADR** (Adversarial + Holdout) | **96.3%** (103/107) | 67 adversarial + 40 holdout (107 available on disk), global threshold=20 |

**3068 tests** across 66 files. **200 rules** (195 RULES + 5 PARANOID).

> **ML retrain methodology (v2.10.51):**
> - Ground truth: 377 confirmed_malicious via auto-labeler (OSSF malicious-packages, GitHub Advisory Database, npm registry takedown correlation)
> - Dataset: 56,564 samples (14,602 malicious, 41,962 clean). Stratified 80/20 split
> - Grid search: depth=4, estimators=300, lr=0.05. AUC-ROC=0.999, F1=0.960
> - Leaky feature filter: 23 dead/leaky features removed (source-identity proxies)
>
> **Static evaluation caveats:**
> - TPR measured on 64 active Node.js attack samples (2 out-of-scope from 66 total)
> - TPR@3 = detection rate (any signal); TPR@20 = operational alert threshold
> - FPR measured on 532 curated popular npm packages (not a random sample)
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

- **3068 tests** across 66 modular test files
- **56 fuzz tests** - Malformed inputs, ReDoS, unicode, binary
- **Datadog 17K benchmark** - 14,587 confirmed malware samples (in-scope)
- **Ground truth validation** - 66 real-world attacks (93.75% TPR@3, 85.9% TPR@20)
- **False positive validation** - 14.0% FPR rules, 8.3% after ML on 532 curated npm packages, 7.5% on 200 random

---

## Community

- Discord: https://discord.gg/y8zxSmue

---

## Documentation

- [Blog](https://dnszlsk.github.io/muad-dib/blog/) - Technical articles on supply-chain threat detection
- [Carnet de bord](docs/CARNET_DE_BORD_MUADDIB.md) - Development journal (in French)
- [Documentation Index](docs/INDEX.md) - All documentation in one place
- [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md) - Experimental protocol, holdout scores
- [Threat Model](docs/threat-model.md) - What MUAD'DIB detects and doesn't detect
- [Adversarial Evaluation](ADVERSARIAL.md) - Red team samples and ADR results
- [Security Policy](SECURITY.md) - Detection rules reference (200 rules)
- [Security Audit](docs/SECURITY_AUDIT.md) - Bypass validation report
- [FP Analysis](docs/EVALUATION.md) - Historical false positive analysis

---

## License

MIT

---

<p align="center">
  <strong>The spice must flow. The worms must die.</strong>
</p>
