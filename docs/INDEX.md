# MUAD'DIB Documentation Index

## Quick Links

| Document | Description |
|----------|-------------|
| [README](../README.md) | Project overview, installation, usage |
| [README.fr.md](README.fr.md) | French version of the README |
| [SECURITY.md](../SECURITY.md) | Security policy, 223 detection rules reference (canonical source) |
| [CHANGELOG.md](../CHANGELOG.md) | Version history and release notes |

## Technical Documentation

| Document | Description |
|----------|-------------|
| [Evaluation Methodology](EVALUATION_METHODOLOGY.md) | Full experimental protocol: TPR, FPR, ADR methodology, holdout history, Datadog 17K benchmark, FP reduction passes |
| [Threat Model](threat-model.md) | What MUAD'DIB detects and doesn't detect, MITRE ATT&CK mapping, known limitations |
| [FP Analysis](EVALUATION.md) | Historical false positive audit and remaining FP analysis |
| [Security Audit](SECURITY_AUDIT.md) | Security audit report with 3 concrete bypass samples (v2.2.12) |

## Project Blog

| Document | Description |
|----------|-------------|
| [Carnet de Bord](CARNET_DE_BORD_MUADDIB.md) | Development journal (French) — project history and decisions |

## Current Metrics (v2.11.6)

| Metric | Value |
|--------|-------|
| Tests | 3529 across 89 files |
| Rules | 223 (218 RULES + 5 PARANOID) |
| Scanners | 16 parallel + 2 pre-analysis (module-graph, deobfuscate) |
| TPR@3 (Ground Truth, v2.10.95 measure) | 93.85% (61/65 active) |
| TPR@20 (Ground Truth, v2.10.95 measure) | 86.2% (56/65 active) |
| FPR rules (Benign curated, v2.10.95 measure) | **15.6%** (85/545 scanned of 548) — v2.10.74 estimated 6-9% reduction did NOT materialize on rebuilt corpus. Contextual FP post-filter v2.10.97 caps an additional 67/198 FP on a separate 302-package human corpus, 0/104 malware impacted |
| FPR after ML (v2.10.95 measure) | 10.28% (56/545) |
| FPR (Benign random, v2.10.95 measure) | 7.0% (14/200) |
| ADR (Adversarial + Holdout) | 96.3% (103/107) |
| Wild TPR (Datadog 17K) | 92.8% (13538/14587 in-scope) |
| Ground truth samples | 67 (65 active + 2 protestware with min_threats=0; react-emits GT-067 added in v2.10.74) |

## Architecture Overview

```
src/
├── index.js              # Main scan orchestration (delegates to src/pipeline/)
├── pipeline/              # Pipeline stages: initializer, executor (16 scanners), processor, outputter
├── scoring.js             # Per-file max scoring + FP reductions + contextual FP caps (F1-F7)
├── intent-graph.js        # Intra-file source-sink coherence analysis
├── scanner/               # 16 parallel scanners + 2 pre-analysis modules
│   ├── ast.js             # AST-based detection (acorn) — 93 rules
│   ├── dataflow.js        # Credential read -> network send
│   ├── module-graph/      # Cross-file taint propagation (pre-analysis)
│   ├── deobfuscate.js     # Static deobfuscation pre-processing
│   ├── obfuscation.js     # Obfuscation detection
│   ├── entropy.js         # Shannon entropy analysis
│   ├── python.js          # PyPI support
│   ├── ai-config.js       # AI agent config injection
│   ├── ioc-strings.js     # YARA-style string IOCs (intel-triage P1.1)
│   ├── anti-forensic.js   # XOR + self-delete + decoy write (intel-triage P1.2)
│   ├── stub-package.js    # Stub + external dep + lifecycle (intel-triage P1.3)
│   └── ...                # package, shell, typosquat, dependencies, hash, gh-actions
├── ml/                    # ML classifier (Phase 2)
├── rules/index.js         # 223 threat rules (218 RULES + 5 PARANOID, MITRE mapped)
├── response/playbooks.js  # Remediation playbooks
├── sandbox/               # Docker dynamic analysis
│   ├── index.js           # Multi-run orchestration [0h, 72h, 7d]
│   └── analyzer.js        # Preload log analysis
├── ioc/                   # IOC management
│   ├── updater.js         # loadCachedIOCs()
│   └── data/iocs-compact.json  # 225K+ IOCs (~5MB)
└── commands/              # CLI commands
    └── evaluate.js        # TPR/FPR/ADR evaluation framework
```
