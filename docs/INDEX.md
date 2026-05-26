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

## Current Metrics (v2.11.47)

| Metric | Value |
|--------|-------|
| Tests | **3902** across 108 files |
| Rules | **259** (254 RULES + 5 PARANOID) |
| Scanners | **20 parallel** + 2 pre-analysis (module-graph, deobfuscate) + 1 async parser bootstrap (python-ast WASM) + 5 conditional/post-processing (paranoid, 3× temporal-*, reachability) + 1 metadata (npm-registry) |
| TPR@3 (Ground Truth, v2.11.47 measure) | **95.06%** (77/81 in-scope) — pre-Track-A+B subset; re-measurement on 94 in-scope pending |
| TPR@20 (Ground Truth, v2.11.47 measure) | **85.19%** (69/81 in-scope) — -1pp vs v2.10.95 reflects 3 intentional `tpr3-only` samples |
| FPR rules (Benign curated, v2.11.47 measure) | **1.10%** (6/545 scanned of 548) — down from 15.6% (v2.10.95), attributable to F1-F14 contextual caps (v2.10.97 → v2.11.31). The 6 remaining FPs are real: meteor, prisma, @prisma/client, drizzle-orm, scrypt, liquid |
| FPR after ML T1 (v2.11.47 measure) | **0.92%** (5/545) |
| FPR (Benign random, v2.11.47 measure) | **2.50%** (5/200) |
| FPR PyPI (v2.11.47, first measurement) | **6.10%** (5/82 scanned of 132) — first PyPI run, small N |
| ADR (Adversarial + Holdout, v2.11.47) | **96.26%** (103/107) |
| Wild TPR (Datadog 17K) | 92.8% (13,538/14,587 in-scope) — last measurement v2.9.4, independent of GT |
| Ground truth samples | **96** (94 active + 2 protestware with `min_threats=0`). 22 added 2026-05-25: 16 Track C synthetic + 6 Track A real-world + 7 Track B reconstructions. 13 PyPI (was 0). |

## Architecture Overview

```
src/
├── index.js              # Main scan orchestration (delegates to src/pipeline/)
├── pipeline/              # Pipeline stages: initializer, executor (20 scanners), processor, outputter
├── scoring.js             # Per-file max scoring + FP reductions + contextual FP caps (F1-F14)
├── intent-graph.js        # Intra-file source-sink coherence analysis
├── scanner/               # 20 parallel scanners + 2 pre-analysis modules + python-ast bootstrap
│   ├── ast.js             # AST-based detection (acorn) — 93 rules
│   ├── dataflow.js        # Credential read -> network send
│   ├── module-graph/      # Cross-file taint propagation (pre-analysis)
│   ├── deobfuscate.js     # Static deobfuscation pre-processing
│   ├── obfuscation.js     # Obfuscation detection
│   ├── entropy.js         # Shannon entropy analysis
│   ├── python.js          # PyPI metadata + typosquat
│   ├── python-source.js   # PYSRC-001..010 (regex, import-time RCE patterns)
│   ├── python-ast-detectors/ # PYAST-001..010 (tree-sitter Python AST + taint tracker)
│   ├── ai-config.js       # AI agent config injection (includes AICONF-004 ZW Unicode)
│   ├── ioc-strings.js     # YARA-style string IOCs (intel-triage P1.1)
│   ├── anti-forensic.js   # XOR + self-delete + decoy write (intel-triage P1.2)
│   ├── stub-package.js    # Stub + external dep + lifecycle (intel-triage P1.3)
│   ├── monorepo.js        # Lerna/pnpm-workspace/turbo detection (Sprint 1 MR-C2 fix)
│   ├── trusted-dep-diff.js # Diff against trusted dep tarballs (opt-in)
│   └── ...                # package, shell, typosquat, dependencies, hash, gh-actions
├── ml/                    # ML classifier (T1 filter, Phase 2)
├── rules/index.js         # 259 threat rules (254 RULES + 5 PARANOID, MITRE mapped)
├── response/playbooks.js  # Remediation playbooks
├── sandbox/               # Docker dynamic analysis
│   ├── index.js           # Multi-run orchestration [0h, 72h, 7d]
│   └── analyzer.js        # Preload log analysis
├── ioc/                   # IOC management
│   ├── bootstrap.js       # First-run IOC download (memoized per-process v2.11.47+)
│   ├── updater.js         # loadCachedIOCs()
│   └── data/iocs-compact.json  # 225K+ IOCs (~5MB)
├── vendor/                # Vendored web-tree-sitter WASM grammar for Python AST
└── commands/              # CLI commands
    └── evaluate.js        # TPR/FPR/ADR evaluation framework
```
