# MUAD'DIB — Evaluation Methodology

## 1. Methodology

MUAD'DIB measures scanner effectiveness using a rigorous experimental protocol inspired by machine learning evaluation practices. Two distinct datasets are used:

### Training Set (Adversarial)

The **adversarial dataset** (`datasets/adversarial/`) contains malicious samples used during rule development. When a sample fails detection, rules are improved until it passes. This measures the scanner's **tuned performance** — the best-case scenario after iterative refinement.

- Samples are created before any rule changes
- Initial scores are recorded with rules frozen (pre-tuning baseline)
- Rules are then improved to close detection gaps
- Final scores represent post-tuning performance

### Holdout Set

The **holdout set** is a separate batch of samples created after rule tuning is complete. Rules are **frozen** — no modifications allowed. The raw scores measure the scanner's **generalization ability**: how well existing rules detect attack patterns they were never tuned for.

- Samples designed independently from current rules
- Scores reported as-is, no threshold adjustments
- Provides an honest assessment of detection gaps

Both metrics (ADR and Holdout) are published together. The gap between them reveals how much the scanner relies on sample-specific tuning vs. genuine pattern recognition.

---

## 2. Raw Scores Before Correction (Holdout History)

Each batch below was evaluated with **rules frozen** at the time of creation. These scores represent pre-tuning baselines — the scanner's genuine first-contact performance on unseen samples.

### Robustness Test (3 samples, rules frozen): 1/3 (33%)

| Sample | Score | Threshold | Result |
|--------|-------|-----------|--------|
| dynamic-require | 28 | 40 | FAIL |
| iife-exfil | 58 | 40 | PASS |
| conditional-chain | 3 | 30 | FAIL |

### Vague 2 (5 samples, rules frozen): 0/5 (0%)

| Sample | Score | Threshold | Result |
|--------|-------|-----------|--------|
| template-literal-obfuscation | 3 | 30 | FAIL |
| proxy-env-intercept | 28 | 40 | FAIL |
| nested-payload | 13 | 30 | FAIL |
| dynamic-import | 13 | 30 | FAIL |
| websocket-exfil | 13 | 30 | FAIL |

### Intermediate Batch (5 samples, rules frozen): 3/5 (60%)

| Sample | Score | Threshold | Result |
|--------|-------|-----------|--------|
| bun-runtime-evasion | 48 | 30 | PASS |
| preinstall-exec | 13 | 35 | FAIL |
| remote-dynamic-dependency | 35 | 35 | PASS |
| github-exfil | 68 | 30 | PASS |
| detached-background | 13 | 35 | FAIL |

### Vague 3 (5 samples, rules frozen): 3/5 (60%)

| Sample | Score | Threshold | Result |
|--------|-------|-----------|--------|
| ai-agent-weaponization | 13 | 35 | FAIL |
| ai-config-injection | 0 | 30 | FAIL |
| rdd-zero-deps | PASS | 35 | PASS |
| discord-webhook-exfil | PASS | 30 | PASS |
| preinstall-background-fork | PASS | 35 | PASS |

### Holdout v1 (10 samples, rules frozen): 3/10 (30%)

| Sample | Score | Threshold | Result |
|--------|-------|-----------|--------|
| silent-error-swallow | 35 | 25 | PASS |
| double-base64-exfil | 13 | 30 | FAIL |
| crypto-wallet-harvest | 0 | 25 | FAIL |
| self-hosted-runner-backdoor | 3 | 20 | FAIL |
| dead-mans-switch | 68 | 30 | PASS |
| fake-captcha-fingerprint | 3 | 20 | FAIL |
| pyinstaller-dropper | 3 | 35 | FAIL |
| gh-cli-token-steal | 0 | 30 | FAIL |
| triple-base64-github-push | 38 | 30 | PASS |
| browser-api-hook | 0 | 20 | FAIL |

### Holdout v2 (10 samples, rules frozen): 4/10 (40%)

| Sample | Score | Threshold | Result |
|--------|-------|-----------|--------|
| env-var-reconstruction | 3 | 25 | FAIL |
| homedir-ssh-key-steal | 35 | 30 | PASS |
| setTimeout-chain | 35 | 25 | PASS |
| wasm-loader | 25 | 20 | PASS |
| npm-lifecycle-preinstall-curl | 13 | 30 | FAIL |
| process-env-proxy-getter | 0 | 20 | FAIL |
| readable-stream-hijack | 0 | 20 | FAIL |
| github-workflow-inject | 0 | 25 | FAIL |
| npm-cache-poison | 0 | 20 | FAIL |
| conditional-os-payload | 35 | 25 | PASS |

---

## 3. Progression

| Batch | Pre-Tuning Rate | Samples |
|-------|-----------------|---------|
| Robustness Test | 33% (1/3) | 3 |
| Vague 2 | 0% (0/5) | 5 |
| Intermediate | 60% (3/5) | 5 |
| Vague 3 | 60% (3/5) | 5 |
| Holdout v1 | 30% (3/10) | 10 |
| **Holdout v2** | **40% (4/10)** | 10 |

**Key observations:**

- The 0% in Vague 2 exposed critical gaps (template literal handling, staged payloads, dynamic imports). Fixing these improved subsequent batches.
- The 60% in Intermediate/Vague 3 shows partial generalization — rules improved for earlier samples also caught new patterns.
- The **Holdout v1 30%** revealed 7 genuine blind spots: binary droppers, prototype hooking, credential CLI theft, workflow injection, crypto wallet harvesting, and more.
- The **Holdout v2 40%** shows marginal improvement in generalization (+10pp). 6 new blind spots identified: env var charcode reconstruction, lifecycle shell pipe, Object.defineProperty proxy, Node.js core prototype hijack, GitHub workflow injection via template literals, npm cache poisoning.
- After corrections, all 45 samples pass (ADR 100%). But the pre-correction holdout scores (30%, 40%) are the true measures of generalization.

---

## 4. Improvement Cycle

MUAD'DIB follows a structured **tune-freeze-holdout-publish** cycle:

```
1. TUNE     Create adversarial samples with rules frozen
            Record pre-tuning scores (raw holdout data)
            Improve rules until all samples pass

2. FREEZE   Lock rules — no further modifications

3. HOLDOUT  Create new samples never seen during tuning
            Run scanner with frozen rules
            Record raw scores (no threshold changes)

4. PUBLISH  Report both metrics:
            - ADR (post-tuning): measures tuned performance
            - Holdout (pre-tuning): measures generalization

5. PROMOTE  Move FAIL samples to adversarial dataset
            Improve rules to close gaps
            Repeat from step 2 with new holdout batch
```

This cycle ensures:
- **Honesty**: pre-tuning scores are always published alongside post-tuning scores
- **No overfitting**: holdout samples test genuine generalization, not memorization
- **Continuous improvement**: each cycle identifies real blind spots and closes them
- **Reproducibility**: `muaddib evaluate` reproduces all metrics locally

---

## 5. Attack Technique Sources

All adversarial samples are based on real-world attack techniques documented by security researchers in 2025-2026:

| Source | Techniques | Reference |
|--------|-----------|-----------|
| **Snyk** | ToxicSkills (AI config injection in .cursorrules, CLAUDE.md), s1ngularity/Nx (AI agent weaponization with --dangerously-skip-permissions), Clinejection (prompt injection via copilot-instructions.md) | Snyk Blog 2025 |
| **Sonatype** | PhantomRaven (zero-deps variant with inline https.get + eval in postinstall), binary droppers via /tmp/ | Sonatype Blog 2025 |
| **Datadog Security Labs** | Shai-Hulud 2.0 (GitHub Actions workflow injection, self-hosted runner backdoor, discussion.yaml persistence) | Datadog Security Research 2025 |
| **Unit 42 (Palo Alto)** | Shai-Hulud v1 campaign analysis, credential exfiltration patterns, dead man's switch (rm -rf if no tokens) | Unit 42 Threat Research 2025 |
| **Check Point Research** | Shai-Hulud 2.0 credential harvesting, Discord webhook exfiltration, base64 multi-layer encoding | Check Point Research 2025 |
| **Zscaler ThreatLabz** | Shai-Hulud V2 evasion techniques, CI-gated payloads, DNS chunked exfiltration | Zscaler ThreatLabz 2025 |
| **StepSecurity** | s1ngularity campaign (Claude/Gemini/Q agent abuse, --yolo flag), postinstall fork + detached credential theft | StepSecurity Blog 2025 |
| **Socket.dev** | Mid-Year Supply Chain Report 2025, preinstall-exec patterns, staged fetch payloads, npm lifecycle hooks abuse | Socket.dev 2025 |
| **NVIDIA** | AI agent security guidance, prompt injection in AI config files, tool-use exploitation | NVIDIA AI Security 2025 |
| **Sygnia** | chalk/debug September 2025 compromise, prototype hooking (globalThis.fetch, XMLHttpRequest.prototype), native API interception | Sygnia Threat Intelligence 2025 |
| **Hive Pro** | Typosquatting credential theft, crypto wallet harvesting (.ethereum, .electrum, .config/solana), gh auth token CLI abuse | Hive Pro Research 2025 |
| **Koi Security** | PackageGate vulnerability, npm registry metadata manipulation, publish frequency anomalies | Koi Security 2025 |

---

## 6. Current Metrics (v2.2.1)

| Metric | Result | Description |
|--------|--------|-------------|
| **TPR** (Ground Truth) | 100% (4/4) | Real-world attacks: event-stream, ua-parser-js, coa, node-ipc |
| **FPR** (Benign) | 0% (0/98) | 98 popular npm packages, threshold > 20 |
| **ADR** (Adversarial) | 100% (45/45) | 45 evasive samples across 4 vagues + promoted holdout v1 + promoted holdout v2 |
| **Holdout v1** (pre-tuning) | 30% (3/10) | 10 unseen samples before rule corrections |
| **Holdout v2** (pre-tuning) | 40% (4/10) | 10 unseen samples before rule corrections |

Run `muaddib evaluate` to reproduce these metrics locally. Results are saved to `metrics/v{version}.json`.
