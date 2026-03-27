# MUAD'DIB Threat Model

## What MUAD'DIB Detects

### npm & PyPI Supply Chain Attacks

| Technique | Detection | Confidence |
|-----------|-----------|------------|
| Known malicious npm packages | SHA256 hash + name | HIGH |
| Shai-Hulud v1/v2/v3 | Markers + files + behaviors | HIGH |
| event-stream (2018) | Name + version | HIGH |
| npm typosquatting | Popular package list | MEDIUM |
| Protestware (node-ipc, colors) | Name + version | HIGH |
| Malicious PyPI packages (14K+ from OSV dump) | Name matching | HIGH |
| PyPI typosquatting | Levenshtein + PEP 503 normalization | MEDIUM |

### Malicious Behaviors

| Technique | Detection | Confidence |
|-----------|-----------|------------|
| Credential theft (.npmrc, .ssh) | AST analysis | HIGH |
| Env var exfiltration (GITHUB_TOKEN) | AST analysis | HIGH |
| Remote code execution (curl \| sh) | Pattern matching | HIGH |
| Reverse shell | Pattern matching | HIGH |
| Dead man's switch (rm -rf $HOME) | Pattern matching | HIGH |
| Obfuscated code | Heuristics | MEDIUM |
| High-entropy strings (base64, hex, encrypted) | Shannon entropy | MEDIUM |
| Inter-module credential exfiltration | Dataflow analysis (module-graph) | HIGH |
| Intra-file credential + network co-occurrence | Intent coherence analysis | HIGH |

### Dataflow Analysis

| Technique | Detection | Confidence |
|-----------|-----------|------------|
| Credential read + network send (same file) | Intra-file dataflow | HIGH |
| Credential read + network send (cross-file) | Module graph taint propagation | HIGH |
| process.env access + fetch/request | AST + dataflow | HIGH |

### CI-Aware Malware Detection (v2.1.2)

Some supply-chain malware only activates in CI/CD environments. It checks for variables like `CI`, `GITHUB_ACTIONS`, `GITLAB_CI` before executing its payload, staying dormant on local machines.

The MUAD'DIB sandbox simulates 6 CI environments: GitHub Actions, GitLab CI, Travis CI, CircleCI, Jenkins. CI-aware malware triggers its payload in the isolated container, enabling detection via strace, tcpdump, and filesystem diff.

### Canary Tokens / Honey Tokens (v2.1.2)

The sandbox injects 6 fake credentials as honeypots:

| Token | Type | Purpose |
|-------|------|---------|
| GITHUB_TOKEN | Registry token | Detect GitHub token theft |
| NPM_TOKEN | Registry token | Detect npm token theft |
| AWS_ACCESS_KEY_ID | Cloud credential | Detect AWS key theft |
| AWS_SECRET_ACCESS_KEY | Cloud credential | Detect AWS secret theft |
| SLACK_WEBHOOK_URL | Messaging webhook | Detect Slack exfiltration |
| DISCORD_WEBHOOK_URL | Messaging webhook | Detect Discord exfiltration |

**Dual-layer detection:**
1. **Dynamic tokens**: Random suffix generated per session via `canary-tokens.js`, injected via Docker `-e`
2. **Static tokens**: Fallback values in `sandbox-runner.sh`, detected by `detectStaticCanaryExfiltration()`

**7 detection vectors:** HTTP bodies, DNS queries, HTTP request URLs, TLS connections, filesystem changes, process commands, npm install output.

If a package attempts to exfiltrate a canary token, it provides direct proof of malicious behavior (CRITICAL, +50 score, rule MUADDIB-CANARY-001).

## What MUAD'DIB Does NOT Detect

### Browser-Only Attacks (Out of Scope)

MUAD'DIB is a Node.js static analyzer. Attacks using exclusively browser APIs (DOM, `document`, `window`, `XMLHttpRequest`) without any Node.js API are not detected. These 3 ground truth samples are documented as out of scope:

| Sample | Technique | Why not detected |
|--------|-----------|-----------------|
| **lottie-player** | `document.createElement('script')` injection | Browser DOM API, no Node.js API |
| **polyfill-io** | Script injection via browser CDN | Client-side resource modification, no Node.js code |
| **trojanized-jquery** | jQuery DOM manipulation | jQuery/DOM browser API, no Node.js API |

Impact on TPR: 46/49 = 93.9% (3 documented and accepted misses).

### Known Limitations

| Technique | Reason |
|-----------|--------|
| Advanced polymorphic malware | No ML/machine learning, static patterns only |
| Advanced obfuscation | Static deobfuscation (v2.2.5) covers concat, charcode, base64, hex arrays + const propagation. Advanced obfuscators (JScrambler, control flow flattening) not covered |
| Zero-day (unknown packages) | IOC database is reactive (v1.x); mitigated by behavioral detection (v2.0) and validated by ground truth (v2.1) |
| Native binary attacks | No binary analysis |
| Subtle backdoors | No semantic code review |
| Encrypted TLS content | SNI capture and DNS/TLS correlation, but no MITM interception |
| Unsupported ecosystems | Limited to npm and PyPI (no RubyGems, Maven, Go) |
| Cloud dashboard/API | Local CLI tool only |

### Potential False Negatives

- Malicious code in non-JS/non-Python files (WASM, binaries)
- Exfiltration via covert channels (DNS tunneling, steganography)
- Malware that detects the analysis environment (anti-sandbox)
- Multi-stage attacks with remote payload
- Advanced JS obfuscation not covered by heuristics

## Internal Security Protections

### Input Sanitization

| Protection | Detail |
|------------|--------|
| YAML safe schema | All `yaml.load()` calls use `{ schema: yaml.JSON_SCHEMA }` to block dangerous tags (`!!js/function`, `!!python/object`) |
| Git ref sanitization | Git references passed to `muaddib diff` are validated against command injection before `git checkout` execution |
| CLI argument validation | Excessive-length arguments (>10000 chars), unicode paths, and shell injection attempts (`$(...)`, backticks) are neutralized |

### Network Security

| Protection | Detail |
|------------|--------|
| SSRF protection | Centralized download in `src/shared/download.js`: registry domain allowlist, private IP blocking (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, IPv6 loopback/link-local), redirect validation |
| Webhook timeout | Webhook sends (Discord/Slack) are time-limited to prevent blocking on slow or malicious endpoints |
| Webhook strict | Alerts only for IOC match, sandbox confirm, or canary exfiltration (no low-confidence heuristics) |
| Fail-closed on registry | If npm registry is unreachable during `muaddib install`, installation fails by default |

### Installation Security

| Protection | Detail |
|------------|--------|
| `--ignore-scripts` | Internal `npm install` commands (sandbox, safe-install) use `--ignore-scripts` to prevent malicious preinstall/postinstall execution |
| Symlink protection | `lstatSync` is used to detect symbolic links and prevent infinite loops or out-of-scope file access |
| XSS in HTML reports | User data in HTML reports is escaped via `escapeHtml()` |
| Docker sandbox | Package name validated via `sanitizePackageName()` before passing to Docker container |
| Command injection prevention | `execFileSync` with array arguments instead of `execSync` with template literals for tar extraction |
| Path traversal prevention | `sanitizePackageName()` removes `..` sequences from package names |

## Adversarial Testing Results

### Detection rate: 101/107 (94.0% ADR, global threshold=20)

107 available adversarial/holdout evasive samples (67 adversarial + 40 holdout across 7 red team waves + 4 holdout batches) tested with real-world evasion techniques.

See [Evaluation Methodology](EVALUATION_METHODOLOGY.md) for pre-tuning and post-tuning score details.

### Robustness (56 fuzz tests)

Parsers tested with malformed inputs:
- **YAML**: invalid, `!!js/function` blocked, empty, 10MB, unicode, null bytes, billion laughs
- **JSON**: invalid, empty, 10000-char keys, type mismatches, prototype pollution
- **AST**: invalid syntax, binary as .js, empty, null bytes, BOM, 100 callback nesting levels
- **CLI**: 10000-char arguments, unicode paths, shell injection `$(...)`, conflicting flags

Result: **56/56 pass**. No crashes, no uncaught exceptions.

### 1940 unit and integration tests

Full coverage of scanners, parsers, IOC matching, typosquatting, CLI integrations, diff, temporal analysis, ground truth, canary tokens, and security (SSRF, injection). 86% code coverage (c8).

### Ground Truth Validation

51 real-world supply-chain attacks replayed automatically. Detection rate: **93.9%** (46/49 active attacks). Includes event-stream, ua-parser-js, coa, node-ipc, eslint-scope, flatmap-stream, solana-web3js, and 43 more.

### Datadog 17K Benchmark

Validated against 17,922 real npm malware samples (v2.9.4 benchmark). Wild TPR: **92.5%** (13,486/14,587 in-scope). 3,335 packages skipped (no JS files). By category: compromised_lib **97.8%** (904/924), malicious_intent **92.1%** (12,582/13,663 in-scope).

## MITRE ATT&CK Mapping

| Technique | ID | MUAD'DIB Detection |
|-----------|----|--------------------|
| Credentials in Files | T1552.001 | AST analysis |
| Private Keys (.ssh/id_rsa) | T1552.004 | AST analysis |
| Command and Scripting Interpreter | T1059 | Pattern matching |
| Unix Shell (reverse shell, netcat) | T1059.004 | Pattern matching |
| JavaScript (eval, new Function) | T1059.007 | AST analysis |
| Application Layer Protocol (DNS/HTTP) | T1071 | Sandbox dynamic analysis |
| Supply Chain Compromise (npm/PyPI) | T1195.002 | IOC matching |
| Obfuscated Files | T1027 | Heuristics |
| Exfiltration Over C2 Channel | T1041 | Dataflow analysis |
| Ingress Tool Transfer | T1105 | Pattern matching |
| Data Destruction | T1485 | Pattern matching |

See [SECURITY.md](../SECURITY.md#detection-rules-v262) for the complete 129-rule reference.

## Assumptions

1. **Source code is available** — MUAD'DIB analyzes JS and Python dependencies, not binaries
2. **IOCs are up to date** — Detection depends on the IOC database
3. **Attacker uses known techniques** — Zero-days pass through
4. **Scan runs before installation** — After `npm install`, it's too late if preinstall executed

## Contacts

- Repository: https://github.com/DNSZLSK/muad-dib
- Issues: https://github.com/DNSZLSK/muad-dib/issues
