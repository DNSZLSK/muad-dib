# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.7.x   | :white_check_mark: |
| 2.6.x   | :white_check_mark: |
| 2.5.x   | :white_check_mark: |
| 2.4.x   | :x:                |
| 2.3.x   | :x:                |
| 2.2.x   | :x:                |
| 2.1.x   | :x:                |
| 2.0.x   | :x:                |
| 1.8.x   | :x:                |
| 1.6.x   | :x:                |
| 1.4.x   | :x:                |
| 1.3.x   | :x:                |
| 1.2.x   | :x:                |
| 1.1.x   | :x:                |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities in MUAD'DIB seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues via one of these methods:

1. **GitHub Security Advisories** (preferred):
   - Go to [Security Advisories](https://github.com/DNSZLSK/muad-dib/security/advisories)
   - Click "New draft security advisory"
   - Fill in the details

2. **Email**:
   - Send details to the maintainer via GitHub profile contact

### What to Include

Please include the following information in your report:

- **Description**: Clear description of the vulnerability
- **Impact**: What an attacker could achieve
- **Steps to reproduce**: Detailed steps to reproduce the issue
- **Affected versions**: Which versions are affected
- **Suggested fix**: If you have one (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release

### Disclosure Policy

- We follow coordinated disclosure
- We will credit reporters in the release notes (unless you prefer anonymity)
- We aim to release fixes before public disclosure
- We request a 90-day disclosure window for complex issues

## Detection Rules (v2.7.8)

MUAD'DIB uses 14 scanner modules (module-graph pre-analysis + 13 parallel scanners) + 5 behavioral anomaly detection features + ground truth validation, producing 134 rule IDs (129 RULES + 5 PARANOID):

### AST Scanner

| Rule ID | Name | Severity | Notes |
|---------|------|----------|-------|
| MUADDIB-AST-001 | Sensitive String Reference | HIGH | .npmrc, .ssh, tokens |
| MUADDIB-AST-002 | Sensitive Env Variable Access | HIGH | GITHUB_TOKEN, NPM_TOKEN, AWS_* |
| MUADDIB-AST-003 | Dangerous Function Call (exec/spawn) | MEDIUM | |
| MUADDIB-AST-004 | Eval Usage | HIGH | eval(variable) = HIGH, eval('literal') = LOW |
| MUADDIB-AST-005 | new Function() Constructor | HIGH | Function(variable) = MEDIUM, Function('literal') = LOW |

### Shell Scanner

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-SHELL-001 | Remote Code Execution via Curl | CRITICAL |
| MUADDIB-SHELL-002 | Reverse Shell | CRITICAL |
| MUADDIB-SHELL-003 | Dead Man's Switch | CRITICAL |
| MUADDIB-SHELL-004 | Curl Pipe to Shell | CRITICAL |
| MUADDIB-SHELL-005 | Wget Download and Execute | CRITICAL |
| MUADDIB-SHELL-006 | Netcat Shell | CRITICAL |
| MUADDIB-SHELL-007 | Home Directory Destruction | CRITICAL |
| MUADDIB-SHELL-008 | Data Exfiltration via Curl | HIGH |
| MUADDIB-SHELL-009 | SSH Key Access | HIGH |
| MUADDIB-SHELL-010 | Python Reverse Shell | CRITICAL |
| MUADDIB-SHELL-011 | Perl Reverse Shell | CRITICAL |
| MUADDIB-SHELL-012 | FIFO Reverse Shell | CRITICAL |
| MUADDIB-SHELL-013 | FIFO + Netcat Reverse Shell (mkfifo + nc) | CRITICAL |
| MUADDIB-SHELL-014 | Base64 Decode Pipe to Shell (base64 -d \| bash) | CRITICAL |
| MUADDIB-SHELL-015 | Wget + Base64 Decode Two-Stage | HIGH |
| MUADDIB-SHELL-016 | Curl IFS Variable Evasion (curl$IFS \| sh) | CRITICAL |
| MUADDIB-SHELL-017 | Eval Curl Command Substitution (eval $(curl)) | CRITICAL |
| MUADDIB-SHELL-018 | Shell -c Curl Execution (sh -c curl) | HIGH |

### Package Scanner

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-PKG-001 | Suspicious Lifecycle Script | MEDIUM |
| MUADDIB-PKG-002 | Curl Pipe to Shell in Script | CRITICAL |
| MUADDIB-PKG-003 | Wget Pipe to Shell in Script | CRITICAL |
| MUADDIB-PKG-004 | Eval in Lifecycle Script | HIGH |
| MUADDIB-PKG-005 | Child Process in Lifecycle Script | HIGH |
| MUADDIB-PKG-006 | npmrc Access | HIGH |
| MUADDIB-PKG-007 | GitHub Token Access | HIGH |
| MUADDIB-PKG-008 | AWS Credential Access | HIGH |
| MUADDIB-PKG-009 | Base64 Encoding in Script | MEDIUM |
| MUADDIB-PKG-010 | Lifecycle Shell Pipe | CRITICAL |

### AST Scanner (v2.2+)

| Rule ID | Name | Severity | MITRE |
|---------|------|----------|-------|
| MUADDIB-AST-008 | Dynamic Require with Decode | HIGH | T1059 |
| MUADDIB-AST-009 | Sandbox Evasion | HIGH | T1497 |
| MUADDIB-AST-010 | Detached Process | HIGH | T1059 |
| MUADDIB-AST-011 | Binary Dropper Pattern | CRITICAL | T1105 |
| MUADDIB-AST-012 | Dynamic Require Decode | HIGH | T1059 |
| MUADDIB-AST-013 | AI Agent Abuse | CRITICAL | T1059 |
| MUADDIB-AST-014 | Credential CLI Theft | CRITICAL | T1552 |
| MUADDIB-AST-015 | Workflow Write | CRITICAL | T1195.002 |
| MUADDIB-AST-016 | Binary Dropper | CRITICAL | T1105 |
| MUADDIB-AST-017 | Prototype Hooking | HIGH | T1574 |
| MUADDIB-AST-018 | Env Charcode Reconstruction | HIGH | T1027 |
| MUADDIB-AST-019 | Require Cache Poisoning | CRITICAL | T1574 |
| MUADDIB-AST-020 | Staged Binary Payload | CRITICAL | T1027 |
| MUADDIB-AST-021 | Staged Eval Decode | CRITICAL | T1140 |
| MUADDIB-AST-022 | Encrypted Payload Decryption | HIGH | T1140 |
| MUADDIB-AST-023 | Module Compile Execution | HIGH | T1059 |
| MUADDIB-AST-024 | Obfuscated Payload via Zlib Inflate | CRITICAL | T1140 |
| MUADDIB-AST-025 | Dynamic Module Compile Execution | HIGH | T1059 |
| MUADDIB-AST-026 | Anti-Forensics Write-Execute-Delete | HIGH | T1070 |
| MUADDIB-AST-027 | MCP Config Injection | CRITICAL | T1059 |
| MUADDIB-AST-028 | Git Hooks Injection | HIGH | T1195.002 |
| MUADDIB-AST-029 | Dynamic Environment Variable Harvesting | HIGH | T1552 |
| MUADDIB-AST-030 | DNS Chunk Exfiltration | HIGH | T1048 |
| MUADDIB-AST-031 | LLM API Key Harvesting | MEDIUM | T1552 |
| MUADDIB-AST-033 | Steganographic Payload Chain (fetch + decrypt + eval) | CRITICAL | T1027.003 |
| MUADDIB-AST-034 | Download-Execute Binary (download + chmod + execSync) | CRITICAL | T1105 |
| MUADDIB-AST-035 | IDE Task Persistence (tasks.json + runOn + writeFileSync) | HIGH | T1546 |
| MUADDIB-AST-036 | VM Module Code Execution (vm.runInThisContext, vm.Script) | HIGH | T1059 |
| MUADDIB-AST-037 | Reflect API Code Execution (Reflect.construct/apply) | CRITICAL | T1059 |
| MUADDIB-AST-038 | Process Binding Abuse (process.binding/_linkedBinding) | CRITICAL | T1059 |
| MUADDIB-AST-039 | Worker Thread Code Execution (new Worker eval:true) | HIGH | T1059 |
| MUADDIB-AST-040 | Remote Code Loading (fetch + eval/Function) | CRITICAL | T1105 |
| MUADDIB-AST-041 | Credential Regex Harvesting (regex + network) | HIGH | T1552 |
| MUADDIB-AST-042 | WASM Host Import Sink (WASM + network callbacks) | CRITICAL | T1059 |
| MUADDIB-AST-043 | Proxy Data Interception (Proxy trap + network) | CRITICAL | T1557 |
| MUADDIB-AST-044 | Built-in Method Override Exfiltration | HIGH | T1557 |
| MUADDIB-AST-045 | Stream Credential Interception (Transform/Duplex + regex) | HIGH | T1557 |
| MUADDIB-AST-046 | WASM Module Load Standalone (no network sinks) | MEDIUM | T1027 |

### AI Config Scanner (v2.2)

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-AICONF-001 | AI Config Prompt Injection | HIGH |
| MUADDIB-AICONF-002 | AI Config Compound Injection | CRITICAL |

### Dataflow Scanner (v2.2+)

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-FLOW-003 | Credential Tampering / Cache Poisoning | CRITICAL |
| MUADDIB-FLOW-004 | Cross-File Dataflow | CRITICAL |

### Obfuscation Scanner

| Rule ID | Name | Severity | Notes |
|---------|------|----------|-------|
| MUADDIB-OBF-001 | Code Obfuscation Detected | HIGH | Hex/unicode escapes alone no longer trigger; .min.js long lines ignored |
| MUADDIB-OBF-002 | Possible Code Obfuscation | MEDIUM | Parse failure + dense code |

### Dependency Scanner

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-DEP-001 | Known Malicious Package | CRITICAL |
| MUADDIB-DEP-002 | Suspicious File in Dependency | CRITICAL |
| MUADDIB-DEP-003 | Shai-Hulud Marker | CRITICAL |
| MUADDIB-DEP-004 | Lifecycle Script in Dependency | MEDIUM |

### Entropy Scanner

| Rule ID | Name | Severity | Notes |
|---------|------|----------|-------|
| MUADDIB-ENTROPY-001 | High Entropy String | MEDIUM | Threshold: 5.5 bits + 50 chars min |
| ~~MUADDIB-ENTROPY-002~~ | ~~High Entropy File~~ | ~~removed~~ | Removed in v1.6.16 — replaced by ENTROPY-003 |
| MUADDIB-ENTROPY-003 | JS Obfuscation Pattern | HIGH | _0x* vars, encoded string arrays, eval+entropy, long base64 |
| MUADDIB-ENTROPY-004 | Fragmented High Entropy Cluster | MEDIUM | Many short high-entropy strings bypassing MIN_STRING_LENGTH |

### Other Scanners

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-HASH-001 | Known Malicious File Hash | CRITICAL |
| MUADDIB-FLOW-001 | Suspicious Data Flow | CRITICAL |
| MUADDIB-TYPO-001 | Typosquatting Detected (npm) | HIGH |
| MUADDIB-PYPI-001 | Malicious PyPI Package | CRITICAL |
| MUADDIB-PYPI-002 | PyPI Typosquatting | HIGH |
| MUADDIB-GHA-001 | Shai-Hulud GH Actions Backdoor | CRITICAL |
| MUADDIB-GHA-002 | Workflow Injection | HIGH |
| MUADDIB-GHA-003 | GitHub Actions Pwn Request | CRITICAL |

### Sandbox Rules (Docker) — Dynamic Analysis

Runtime behavioral analysis: packages are installed in an isolated Docker container and monitored for suspicious activity (file access, network traffic, process spawns) via strace, tcpdump, and filesystem diffing. The sandbox simulates a CI environment (v2.1.2) to trigger CI-aware malware and injects 6 canary token honeypots for exfiltration detection.

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-SANDBOX-001 | Sensitive File Read | CRITICAL |
| MUADDIB-SANDBOX-002 | Sensitive File Write | CRITICAL |
| MUADDIB-SANDBOX-003 | Suspicious Filesystem Change | HIGH |
| MUADDIB-SANDBOX-004 | Suspicious DNS Query | HIGH |
| MUADDIB-SANDBOX-005 | Suspicious Network Connection | HIGH |
| MUADDIB-SANDBOX-006 | Dangerous Process Spawned | CRITICAL |
| MUADDIB-SANDBOX-007 | Unknown Process Spawned | MEDIUM |
| MUADDIB-SANDBOX-008 | Container Timeout | CRITICAL |

### Sandbox Preload Rules (v2.4.9) — Runtime Monkey-Patching

Runtime behavioral analysis via monkey-patching preload (`NODE_OPTIONS=--require /opt/preload.js`). Patches time APIs, intercepts network/filesystem/process/env calls. Multi-run mode at [0h, 72h, 7d] offsets to detect time-bomb malware (MITRE T1497.003).

| Rule ID | Name | Severity | MITRE |
|---------|------|----------|-------|
| MUADDIB-SANDBOX-009 | Suspicious Timer Delay (> 1h) | MEDIUM | T1497.003 |
| MUADDIB-SANDBOX-010 | Critical Timer Delay / Time-Bomb (> 24h) | CRITICAL | T1497.003 |
| MUADDIB-SANDBOX-011 | Preload Sensitive File Read (.npmrc, .ssh, .aws, .env) | HIGH | T1552.001 |
| MUADDIB-SANDBOX-012 | Network After Sensitive Read (compound: file + network) | CRITICAL | T1041 |
| MUADDIB-SANDBOX-013 | Suspicious Command Execution (curl, wget, bash, powershell) | HIGH | T1059 |
| MUADDIB-SANDBOX-014 | Sensitive Environment Variable Access (TOKEN, SECRET, KEY) | MEDIUM | T1552.001 |

### Intent Coherence Rules (v2.6.0) — Intra-File Source-Sink Analysis

Intra-file coherence analysis detects when a single file contains both a credential source and a dangerous sink. Cross-file detection is handled by module-graph (FLOW-004). LOW-severity threats are excluded to respect FP reductions.

| Rule ID | Name | Severity | MITRE |
|---------|------|----------|-------|
| MUADDIB-INTENT-001 | Intent Credential Exfiltration (credential_read + exec/network sink) | CRITICAL | T1041 |
| MUADDIB-INTENT-002 | Intent Command Output Exfiltration (command_output + network sink) | HIGH | T1041 |

### Temporal Analysis Rules (v2.0) — Behavioral Anomaly Detection

Behavioral detection analyzes changes between package versions to detect supply-chain attacks before they appear in IOC databases. These features query the npm registry at scan time and compare metadata/code across versions.

#### Sudden Lifecycle Script Detection (`--temporal`)

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| MUADDIB-TEMPORAL-001 | Sudden Lifecycle Script Added (Critical) | CRITICAL | `preinstall`/`install`/`postinstall` script added in latest version. Attack vector #1 (Shai-Hulud, ua-parser-js, coa). |
| MUADDIB-TEMPORAL-002 | Sudden Lifecycle Script Added | HIGH | Other lifecycle script (`prepare`, `prepack`, etc.) added in latest version. |
| MUADDIB-TEMPORAL-003 | Lifecycle Script Modified | MEDIUM | Existing lifecycle script content changed between versions. |

MITRE: T1195.002 (Supply Chain Compromise: Software Supply Chain)

#### Temporal AST Diff (`--temporal-ast`)

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| MUADDIB-TEMPORAL-AST-001 | Dangerous API Added (Critical) | CRITICAL | `child_process`, `eval`, `Function`, `net.connect` appeared in latest version (absent from previous). |
| MUADDIB-TEMPORAL-AST-002 | Dangerous API Added (High) | HIGH | `process.env`, `fetch`, `http`/`https` request appeared in latest version. |
| MUADDIB-TEMPORAL-AST-003 | Dangerous API Added (Medium) | MEDIUM | `dns.lookup`, `fs.readFile` on sensitive path appeared in latest version. |

MITRE: T1195.002 (Supply Chain Compromise: Software Supply Chain)

#### Publish Frequency Anomaly (`--temporal-publish`)

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| MUADDIB-PUBLISH-001 | Publish Burst Detected | HIGH | Multiple versions published within 24h. Possible account compromise or automated attack. |
| MUADDIB-PUBLISH-002 | Dormant Package Spike | HIGH | Package inactive for 6+ months with a sudden new version. Possible maintainer change or compromise. |
| MUADDIB-PUBLISH-003 | Rapid Version Succession | MEDIUM | Versions published in rapid succession (< 1h). Possible automated attack or compromised CI/CD. |

MITRE: T1195.002 (Supply Chain Compromise: Software Supply Chain)

#### Maintainer Change Detection (`--temporal-maintainer`)

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| MUADDIB-MAINTAINER-001 | New Maintainer Added | HIGH | A new maintainer was added between the two latest versions. |
| MUADDIB-MAINTAINER-002 | Suspicious Maintainer Detected | CRITICAL | Maintainer with suspicious name (generic, auto-generated, very short). High risk of account takeover. |
| MUADDIB-MAINTAINER-003 | Sole Maintainer Changed | HIGH | The sole maintainer has changed. Strong indicator of account compromise (event-stream pattern). |
| MUADDIB-MAINTAINER-004 | New Publisher Detected | MEDIUM | Latest version published by a different user than the previous version. |

MITRE: T1195.002 (Supply Chain Compromise: Software Supply Chain)

#### Canary Tokens / Honey Tokens (sandbox)

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| MUADDIB-CANARY-001 | Canary Token Exfiltration | CRITICAL | Package attempted to exfiltrate honey tokens (fake secrets) injected in the sandbox. Confirmed malicious behavior. |

MITRE: T1552.001 (Unsecured Credentials: Credentials in Files)

6 honeypot credentials are injected (v2.1.2):
- `GITHUB_TOKEN` / `NPM_TOKEN` — Package registry tokens
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` — Cloud credentials
- `SLACK_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` — Messaging webhooks

Detection uses both dynamic tokens (random per session) and static fallback tokens. Exfiltration is searched in HTTP bodies, DNS queries, HTTP request URLs, TLS domains, filesystem changes, process commands, and install output.

#### CI-Aware Sandbox (v2.1.2)

The sandbox simulates CI environments by setting: `CI=true`, `GITHUB_ACTIONS=true`, `GITLAB_CI=true`, `TRAVIS=true`, `CIRCLECI=true`, `JENKINS_URL=http://localhost:8080`. This triggers CI-aware malware that checks for these environment variables before activating, which would otherwise stay dormant in local development environments.

### Paranoid Mode Rules

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-PARANOID-001 | Network Access | HIGH |
| MUADDIB-PARANOID-002 | Sensitive File Access | HIGH |
| MUADDIB-PARANOID-003 | Dynamic Execution | CRITICAL |
| MUADDIB-PARANOID-004 | Subprocess Execution | CRITICAL |
| MUADDIB-PARANOID-005 | Env Variable Access | MEDIUM |

## Security Measures in MUAD'DIB

### Input Validation

- Package names are validated against npm naming rules to prevent command injection
- Webhook URLs are validated against a whitelist of allowed domains
- File paths are sanitized to prevent directory traversal

### SSRF Protection

- Webhook module only allows connections to whitelisted domains:
  - discord.com
  - discordapp.com
  - hooks.slack.com
- Download module (v2.1.2) only allows redirects to whitelisted registry domains:
  - registry.npmjs.org, registry.yarnpkg.com
  - pypi.org, files.pythonhosted.org
- Private IP ranges are blocked (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, IPv6 loopback/link-local)
- Redirect validation prevents SSRF via open redirects

### Command Injection Protection (v2.1.2)

- `execFileSync` with array arguments replaces `execSync` with template literals for tar extraction
- Package names are sanitized via `sanitizePackageName()` to remove `..` path traversal sequences
- `NPM_PACKAGE_REGEX` is centralized in `src/shared/constants.js` and enforced across all modules

### XSS Protection

- HTML reports escape all user-provided data
- No inline JavaScript in generated reports

### Dependency Security

- All dependencies are pinned to exact versions
- Regular updates via Dependabot (when enabled)
- Minimal dependency footprint (7 production dependencies)

## Security Best Practices for Users

### When Using MUAD'DIB

1. **Keep updated**: Run `npm update -g muaddib-scanner` regularly
2. **Update IOCs**: Run `muaddib update` to get the latest threat database
3. **Use in CI/CD**: Integrate with GitHub Actions for continuous scanning
4. **Review results**: Don't blindly trust automated tools - review flagged packages

### When Contributing

1. **No secrets**: Never commit API keys, tokens, or credentials
2. **Signed commits**: Use GPG-signed commits when possible
3. **Review dependencies**: Check new dependencies before adding them

## Threat Model (v2.7.8)

MUAD'DIB 2.6 uses a **triple detection approach**:

1. **IOC-based detection** (v1.x): Matches packages against 225,000+ known malicious packages from OSV, DataDog, OSSF, GitHub Advisory, and other sources. Fast and reliable for known threats.

2. **Behavioral anomaly detection** (v2.0): Analyzes changes between package versions to detect supply-chain attacks before they appear in IOC databases. Compares lifecycle scripts, AST, publish frequency, and maintainer metadata across versions. This approach can detect 0-day behavioral anomalies without any prior knowledge of the specific attack.

3. **Ground truth validation** (v2.1–v2.6.5): Validates detection accuracy against 51 real-world attacks (49 active samples), tracks detection lead times vs. public advisories, and monitors false positive rates over time. 1974 tests with 86% code coverage. Provides observability into scanner effectiveness.

The behavioral detection features are opt-in (`--temporal-full`) and query the npm registry at scan time. They are particularly effective against:
- Account takeover attacks (event-stream pattern)
- Compromised CI/CD pipelines (automated malicious publishes)
- Dormant package hijacking (abandonware takeover)
- Sudden code injection (Shai-Hulud, ua-parser-js pattern)

## Ground Truth Validation (v2.6.5)

MUAD'DIB includes a ground truth dataset of 51 real-world supply-chain attacks (49 active samples) to continuously validate detection coverage.

**TPR: 93.9% (46/49 detected)**

3 out-of-scope misses (browser-only):
- lottie-player, polyfill-io, trojanized-jquery (browser-only DOM attacks)

Run `muaddib evaluate --ground-truth` to validate detection at any time.

## Evaluation Methodology Caveats (v2.6.5)

The metrics reported above should be interpreted with the following caveats:

- **TPR scope:** Measured on 49 Node.js attack samples from 51 total. 3 browser-only attacks (lottie-player, polyfill-io, trojanized-jquery) are excluded because MUAD'DIB is a Node.js static analyzer and cannot detect DOM/browser-only patterns.
- **FPR dataset:** Measured on 529 curated popular npm packages, not a random sample. FPR varies significantly by package size: small packages (<10 JS files) have lower FPR than very large packages (100+ files) due to accumulation of benign patterns that resemble threats.
- **ADR methodology:** As of v2.6.5, ADR uses a global threshold (score >= 20) aligned with the benign threshold. Earlier versions used per-sample tuned thresholds which inflated the ADR metric.
- **Node.js scope:** MUAD'DIB is designed for Node.js/npm supply-chain attacks. Browser-only attacks, native binary payloads, and phishing pages are out of scope.
- **Static analysis limitations:** Dynamic obfuscation, encrypted payloads that require runtime keys, and multi-stage attacks fetching payloads from external servers may evade static detection.

## Datadog 17K Benchmark (v2.6.5)

Validated against the [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset) (17,922 real malware npm packages).

**Raw TPR: 88.2% (15,810/17,922)**

The 2,077 misses (score=0) are all out-of-scope:
- 1,233 phishing pages (HTML/CSS/JS frontend — no Node.js APIs)
- 824 native binaries (no JS files)
- 20 corrected libraries (malicious code already removed)

**Adjusted TPR on JS/Node.js malware: ~100%** (15,810/~15,845). See [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md#14-datadog-17k-benchmark) for the full categorization methodology.

## Threat Feed API Security

The `muaddib serve` HTTP server binds to `localhost` (127.0.0.1) by default. It serves detection data as JSON for SIEM integration.

- **No authentication**: the server is designed for local use only. Do not expose to the public internet. For production deployment, use a reverse proxy (nginx, Caddy) with authentication and TLS termination.
- **No sensitive data**: the feed contains detection metadata (package names, severities, timestamps), not raw file contents or credentials.
- **Localhost binding**: default port 3000, binds to 127.0.0.1 only.

## Scoring & FP Reduction (v2.6.5)

### Risk Score Formula

```
riskScore = min(100, maxFileScore + crossFileBonus + intentBonus + packageScore)
```

- **Severity weights**: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1
- **Per-file max**: Threats grouped by file, each group scored independently. Only the maximum file score counts.
- **Cross-file bonus**: 25% of non-max file scores (MEDIUM+ only), capped at 25.
- **Intent bonus**: Intra-file source-sink coherence, capped at 30.
- **Package score**: Lifecycle scripts, typosquat, IOC matches. CRITICAL floor at 50 when present.

### Risk Levels

| Level | Threshold |
|-------|-----------|
| CRITICAL | >= 80 |
| HIGH | >= 50 |
| MEDIUM | >= 20 |
| LOW | > 0 |
| SAFE | 0 |

### FP Count Thresholds

Legitimate frameworks produce high volumes of certain threat types that malware never does. When the count exceeds these thresholds, severity is downgraded to LOW:

| Threat Type | Max Count | From | Rationale |
|-------------|-----------|------|-----------|
| dynamic_require | 10 | HIGH | Plugin loaders (webpack, eslint) |
| dangerous_call_function | 5 | MEDIUM | Template engines, bundlers |
| require_cache_poison | 3 | CRITICAL | Hot-reload systems (1 hit → HIGH) |
| suspicious_dataflow | 3 | any | SDKs with many flows |
| obfuscation_detected | 3 | any | Minified bundles |
| module_compile | 3 | HIGH | Framework module systems |
| module_compile_dynamic | 3 | HIGH | Dynamic module loaders |
| zlib_inflate_eval | 2 | CRITICAL | Compression libraries |
| vm_code_execution | 3 | HIGH | Build tools (webpack, jest) |
| dynamic_import | 5 | HIGH | Plugin loaders |
| js_obfuscation_pattern | 1 | HIGH | Hash algorithm bit manipulation |
| credential_tampering | 5 | any | Minified alias resolution |
| dangerous_call_eval | 3 | MEDIUM | Bundled globalThis eval |
| credential_regex_harvest | 2 | HIGH | HTTP client Authorization parsing |
| env_access | 10 | HIGH | Config frameworks (dotenv, aws-sdk) |
| high_entropy_string | 5 | any | Bundled data/assets |

A percentage guard (< 40% of total threats) prevents downgrading when a type dominates findings.

### Other Reduction Heuristics

- **Dist/build files**: One-notch severity downgrade; bundler artifacts get two-notch (CRITICAL→MEDIUM).
- **Reachability**: Findings in files not reachable from entry points → LOW.
- **Framework prototypes**: Request/Response/App/Router.prototype → MEDIUM.
- **HTTP client whitelist**: >20 prototype_hook hits targeting HTTP class names → MEDIUM.

## Known Limitations

MUAD'DIB is an educational tool and first-line defense. It has known limitations:

- **Behavioral detection requires network**: Temporal features query the npm registry (requires internet access)
- **No ML/AI**: Pattern matching is deterministic, sophisticated obfuscation may bypass
- **npm and PyPI only**: Does not scan other package ecosystems (RubyGems, Maven, Go, etc.)
- **Sandbox requires Docker**: Behavioral analysis needs Docker Desktop
- **Temporal analysis is npm-only**: Behavioral anomaly detection (`--temporal-*`) currently only supports npm packages, not PyPI

For enterprise-grade protection, consider complementing with:
- [Socket.dev](https://socket.dev) - ML behavioral analysis
- [Snyk](https://snyk.io) - Vulnerability database
- [Semgrep](https://semgrep.dev) - Advanced static analysis

## Acknowledgments

We thank the following for responsible disclosure:

*No vulnerabilities have been reported yet.*

---

Thank you for helping keep MUAD'DIB and its users safe!
