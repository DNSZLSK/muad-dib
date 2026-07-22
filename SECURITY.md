# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.11.x  | :white_check_mark: |
| 2.10.x  | :white_check_mark: |
| 2.9.x   | :white_check_mark: |
| 2.8.x   | :white_check_mark: |
| 2.7.x   | :white_check_mark: |
| 2.6.x   | :x:                |
| 2.5.x   | :x:                |
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

## Detection Rules

MUAD'DIB uses 33 scanner modules (2 pre-analysis: `module-graph/` + `deobfuscate`; 1 async parser bootstrap: `python-ast` WASM init; <!--stat:scanners-->22<!--/stat:scanners--> parallel scanners; 7 conditional/post-processing: paranoid + 3× temporal-* + reachability + `phantom-gyp` correlator + `native-drop-exec` correlator; 1 metadata: `npm-registry`) + 5 behavioral anomaly detection features + ground truth validation, producing <!--stat:rulesTotal-->277<!--/stat:rulesTotal--> rule IDs (<!--stat:rulesCore-->272<!--/stat:rulesCore--> RULES + <!--stat:rulesParanoid-->5<!--/stat:rulesParanoid--> PARANOID - Track D added AST-093 `linux_fingerprint_exec` + AST-094 `direct_ip_exfil` + COMPOUND-016 `recon_exfil_direct_ip` ; v2.11.67/70 Phantom Gyp added PKG-023 `gyp_command_exec` speed-bump + COMPOUND-017 `gyp_phantom_exec` compound ; 2026-07 anti-evasion added AST-095 `anti_analysis_evasion` + AST-096 `analyzer_honeytoken_reference`). The parallel scanners include the v2.11 intel-triage trio (`ioc-strings` YARA-style, `anti-forensic` XOR/self-delete compound, `stub-package` tiny main + external dep + lifecycle), the PyPI source-analysis pair (`python-source` PYSRC-001..010 regex, `python-ast` PYAST-001..010 tree-sitter AST + taint tracker), `monorepo`/`trusted-dep-diff`, `anti-scanner-injection` (ASI-001..004, anti-scanner prompt injection targeting LLM reviewers, Hades campaign 2026-06), and `binary-source` (BINSRC-001, binary masquerading as `.js`/`.ts` source in the `dist/build/out` blind spot):

### AST Scanner (core rules)

| Rule ID | Name | Severity | Notes |
|---------|------|----------|-------|
| MUADDIB-AST-001 | Sensitive String Reference | HIGH | .npmrc, .ssh, tokens |
| MUADDIB-AST-002 | Sensitive Environment Variable Access | HIGH | GITHUB_TOKEN, NPM_TOKEN, AWS_* |
| MUADDIB-AST-003 | Dangerous Function Call | MEDIUM | exec/spawn |
| MUADDIB-AST-004 | Eval Usage | HIGH | eval(variable) = HIGH, eval('literal') = LOW |
| MUADDIB-AST-005 | new Function() Constructor | HIGH | Function(variable) = MEDIUM, Function('literal') = LOW |
| MUADDIB-AST-006 | Dynamic Require with Concatenation | HIGH | T1027 |
| MUADDIB-AST-007 | Dangerous Shell Command Execution | CRITICAL | T1059.004 |

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
| MUADDIB-SHELL-019 | Python Time Delay Execution (time.sleep >= 100s sandbox evasion) | HIGH |
| MUADDIB-SHELL-020 | Root Filesystem Wipe (rm -rf /, CanisterWorm kamikaze.sh) | CRITICAL |
| MUADDIB-SHELL-021 | Process Memory Scanning (/proc/*/mem, TeamPCP credential stealer) | CRITICAL |

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
| MUADDIB-PKG-011 | Network Module in Lifecycle Script | HIGH |
| MUADDIB-PKG-012 | Node Inline Execution in Lifecycle Script | HIGH |
| MUADDIB-PKG-013 | Bin Field PATH Hijack | CRITICAL |
| MUADDIB-PKG-014 | Git Dependency RCE (PackageGate) | HIGH |
| MUADDIB-PKG-015 | .npmrc Git Binary Override | CRITICAL |
| MUADDIB-PKG-016 | Lifecycle Script Targets Hidden Payload | CRITICAL |
| MUADDIB-PKG-017 | Phantom Lifecycle Script | CRITICAL |
| MUADDIB-PKG-018 | Curl/Wget Environment Exfiltration | CRITICAL |
| MUADDIB-PKG-019 | Dependency Confusion Version Indicator | HIGH |
| MUADDIB-PKG-020 | External Tarball Dependency URL (ltidi pattern, cloud storage non-allowlist) | CRITICAL |
| MUADDIB-PKG-021 | Monorepo Detected | MEDIUM |
| MUADDIB-PKG-022 | Release Zero Package (0.0.0 + install scripts or recent publish) | MEDIUM |
| MUADDIB-PKG-023 | GYP Command-Substitution Install Execution (Phantom Gyp speed-bump / danger-marker) | CRITICAL |

### AST Scanner (v2.2+)

| Rule ID | Name | Severity | MITRE |
|---------|------|----------|-------|
| MUADDIB-AST-008 | Dynamic import() of Dangerous Module | HIGH | T1027 |
| MUADDIB-AST-009 | Environment Variable Proxy Interception | CRITICAL | T1552.001 |
| MUADDIB-AST-010 | Command Execution via Dynamic Require | CRITICAL | T1059.007 |
| MUADDIB-AST-011 | Sandbox/Container Evasion | HIGH | T1497.001 |
| MUADDIB-AST-012 | Detached Background Process | HIGH | T1036.009 |
| MUADDIB-AST-013 | AI Agent Weaponization | CRITICAL | T1059 |
| MUADDIB-AST-014 | Credential Theft via CLI Tool | CRITICAL | T1059 |
| MUADDIB-AST-015 | GitHub Actions Workflow Write | CRITICAL | T1195.002 |
| MUADDIB-AST-016 | Binary Dropper Pattern | CRITICAL | T1105 |
| MUADDIB-AST-017 | Native API Prototype Hooking | HIGH | T1557 |
| MUADDIB-AST-018 | Environment Variable Key Reconstruction | HIGH | T1027 |
| MUADDIB-AST-019 | Require Cache Poisoning | CRITICAL | T1574.006 |
| MUADDIB-AST-020 | Staged Binary Payload Execution | HIGH | T1027.003 |
| MUADDIB-AST-021 | Staged Eval Decode | CRITICAL | T1140 |
| MUADDIB-AST-022 | Encrypted Payload Decryption | HIGH | T1140 |
| MUADDIB-AST-023 | Module Compile Execution | HIGH | T1059 |
| MUADDIB-AST-024 | Obfuscated Payload via Zlib Inflate | CRITICAL | T1027.002 |
| MUADDIB-AST-025 | Dynamic Module Compile Execution | HIGH | T1059 |
| MUADDIB-AST-026 | Anti-Forensics Write-Execute-Delete | HIGH | T1070.004 |
| MUADDIB-AST-027 | MCP Config Injection | CRITICAL | T1546.016 |
| MUADDIB-AST-028 | Git Hooks Injection | HIGH | T1546.004 |
| MUADDIB-AST-029 | Dynamic Environment Variable Harvesting | HIGH | T1552.001 |
| MUADDIB-AST-030 | DNS Chunk Exfiltration | HIGH | T1048.003 |
| MUADDIB-AST-031 | LLM API Key Harvesting | MEDIUM | T1552.001 |
| MUADDIB-AST-032 | Suspicious C2/Exfiltration Domain | HIGH | T1071.001 |
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
| MUADDIB-AST-047 | Detached Process Credential Exfiltration | CRITICAL | T1041 |
| MUADDIB-AST-048 | Write to node_modules/ (Worm Propagation) | CRITICAL | T1195.002 |
| MUADDIB-AST-049 | Bun Runtime Evasion | HIGH | T1059 |
| MUADDIB-AST-050 | Static Timer Bomb | MEDIUM | T1497.003 |
| MUADDIB-AST-051 | npm publish Worm Propagation | CRITICAL | T1195.002 |
| MUADDIB-AST-052 | Ollama Local LLM (Polymorphic Engine) | HIGH | T1027.005 |
| MUADDIB-AST-053 | Unicode Variation Selector Decoder (GlassWorm) | CRITICAL | T1140 |
| MUADDIB-AST-054 | Blockchain C2 Resolution (GlassWorm) | HIGH | T1102 |
| MUADDIB-AST-055 | Hardcoded Blockchain RPC Endpoint (GlassWorm) | MEDIUM | T1102 |
| MUADDIB-AST-056 | Module._load() Internal Loader Bypass | CRITICAL | T1059 |
| MUADDIB-AST-057 | AsyncFunction/GeneratorFunction Constructor via Prototype Chain | CRITICAL | T1059.007 |
| MUADDIB-AST-058 | Split High-Entropy Payload | CRITICAL | T1027.002 |
| MUADDIB-AST-059 | Systemd Service Persistence | CRITICAL | T1543.002 |
| MUADDIB-AST-060 | NPM Token Extraction via CLI | CRITICAL | T1552.001 |
| MUADDIB-AST-061 | Python .pth Auto-Exec Persistence | CRITICAL | T1546.004 |
| MUADDIB-AST-062 | Reflect.apply(require) Bypass | CRITICAL | T1059 |
| MUADDIB-AST-063 | FinalizationRegistry Deferred Execution | CRITICAL | T1497.003 |
| MUADDIB-AST-064 | Function via Prototype Chain | CRITICAL | T1059 |
| MUADDIB-AST-065 | Prototype Pollution | HIGH | T1574 |
| MUADDIB-AST-066 | Module.wrap Override | CRITICAL | T1574.006 |
| MUADDIB-AST-067 | Symbol Property Hiding | HIGH | T1564 |
| MUADDIB-AST-068 | WithStatement Dangerous Body | HIGH | T1027 |
| MUADDIB-AST-069 | require("process").mainModule Bypass | CRITICAL | T1059 |
| MUADDIB-AST-070 | Shared Memory IPC | MEDIUM | T1559 |
| MUADDIB-AST-071 | WebSocket C2 Channel | HIGH | T1071.001 |
| MUADDIB-AST-072 | UDP Data Exfiltration | HIGH | T1048.003 |
| MUADDIB-AST-073 | Native Addon Installation | HIGH | T1195.002 |
| MUADDIB-AST-074 | String Mutation Obfuscation | HIGH | T1027 |
| MUADDIB-AST-075 | Module Internals Hijack (_resolveFilename/_compile/_extensions) | CRITICAL | T1574.006 |
| MUADDIB-AST-076 | JSON Reviver Prototype Pollution | HIGH | T1059.007 |
| MUADDIB-AST-077 | VM Dynamic Code Execution (vm.runInContext + variable code) | CRITICAL | T1059.007 |
| MUADDIB-AST-078 | Callback Remote Code Execution (exec/spawn inside .on message/data) | CRITICAL | T1059 |
| MUADDIB-AST-079 | Steganographic Binary Execution (image read + dynamic exec) | CRITICAL | T1027.003 |
| MUADDIB-AST-080 | AsyncLocalStorage Context Execution | HIGH | T1059.007 |
| MUADDIB-AST-081 | Prototype Chain Constructor Access via Variable | CRITICAL | T1059.007 |
| MUADDIB-AST-082 | CI Environment Fingerprinting (>=3 CI env vars) | HIGH | T1082 |
| MUADDIB-AST-083 | Proxy GlobalThis Interception | CRITICAL | T1574 |
| MUADDIB-AST-084 | Reflect.apply Prototype Method Code Execution | CRITICAL | T1059 |
| MUADDIB-AST-085 | Timer Delayed Payload | HIGH | T1497.003 |
| MUADDIB-AST-086 | Function Constructor Require Evasion | CRITICAL | T1059.007 |
| MUADDIB-AST-087 | Process Variable Shadowing (const process = {...}) | HIGH | T1036 |
| MUADDIB-AST-088 | Baileys Newsletter Auto-Follow Hijack | HIGH | T1496 |
| MUADDIB-AST-089 | Self-Destructing Dynamic Execution (csec pattern) | CRITICAL | T1070.004 |
| MUADDIB-AST-090 | Function() with Runtime Identifiers as Arguments (csec pattern) | CRITICAL | T1059.007 |

### AI Config Scanner (v2.2)

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-AICONF-001 | AI Config Prompt Injection | HIGH |
| MUADDIB-AICONF-002 | AI Config Compound Injection | CRITICAL |

### Dataflow Scanner (v2.2+)

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-FLOW-002 | Suspicious Module Sink (ws/mqtt/socket.io) | HIGH |
| MUADDIB-FLOW-003 | Credential Tampering / Cache Poisoning | CRITICAL |
| MUADDIB-FLOW-004 | Cross-File Dataflow | CRITICAL |
| MUADDIB-FLOW-005 | Non-HTTP Network Module Sink (ws/mqtt/socket.io) | MEDIUM |

### Obfuscation Scanner

| Rule ID | Name | Severity | Notes |
|---------|------|----------|-------|
| MUADDIB-OBF-001 | Code Obfuscation Detected | HIGH | Hex/unicode escapes alone no longer trigger; .min.js long lines ignored |
| MUADDIB-OBF-002 | Possible Code Obfuscation | MEDIUM | Parse failure + dense code |
| MUADDIB-OBF-003 | Unicode Invisible Injection (GlassWorm) | HIGH | >=3 invisible Unicode chars |

### Compound Scoring Rules (v2.9.2)

Co-occurring threat type combinations that never appear in benign packages. Inject synthetic CRITICAL threats.

| Rule ID | Name | Required Types | Severity |
|---------|------|---------------|----------|
| MUADDIB-COMPOUND-001 | Crypto Staged Payload | staged_binary_payload + crypto_decipher | CRITICAL |
| MUADDIB-COMPOUND-002 | Lifecycle Typosquat | lifecycle_script + typosquat_detected | CRITICAL |
| MUADDIB-COMPOUND-004 | Lifecycle Inline Exec | lifecycle_script + node_inline_exec | CRITICAL |
| MUADDIB-COMPOUND-005 | Lifecycle Remote Require | lifecycle_script + network_require | CRITICAL |
| MUADDIB-COMPOUND-006 | WebSocket/MQTT Credential Exfil | env_access + ws/mqtt/socket.io sink (same file) | CRITICAL |
| MUADDIB-COMPOUND-007 | Lifecycle File Exec | lifecycle_script + threats in referenced file | CRITICAL |
| MUADDIB-COMPOUND-008 | Uncaught Exception Handler Credential Exfil | uncaughtException/unhandledRejection hijack + credential read | CRITICAL |
| MUADDIB-COMPOUND-009 | Lifecycle Dataflow | lifecycle_script + dataflow threat (same file) | HIGH |
| MUADDIB-COMPOUND-010 | Lifecycle Dangerous Exec | lifecycle_script + dangerous_exec | CRITICAL |
| MUADDIB-COMPOUND-011 | Obfuscated Lifecycle Env | lifecycle_script + obfuscation + env_access | HIGH |
| MUADDIB-COMPOUND-012 | Staged Remote Loader (Function.constructor + shadowed process) | function_constructor_require + process_variable_shadow (same file) | CRITICAL |
| MUADDIB-COMPOUND-AXIOS | Axios / csec Family Compound | ioc_string_match + lifecycle_script + anti_forensic_partial | CRITICAL |
| MUADDIB-COMPOUND-STUB-IOC | Stub Package + Known String IOC | stub_package_external_dep + ioc_string_match | CRITICAL |
| MUADDIB-COMPOUND-016 | Recon + Exfil to Direct IP | linux_fingerprint_exec + direct_ip_exfil (same file) | CRITICAL |
| MUADDIB-COMPOUND-017 | Phantom Gyp Install-Time Payload | binding.gyp command-substitution sink + independent malice verdict on invoked file | CRITICAL |

### Intel-Triage Scanners (v2.11, mai 2026) — Static-First Detection

Trio of static scanners aligned on 2026 npm/PyPI threat landscape. The rationale (commercial sandboxes flag Axios 2026 as CLEAN with 99% confidence; modern malware defeats sandboxes by design) is documented in `feedback_static_over_dynamic` and `feedback_sandbox_wrong_layer` memories.

| Rule ID | Name | Severity | MITRE |
|---------|------|----------|-------|
| MUADDIB-IOC-001 | YARA-Style String IOC Match (Axios 2026, TeamPCP, GlassWorm, CanisterSprawl) | CRITICAL | T1195.002 |
| MUADDIB-AF-001 | Anti-Forensic XOR + Self-Delete + Decoy Write (3 of 3 patterns) | CRITICAL | T1140 |
| MUADDIB-AF-002 | Anti-Forensic Partial (2 of 3 patterns) | HIGH | T1140 |
| MUADDIB-STUB-001 | Stub Package + External URL Dep + Lifecycle Hook (ltidi pattern) | CRITICAL | T1195.002 |
| MUADDIB-STUB-002 | Stub Package + External URL Dep (no lifecycle) | HIGH | T1195.002 |

### Dependency Scanner

| Rule ID | Name | Severity |
|---------|------|----------|
| MUADDIB-DEP-001 | Known Malicious Package | CRITICAL |
| MUADDIB-DEP-002 | Suspicious File in Dependency | CRITICAL |
| MUADDIB-DEP-003 | Shai-Hulud Marker | CRITICAL |
| MUADDIB-DEP-004 | Lifecycle Script in Dependency | MEDIUM |
| MUADDIB-DEP-005 | Suspicious Dependency URL (HTTP/ngrok/localhost/private IP) | HIGH |

### Entropy Scanner

| Rule ID | Name | Severity | Notes |
|---------|------|----------|-------|
| MUADDIB-ENTROPY-001 | High Entropy String | MEDIUM | Threshold: 5.5 bits + 50 chars min |
| ~~MUADDIB-ENTROPY-002~~ | ~~High Entropy File~~ | ~~removed~~ | Removed in v1.6.16 — replaced by ENTROPY-003 |
| MUADDIB-ENTROPY-003 | JS Obfuscation Pattern | HIGH | _0x* vars, encoded string arrays, eval+entropy, long base64 |
| MUADDIB-ENTROPY-004 | Fragmented High Entropy Cluster | MEDIUM | Many short high-entropy strings bypassing MIN_STRING_LENGTH |
| MUADDIB-ENTROPY-005 | Split Entropy Payload | CRITICAL/HIGH | High-entropy payload split across string concatenation (3+ chunks, entropy >= 5.5) |

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

### Trusted Package Monitoring (v2.10.74)

| Rule ID | Name | Severity | Notes |
|---------|------|----------|-------|
| MUADDIB-TRUSTED-001 | Trusted Package Added Unknown Dependency | CRITICAL | New dep < 7 days old on popular package (HC type) |
| MUADDIB-TRUSTED-002 | Trusted Package Added New Dependency | HIGH | Known dep added to popular package |

These rules apply only in monitor mode to packages with >= 50,000 weekly downloads. A CRITICAL finding bypasses the TRUSTED fast-track and routes the package to full scan + sandbox.

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
- Minimal dependency footprint (5 production dependencies)

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

## Threat Model (v2.9.4)

MUAD'DIB 2.9 uses a **triple detection approach**:

1. **IOC-based detection** (v1.x): Matches packages against 225,000+ known malicious packages from OSV, DataDog, OSSF, GitHub Advisory, Aikido OSS Malware Feed, OpenSourceMalware.com (community-verified), and GenSecAI Shai-Hulud Detector. Fast and reliable for known threats. On the VPS, these feeds are refreshed automatically via two systemd timers: `muaddib-scrape-light.timer` (every 15 min, JSON/REST feeds incl. OSM) and `muaddib-scrape.timer` (every 6 h, bulk zip dumps).

2. **Behavioral anomaly detection** (v2.0): Analyzes changes between package versions to detect supply-chain attacks before they appear in IOC databases. Compares lifecycle scripts, AST, publish frequency, and maintainer metadata across versions. This approach can detect 0-day behavioral anomalies without any prior knowledge of the specific attack.

3. **Ground truth validation** (v2.1–v2.11.48): Validates detection accuracy against **96 real-world attacks** (94 in-scope; 2 out-of-scope: GT-005 colors and GT-009 faker protestware with min_threats=0). The 2026-05-25 enrichment added 29 samples — 16 synthetic for PYSRC/PYAST/AST-092/AICONF-004/PKG-022 (GT-068..083), 6 real-world npm tarballs from VPS archive (GT-084..089: TrapDoor twins, dep-confusion, MCP exfil), 7 reconstructions from `data/all-review-results.json` review reasoning (GT-090..096). Includes **13 PyPI samples** (was 0). Tracks detection lead times vs. public advisories, and monitors false positive rates over time. <!--stat:tests-->4539<!--/stat:tests--> tests across <!--stat:testFiles-->152<!--/stat:testFiles--> files. Current TPR@3: **95.74%** (90/94 in-scope, v2.11.48 full measurement). TPR@20: **88.30%** (83/94, +3.1pp vs v2.11.47 thanks to Track D `recon_exfil_direct_ip` compound). ADR: **96.26%** (103/107). Provides observability into scanner effectiveness.

The behavioral detection features are opt-in (`--temporal-full`) and query the npm registry at scan time. They are particularly effective against:
- Account takeover attacks (event-stream pattern)
- Compromised CI/CD pipelines (automated malicious publishes)
- Dormant package hijacking (abandonware takeover)
- Sudden code injection (Shai-Hulud, ua-parser-js pattern)

## Ground Truth Validation (v2.11.48)

MUAD'DIB includes a ground truth dataset of **96 real-world supply-chain attacks** (94 active samples; 2 out-of-scope GT-005 colors / GT-009 faker, both protestware with min_threats=0) to continuously validate detection coverage. 13 PyPI samples were added 2026-05-25 (first PyPI coverage in the GT).

**TPR@3: 95.74% (90/94 in-scope detected)** — v2.11.48 full measurement on the enriched GT.

**TPR@20: 88.30% (83/94)** — operational alert threshold, **+3.1pp vs v2.11.47** thanks to Track D `recon_exfil_direct_ip` compound (GT-095 went from risk 3 to 50, plus GT-091/GT-092 gained from `linux_fingerprint_exec`). 2 intentional `tpr3-only` samples remain (GT-072 PYSRC-007, GT-077 PYAST-002 — HIGH/MEDIUM rules that don't cross 20 in isolation by design), documented in `attacks.json` with `expected.tpr_tier: "tpr3"`.

4 active misses include the 3 browser-only attacks (lottie-player, polyfill-io, trojanized-jquery) plus 1 other.

Run `muaddib evaluate` to re-measure at any time.

**Operational coverage (v2.11.73+):** beyond the static ground-truth TPR above, `scripts/coverage-audit.js` (Phase 5) computes an honest **operational TPR** by joining the GitHub Advisory Database malware denominator (`data/ghsa-malware.jsonl`, refreshed by the active GHSA poller every ~15 min) against real scan-ledger outcomes and the tarball archive (`classifyCoverage()`: alerted / scannedClean / dropped / neverSeen). This GHSA-denominated rate is the true production detection rate. It is distinct from the ledger `alertRate` (an operational throughput signal, NOT TPR). It runs daily on the VPS via `muaddib-coverage-audit.timer` (05:00 UTC), surfacing `scannedClean` misses as human-gated ground-truth candidates (`data/gt-proposals.json`).

## Evaluation Methodology Caveats (v2.11.48)

The metrics reported above should be interpreted with the following caveats:

- **TPR scope:** Measured on the full 94 in-scope samples from the 96-sample ground truth. 4 misses include 3 browser-only attacks (lottie-player, polyfill-io, trojanized-jquery — DOM patterns outside MUAD'DIB's Node.js static analyzer scope). 2 samples are out-of-scope by design (`min_threats: 0`, protestware).
- **FPR dataset:** Measured on 545 scanned of 548 curated popular npm packages — not a random sample. FPR varies significantly by package size: small packages (<10 JS files) have lower FPR than very large packages (100+ files). The v2.11.48 FPR of 1.10% (down from 15.6% at v2.10.95) reflects the F1-F14 contextual FP caps shipped between v2.10.97 and v2.11.31; Track D (v2.11.48) added 3 rules without creating new FPs.
- **FPR random sample:** Measured separately on 200 random npm packages (2.50% v2.11.48).
- **FPR PyPI:** First honest measurement at v2.11.48 — 9.68% on 124 scanned of 132. Track D fixed the PyPI downloader (removed `pip --no-binary :all:` + added `.whl` extraction), bringing 42 previously-skipped giants (numpy/pandas/django/matplotlib/...) into scope. The previous 6.10% (v2.11.47, 82/132) was biased — small pure-Python packages only. All 12 current FPs cluster at score 25-35: this is the cap-PyPI-35 artifact, not new rule misfires. Lifting the cap (Track E) will drop FPR PyPI to ~0%. 8 residual fails are >500MB packages (torch, tensorflow, scipy, opencv-python, ansible, playwright) hitting the 30s `PACK_TIMEOUT_MS`.
- **ADR methodology:** As of v2.6.5+, ADR uses a global threshold (score >= 20) aligned with the benign threshold. Earlier versions used per-sample tuned thresholds which inflated the ADR metric. Current ADR: 96.26% (103/107).
- **Node.js + PyPI scope:** MUAD'DIB now covers npm and PyPI (PYSRC/PYAST scanners added v2.11.41-45). Browser-only attacks, native binary payloads, and phishing pages remain out of scope.
- **Static analysis limitations:** Dynamic obfuscation, encrypted payloads that require runtime keys, and multi-stage attacks fetching payloads from external servers may evade static detection.

## Datadog 17K Benchmark (v2.9.4)

Validated against the [DataDog Malicious Software Packages Dataset](https://github.com/DataDog/malicious-software-packages-dataset) (17,922 real malware npm packages).

**Wild TPR: 92.5% (13,486/14,587 in-scope)**

- Total packages: 17,922
- Out-of-scope (no JS files): 3,335 skipped
- In-scope: 14,587
- Detected: 13,486
- Score=0 misses: 1,101 in-scope packages
- Errors: 0

**By category:**
- compromised_lib: **97.8%** (904/924)
- malicious_intent: **92.1%** (12,582/13,663 in-scope, 3,335 skipped)

See [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md#14-datadog-17k-benchmark) for the full methodology.

## Threat Feed API Security

The `muaddib serve` HTTP server binds to `localhost` (127.0.0.1) by default. It serves detection data as JSON for SIEM integration.

- **No authentication**: the server is designed for local use only. Do not expose to the public internet. For production deployment, use a reverse proxy (nginx, Caddy) with authentication and TLS termination.
- **No sensitive data**: the feed contains detection metadata (package names, severities, timestamps), not raw file contents or credentials.
- **Localhost binding**: default port 3000, binds to 127.0.0.1 only.

## Scoring & FP Reduction (v2.9.4)

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
- **ML pipeline (experimental)**: v2.8.6 adds JSONL feature extraction (62 features) for offline model training, but detection remains deterministic rule-based
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
