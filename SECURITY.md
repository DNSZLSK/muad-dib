# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.6.x   | :white_check_mark: |
| 1.5.x   | :white_check_mark: |
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

## Detection Rules (v1.6.18)

MUAD'DIB uses 12 parallel scanners producing the following rule IDs:

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

### Sandbox Rules (Docker) — Dynamic Analysis

Runtime behavioral analysis: packages are installed in an isolated Docker container and monitored for suspicious activity (file access, network traffic, process spawns) via strace, tcpdump, and filesystem diffing.

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
- Private IP ranges are blocked (127.x, 10.x, 172.16-31.x, 192.168.x)
- Redirect validation prevents SSRF via open redirects

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

## Known Limitations

MUAD'DIB is an educational tool and first-line defense. It has known limitations:

- **IOC-based detection**: Only detects known threats, not zero-days
- **No ML/AI**: Pattern matching is deterministic, sophisticated obfuscation may bypass
- **npm and PyPI only**: Does not scan other package ecosystems (RubyGems, Maven, Go, etc.)
- **Sandbox requires Docker**: Behavioral analysis needs Docker Desktop

For enterprise-grade protection, consider complementing with:
- [Socket.dev](https://socket.dev) - ML behavioral analysis
- [Snyk](https://snyk.io) - Vulnerability database
- [Semgrep](https://semgrep.dev) - Advanced static analysis

## Acknowledgments

We thank the following for responsible disclosure:

*No vulnerabilities have been reported yet.*

---

Thank you for helping keep MUAD'DIB and its users safe!
