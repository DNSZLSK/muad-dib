# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
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

## Security Measures in MUAD'DIB

### Input Validation

- Package names are validated against npm naming rules to prevent command injection
- Webhook URLs are validated against a whitelist of allowed domains
- File paths are sanitized to prevent directory traversal

### SSRF Protection

- Webhook module only allows connections to whitelisted domains:
  - discord.com
  - hooks.slack.com
  - webhook.site (testing)
  - localhost (development)
- Private IP ranges are blocked (127.x, 10.x, 172.16-31.x, 192.168.x)
- Redirect validation prevents SSRF via open redirects

### XSS Protection

- HTML reports escape all user-provided data
- No inline JavaScript in generated reports

### Dependency Security

- All dependencies are pinned to exact versions
- Regular updates via Dependabot (when enabled)
- Minimal dependency footprint (6 production dependencies)

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
- **npm only**: Does not scan other package ecosystems (PyPI, RubyGems, etc.)
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
