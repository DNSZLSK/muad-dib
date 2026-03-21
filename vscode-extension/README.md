# MUAD'DIB VS Code Extension

Supply-chain threat detection for npm and PyPI projects, directly in VS Code.

## Features

- **Scan Project** -- Analyzes all npm/PyPI dependencies in the open workspace
- **Scan Current File** -- Analyzes only the active file (.js, .json, .py, .toml, .yaml, .md)
- **Update IOCs** -- Downloads the latest indicators of compromise
- **Auto-scan** -- Automatic scan on project open and on each `package.json` or `requirements.txt` change
- **Inline diagnostics** -- Detected threats appear in VS Code's "Problems" tab
- **Detailed report** -- Panel with color-coded severity table and clickable file links
- **Webhook alerts** -- Optional alert forwarding to Discord or Slack
- **Cancellable scan** -- Ability to cancel a running scan from the notification
- **14 specialized scanners** -- AST, dataflow, obfuscation, typosquatting, IOC, AI config, etc.
- **158 detection rules** -- Mapped to the MITRE ATT&CK framework

## Prerequisites

The `muaddib-scanner` CLI must be installed globally:

```bash
npm install -g muaddib-scanner
```

Requires Node.js >= 18.0.0.

## Installation

### From the Marketplace

1. Open VS Code
2. Extensions (Ctrl+Shift+X)
3. Search for "MUAD'DIB Security Scanner"
4. Install

Or directly: [MUAD'DIB Security Scanner](https://marketplace.visualstudio.com/items?itemName=dnszlsk.muaddib-vscode)

### From a VSIX

1. Build the extension:
   ```bash
   cd vscode-extension
   npx @vscode/vsce package
   ```
2. In VS Code: Extensions > `...` > Install from VSIX > select the `.vsix` file

## Commands

Shortcut: open the command palette (Ctrl+Shift+P) and type "MUAD'DIB".

| Command | Description |
|---------|-------------|
| `MUAD'DIB: Scan Project` | Run a full workspace scan |
| `MUAD'DIB: Scan Current File` | Scan the currently open file |
| `MUAD'DIB: Update IOCs` | Update indicators of compromise |

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `muaddib.autoScan` | boolean | `true` | Automatically scan on project open |
| `muaddib.webhookUrl` | string | `""` | Discord/Slack webhook URL for alerts (HTTPS only) |
| `muaddib.failLevel` | string | `"high"` | Minimum severity level (`critical`, `high`, `medium`, `low`) |
| `muaddib.explain` | boolean | `false` | Show detailed explanations for each threat |
| `muaddib.paranoid` | boolean | `false` | Ultra-strict mode (more detections, more false positives) |
| `muaddib.temporalAnalysis` | boolean | `false` | Temporal analysis (network queries to npm/PyPI) |

## How It Works

The extension activates automatically when a `package.json`, `requirements.txt`, `pyproject.toml`, or `setup.py` is detected in the workspace.

It runs `muaddib-scanner scan --json` on the workspace or current file, then converts results into VS Code diagnostics (warnings/errors in the Problems tab).

The scan detects:
- Known malicious npm/PyPI packages (225,000+ IOCs)
- Supply-chain attack patterns (lifecycle scripts, obfuscation, exfiltration)
- Package name typosquatting
- Inter-module dataflow (credentials -> exfiltration)
- AI configuration file injection (.cursorrules, CLAUDE.md, etc.)

## Severity Levels

| Level | VS Code | Meaning |
|-------|---------|---------|
| CRITICAL | Error (red) | Package almost certainly malicious |
| HIGH | Error (red) | Strong indicators of malicious intent |
| MEDIUM | Warning (yellow) | Suspicious patterns to investigate |
| LOW | Information (blue) | Minor or informational concerns |

## License

MIT - See [LICENSE](LICENSE) for details.

## Links

- [MUAD'DIB CLI](https://github.com/DNSZLSK/muad-dib)
- [Report a bug](https://github.com/DNSZLSK/muad-dib/issues)
