# clipboard-hijack — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/dormant-npm-package-update-targets-ethereum-private-keys/

## Date
2024

## Technique
- Dormant package suddenly updated with malicious code
- Clipboard monitoring for Ethereum private keys (64-char hex strings)
- Cross-platform clipboard reading (PowerShell, pbpaste, xclip/xsel)
- Startup persistence (Windows Startup folder, Linux crontab)
- Exfiltration to Vercel endpoint

## What was reconstructed
- Startup persistence for Windows and Linux/macOS
- Clipboard polling with setInterval
- Ethereum private key pattern detection (64 hex chars, with/without 0x prefix)
- HTTPS POST exfiltration

## What was simplified
- Original was a dormant legitimate package that was hijacked after 8 months
