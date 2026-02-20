# Ground Truth — Known Malicious Packages

This directory documents real-world supply-chain malware for reference and validation purposes.

## Files

- **`known-malware.json`** — Database of 65 documented malicious packages (npm + PyPI) with metadata:
  - `name`: package name or campaign name
  - `ecosystem`: npm, pypi, or npm/pypi
  - `version`: malicious version(s)
  - `date`: discovery date (YYYY-MM)
  - `source`: who discovered it
  - `technique`: attack technique used
  - `url`: link to advisory/report
  - `severity`: critical, high, or medium

## Why document but not store?

Malicious packages are removed from registries shortly after discovery. We cannot redistribute them. Instead, we document:
1. The techniques used (for rule development)
2. The detection timeline (for lead time measurement)
3. The sources (for IOC enrichment)

## Separate from scanner ground truth

The scanner's ground truth dataset (`tests/ground-truth/`) contains recreated fixtures of 5 real attacks (event-stream, ua-parser-js, coa, node-ipc, colors) with expected findings. That dataset is used by `muaddib evaluate` for TPR measurement.

This directory (`datasets/ground-truth/`) is a broader reference database documenting the full landscape of known supply-chain malware for research and rule development.

## Sources

| Source | Coverage |
|--------|----------|
| Microsoft Security | Shai-Hulud 2.0 analysis |
| Datadog Security Labs | Shai-Hulud, MUT-8694, targeted malware |
| Socket.dev | Contagious Interview, typosquatting, Flashbots, WhatsApp |
| Snyk | Nx/s1ngularity, chalk/debug, ngx-bootstrap, ESLint |
| Sonatype | coa/rc, Bladeroid, PyPI crypto-stealers |
| ReversingLabs | Roblox, crypto wallets, ML steganography, Solana |
| Phylum | Lazarus APT, Django-log-tracker, npm campaigns |
| JFrog | Discord token stealers |
| CISA | ua-parser-js advisory |
| PyPI Security | aiocpa analysis, 500+ package campaign |
| Fortinet | PyPI malware statistics, open-source registry trends |
| Zscaler ThreatLabz | NodeCordRAT, SilentSync RAT |
| Kaspersky | LofyLife campaign |
| Orca Security | protestware analysis |

## Statistics

- **65 entries** (45 npm, 18 PyPI, 2 cross-ecosystem)
- **Date range**: 2018-2026
- **Severity**: 47 critical, 16 high, 2 medium
- **Campaigns**: Shai-Hulud (796+), Contagious Interview (338+), 287 typosquats, 500+ PyPI uploads
