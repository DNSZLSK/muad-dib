# anti-sandbox-evasion — Ground Truth Reconstruction

## Source
- https://socket.dev/blog/60-malicious-npm-packages-leak-network-and-host-data

## Date
2024

## Technique
- Anti-sandbox evasion checks: cloud hostnames, VM usernames, uptime, CPU count, memory
- Conditional data collection (only on real developer machines)
- Network enumeration: hostname, network interfaces, DNS servers
- CI environment detection (GITHUB_ACTIONS, TRAVIS, CIRCLECI)
- Part of 60-package campaign across 3 npm accounts

## What was reconstructed
- Multiple sandbox detection heuristics (hostname, user, uptime, CPU, memory)
- Conditional exfiltration based on sandbox check results
- System and network enumeration
- CI environment variable collection

## What was simplified
- Original 60 packages had varying levels of evasion
