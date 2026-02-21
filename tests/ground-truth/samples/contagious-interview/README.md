# Contagious Interview / BeaverTail — Ground Truth Reconstruction

## Source
- https://socket.dev/blog/north-korea-contagious-interview-campaign-338-malicious-npm-packages
- https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/
- https://blog.phylum.io/lazarus-group-npm-attack/

## Date
2024-2025

## Technique
- North Korean APT (Lazarus / Famous Chollima) campaign
- 338+ malicious npm packages published as fake job interview coding tests
- Multi-stage attack: fingerprint → harvest → exfiltrate → download payload
- Steals: SSH keys, browser credentials, crypto wallets, env tokens
- Downloads second-stage payload (InvisibleFerret) for persistence

## What was reconstructed
- 4-stage attack chain from public analyses
- System fingerprinting (hostname, platform, arch, user)
- SSH key harvesting from ~/.ssh
- Crypto wallet path scanning
- Environment variable token theft
- HTTPS POST exfiltration to C2
- Second-stage payload download and execution

## What was simplified
- Real campaign used 180+ fake personas on LinkedIn/GitHub
- InvisibleFerret payload not included (separate binary)
- Browser credential parsing simplified (real version used SQLite)
