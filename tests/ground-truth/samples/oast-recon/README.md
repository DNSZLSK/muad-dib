# oast-recon — Ground Truth Reconstruction

## Source
- https://socket.dev/blog/weaponizing-oast-how-malicious-packages-exploit-npm-pypi-and-rubygems

## Date
2024

## Technique
- OAST (Out-of-band Application Security Testing) endpoint exfiltration
- Burp Collaborator / oastify.com used for data collection
- Dual channel: HTTPS POST + DNS subdomain encoding
- Dependency confusion (version 99.99.99 to override internal packages)
- System enumeration: hostname, username, /etc/passwd, /etc/hosts, DNS servers

## What was reconstructed
- OAST endpoint exfiltration via HTTPS and DNS
- System info collection (hostname, user, platform, cwd, DNS servers)
- /etc/passwd and /etc/hosts reading
- DNS subdomain hex encoding fallback

## What was simplified
- Original was part of 50+ package campaign using multiple oastify.com domains
