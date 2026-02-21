# dns-exfil-recon — Ground Truth Reconstruction

## Source
- https://snyk.io/blog/npm-dependency-confusion-attack-gxm-reference/

## Date
2021

## Technique
- Dependency confusion (version 9.9.9 to override internal packages)
- DNS subdomain exfiltration (bypasses firewalls since DNS is typically allowed)
- Host metadata encoding: username, hostname, proxy config, DNS servers
- Preinstall hook trigger

## What was reconstructed
- DNS lookup with data encoded in subdomains (.h for host, .n for name, .p for proxy, .d for DNS)
- replaceSpecialChars sanitization for DNS-safe encoding
- OS metadata collection (hostname, username, proxy, DNS servers)

## What was simplified
- Original also included obfuscated copies of npmi and global-npm modules
- More extensive network enumeration
