# mathjs-min — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/phylum-discovers-npm-package-mathjs-min-contains-discord-token-grabber/

## Date
January 2024

## Technique
- Typosquatting the legitimate 'mathjs' package
- Discord token grabber searching leveldb storage
- Hex-encoded strings for evasion
- Exfiltration via Discord webhook

## What was reconstructed
- Discord token regex matching
- Hex-encoded string obfuscation pattern
- Discord webhook exfiltration

## What was simplified
- Full obfuscation reduced to hex encoding only
