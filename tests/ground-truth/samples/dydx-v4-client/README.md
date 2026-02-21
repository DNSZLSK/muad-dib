# dydx-v4-client — Ground Truth Reconstruction

## Source
- https://socket.dev/blog/malicious-dydx-packages-published-to-npm-and-pypi

## Date
February 2026

## Technique
- Account compromise of dYdX protocol packages
- Device fingerprinting (hostname, platform, arch, CPU, memory, user)
- Cryptocurrency wallet harvesting: Ethereum keystore, Solana id.json, MetaMask extension
- Seed phrase file search (.seed, seed.txt, mnemonic.txt)
- Exfiltration via HTTPS POST to attacker domain mimicking dydx

## What was reconstructed
- Device fingerprinting with MD5 hash
- Multi-wallet harvesting (ETH, SOL, MetaMask)
- Seed phrase file scanning
- HTTPS exfiltration

## What was simplified
- Original also included Python RAT component (PyPI package)
- Browser extension data parsing simplified
