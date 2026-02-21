# @ledgerhq/connect-kit@1.1.7 — Ground Truth Reconstruction

## Source
- https://www.ledger.com/blog/a-letter-from-ledger-chairman-ceo-pascal-gauthier-regarding-ledger-connect-kit-exploit
- Blockaid wallet drainer analysis
- https://cointelegraph.com/news/ledger-library-exploit-14-december

## Date
December 2023

## Technique
- Former employee phished, npm token stolen
- Malicious versions 1.1.5-1.1.7 published
- Injected script tag loading wallet drainer from CDN
- Drainer prompted wallet approvals to drain cryptocurrency funds
- Intercepted wallet provider.request for eth_sendTransaction/personal_sign
- ~$600K stolen before remediation

## What was reconstructed
- Dynamic script injection from CDN
- Server-side https.get + eval fallback
- Wallet provider.request hooking
- Transaction data exfiltration

## What was simplified
- Actual drainer CDN URL was different (used compromised npm package)
- Full wallet draining logic was more sophisticated
