# @solana/web3.js@1.95.6 — Ground Truth Reconstruction

## Source
- https://www.reversinglabs.com/blog/malware-found-in-solana-npm-library-with-50m-downloads
- https://socket.dev/blog/supply-chain-attack-solana-web3js-library

## Date
December 2024

## Technique
- Account compromise via phishing of npm maintainer
- Injected "addToQueue" backdoor function
- Hooks into Keypair class to intercept secret key creation
- Exfiltrates secret keys (base64-encoded) via HTTPS POST
- C2 domain: sol-rpc.xyz (from public reports)

## What was reconstructed
- The addToQueue exfiltration function pattern
- Keypair class hooking with secret key interception
- HTTPS POST exfiltration to attacker domain

## What was simplified
- Full Solana SDK code omitted (only backdoor portion reconstructed)
- The actual obfuscation was more complex
