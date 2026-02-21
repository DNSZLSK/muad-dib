# chalk@5.6.1 — Ground Truth Reconstruction

## Source
- https://semgrep.dev/blog/2025/chalk-debug-and-color-on-npm-compromised-in-new-supply-chain-attack/
- https://www.sonatype.com/blog/npm-chalk-and-debug-packages-hit-in-software-supply-chain-attack
- Sygnia threat intelligence report on prototype hooking

## Date
September 2025

## Technique
- Maintainer phished, compromised npm credentials
- Malicious payload hooking globalThis.fetch and XMLHttpRequest.prototype
- Intercepts web3/Ethereum wallet transactions (eth_sendTransaction, eth_signTransaction)
- Exfiltrates transaction data via HTTPS POST to attacker C2
- Silent operation — original functions still called (pass-through proxy)

## What was reconstructed
- globalThis.fetch hooking with transaction body inspection
- XMLHttpRequest.prototype.open/send hooking
- Web3 transaction keyword detection
- HTTPS exfiltration to C2 domain

## What was simplified
- Full chalk module code omitted
- Actual obfuscation techniques not replicated
- Wallet address substitution logic simplified
