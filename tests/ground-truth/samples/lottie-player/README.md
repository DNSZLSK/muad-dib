# @lottiefiles/lottie-player@2.0.7 — Ground Truth Reconstruction

## Source
- https://blog.lottiefiles.com/security-incident-update/
- https://socket.dev/blog/lottiefiles-supply-chain-attack

## Date
October 2024

## Technique
- Developer token compromised
- Malicious versions 2.0.5-2.0.7 published
- Injected wallet drainer that prompted users to connect cryptocurrency wallets
- Used window.ethereum.request to get accounts and send transactions
- Exfiltrated wallet addresses to attacker C2 (castleservices01.com)
- Attempted ERC-20 token approval for max drain

## What was reconstructed
- Wallet connect popup injection
- window.ethereum.request for account access
- Wallet address exfiltration via fetch
- Token approval transaction attempt

## What was simplified
- Actual drainer was more sophisticated with multiple chain support
- Full lottie-player code omitted
