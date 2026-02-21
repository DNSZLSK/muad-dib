# atomic-wallet-patch — Ground Truth Reconstruction

## Source
- https://thehackernews.com/2025/04/malicious-npm-package-targets-atomic.html

## Date
2025

## Technique
- Targets Atomic cryptocurrency wallet Electron app
- Finds app.asar and unpacked vendor bundles
- Patches vendor JavaScript to inject crypto address replacement
- XMLHttpRequest.prototype.send hooking
- BTC (bc1...) and ETH (0x...) address regex replacement
- Silent address swap during transactions

## What was reconstructed
- Atomic Wallet installation finder (cross-platform)
- Vendor bundle patching with address replacement hook
- XMLHttpRequest prototype hooking for transaction interception
- BTC and ETH address regex patterns

## What was simplified
- Original used full ASAR extract/repack cycle
- More sophisticated address selection (similar-looking addresses)
- Evidence cleanup after patching
