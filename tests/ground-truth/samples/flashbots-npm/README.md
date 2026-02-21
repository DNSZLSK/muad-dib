# flashbots-npm — Ground Truth Reconstruction

## Source
- https://socket.dev/blog/typosquatted-flashbots-ethers-provider-bundle-steals-private-keys

## Date
2024

## Technique
- Typosquatting legitimate Flashbots packages targeting Ethereum developers
- Environment variable harvesting for private keys (PRIVATE_KEY, ETH_PRIVATE_KEY, MNEMONIC, etc.)
- .env file scanning for private key patterns
- Hardhat/Truffle config file scanning for hex private keys (0x + 64 hex chars)
- Exfiltration via Telegram Bot API (sendMessage endpoint)
- postinstall trigger

## What was reconstructed
- Environment variable key harvesting
- .env file scanning with regex for key patterns
- Config file scanning for Ethereum private keys
- Telegram bot exfiltration

## What was simplified
- Original also intercepted ethers.js Wallet constructor to steal keys at runtime
- Used more obfuscation to hide the Telegram bot token
