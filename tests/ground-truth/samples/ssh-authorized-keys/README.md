# ssh-authorized-keys — Ground Truth Reconstruction

## Source
- https://github.com/advisories/GHSA-wwg3-329c-vh59

## Date
2025

## Technique
- SSH authorized_keys backdoor injection (persists after package removal)
- Creates .ssh directory if not present
- Appends attacker's public key to authorized_keys
- Sets correct permissions (700 for dir, 600 for file)
- Also exfiltrates existing SSH private keys (id_rsa, id_ed25519, id_ecdsa)
- HTTPS POST exfiltration of stolen keys

## What was reconstructed
- authorized_keys injection with idempotency check
- SSH private key theft from common key file names
- HTTPS exfiltration with host/user metadata

## What was simplified
- Original was part of a campaign across multiple packages (telegram-util, node-telegram-sdk, ethers-mew)
