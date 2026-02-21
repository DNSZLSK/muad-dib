# slack-webhook-exfil — Ground Truth Reconstruction

## Source
- https://www.sonatype.com/blog/npm-packages-target-solana-devs-drop-keylogging-trojans

## Date
2025

## Technique
- Targets Solana developers
- Solana CLI wallet theft (~/.config/solana/id.json)
- Phantom wallet browser extension data
- .env file harvesting from project directory
- Slack webhook exfiltration (hooks.slack.com)
- Part of larger campaign including keylogger + screenshot

## What was reconstructed
- Solana wallet file harvesting
- Phantom extension data detection
- .env file collection
- Slack webhook exfiltration

## What was simplified
- Original also included keylogger, screenshot, and VBS persistence
- PowerShell used for browser password extraction
