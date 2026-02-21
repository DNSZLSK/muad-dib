# noblox.js-vps — Ground Truth Reconstruction

## Source
- https://www.reversinglabs.com/blog/fake-roblox-api-packages-luna-grabber-npm

## Date
August 2024

## Technique
- Typosquatting noblox.js (legitimate Roblox API wrapper)
- Steals Discord tokens from browser local storage (leveldb files)
- Searches %APPDATA%/discord, discordcanary, discordptb
- Regex matches Discord token patterns
- Exfiltrates via Discord webhook (embeds with hostname, username, platform)

## What was reconstructed
- Discord token harvesting from leveldb files
- Token regex patterns (standard and MFA tokens)
- Discord webhook exfiltration with embed

## What was simplified
- Original also deployed Quasar RAT binary
- Additional browser credential theft omitted
