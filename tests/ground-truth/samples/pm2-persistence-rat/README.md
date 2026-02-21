# pm2-persistence-rat — Ground Truth Reconstruction

## Source
- https://www.zscaler.com/blogs/security-research/malicious-npm-packages-deliver-nodecordrat

## Date
2024

## Technique
- Discord-based C2 using webhook for exfiltration
- PM2 process manager persistence (auto-restart on crash)
- Crontab fallback persistence for non-PM2 systems
- Machine fingerprinting (wmic UUID / ioreg / /etc/machine-id)
- .env file harvesting (recursive search)
- Chrome Login Data detection
- Channel naming with machine fingerprint for victim tracking

## What was reconstructed
- PM2 persistence installation with crontab fallback
- Machine ID fingerprinting (cross-platform)
- .env file recursive scanning
- Discord webhook exfiltration

## What was simplified
- Original used full Discord bot API (not just webhooks)
- Supported commands: !run (shell), !screenshot, !sendfile
- MetaMask LevelDB harvesting
