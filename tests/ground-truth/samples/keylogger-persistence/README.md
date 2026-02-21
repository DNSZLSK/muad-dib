# keylogger-persistence — Ground Truth Reconstruction

## Source
- https://www.sonatype.com/blog/npm-packages-target-solana-devs-drop-keylogging-trojans

## Date
2025

## Technique
- Full infostealer suite (browser passwords, env secrets)
- VBScript startup persistence (Windows Startup folder)
- Chrome Login Data harvesting (SQLite copy while locked)
- Firefox profile enumeration
- Environment variable scanning for tokens/secrets
- Slack webhook exfiltration (not HTTPS POST to custom C2)

## What was reconstructed
- VBScript startup persistence
- Browser data harvesting (Chrome Login Data, Firefox profiles)
- Environment variable secret scanning
- Slack webhook exfiltration

## What was simplified
- Original also included keylogger and screenshot functionality
- PowerShell scripts for deeper credential extraction
