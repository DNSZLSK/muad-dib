# github-actions-inject — Ground Truth Reconstruction

## Source
- https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack

## Date
2025

## Technique
- Shai-Hulud V2: Self-replicating worm with GitHub Actions persistence
- Writes malicious .github/workflows/shai-hulud.yml to git repositories
- Workflow runs on push and every 6 hours (cron schedule)
- Downloads and executes worm payload + npm publish for propagation
- Token harvesting (GITHUB_TOKEN, NPM_TOKEN, .npmrc)
- Searches for git repos in home directory

## What was reconstructed
- GitHub Actions workflow YAML injection
- Git repository discovery across common directories
- Token harvesting from environment and .npmrc
- HTTPS exfiltration to C2

## What was simplified
- Original also destroyed home directory as destructive payload
- More sophisticated repo discovery and worm propagation
- Dead man's switch if containment detected
