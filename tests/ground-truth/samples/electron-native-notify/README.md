# electron-native-notify — Ground Truth Reconstruction

## Source
- https://blog.npmjs.org/post/185397814280/plot-to-steal-cryptocurrency-foiled-by-the-npm

## Date
June 2019

## Technique
- Social engineering: attacker befriended maintainer, gained npm publish access
- postinstall script triggers credential harvesting
- Targets .npmrc tokens, environment variable tokens (NPM_TOKEN, GH_TOKEN, AWS keys)
- Cryptocurrency wallet file theft (Bitcoin, Ethereum, Exodus)
- HTTPS exfiltration to histats.com (same C2 as eslint-scope campaign)

## What was reconstructed
- postinstall credential harvesting
- npm token theft from .npmrc
- Environment variable token scanning
- Cryptocurrency wallet file access
- HTTPS POST exfiltration

## What was simplified
- Original also targeted Agama cryptocurrency wallet specifically
- Social engineering aspect not reproducible in code
- Targeted specific Electron app (Agama) for delivery
