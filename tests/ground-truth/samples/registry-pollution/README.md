# registry-pollution — Ground Truth Reconstruction

## Source
- ossf/malicious-packages MAL-2025-67014 (tea.xyz campaign)

## Date
2025

## Technique
- Registry pollution worm for tea.xyz token reward farming
- Automatically generates and publishes derivative npm packages
- Random package name generation (prefix + noun + hex suffix)
- npm whoami check for authentication before publishing
- Self-replicating: published packages contain the same publish code
- Removes private flags from package.json to enable public publishing

## What was reconstructed
- Package name generation with word lists
- npm publish automation in temp directory
- Authentication check (npm whoami)
- Self-replicating index.js

## What was simplified
- Original generated Indonesian-themed names
- Version number manipulation more sophisticated
- Larger batch publishing
