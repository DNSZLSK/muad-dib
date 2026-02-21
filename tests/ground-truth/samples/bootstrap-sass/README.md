# bootstrap-sass — Ground Truth Reconstruction

## Source
- https://snyk.io/blog/a-malicious-backdoor-in-popular-bootstrap-sass-npm-package/

## Date
April 2019

## Technique
- Account takeover of popular bootstrap-sass npm package
- postinstall script searches project for JavaScript files
- Injects cookie-stealing snippet (document.cookie exfiltration via Image beacon)
- Targets public/static/dist/build directories
- Sends installation beacon to attacker server

## What was reconstructed
- postinstall trigger with project root detection
- JavaScript file injection in common output directories
- Cookie-stealing payload injection (Image beacon pattern)
- Installation beacon to attacker C2

## What was simplified
- Original obfuscated the injected payload more heavily
- Used more sophisticated file targeting
