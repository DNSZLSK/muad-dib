# flatmap-stream@0.1.1 — Ground Truth Reconstruction

## Source
- https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream/
- https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
- https://github.com/nickcash/event-stream-malicious-code (deobfuscated analysis)

## Date
September-November 2018

## Technique
- Minified malicious code appended to legitimate flatmap-stream module
- AES-256-CBC encrypted payload using npm_package_description as decryption key
- `require('crypto').createDecipher()` to decrypt payload
- `module._compile()` to execute decrypted code in memory
- Targeted Copay Bitcoin wallet (bitcore-wallet-client)
- Stole wallet credentials (xPrivKey) and exfiltrated to copayapi.host

## What was reconstructed
- The deobfuscated payload structure from public analyses (hex-encoded require paths, createDecipher usage, module._compile execution)
- The test/data.js encrypted payload file (placeholder, not real encrypted data)

## What was simplified
- The actual AES-encrypted payload is a placeholder (real payload targeted Copay specifically)
- The legitimate flatmap-stream code is omitted
- The minification/obfuscation is partially reconstructed
