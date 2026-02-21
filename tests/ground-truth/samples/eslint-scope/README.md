# eslint-scope@3.7.2 — Ground Truth Reconstruction

## Source
- https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/
- https://github.com/eslint/eslint-scope/issues/39

## Date
July 2018

## Technique
- Compromised npm credentials used to publish malicious version
- postinstall script reads ~/.npmrc (contains npm auth tokens)
- Exfiltrates tokens via HTTPS POST to attacker-controlled domain (sstatic1.histats.com)
- Also read os.hostname() for identification

## What was reconstructed
- The postinstall script reading .npmrc and exfiltrating via https.request
- The actual C2 domain from public reports (sstatic1.histats.com)
- The credential reading pattern (HOME/USERPROFILE/HOMEPATH fallback)

## What was simplified
- Original code was obfuscated/packed — reconstruction is deobfuscated
- The pastebin endpoint path is simplified
