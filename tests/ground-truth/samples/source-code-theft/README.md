# source-code-theft — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/targeted-npm-malware-attempts-to-steal-developers-source-code-and-secrets/

## Date
2024

## Technique
- Source code and secrets theft from developer's working directory
- Recursive file listing with depth limit
- Sensitive file pattern matching (.env, .npmrc, config.json, secrets.json)
- gzip compression of stolen data
- HTTPS exfiltration to attacker IP
- Detached child process (survives npm install exit)

## What was reconstructed
- Recursive file walker with node_modules/.git exclusion
- Sensitive file pattern matching and collection
- gzip compressed exfiltration
- Detached process pattern (spawn with --run flag)

## What was simplified
- Original used FTP upload (archiver + ftp modules)
- More extensive file collection (full project archive, not just sensitive files)
