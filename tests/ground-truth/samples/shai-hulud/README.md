# Shai-Hulud 2.0 Worm — Ground Truth Reconstruction

## Source
- https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
- https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance/
- https://snyk.io/blog/embedded-malicious-code-in-tinycolor-and-ngx-bootstrap-releases-on-npm/

## Date
September-November 2025

## Technique
- Self-replicating npm worm (796+ packages infected)
- Phase 1: preinstall script harvests npm tokens from .npmrc and environment
- Phase 2: Exfiltrates tokens + AWS/GitHub credentials to C2 (euw.bfrntend.com)
- Phase 3: Uses stolen npm token to modify victim's packages (add preinstall script + worm payload)
- Phase 4: npm publish — exponential propagation

## What was reconstructed
- 3-phase attack: harvest → exfiltrate → self-replicate
- .npmrc token parsing, env var harvesting (NPM_TOKEN, GITHUB_TOKEN, AWS keys)
- HTTPS POST exfiltration to actual C2 domain from Datadog report
- Self-replication via package.json modification and npm publish
- setup_bun.js filename from actual reports

## What was simplified
- Real worm had more sophisticated evasion (CI detection, exponential backoff)
- GitHub Actions workflow injection (discussion.yaml persistence) not included
- GCP/Azure credential harvesting simplified
