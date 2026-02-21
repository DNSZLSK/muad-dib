# cloud-sdk-credential-inject — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/cloud-provider-credentials-targeted-in-new-pypi-malware-campaign/

## Date
2023

## Technique
- Cloud SDK impersonation (Tencent Cloud, AWS, Alibaba Cloud)
- Credential exfiltration injected into credential handler constructor
- Base64-encoded C2 URL to evade string matching
- Environment variable harvesting for cloud provider keys
- Coordinated campaign across multiple cloud providers (published same day)

## What was reconstructed
- SDK credential handler with injected exfiltration
- Base64-encoded C2 URL pattern
- Environment variable credential harvesting (AWS, Tencent, Alibaba)
- HTTPS POST exfiltration

## What was simplified
- Original targeted Python (PyPI) with exec(base64.b64decode()) pattern
- Reconstructed as Node.js equivalent for npm ground truth
