# kubeconfig-theft — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/sensitive-data-exfiltration-campaign-targets-npm-and-pypi/

## Date
2024

## Technique
- SSH key theft (entire ~/.ssh/ directory)
- Kubernetes config theft (~/.kube/config)
- AWS credentials theft (~/.aws/credentials)
- Cross-ecosystem campaign (npm + PyPI, 46+ packages)
- HTTPS POST exfiltration

## What was reconstructed
- SSH directory enumeration and key reading
- Kubernetes config file reading
- AWS credentials file reading
- System metadata collection
- HTTPS exfiltration to app.threatest.com

## What was simplified
- Original campaign spanned 38+ packages with obfuscated versions
- Later iterations added preinstall hooks and base64 encoding
