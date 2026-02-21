# trojanized-jquery — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/persistent-npm-campaign-shipping-trojanized-jquery

## Date
2024

## Technique
- Modified jQuery library with injected malicious code
- Form submission event listener for data harvesting
- Image beacon exfiltration (new Image().src = ...)
- Malicious code buried deep within legitimate library code
- Persistent npm campaign across multiple package names

## What was reconstructed
- jQuery-like library structure with injected form data theft
- Document submit event listener
- Form input enumeration and data collection
- Image beacon exfiltration pattern

## What was simplified
- Actual jQuery code not included (only structure)
- Original had the payload buried within 3500+ lines of real jQuery
