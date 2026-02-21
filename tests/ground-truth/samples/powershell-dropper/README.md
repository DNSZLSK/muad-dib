# powershell-dropper — Ground Truth Reconstruction

## Source
- https://github.com/advisories/GHSA-6gqx-3gpv-vg7v

## Date
2025

## Technique
- PowerShell download cradle for Cobalt Strike beacon delivery
- EncodedCommand (base64 UTF-16LE) to evade command-line detection
- .NET Assembly.Load for in-memory execution (fileless)
- Windows-only with Linux curl|bash fallback
- Installation beacon with system fingerprint

## What was reconstructed
- PowerShell encoded command generation from JavaScript
- .NET reflection-based in-memory execution
- Cross-platform dropper (PowerShell vs curl|bash)
- System fingerprint beacon

## What was simplified
- Actual Cobalt Strike beacon not included
- Original used Go-variant beacon in some packages
