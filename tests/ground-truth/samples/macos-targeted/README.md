# macos-targeted — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/malware-campaign-targets-npm-pypi-and-rubygems-developers/

## Date
2024

## Technique
- macOS-only targeting (process.exit on non-Darwin platforms)
- Cross-ecosystem coordination (npm + PyPI + RubyGems)
- macOS-specific data collection (serial number via system_profiler, MAC address)
- AES-256-CBC encrypted exfiltration
- Network interface enumeration for internal IP discovery
- Coordinated version numbers across ecosystems (9.1.10)

## What was reconstructed
- Platform check with early exit
- macOS-specific system profiling
- AES encryption of exfiltrated data
- Network interface enumeration

## What was simplified
- Original also included Python (socket + os) and Ruby variants
- More extensive network reconnaissance
