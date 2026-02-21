# quasar-rat-delivery — Ground Truth Reconstruction

## Source
- ossf/malicious-packages MAL-2024-7769

## Date
2024

## Technique
- Multi-stage QuasarRAT (.NET RAT) delivery
- Base64-encoded string arrays for obfuscation
- Remote binary download via HTTPS
- File write to temp directory + execution
- Anti-debugger check (typeof v8debug)
- Cross-platform execution (direct on Windows, mono on Linux)

## What was reconstructed
- Base64 string array obfuscation pattern
- Remote binary download pipeline
- File write + chmod + execute pattern
- Anti-debugger evasion check

## What was simplified
- Original had 5+ layers of obfuscation (obfuscator.io style)
- Actual QuasarRAT binary not included
