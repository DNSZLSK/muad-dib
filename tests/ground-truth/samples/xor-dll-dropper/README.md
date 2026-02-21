# xor-dll-dropper — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/crypto-themed-npm-packages-found-delivering-stealthy-malware/

## Date
2024

## Technique
- Multi-stage dropper chain: JavaScript → .bat → PowerShell → XOR decrypt → rundll32
- Downloads XOR-encrypted payload disguised as .mov file
- PowerShell decrypts with bitwise XOR (key 0xef)
- Executes DLL via rundll32 with exported function name
- All intermediate files deleted after execution (anti-forensics)
- Windows-only targeting

## What was reconstructed
- JavaScript generating batch and PowerShell scripts at runtime
- curl download of encrypted payload
- PowerShell XOR decryption loop
- rundll32 DLL execution with function export
- Evidence cleanup (file deletion)

## What was simplified
- Actual DLL payload not included (only the dropper chain)
- Original used more sophisticated obfuscation
