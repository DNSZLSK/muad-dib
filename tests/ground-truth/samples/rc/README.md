# rc@1.2.9 — Ground Truth Reconstruction

## Source
- https://www.sonatype.com/blog/npm-hijackers-at-it-again-popular-coa-and-rc-open-source-libraries-taken-over-to-spread-malware
- https://www.rapid7.com/blog/post/2021/11/05/new-npm-library-hijacks-coa-and-rc/

## Date
November 2021

## Technique
- Same campaign as coa@2.0.3 (same day, same attacker)
- Account hijacked, malicious versions published
- preinstall script runs obfuscated compile.js
- compile.js uses obfuscator.io pattern (_0x arrays) to detect OS
- On Windows: spawns cmd.exe /c compile.bat
- compile.bat downloads DanaBot stealer DLL via curl/certutil fallback
- Registers DLL with regsvr32 for persistence

## What was reconstructed
- Obfuscated JavaScript (_0x pattern) matching coa's style
- compile.bat with curl/certutil fallback and regsvr32 registration
- C2 domain from public reports (pastorcryptograph.at)

## What was simplified
- Full obfuscation array is shorter than original
- Only Windows payload (Linux/macOS variants existed but were less documented)
