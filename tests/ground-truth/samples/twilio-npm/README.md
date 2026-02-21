# twilio-npm — Ground Truth Reconstruction

## Source
- https://www.sonatype.com/blog/open-source-attacks-on-the-rise-top-8-malicious-packages-found-in-npm

## Date
2024

## Technique
- Typosquatting the legitimate 'twilio' package
- Reverse shell via net.Socket + child_process.spawn
- Connects to attacker C2 on port 4242
- Pipes /bin/sh stdin/stdout through socket

## What was reconstructed
- Classic reverse shell pattern from report descriptions
- postinstall execution trigger

## What was simplified
- Actual package may have had additional evasion
