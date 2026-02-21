# jpeg-stego-c2 — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/fake-aws-packages-ship-command-and-control-malware-in-jpeg-files/

## Date
2024

## Technique
- Steganography: C2 payload hidden inside JPEG image files
- Extracts printable ASCII (bytes 32-126) from image binary data
- If extracted string > 2000 chars, executes via new Function()
- Detached child process for payload extraction (survives parent exit)
- Fallback C2 registration if no image payload found

## What was reconstructed
- JPEG binary reading and ASCII extraction loop
- convertertree switch pattern for payload detection
- new Function() eval for extracted payload
- Detached process spawning
- C2 registration fallback

## What was simplified
- Original included actual JPEG files with embedded payloads
- C2 polling mechanism (setInterval every 5 seconds)
- Full command execution pipeline
