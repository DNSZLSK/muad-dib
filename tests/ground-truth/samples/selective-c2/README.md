# selective-c2 — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/sophisticated-highly-targeted-attacks-continue-to-plague-npm/

## Date
2024

## Technique
- North Korean APT (Jade Sleet / TraderTraitor) campaign
- AES-128-CBC encrypted two-way C2 communication
- Selective payload delivery based on machine GUID
- 45-second delayed first heartbeat to evade sandbox analysis
- Periodic heartbeat (every 45 seconds)
- new Function() for executing decrypted C2 payloads

## What was reconstructed
- AES encryption/decryption for C2 messages
- Machine GUID fingerprinting (wmic/machine-id)
- Delayed heartbeat pattern with setInterval
- C2 response handling with decryption and eval

## What was simplified
- Original required paired packages (second provides download token)
- Earlier variant used Base64 only (no AES)
- C2 infrastructure more sophisticated with multiple endpoints
