# warbeast-ssh-steal — Ground Truth Reconstruction

## Source
- https://thehackernews.com/2024/01/malicious-npm-packages-exfiltrate-1600.html

## Date
2024

## Technique
- SSH private key theft from ~/.ssh/id_rsa
- HTTPS POST exfiltration of stolen keys
- Second-stage payload download (Empire post-exploitation framework)
- new Function() execution of downloaded code
- 1,600+ downloads before takedown

## What was reconstructed
- SSH key file reading and exfiltration
- Two-stage attack: key theft + Empire launcher download
- new Function() eval for second stage

## What was simplified
- Original kodiak2k variant included Mimikatz execution
- Empire framework scripts more complex
