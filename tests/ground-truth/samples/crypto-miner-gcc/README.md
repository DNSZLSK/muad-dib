# crypto-miner-gcc — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/cryptocurrency-miner-masquerading-as-gcc-compiler-found-in-npm-package/

## Date
2024

## Technique
- ELF binary named "gcc" that is actually XMRig cryptocurrency miner
- chmod a+x to make binary executable
- Detached process execution (survives npm install exit)
- Monero mining pool connection (pool.minexmr.com:443)
- Windows fallback: curl download from GitHub releases

## What was reconstructed
- chmod + exec of disguised binary
- XMRig command line arguments (pool, wallet, TLS)
- Detached process for persistence
- Cross-platform targeting (Linux/macOS binary, Windows curl download)

## What was simplified
- Actual ELF binary not included
- Original gcc-builder variant pulled bash script from GitHub
