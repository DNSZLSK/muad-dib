# haski — Ground Truth Reconstruction

## Source
- https://checkmarx.com/blog/new-technique-to-hide-malicious-npm-packages-using-ethereum-blockchain/

## Date
2024

## Technique
- Novel blockchain-based C2: reads Ethereum smart contract to retrieve payload URL
- Ethereum JSON-RPC call via public gateway (cloudflare-eth.com)
- Smart contract stores C2 URL in immutable blockchain storage
- Dynamic payload fetch via HTTPS + new Function() eval
- System fingerprinting exfiltration as fallback
- Makes takedown harder: blockchain data is immutable

## What was reconstructed
- Ethereum JSON-RPC eth_call to read smart contract storage
- Hex response decoding to extract URL
- Dynamic code fetch and eval via new Function()
- System fingerprinting with HTTPS exfiltration
- postinstall trigger

## What was simplified
- Original used more complex ABI encoding for contract interaction
- Multiple fallback RPC endpoints (Infura, Alchemy, etc.)
- The actual smart contract deployment details
