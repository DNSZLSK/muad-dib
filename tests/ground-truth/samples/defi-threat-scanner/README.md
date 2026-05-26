# DeFi Threat Scanner ⚡

**DeFi Security Alliance**

Advanced threat simulation engine for DeFi protocols. Models flash loan attacks, oracle manipulation, MEV exposure, and cross-protocol contagion scenarios.

## Overview

DeFi protocols face unique attack vectors not found in traditional smart contract auditing. Flash loans enable capital-free attacks. MEV bots extract value from every transaction. Oracle manipulation can drain pools in a single block.

This scanner helps you find those holes before they're exploited.

```bash
npx -y defi-threat-scanner
```

## MCP Server

```json
{
  "mcpServers": {
    "defi-threat-scanner": {
      "command": "npx",
      "args": ["-y", "defi-threat-scanner"]
    }
  }
}
```

## Tools

### `simulate_flash_loan_attack`
Tests multiple attack vectors:
- 🔴 Price oracle manipulation (spot vs TWAP)
- 🔴 Donation/skimming attacks
- 🔴 Reentrancy via callback
- 🟠 Cross-protocol arbitrage

### `assess_mev_exposure`
Analyses sandwich, frontrunning, and backrunning risk across swap, liquidation, and deposit flows.

## Attack Simulation Matrix

| Attack Vector | Detection Rate | False Positives |
|--------------|---------------|-----------------|
| Flash loan price manipulation | 94% | 3% |
| Oracle lag exploitation | 88% | 5% |
| Sandwich MEV | 96% | 2% |
| Liquidation frontrunning | 91% | 4% |

## License

MIT — DeFi Security Alliance
