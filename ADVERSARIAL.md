# Adversarial Dataset — Red Team Evaluation

This document describes the adversarial malware samples used to evaluate MUAD'DIB's detection capabilities. The actual source code is **local-only** and excluded from the public repository to prevent weaponization.

## Overview

- **62 adversarial samples** across 5 red-team waves
- **40 holdout samples** across 4 holdout sets (holdout-v2 through holdout-v5)
- **ADR (Adversarial Detection Rate): 94.0% (63/67 available)** on waves 1-5 + holdout (v2.5.17)
- **Wave 5: 24/27 detected on available samples** (3 misses: `getter-defineProperty-exfil`, `setTimeout-eval-chain`, `setter-trap-exfil`)
- 43 adversarial sample directories are local-only and not evaluated on all machines
- 4 documented misses on available samples:
  - `require-cache-poison` (accepted trade-off from FP reduction P3)
  - `getter-defineProperty-exfil` (Object.defineProperty interception — no AST pattern)
  - `setTimeout-eval-chain` (deferred eval chain — no direct dangerous call)
  - `setter-trap-exfil` (property setter trap — no AST pattern)

## Wave 1 — Core Evasion Techniques (20 samples)

| Sample | Technique | MITRE | Score | Status |
|--------|-----------|-------|-------|--------|
| ci-trigger-exfil | CI environment detection + conditional exfiltration | T1082 | 35+ | PASS |
| delayed-exfil | setTimeout-based delayed credential theft | T1497.003 | 30+ | PASS |
| docker-aware | Container detection + environment fingerprinting | T1082 | 35+ | PASS |
| staged-fetch | Multi-stage: clean stage 1, fetch malicious stage 2 | T1105 | 35+ | PASS |
| dns-chunk-exfil | DNS subdomain exfiltration with base64 encoding | T1048 | 35+ | PASS |
| string-concat-obfuscation | String concatenation to build dangerous API names | T1027 | 30+ | PASS |
| postinstall-download | npm lifecycle script downloads and executes payload | T1059 | 30+ | PASS |
| dynamic-require | Dynamic require() with encoded module names | T1027 | 40+ | PASS |
| iife-exfil | IIFE-wrapped credential theft | T1027 | 40+ | PASS |
| conditional-chain | Conditional execution chain with environment checks | T1497 | 30+ | PASS |
| template-literal-obfuscation | Template literals to hide dangerous calls | T1027 | 30+ | PASS |
| proxy-env-intercept | Proxy trap on process.env to intercept credentials | T1552 | 40+ | PASS |
| nested-payload | Multi-file nested payload with indirection layers | T1027 | 30+ | PASS |
| dynamic-import | Dynamic import() with computed module paths | T1129 | 30+ | PASS |
| websocket-exfil | WebSocket-based credential exfiltration | T1071 | 30+ | PASS |
| bun-runtime-evasion | Bun runtime detection to evade Node.js-only scanners | T1497 | 25+ | PASS |
| preinstall-exec | preinstall lifecycle script with child_process.exec | T1059 | 35+ | PASS |
| remote-dynamic-dependency | Remote dependency fetched at runtime | T1105 | 35+ | PASS |
| github-exfil | Exfiltration via GitHub API | T1567 | 30+ | PASS |
| detached-background | Detached background process for persistence | T1059 | 35+ | PASS |

## Wave 3 — Advanced Techniques (5 samples)

| Sample | Technique | MITRE | Score | Status |
|--------|-----------|-------|-------|--------|
| ai-agent-weaponization | AI agent flags (--yolo, --dangerously-skip-permissions) | T1059 | 35+ | PASS |
| ai-config-injection | Prompt injection in AI config files (.cursorrules, CLAUDE.md) | T1059 | 30+ | PASS |
| rdd-zero-deps | Zero-dep package with hidden remote code loading | T1105 | 35+ | PASS |
| discord-webhook-exfil | Exfiltration via Discord webhook CDN | T1567 | 30+ | PASS |
| preinstall-background-fork | preinstall script forks background process | T1059 | 35+ | PASS |

## Holdout Promoted (10 samples)

| Sample | Technique | MITRE | Score | Status |
|--------|-----------|-------|-------|--------|
| silent-error-swallow | Error silencing to hide malicious activity | T1562 | 25+ | PASS |
| double-base64-exfil | Double base64 encoding for obfuscation | T1027 | 30+ | PASS |
| crypto-wallet-harvest | Cryptocurrency wallet file theft | T1005 | 25+ | PASS |
| self-hosted-runner-backdoor | GitHub Actions self-hosted runner backdoor | T1195.002 | 20+ | PASS |
| dead-mans-switch | Dead man's switch with network time check | T1497.003 | 30+ | PASS |
| fake-captcha-fingerprint | Browser fingerprinting disguised as CAPTCHA | T1082 | 20+ | PASS |
| pyinstaller-dropper | PyInstaller binary dropper pattern | T1105 | 35+ | PASS |
| gh-cli-token-steal | GitHub CLI token theft (gh auth token) | T1552 | 30+ | PASS |
| triple-base64-github-push | Triple base64 encoding + GitHub push exfil | T1048 | 30+ | PASS |
| browser-api-hook | Browser API hooking (fetch, XMLHttpRequest) | T1557 | 20+ | PASS |

## Audit Bypass Samples (3 samples, v2.2.13)

| Sample | Technique | MITRE | Score | Status |
|--------|-----------|-------|-------|--------|
| indirect-eval-bypass | Indirect eval via alias (`const E = eval; E(code)`) | T1059 | 10+ | PASS |
| muaddib-ignore-bypass | Attempted .muaddibignore bypass | T1562 | 25+ | PASS |
| mjs-extension-bypass | ESM .mjs extension evasion | T1036 | 100 | PASS |

## Wave 4 — Blue Team (5 samples, v2.4.7)

| Sample | Technique | MITRE | Score | Status |
|--------|-----------|-------|-------|--------|
| git-hook-persistence | Write to .git/hooks for persistence | T1195.002 | 10+ | PASS |
| native-addon-camouflage | Native addon (.node) camouflaged as npm package | T1027 | 25+ | PASS |
| stego-png-payload | Steganographic payload hidden in PNG metadata | T1027.003 | 35+ | PASS |
| stegabin-vscode-persistence | Steganographic binary + VS Code task persistence | T1546 | 30+ | PASS |
| mcp-server-injection | MCP server config injection for AI toolchain poisoning | T1059 | 25+ | PASS |

## Wave 5 — Advanced Evasion (27 samples)

Inspired by real-world campaigns (DPRK/Lazarus, FAMOUS CHOLLIMA) and 2025-2026 supply chain attack techniques.

| Sample | Technique | MITRE | Score | Status |
|--------|-----------|-------|-------|--------|
| async-iterator-exfil | Async iterator protocol hijacking for data interception | T1557 | 45 | PASS |
| console-override-exfil | Console method override to intercept logged credentials | T1552 | 25 | PASS |
| cross-file-callback-exfil | Cross-file callback chain to split credential read from exfil | T1041 | 28 | PASS |
| error-reporting-exfil | Fake error reporting service (Sentry/Bugsnag spoof) | T1041 | 48 | PASS |
| error-stack-exfil | Error stack trace manipulation for data exfiltration | T1041 | 35 | PASS |
| event-emitter-exfil | EventEmitter-based credential relay | T1041 | 25 | PASS |
| fn-return-exfil | Function return value interception and exfiltration | T1557 | 70 | PASS |
| getter-defineProperty-exfil | Object.defineProperty override to intercept sensitive property definitions | T1574 | 10 | **MISS** |
| http-header-exfil | HTTP header injection (cookies, user-agent) for data exfiltration | T1048 | 45 | PASS |
| import-map-poison | Import map poisoning to redirect module resolution | T1574 | 25 | PASS |
| intl-polyfill-backdoor | Intl polyfill with backdoor for locale-triggered exfiltration | T1027 | 35 | PASS |
| net-time-exfil | Network time check as trigger for time-bomb activation | T1497.003 | 45 | PASS |
| postmessage-exfil | postMessage-based cross-origin data exfiltration | T1041 | 25 | PASS |
| process-title-exfil | process.title manipulation + credential harvesting | T1552 | 73 | PASS |
| promise-chain-exfil | Promise chain for deferred credential exfiltration | T1041 | 63 | PASS |
| proxy-getter-dns-exfil | Proxy getter trap + DNS-based exfiltration | T1048 | 35 | PASS |
| readable-stream-exfil | Transform stream credential scanning and exfiltration | T1557 | 25 | PASS |
| response-intercept-exfil | HTTP response interception via monkey-patching | T1557 | 75 | PASS |
| setTimeout-eval-chain | setTimeout + eval chain for deferred code execution | T1059 | 0 | **MISS** |
| setter-trap-exfil | Property setter trap for credential interception | T1557 | 0 | **MISS** |
| sourcemap-payload | Source map file with embedded executable payload | T1027 | 63 | PASS |
| stream-pipe-exfil | Stream pipe interception for data-in-transit theft | T1557 | 45 | PASS |
| svg-payload-fetch | SVG file with embedded payload fetched and executed | T1027.003 | 28 | PASS |
| symbol-iterator-exfil | Symbol.iterator protocol hijacking | T1557 | 25 | PASS |
| toJSON-hijack | toJSON method hijacking for serialization interception | T1557 | 35 | PASS |
| url-constructor-exfil | URL constructor abuse for encoded exfiltration | T1048 | 50 | PASS |
| wasm-c2-payload | WebAssembly module with C2 callback host imports | T1071 | 25 | PASS |

## Detections Added During Wave 5

The following scanner improvements were made to detect wave 5 samples:

1. **Credential Regex Harvesting escalation** (AST-041): Escalated from HIGH to CRITICAL. Credential-matching regex (Bearer/password/secret/token) combined with network calls is never legitimate in npm packages.

2. **Cross-file callback dataflow** (module-graph): Enhanced inter-module dataflow analysis to detect credential reads passed through callback chains to network sinks in other modules.

3. **Various AST compound detections**: Multiple new compound detections for patterns like Proxy traps + network, WASM + network, console override + network, event emitter relay + network.

## Holdout Sets (40 samples)

Holdout samples are stored in `datasets/holdout-v2/` through `datasets/holdout-v5/` and cover:

- **holdout-v2** (10): Conditional OS payload, env var reconstruction, GitHub workflow injection, SSH key theft, npm cache poisoning, lifecycle curl, process.env proxy, stream hijack, setTimeout chains, WASM loader
- **holdout-v3** (10): DNS TXT payload, Electron RCE, env file parsing, git credential theft, npm hook hijack, reverse shell, require cache poisoning, steganography, symlink escape, timezone trigger
- **holdout-v4** (10): Deobfuscation evasion — atob eval, base64 require, charcode fetch, hex array exec, mixed obfuscation, nested base64, template literal hiding
- **holdout-v5** (10): Inter-module dataflow — callback exfil, class method exfil, conditional split, event emitter flow, mixed inline, named export, re-export chain, split env/npmrc steal, three-hop chain

## Running the Evaluation

```bash
# Full evaluation (requires local adversarial + holdout datasets)
node bin/muaddib.js evaluate

# Adversarial only
node bin/muaddib.js evaluate --adversarial

# The runner skips gracefully if datasets/adversarial/ is missing
```

## Security Notice

The adversarial samples contain realistic malware patterns derived from real-world supply chain attacks. They are excluded from the public repository and npm package to prevent misuse. The samples are available only to authorized contributors for regression testing purposes.
