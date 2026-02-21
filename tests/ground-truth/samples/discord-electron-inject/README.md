# discord-electron-inject — Ground Truth Reconstruction

## Source
- https://research.jfrog.com/post/duer-js-malicious-package/

## Date
2024

## Technique
- Discord Electron injection by overwriting core index.js
- webContents.debugger.attach("1.3") for network protocol hooking
- Intercepts /login, /register, /mfa/totp, /@me endpoints
- Network.getResponseBody to steal response data
- Cross-platform Discord path detection (Windows, macOS, Linux)

## What was reconstructed
- Discord installation finder (cross-platform)
- Core module index.js location and overwrite
- Electron debugger protocol hooking
- Sensitive endpoint filtering and data exfiltration

## What was simplified
- Original used 64,000-char eval() string with URI encoding and key-based decryption
- Two-stage payload download before injection
- More extensive data harvesting (Nitro, billing, payment, friends, 2FA codes)
