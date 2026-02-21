# websocket-rat — Ground Truth Reconstruction

## Source
- https://blog.phylum.io/sophisticated-rat-shell-targeting-gulp-projects-on-npm/

## Date
2024

## Technique
- HTTP-based RAT server listening on port 3004
- Every POST body executed as shell command via exec()
- Lock file mechanism (PID-based) prevents multiple instances
- Anti-sandbox hostname/username checks
- Typosquat of gulp package

## What was reconstructed
- HTTP server with command execution on POST
- Lock file mechanism with PID tracking
- Anti-sandbox environment checks (hostname, username)

## What was simplified
- Original had two-file architecture (play.js dropper + play-safe.js C2)
- More sophisticated environment validation
