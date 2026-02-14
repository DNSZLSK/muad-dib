# Ground Truth Dataset

Validated dataset of real-world supply-chain attacks for testing MUAD'DIB detection accuracy.

## Purpose

This dataset contains reconstructed samples from known malicious packages (npm + PyPI). Each attack is documented with expected detection results, allowing automated replay to measure:

- **True Positive Rate** — attacks correctly detected
- **Detection coverage** — which scanners fire on which attack types
- **Rule accuracy** — expected rules vs actual rules triggered

## Format — attacks.json

```json
{
  "version": "1.0",
  "attacks": [
    {
      "id": "GT-001",
      "name": "event-stream",
      "ecosystem": "npm",
      "version": "3.3.6",
      "description": "Flatmap-stream dependency injection targeting copay bitcoin wallet",
      "source": "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
      "mitre": ["T1195.002", "T1059"],
      "sample_dir": "samples/GT-001-event-stream/",
      "expected": {
        "min_threats": 2,
        "rules": ["MUADDIB-AST-001", "MUADDIB-SHELL-001"],
        "severities": ["HIGH", "CRITICAL"],
        "scanners": ["ast", "package"]
      }
    }
  ]
}
```

### Field reference

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (GT-NNN) |
| `name` | string | Package name |
| `ecosystem` | string | `npm` or `pypi` |
| `version` | string | Compromised version |
| `description` | string | Brief description of the attack |
| `source` | string | URL to writeup / advisory |
| `mitre` | string[] | MITRE ATT&CK technique IDs |
| `sample_dir` | string | Path to reconstructed sample (relative to ground-truth/) |
| `expected.min_threats` | number | Minimum number of threats expected |
| `expected.rules` | string[] | Rule IDs that MUST fire |
| `expected.severities` | string[] | Severity levels expected (at least one must match) |
| `expected.scanners` | string[] | Scanners expected to detect (informational) |

## Adding a new attack

1. Choose the next available ID: `GT-NNN`
2. Create the sample directory: `samples/GT-NNN-package-name/`
3. Reconstruct the malicious code (stripped of actual payloads — use dummy URLs/IPs)
4. Add the entry to `attacks.json`
5. Run the replay to verify detection: `node tests/ground-truth/replay.js`

### Sample reconstruction rules

- Reproduce the **technique**, not the exact payload
- Replace real C2 domains with `evil.example.com`
- Replace real IPs with `198.51.100.1` (RFC 5737 documentation range)
- Replace real credentials/tokens with `FAKE_TOKEN_XXXXX`
- Keep the code structure and obfuscation patterns intact

## Running the replay

```bash
# Replay all attacks
node tests/ground-truth/replay.js

# Replay a single attack
node tests/ground-truth/replay.js GT-001

# Replay with verbose output
node tests/ground-truth/replay.js --verbose
```

The replay runner scans each sample directory with `muaddib scan --json` and compares results against `expected` fields. Output shows pass/fail per attack with a summary of detection coverage.
