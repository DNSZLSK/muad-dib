# Contributing to MUAD'DIB

Thanks for your interest in improving MUAD'DIB!

## Ways to contribute

### 1. Add new IOCs (Indicators of Compromise)

Edit `iocs/packages.yaml` and add:
```yaml
- id: MALWARE-XXX-001
  name: "malicious-package-name"
  version: "*"
  severity: critical
  confidence: high
  source: your-name
  description: "Short description of the threat"
  references:
    - https://link-to-blog-or-advisory
  mitre: T1195.002
```

**Severity levels:** critical, high, medium, low

**MITRE techniques:**
- T1195.002 — Supply chain compromise
- T1552.001 — Credentials in files
- T1059 — Command execution
- T1027 — Obfuscation
- T1041 — Exfiltration

### 2. Add detection rules

Edit `src/rules/index.js` and add a new rule:
```javascript
my_new_rule: {
  id: 'MUADDIB-XXX-001',
  name: 'My New Detection',
  severity: 'HIGH',
  confidence: 'high',
  description: 'What this rule detects',
  references: ['https://...'],
  mitre: 'T1195.002'
}
```

### 3. Add response playbooks

Edit `src/response/playbooks.js` and add:
```javascript
case 'my_new_rule':
  return 'Step-by-step response instructions';
```

### 4. Report false positives

Open an issue with:
- Package name
- Detection rule triggered
- Why it's a false positive

### 5. Report missed detections

Open an issue with:
- Malicious package name (npm or PyPI)
- What it does
- Links to advisories

### 6. Improve Python/PyPI support

MUAD'DIB scans Python projects via `src/scanner/python.js` (requirements.txt, setup.py, pyproject.toml). PyPI IOCs come from the OSV dump (14,000+ malicious packages). To contribute:
- Add PyPI IOCs to the YAML database
- Improve Python dependency parsing in `src/scanner/python.js`
- Add popular PyPI packages to the typosquatting whitelist in `src/scanner/typosquat.js`

### 7. Add adversarial test samples

MUAD'DIB maintains evasive samples to validate scanner robustness (102 samples, 94.0% ADR on available samples):
- `datasets/adversarial/` -- 62 samples with evasion techniques (encoding, splitting, indirection)
- `datasets/holdout-v2/` through `datasets/holdout-v5/` -- 40 holdout samples (4 rounds of 10)

To add a new adversarial sample:
1. Create a directory in `datasets/adversarial/` with a malicious pattern that evades detection
2. Add a threshold entry in `src/commands/evaluate.js` (`ADVERSARIAL_THRESHOLDS`)
3. Run `node bin/muaddib.js evaluate --adversarial` to verify detection

### 8. Expand ground truth

The ground truth dataset (`tests/ground-truth/`) contains 51 real-world attack samples (49 active). To add a new sample:
1. Add the malicious package source to `tests/ground-truth/`
2. Add an entry in `tests/ground-truth/attacks.json` with `name`, `min_threats`, `expected_types`
3. Run `node bin/muaddib.js evaluate --ground-truth` to verify TPR

## Development
```bash
git clone https://github.com/DNSZLSK/muad-dib.git
cd muad-dib
npm install
npm test
```

## Testing your changes
```bash
# Scan test fixtures
node bin/muaddib.js scan tests/samples --explain

# Run evaluation (TPR, FPR, ADR)
node bin/muaddib.js evaluate --ground-truth    # TPR on 49 real attacks
node bin/muaddib.js evaluate --adversarial     # ADR on 83 evasive samples
node bin/muaddib.js evaluate --benign          # FPR on 529 npm packages
```

## Pull request process

1. Fork the repo
2. Create a branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests (`npm test`)
5. Run `node bin/muaddib.js evaluate --ground-truth --adversarial` to check for regressions
6. Commit (`git commit -m "Add my feature"`)
7. Push (`git push origin feature/my-feature`)
8. Open a Pull Request

## Code of conduct

Be respectful. We're all here to make npm safer.

## Questions?

Open an issue or join our Discord: https://discord.gg/y8zxSmue