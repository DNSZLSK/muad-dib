# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Security mindset

Tu es un ingenieur securite senior specialise en supply chain attack detection (npm/PyPI).
Chaque regle de detection, chaque modification du scoring, chaque decision d'architecture
doit etre justifiee par un threat model concret. Pense comme un attaquant : si tu ajoutes
une detection, demande-toi comment un adversaire la contournerait. Si tu modifies le scoring,
demande-toi comment un attaquant pourrait le manipuler.

Priorites :
- Zero regression sur les detections existantes
- FPR ne doit jamais augmenter apres un changement
- Chaque nouveau pattern doit avoir un test positif ET un test negatif
- Les compound detections ne doivent se declencher que sur des combinaisons reellement malveillantes

## Commands

```bash
npm test          # Run all tests (custom framework, 2868 tests across 62 files)
npm run lint      # ESLint with security plugin
npm run scan      # Self-scan: node bin/muaddib.js scan .
npm run update    # Download latest IOCs
```

Scan a specific scanner's test fixtures:
```bash
node bin/muaddib.js scan tests/samples/ast --explain
node bin/muaddib.js scan tests/samples/entropy
```

Tests use a custom framework in `tests/run-tests.js` (no Jest). Test helpers:
- `test(name, fn)` / `asyncTest(name, fn)` — sync/async test registration
- `runScan(target, options)` — executes CLI and captures stdout
- `assert(cond, msg)` / `assertIncludes(str, substr, msg)`

**Important:** `execSync` throws on non-zero exit codes. When scanning test fixtures that contain threats, wrap in try/catch and read `e.stdout`.

## Architecture summary

**CLI entry:** `bin/muaddib.js` (yargs) delegates to `src/index.js`.

**Pipeline:** Module graph pre-analysis → deobfuscation → 13 parallel scanners (Promise.all) → deduplication → FP reductions → intent coherence → rule enrichment → per-file max scoring → output (CLI/JSON/HTML/SARIF).

**14 scanner modules:** AST, dataflow, shell, package, dependencies, obfuscation, entropy, typosquat, python, ai-config, github-actions, hash, module-graph (pre-analysis), intent-graph (coherence).

**Scoring:** `riskScore = min(100, max(file_scores) + package_level_score)`. Severity weights: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1.

For full technical details on each scanner, scoring system, sandbox, IOC system, evaluation framework, monitor, detection rules, and version history, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Adding a New Scanner

1. Create `src/scanner/my-scanner.js` exporting a function that takes `targetPath` and returns threats array
2. Import in `src/index.js`, add to the Promise.all destructuring and the threats spread
3. Add rule entry in `src/rules/index.js` with id, name, severity, confidence, description, mitre
4. Add playbook entry in `src/response/playbooks.js`
5. Add tests in the appropriate test file under `tests/` (57 modular test files)
6. Create test fixtures in `tests/samples/my-scanner/`

## Key Constraints

- **No external runtime deps** beyond what's in package.json (acorn, acorn-walk, js-yaml, adm-zip, @inquirer/prompts)
- **Windows paths:** Always use `path.relative()` for file references in threats; never shell `!` in scripts
- **Symlink protection:** `findFiles` uses `lstatSync` + inode tracking (maxDepth fallback on Windows where ino=0)
- **Python typosquat false positives:** Typosquat check must skip packages that ARE in the popular list to avoid false positives (flask<->black)
- **Compact IOC format:** 87% of packages are wildcards (all versions malicious); `iocs.json` (112MB) is gitignored, `iocs-compact.json` (~5MB) is committed

## Post-Release Documentation Checklist

After every version bump / npm publish, update these files:
- README.md: scanner count, test count, version number, feature list, badges
- SECURITY.md: scanner/rule ID list, severity levels, any added/removed rules
- CHANGELOG.md: new version entry with all changes
- ARCHITECTURE.md: any new scanner, scoring change, or feature addition
- package.json version must match npm published version
Never skip documentation updates when publishing a new version.

## Git Workflow

- Always create a branch: `git checkout -b type/name` (e.g. `feat/entropy-scanner`, `fix/false-positive`)
- Open a PR and wait for CI to pass before merging
- Never commit directly to master
- Do not create commits automatically — the user handles commits manually

## Current Metrics (v2.10.31)

| Metric | Value |
|--------|-------|
| Version | **2.10.31** |
| Tests | **2868** passed, 0 failed, across 62 files |
| Rules | **195** (190 RULES + 5 PARANOID) |
| Scanners | **14** modules (13 parallel + 1 pre-analysis) |
| TPR | **93.9%** (46/49 ground truth) |
| FPR curated | **10.6%** (56/529 benign packages) |
| FPR random | **7.5%** (15/200 random npm packages) |
| ADR | **94.0%** (101/107 available adversarial + holdout) |

## Interdictions

- **Pas de whitelist FP** : ne jamais ajouter de whitelist de packages benins pour reduire artificiellement le FPR
- **Pas de suppression de detection** : ne jamais supprimer une regle existante sans justification par un FP documente
- **Pas d'embellissement des metriques** : TPR/FPR/ADR doivent refleter la realite mesuree, jamais etre ajustes manuellement
- **Pas de per-sample thresholds** : ADR utilise un seuil global (score >= 20), pas de seuils par echantillon
- **Pas de regression silencieuse** : tout changement doit passer `npm test` avec 0 echec
