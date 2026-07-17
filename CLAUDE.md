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
npm test          # Run all tests (custom framework, 4561 tests across 152 files)
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

**Source-grep guard (enforced since v2.11.57):** `tests/meta/no-source-grep.test.js` fails the suite if a test reads a `src/`/`bin/`/`docker/`/`deploy/` file and asserts it `.includes()` a string, unless that `file:line` is in the documented C4 allowlist (irreducible Docker/bash/daemon-loop/absence-guard sites). Test behavior, not source text — call the function, run the CLI (`runScan`/`runCommand`), or use the `runWithPreload` subprocess harness in `tests/unit/preload.test.js`. `tests/meta/structural-test-scanner.js` is the detector; set `MUADDIB_META_VERBOSE=1` to list every site. Adding a new source-grep without allowlisting it (with a rationale) will fail CI.

## Architecture summary

**CLI entry:** `bin/muaddib.js` (yargs) delegates to `src/index.js`.

**Pipeline:** Module graph pre-analysis → tree-sitter-python parser bootstrap (async WASM load, no analysis) → deobfuscation → 22 parallel scanners (Promise.allSettled) → deduplication → FP reductions → intent coherence → rule enrichment → per-file max scoring → contextual FP caps → output (CLI/JSON/HTML/SARIF). **Note:** `muaddib scan` does NOT run the ML classifier — the XGBoost model in `src/ml/` is exercised only by `muaddib evaluate` (offline metric replay) and `muaddib monitor` (LOG-ONLY since 2026-04-08, model collapsed pending retrain — see `src/monitor/queue.js:1154`).

**Scanner modules (22 parallel + 2 pre-analysis + 7 conditional/post-processing + 1 metadata):**

- **22 parallel** via `Promise.allSettled` (`src/pipeline/executor.js`): AST, dataflow, shell, package, dependencies, obfuscation, entropy, typosquat (npm + PyPI from python.js), python (IOC match), ai-config, github-actions, hash, ioc-strings (intel-triage P1.1), anti-forensic (P1.2), stub-package (P1.3), monorepo (Sprint 1 audit MR-C2 fix), trusted-dep-diff (opt-in via flag), python-source (PYSRC-001..010, TrapDoor PyPI gap fix v2.11.41), python-ast (PYAST-001..010, tree-sitter Python AST scanner v2.11.42+), anti-scanner-injection (ASI-001..004 anti-scanner prompt injection targeting LLM reviewers, Hades campaign, chantier 2026-06-20), binary-source (BINSRC-001 binary masquerading as .js/.ts source — reads an 8 KB prefix and descends into the `dist/build/out` blind spot the text scanners exclude, jscrambler@8.14.0 `dist/intro.js` gap, chantier 2026-07-11).
- **2 pre-analysis** (before Promise.allSettled): `module-graph/` (directory, 9 files, 5s timeout — builds cross-file flow graph, emits crossFileFlows + moduleGraphThreats), `deobfuscate.js` (transformation helper, passed as arg to AST + dataflow scanners). The `python-ast` scanner additionally requires an async parser bootstrap (`initPythonParser()` loads the WASM grammar once before the parallel batch) — this bootstrap performs no analysis and emits no threats, so it is NOT counted as a pre-analysis scanner.
- **7 conditional/post-processing**: `paranoid.js` (--paranoid flag), `temporal-runner.js` + `temporal-analysis.js` + `temporal-ast-diff.js` (--temporal* flags), `reachability.js` (post-processor FP downgrade, called from pipeline processor), `phantom-gyp.js` (Phantom Gyp compound correlator `gyp_phantom_exec`, post-processor at `processor.js:451`), `native-drop-exec.js` (install-time native-binary drop-and-execute compound correlator `install_native_drop_exec` COMPOUND-020, post-processor).
- **1 metadata fetcher**: `npm-registry.js` (NPM API for age/downloads/maintainers — ML features, used by monitor/evaluate).

Intent coherence (`src/intent-graph.js`) runs in pipeline processor (not in `src/scanner/`). Total: 34 `.js` files in `src/scanner/` (incl. 5 monitor-side: release-zero, email-domain, pypi-maintainer, pypi-registry, pypi-release-zero; and the `env-var-classification.js` taint-source helper) + 3 directories: `ast-detectors/` (13 files, AST scanner detector modules split out of `ast.js`), `module-graph/` (9 files), `python-ast-detectors/` (6 files).

**Scoring:** `riskScore = min(100, max(file_scores) + package_level_score)`. Severity weights: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1 — multiplied by `CONFIDENCE_FACTORS` (`high=1.0`, `medium=0.85`, `low=0.6`) based on `rule.confidence`. Details: ARCHITECTURE.md `### Confidence Factors`.

For full technical details on each scanner, scoring system, sandbox, IOC system, evaluation framework, monitor, detection rules, and version history, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Adding a New Scanner

1. Create `src/scanner/my-scanner.js` exporting a function that takes `targetPath` and returns threats array
2. Import in `src/index.js`, add to the Promise.all destructuring and the threats spread
3. Add rule entry in `src/rules/index.js` with id, name, severity, confidence, description, mitre
4. Add playbook entry in `src/response/playbooks.js`
5. Add tests in the appropriate test file under `tests/` (147 modular test files)
6. Create test fixtures in `tests/samples/my-scanner/`

## Key Constraints

- **No external runtime deps** beyond what's in package.json (acorn, acorn-walk, js-yaml, adm-zip, @inquirer/prompts, web-tree-sitter). The `web-tree-sitter` dep loads the vendored `src/vendor/tree-sitter-python.wasm` (449 KB, SHA-256 audited via `src/vendor/tree-sitter-python.wasm.sha256`) for the PYAST scanner.
- **Windows paths:** Always use `path.relative()` for file references in threats; never shell `!` in scripts
- **Symlink protection:** `findFiles` uses `lstatSync` + inode tracking (maxDepth fallback on Windows where ino=0)
- **Python typosquat false positives:** Typosquat check must skip packages that ARE in the popular list to avoid false positives (flask<->black)
- **Compact IOC format:** 87% of packages are wildcards (all versions malicious). Both `iocs.json` (~112MB) and `iocs-compact.json` (~5MB) are **gitignored** (`.gitignore`) and generated at runtime by `src/ioc/scraper.js` / `muaddib update`; only `tests/fixtures/test-iocs.json` is committed. IOC totals (e.g. the README badge) are therefore not verifiable from the committed tree.

## Production Engineering

1. **Defensive by default** — Toute fonction qui ecrit un fichier, ouvre une connexion, ou alloue de la memoire doit gerer le cas d'echec AVANT le happy path. Verifier les prerequis (permissions, reseau, espace disque) dans les premieres lignes et fail fast si absent.

2. **Bounded resources** — Toute structure en memoire (queue, cache, buffer, array de resultats) doit avoir une taille max explicite. Toute boucle longue doit liberer les objets intermediaires (block scope, nulling). Tout process de plus de 30s doit etre observable : progression, memoire, erreurs cumulees.

3. **Crash resilience** — Le travail partiel a de la valeur. Si un process de 5h crash a 90%, les 90% deja faits doivent etre recuperables. Ecrire les resultats au fur et a mesure (streaming, append, checkpoints), jamais tout en memoire pour ecrire a la fin. Toujours logger un resume meme en cas d'erreur.

4. **Production != tests** — Les tests unitaires valident la logique. La production a des permissions restreintes, de la contention reseau, des process concurrents, des volumes 1000x plus grands, et des timeouts reels. Chaque feature qui tourne sur le VPS doit etre testee mentalement avec 30K+ entrees, pas 3.

5. **Metriques honnetes** — Une metrique evaluee sur un dataset contamine par le meme biais que le training set est sans valeur. Toute evaluation ML doit inclure une validation sur des cas reels en production, pas uniquement sur un holdout statique. Documenter les limites de chaque metrique.

6. **CLI vs daemon** — Les commandes CLI sont des one-shots independants. Elles ne partagent pas les ressources du daemon (semaphores, slots, connexions). Elles verifient leurs prerequis dans les 5 premieres secondes et echouent bruyamment si manquant.

## Post-Release Documentation Checklist

After every version bump / npm publish, update these files:
- README.md: scanner count, test count, version number, feature list, badges
- SECURITY.md: scanner/rule ID list, severity levels, any added/removed rules
- CHANGELOG.md: new version entry with all changes
- ARCHITECTURE.md: any new scanner, scoring change, or feature addition
- package.json version must match npm published version
- Run `npm run docs:stats` to re-sync all **structural counts** (scanners, rules, compound, tests, test/scanner files, version) into the doc markers from source — never hand-edit these numbers. They live in HTML-comment `stat:` marker pairs (plus a few fenced-diagram RAW_SITES), sourced from `stats.json` (generated by `scripts/collect-stats.js`; see `scripts/sync-stats.js` for the exact marker syntax). Use `npm run docs:stats:tests` to also refresh the runtime test count. CI (`npm run docs:stats:check`, in the `test` job) fails on drift. **Metrics (TPR/FPR/ADR, GT/adversarial sample counts) are deliberately NOT auto-synced** — update those only from a real `muaddib evaluate` run.
Never skip documentation updates when publishing a new version.

## Git Workflow

- Always create a branch: `git checkout -b type/name` (e.g. `feat/entropy-scanner`, `fix/false-positive`)
- Open a PR and wait for CI to pass before merging
- Never commit directly to master
- Do not create commits automatically — the user handles commits manually

## Current Metrics (v<!--stat:version-->2.11.174<!--/stat:version-->; detection metrics last fully measured v2.11.48)

| Metric | Value |
|--------|-------|
| Version | **<!--stat:version-->2.11.174<!--/stat:version-->** |
| Tests | **4535** passed, **5 failed** locally (Windows-only env flakes — `tar --force-local` ×3 EXTRACT-POOL, temp-file `UNKNOWN` ×2 PACKAGE; **0 failed on Linux/CI**), across **<!--stat:testFiles-->152<!--/stat:testFiles-->** files (14511 skipped when Docker absent). Total non-skipped: <!--stat:tests-->4561<!--/stat:tests-->. |
| Rules | **<!--stat:rulesTotal-->277<!--/stat:rulesTotal-->** (<!--stat:rulesCore-->272<!--/stat:rulesCore--> RULES + <!--stat:rulesParanoid-->5<!--/stat:rulesParanoid--> PARANOID - v2.11.67/70 Phantom Gyp adds PKG-023 `gyp_command_exec` + COMPOUND-017 `gyp_phantom_exec`; 2026-07 anti-evasion adds AST-095 `anti_analysis_evasion` + AST-096 `analyzer_honeytoken_reference`) |
| Scanners | **<!--stat:scanners-->22<!--/stat:scanners--> parallel** (Promise.allSettled) + **2 pre-analysis** (module-graph/, deobfuscate) + **1 async parser bootstrap** (python-ast WASM init, no analysis emitted) + **7 conditional/post-processing** (paranoid, 3× temporal-*, reachability, phantom-gyp, native-drop-exec) + **1 metadata** (npm-registry). <!--stat:scannerFiles-->36<!--/stat:scannerFiles--> fichiers `src/scanner/*.js` + 3 dirs : `ast-detectors/` (<!--stat:astDetectors-->15<!--/stat:astDetectors-->), `module-graph/` (<!--stat:moduleGraph-->9<!--/stat:moduleGraph-->), `python-ast-detectors/` (<!--stat:pythonAstDetectors-->6<!--/stat:pythonAstDetectors--> fichiers). Détails : ARCHITECTURE.md. |
| Ground Truth size | **96 samples** (was 67 in v2.10.95). 22 added 2026-05-25: 16 synthetic for new PYSRC/PYAST/AST-092/AICONF-004/PKG-022 rules (GT-068..083), 6 real-world tarballs from VPS archive (GT-084..089), 7 reconstructions from `data/all-review-results.json` review reasoning (GT-090..096). 13 PyPI samples (was 0). 3 explicit `tpr_tier: tpr3` (HIGH/MEDIUM rules that don't cross 20 in isolation, documented in `attacks.json` schema). |
| TPR@3 (detection rate) | **95.74%** (90/94 in-scope) — v2.11.48 full re-measurement on enriched GT. 4 misses: same browser-only patterns as historical (lottie-player, polyfill-io, trojanized-jquery) + 1 other. |
| TPR@20 (alert rate) | **88.30%** (83/94 in-scope) — v2.11.48. **+3.1pp vs v2.11.47** (85.19%) — Track D compound (`recon_exfil_direct_ip`) brought GT-095 from 3 → 50, plus 2 other Track A+B samples crossed 20. |
| FPR rules (curated, v2.11.48 measure) | **1.10%** (6/545 scanned of 548 benign packages) — **unchanged** after Track D. Major drop from 15.6% (v2.10.95) is attributable to FP caps F1-F14 (v2.10.97 → v2.11.31). The 6 remaining FPs are real (meteor, prisma, @prisma/client, drizzle-orm, scrypt, liquid) — not whitelist artifacts. **This is the operational number** — what an operator gets from `muaddib scan` (rules + FP caps, no ML). |
| FPR after ML T1 (v2.11.48, offline only) | **1.10%** (6/545 scanned) — `muaddib evaluate` replay; classifier filters 0 FPs in this run (was filtering 1 in v2.11.47). **Not applied in production**: scan never calls the classifier; monitor runs it in LOG-ONLY mode since 2026-04-08 (`src/monitor/queue.js:1154`). Kept for retrain validation. |
| FPR random (v2.11.48) | **2.50%** (5/200 random npm packages) — unchanged. |
| FPR PyPI (v2.11.48, first honest measurement) | **9.68%** (12/124 scanned of 132 — 8 download failures on giant packages: torch, tensorflow, scipy, xgboost, catboost, opencv-python, ansible, playwright). Up from biased 6.10% (v2.11.47, 82/132 scanned) because the Track D PyPI-download fix (removed `pip --no-binary :all:` + added `.whl` extraction via `extractArchive()`) brought 42 previously-skipped giants (numpy/pandas/django/matplotlib/...) into scope. **All 12 FPs cluster at score 25-35**: this is the cap-PyPI-35 artifact, not new rule misfires. |
| ADR | **96.26%** (103/107 available adversarial + holdout) — v2.11.48, stable. |
| Operational coverage (v2.11.67-76) | Distinct from the static GT above (NOT re-measured since v2.11.48). Phase 0b ledger rollup -> `alertRate` (throughput, **not** TPR). Phase 5 `coverage-audit.js` (daily 05:00 UTC) joins the GHSA `ghsa-malware.jsonl` denominator x scan-ledger x archive -> honest GHSA-denominated operational TPR. GHSA poller: npm/pypi/crates, 15 min. |

**Known issues to address before next release:**
- ~~**Benign FPR "drift" 1.10% -> 6.6% measurement artifact**~~: ✅ **resolved v2.11.58** (coordinated 429 backoff + env-tunable registry limits). Root cause was transient npm-registry metadata rate-limiting: `fetchWithRetry` (`src/scanner/npm-registry.js`) never called the limiter's `signal429()` coordinated backoff -> thundering-herd 429s -> packages with no metadata -> `reputationFactor` (the 0.1x mature/popular suppression) did not apply -> famous packages (eslint, npm, rollup, cypress, mongoose) scored at raw `globalRiskScore`. v2.11.58 wired `signal429()` so `evaluate` no longer starves metadata. Operational FPR (`muaddib scan` with metadata available) was always ~1.10%.
- **Cap PyPI à 35/100**: Python samples plafonnent à `riskScore=35` même quand `globalRiskScore=100`. v2.11.48 measurement confirms the impact: all 12 PyPI FPs are exactly at 25–35 (flask 32, django 35, tornado 35, bottle 30, pandas 25, matplotlib 25, plotly 25, bokeh 25, pymongo 35, coverage 32, fabric 35, websockets 35). Lifting the cap to 100 would drop FPR PyPI to ≈0% and also unblock all PyPI MALWARE detection at higher thresholds. **Track E** target.
- ~~**Direct-IP + linux-fingerprint compound gap**~~: ✅ **closed v2.11.48 (Track D)**. Added `linux_fingerprint_exec` (MUADDIB-AST-093) + `direct_ip_exfil` (MUADDIB-AST-094) + `recon_exfil_direct_ip` compound (MUADDIB-COMPOUND-016, sameFile, CRITICAL). GT-095 risk 3→50, matches human-reviewed score 47. Also boosts GT-091 byvendors (90→100) and GT-092 heloo131313 (89→99). TPR@20 +3.1pp on full GT.
- ~~**PyPI download fail 38%**~~: ✅ **closed v2.11.48 (Track D PyPI fix)**. `pip download --no-binary :all:` forced compilation of wheels-only packages and timed out. Removed flag + added `.whl` extraction via `extractArchive()`. Scanned 82/132 → 124/132 (94%). 8 residual fails are >500MB packages (torch, tensorflow, ansible…) hitting the 30s `PACK_TIMEOUT_MS` — relax this if PyPI giants are a target.
- ~~**Eval re-measurement on full 96-sample GT**~~: ✅ done v2.11.48 (`metrics/v2.11.48.json`). 94 in-scope, TPR@3 95.74%, TPR@20 88.30%.
- ~~**Phantom Gyp install-time RCE gap**~~: ✅ closed v2.11.67/70. PKG-023 `gyp_command_exec` speed-bump / danger-marker (v2.11.67, CRITICAL marker on `binding.gyp` command-substitution) + COMPOUND-017 `gyp_phantom_exec` compound (v2.11.70): correlates the `binding.gyp` sink with an independent malice verdict on the invoked file (FP~0 by construction). In `SINGLE_FIRE_CRITICAL_TYPES` (6) + `HIGH_CONFIDENCE_MALICE_TYPES` (30).

## Interdictions

- **Pas de whitelist FP** : ne jamais ajouter de whitelist de packages benins pour reduire artificiellement le FPR
- **Pas de suppression de detection** : ne jamais supprimer une regle existante sans justification par un FP documente
- **Pas d'embellissement des metriques** : TPR/FPR/ADR doivent refleter la realite mesuree, jamais etre ajustes manuellement
- **Pas de per-sample thresholds** : ADR utilise un seuil global (score >= 20), pas de seuils par echantillon
- **Pas de regression silencieuse** : tout changement doit passer `npm test` avec 0 echec
- **Jamais `loadash` en dépendance** : `loadash` est un typosquat connu de `lodash`. Le projet n'utilise NI `lodash` NI `loadash` (zéro `require` dans `src/`/`bin/`). Toute occurrence de `loadash` dans `dependencies`/`devDependencies` de `package.json` est un BUG de supply-chain — ne jamais l'ajouter, l'installer, ni le restaurer en réécrivant `package.json` depuis un état périmé. Les `loadash` dans `tests/`, `data/`, IOCs sont des **données de test légitimes** (chaînes, pas des deps) : ne pas y toucher. Gate au niveau PR : `scripts/check-deps-typosquats.js` (job `test` de `.github/workflows/scan.yml`) fait échouer le CI si `loadash` réapparaît dans les deps.
