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
npm test          # Run all tests (custom framework, 4545 tests across 167 files)
npm run lint      # ESLint with security plugin (0 errors, warning ratchet)
npm run test:coverage  # c8 + coverage floors (.c8rc.json)
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

- **22 parallel** via `Promise.allSettled` (`src/pipeline/executor.js`): AST, dataflow, shell, package, dependencies, obfuscation, entropy, typosquat (npm + PyPI), python (IOC match), ai-config, github-actions, hash, ioc-strings, anti-forensic, stub-package, monorepo, trusted-dep-diff (opt-in), python-source (PYSRC), python-ast (PYAST, tree-sitter WASM), anti-scanner-injection (ASI), binary-source (BINSRC).
- **2 pre-analysis**: `module-graph/` (cross-file flows, 5 s timeout) and `deobfuscate.js`. The python-ast WASM bootstrap (`initPythonParser()`) emits nothing and is not counted.
- **7 conditional/post-processing**: `paranoid.js`, 3x `temporal-*`, `reachability.js` (FP downgrade), `phantom-gyp.js` (COMPOUND-017), `native-drop-exec.js` (COMPOUND-020).
- **1 metadata fetcher**: `npm-registry.js` (age/downloads/maintainers, used by monitor/evaluate).

Intent coherence (`src/intent-graph.js`) runs in the pipeline processor. File counts: see Current Metrics.

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

### Pre-push checklist (mirrors the CI `test` job gate)

Run `npm run ci:local` before every push. It replays the exact PR gate from `.github/workflows/scan.yml` in order:
1. `node scripts/check-deps-typosquats.js` (loadash guard)
2. `node scripts/check-overrides.js` (npm `overrides`: documented in its REGISTRY, plain registry version only - no alias/URL/git/file -, locked, and still needed; fails with "remove it" once the parents admit a patched version)
3. `node scripts/check-no-tracked-node-modules.js`
4. `npm audit --audit-level=high` (needs network; advisories can appear between pushes without any code change)
5. `npm run docs:stats:check` (stats.json + doc markers vs source)
6. `npm run lint` (0 errors, stale `eslint-disable` directives are errors, `--max-warnings` ratchet: fix warnings and lower the number, never raise it)
7. `npm test`

The `coverage` CI job is blocking: `npm run test:coverage` runs c8 (locked devDependency) with the floors of `.c8rc.json`. Raise the floors when coverage rises, never lower them to pass.

**Version bump rule:** a version change must land in the SAME commit as ALL files rewritten by `npm run docs:stats` — `stats.json` plus every marker-bearing doc (`CLAUDE.md`, `README.md`, `SECURITY.md`, `ARCHITECTURE.md`, `docs/INDEX.md`, `docs/README.fr.md`, `docs/threat-model.md`). Committing a subset makes `docs:stats:check` fail in CI even when it passes locally, because the local working tree is coherent but the pushed tree is not. After any bump: `npm run docs:stats`, then `git add` everything it touched (`git diff --name-only` to list), then commit.

## Current Metrics (v<!--stat:version-->2.12.0<!--/stat:version-->; detection metrics last fully measured v2.11.48)

| Metric | Value |
|--------|-------|
| Version | **<!--stat:version-->2.12.0<!--/stat:version-->** |
| Tests | <!--stat:tests-->4545<!--/stat:tests--> non-skipped, across **<!--stat:testFiles-->167<!--/stat:testFiles-->** files. CI (Linux) is the reference: 0 failed. Local Windows runs on D: worktrees show environment-only failures (Defender quarantining `tests/samples/package/package.json`, git hooks, preload), never in CI. |
| Rules | **<!--stat:rulesTotal-->274<!--/stat:rulesTotal-->** (<!--stat:rulesCore-->269<!--/stat:rulesCore--> RULES + <!--stat:rulesParanoid-->5<!--/stat:rulesParanoid--> PARANOID). IDs: SECURITY.md; history: CHANGELOG.md. |
| Scanners | **<!--stat:scanners-->22<!--/stat:scanners--> parallel** (Promise.allSettled) + **2 pre-analysis** (module-graph/, deobfuscate) + **1 async parser bootstrap** (python-ast WASM init, no analysis emitted) + **7 conditional/post-processing** (paranoid, 3× temporal-*, reachability, phantom-gyp, native-drop-exec) + **1 metadata** (npm-registry). <!--stat:scannerFiles-->36<!--/stat:scannerFiles--> fichiers `src/scanner/*.js` + 3 dirs : `ast-detectors/` (<!--stat:astDetectors-->15<!--/stat:astDetectors-->), `module-graph/` (<!--stat:moduleGraph-->9<!--/stat:moduleGraph-->), `python-ast-detectors/` (<!--stat:pythonAstDetectors-->7<!--/stat:pythonAstDetectors--> fichiers). Détails : ARCHITECTURE.md. |
| Ground Truth size | **99 samples** in `tests/ground-truth/attacks.json` (npm + PyPI; 96 at the v2.11.48 measurement below). |
| TPR@3 (detection rate) | **95.74%** (90/94 in-scope), v2.11.48. Misses: browser-only patterns (lottie-player, polyfill-io, trojanized-jquery) + 1. |
| TPR@20 (alert rate) | **88.30%** (83/94 in-scope), v2.11.48. |
| FPR rules (curated, v2.11.48) | **1.10%** (6/545 scanned of 548 benign). The operational number (`muaddib scan`: rules + FP caps, no ML). The 6 FPs are real pattern hits (meteor, prisma, @prisma/client, drizzle-orm, scrypt, liquid), not whitelist artifacts. |
| FPR after ML T1 (v2.11.48, offline only) | **1.10%**, `muaddib evaluate` replay only. Not applied in production: scan never calls the classifier; monitor runs it LOG-ONLY since 2026-04-08 (model collapsed, pending retrain). |
| FPR random (v2.11.48) | **2.50%** (5/200 random npm packages) — unchanged. |
| FPR PyPI (v2.11.48) | **9.68%** (12/124 scanned of 132; 8 giant packages failed to download). Most of these FPs came from the MT-1 35 ceiling, closed since (CHANGELOG, Track E). Refresh only from a full `muaddib evaluate`. |
| ADR | **96.26%** (103/107 available adversarial + holdout) — v2.11.48, stable. |
| Operational coverage | Not the static GT. `coverage-audit.js` (daily) joins the GHSA malware feed with the scan ledger and archive for a GHSA-denominated operational TPR; `alertRate` is throughput, not TPR. |

**Known issues:**
- **plotly OOM**: `muaddib scan` on plotly 6.7.0 hits the 4 GB Node heap (scannable at v2.11.48). Memory regression on giant JS bundles, independent of scoring.
- **Defensive IOC catalogs in `dist/`** (@hasna/shield 37 -> 100): a security tool shipping an IOC catalog in its executed `dist/` files is structurally indistinguishable from a real IOC hidden among decoys. Accepted known FP (CHANGELOG, hash/string IOC blind-spot fix).
- **RC-H1** (reachability fail-open on `fork(path.resolve(__dirname, ...))`): the fail-closed fix exposes 8 benign agent/CLI tools at >= 75 (detached browser open, loopback servers, MCP self-registration). Not shippable until those rules are more precise.

Resolved items and their history: CHANGELOG.md.

## Interdictions

- **Pas de whitelist FP** : ne jamais ajouter de whitelist de packages benins pour reduire artificiellement le FPR
- **Pas de suppression de detection** : ne jamais supprimer une regle existante sans justification par un FP documente
- **Pas d'embellissement des metriques** : TPR/FPR/ADR doivent refleter la realite mesuree, jamais etre ajustes manuellement
- **Pas de per-sample thresholds** : ADR utilise un seuil global (score >= 20), pas de seuils par echantillon
- **Pas de regression silencieuse** : tout changement doit passer `npm test` avec 0 echec
- **Jamais `loadash` en dépendance** : `loadash` est un typosquat connu de `lodash`. Le projet n'utilise NI `lodash` NI `loadash` (zéro `require` dans `src/`/`bin/`). Toute occurrence de `loadash` dans `dependencies`/`devDependencies` de `package.json` est un BUG de supply-chain — ne jamais l'ajouter, l'installer, ni le restaurer en réécrivant `package.json` depuis un état périmé. Les `loadash` dans `tests/`, `data/`, IOCs sont des **données de test légitimes** (chaînes, pas des deps) : ne pas y toucher. Gate au niveau PR : `scripts/check-deps-typosquats.js` (job `test` de `.github/workflows/scan.yml`) fait échouer le CI si `loadash` réapparaît dans les deps.
