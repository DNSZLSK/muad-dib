# FPR measurement — dependency_typosquat & lifecycle_script (2026-06-14)

**Goal:** size the two top live FP drivers (`dependency_typosquat` 2108 live fires, `lifecycle_script` 2043 — the #1/#2 `topFiringRules` in `muaddib fpr-live`) by *measured* blind adjudication, and propose a scoped fix. Measurement chantier — **no source changes**.

## Method
Blind adjudication: read the flagged package's actual code from the archived tarball (`archive/2026-06-14/`), judge TP/FP/UNCERTAIN on sink-coupling + legitimacy, **do not trust the scanner's own label** (circular). Two sources combined:
- **Reused** the prior blind baseline `audit-data/fpr-baseline-2026-06-14.json` (105 pkgs, same method), filtered by `flagged_rules`.
- **Fresh supplement** for typosquat (under-sampled in the baseline): 40 distinct-name, stratified-random, tarball-archived packages (excluding baseline names), adjudicated blind by 3 independent reviewers.

## Results

| Rule | n | FP | TP | UNC | **FP rate** | sampling |
|---|---|---|---|---|---|---|
| **dependency_typosquat** | 61 | 61 | 0 | 0 | **100%** | 21 baseline + 40 fresh; cluster 337 → 18% sampled |
| **lifecycle_script** | 71 | 68 | 2 | 1 | **95.8%** | baseline; cluster 403 → 18% sampled |

Both are overwhelmingly false. The 2 lifecycle TPs (`chalk-plus-js`, `ecto-corsair-whisper`) are real malware that fire `lifecycle_script` **only alongside** independent exfil/exec signals (`detached_process`, `silent_stealth_process`, `direct_ip_exfil`, `lifecycle_file_exec`) — never on the lifecycle hook alone.

## Root cause — dependency_typosquat (the bigger, more precise finding)

The driver is **MUADDIB-TYPO-002 "dependency boundary-squat"** (`src/scanner/typosquat.js:437` `boundaryMatch`, called at `:381`). It flags a *declared dependency* whose name **contains a popular package name as a hyphen-token** (`<prefix>-<popular>` / `<popular>-<suffix>`). The **only** way out is the curated `LEGIT_BOUNDARY_TOKENS` allowlist (`:58`) or an *exact* popular match (`:451`) — there is **no check that the full compound dep is itself an established package**, even though `getPackageMetadata` is already imported (`:9`).

Every "squat" in the 40-pkg sample is a legit, popular npm package matched on a substring:
`class-validator`⊃validator · `date-fns-tz`⊃date-fns · `sinon-chai`⊃chai · `swagger-ui-express`⊃express · `openapi-typescript`/`tree-sitter-typescript`/`json-schema-to-typescript`⊃typescript · `aws-sdk-client-mock`⊃aws-sdk · `ansi-colors`⊃colors · `graphile-config`⊃config · `core-js-compat`⊃core-js · `react-helmet-async`⊃async · `short-uuid`⊃uuid · `lite-request`⊃request · `agent-commander`⊃commander · `react-router-redux`⊃redux.

Host packages were all real, well-resourced projects: **Backstage, GoodData, Salesforce CLI, Nrwl `nx` (the canonical package, self-flagged at 75), News UK times-components, Graphile, Tinkoff/Tramvai, KudoAI chatgpt.js, WatermelonDB OpenHarmony port**. Two CRITICAL multipliers worsen it:
- **COMPOUND-014** (`boundary-squat + lifecycle hook`) → fires on ordinary `prepare`/`prepack`/`husky`/`svelte-kit sync` build hooks.
- **COMPOUND-015** (`boundary-squat + dep is require()d`) → fires trivially on legitimate usage.

The high scores (72–100: `the-bodyguard`, `opticore-asymmetric-cryption`, `aws-lambda-api-tools`, `graphile-worker`) are **not** driven by the typosquat axis — they come from unrelated heuristics on bundled/minified build artifacts (esbuild'd AWS-SDK blobs, proto-pollution / `new Function` on minified bins) plus the compound escalation. So TYPO-002 is also acting as a force-multiplier into CRITICAL compounds. (FP-shape breakdown: ~all `boundary-squat-on-legit-dep`; subset `canonical-pkg-self-flagged` (nx/backstage/salesforce/chatgpt.js/graphile-worker), `boundary-squat-sibling` (`@react-native-oh-tpl/*` tpl forks).)

## Root cause — lifecycle_script

`lifecycle_script` fires on the *presence* of any lifecycle hook. 95.8% FP because the overwhelming majority are benign dev/build hooks (`husky`, `prepack` tsc build, `prepare: npm run build`, banner scripts, `npm -v` checks) with zero install-time remote fetch. It is a TP **only** in coincidence with a real exfil/exec sink — exactly the shape the `credential_regex_harvest` sink-coupling gate (PR #571) already handles for another rule.

## Leverage (live volume × measured FP rate)
- typosquat: ~2108 fires × ~100% ≈ **2108 false alerts**
- lifecycle_script: ~2043 fires × ~95.8% ≈ **1957 false alerts**
- Combined ≈ **4000 false alerts** — the bulk of the operational alert load (`alertRate` ~13–17%).

## Scoped fix proposals (input for a possible chantier 4)

1. **TYPO-002 boundary-squat — popularity/registry gate (highest leverage, precise).** In `boundaryMatch()` (`typosquat.js:~451`), before flagging `<token>-<popular>`, confirm the **full compound dep is not itself an established package**: check it against an offline popular/known list first (no network), and/or `getPackageMetadata` (already imported) for registry presence + maturity. Also tighten COMPOUND-014/015 to require a *confirmed* squat, not co-occurrence with a benign hook / require(). FN risk: a real squat that looks established (rare; a registry-age/downloads floor mitigates). Network risk: gate on the cached popular-list path, treat registry-metadata as best-effort (respect the 429 backoff lessons). **Expected: removes the large majority of 2108 fires.**

2. **lifecycle_script — sink-coupling gate (mirror PR #571).** Downgrade `lifecycle_script` HIGH/MEDIUM → LOW unless it co-occurs with a real exfil/exec sink (the same `EXFIL_SINK_TYPES` set used for `credential_regex_harvest`). The 2 TPs stay flagged (they carry `detached_process`/`direct_ip_exfil`/`lifecycle_file_exec`). **Expected: removes ~1957 false alerts; reuses an established, validated pattern.**

## Recommendation
**TYPO-002 boundary-squat popularity-gate is the single highest-leverage FPR fix currently available** — ~2108 false alerts, a precisely-located mechanism (`typosquat.js:437/451`), and a fix the codebase is already plumbed for (`getPackageMetadata`). The lifecycle_script sink-coupling gate is the natural #2 (reuses PR #571's pattern). Either is a clean chantier 4. Adjudication sample: `/tmp/fpr-adj/typosquat-supp.json` (+ the 3 reviewer verdict sets); 40/40 FP, all the boundary-squat-on-legit-dep class.
