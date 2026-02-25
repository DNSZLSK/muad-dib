# FPR Diagnostic: Remaining 47 False Positives (pre-P2/P3)

**Date:** 2026-02-25
**Version:** v2.2.28 (pre-P2/P3 baseline)
**FPR at time of analysis:** 8.9% (47/527 benign packages flagged at threshold >= 20)
**Goal:** Identify high-impact rule fixes to push FPR below 6% (~31 FPs max)

> **Post-P2/P3 status (v2.3.1):** FPR reduced to **7.4% (39/525)**. Fixes P1+P2+P3 from Section 5 were implemented. See CHANGELOG.md and EVALUATION_METHODOLOGY.md for details.

---

## 1. Score Distribution

| Score Band | Count | Packages |
|-----------|-------|----------|
| 20-25     | 8     | webpack-dev-server, esbuild, mini-css-extract-plugin, storybook, prettier, fastify, mocha, zod |
| 26-35     | 14    | moment, bluebird, eslint-plugin-import, release-it, postcss-loader, typeorm, aws-sdk, dotenv, puppeteer-core, oxlint, moleculer, eslint, vercel, kue, sass-loader |
| 36-50     | 11    | @prisma/client, mathjs, iconv-lite, nunjucks, art-template, @vue/compiler-sfc, msw, svelte, @babel/core, xlsx, yarn |
| 51-75     | 10    | undici, superagent, webpack, npm, typescript, mailgun.js, pnpm, vite, esbuild(dup removed), total.js |
| 76-100    | 4     | pm2, keystone, playwright, total.js |

8 packages are marginal (score 20-25) and easiest to fix.

---

## 2. Package Detail Table

| # | Package | Score | Threats | Top 3 Rules (points) |
|---|---------|-------|---------|---------------------|
| 1 | keystone | 100 | 58 | env_access(170), suspicious_dataflow(85), dynamic_require(41) |
| 2 | total.js | 100 | 27 | dangerous_call_eval(31), require_cache_poison(25), zlib_inflate_eval(25) |
| 3 | playwright | 100 | 42 | dynamic_require(71), suspicious_dataflow(61), obfuscation_detected(50) |
| 4 | pm2 | 80 | 37 | env_access(130), dynamic_require(42), suspicious_dataflow(30) |
| 5 | npm | 72 | 17 | high_entropy_string(59), dynamic_require(11), env_access(4) |
| 6 | vite | 71 | 21 | module_compile(10), module_compile_dynamic(10), reverse_shell(10) |
| 7 | pnpm | 62 | 18 | suspicious_dataflow(11), reverse_shell(10), staged_payload(10) |
| 8 | typescript | 58 | 10 | obfuscation_detected(50), env_charcode_reconstruction(20), dynamic_require(20) |
| 9 | mailgun.js | 57 | 27 | suspicious_dataflow(50), env_charcode_reconstruction(20), env_harvesting_dynamic(20) |
| 10 | webpack | 53 | 17 | dynamic_require(30), known_malicious_package(25), require_cache_poison(25) |
| 11 | undici | 53 | 12 | prototype_hook(90), js_obfuscation_pattern(20), lifecycle_script(3) |
| 12 | superagent | 53 | 78 | prototype_hook(181), suspicious_dataflow(25), env_access(10) |
| 13 | xlsx | 52 | 18 | obfuscation_detected(51), high_entropy_string(45) |
| 14 | yarn | 51 | 51 | prototype_hook(28), env_access(5), lifecycle_script(3) |
| 15 | @babel/core | 50 | 3 | module_compile(25), module_compile_dynamic(25), dynamic_import(10) |
| 16 | art-template | 50 | 7 | module_compile(25), module_compile_dynamic(25), dangerous_call_function(5) |
| 17 | svelte | 48 | 5 | obfuscation_detected(25), high_entropy_string(23), dynamic_import(10) |
| 18 | nx | 48 | 62 | env_access(155), suspicious_dataflow(50), require_cache_poison(25) |
| 19 | msw | 46 | 15 | prototype_hook(42), suspicious_dataflow(21), node_inline_exec(10) |
| 20 | dotenv | 45 | 4 | suspicious_dataflow(25), env_access(20), crypto_decipher(10) |
| 21 | @vue/compiler-sfc | 44 | 8 | module_compile(10), module_compile_dynamic(10), require_cache_poison(10) |
| 22 | nunjucks | 40 | 17 | module_compile(51), dangerous_call_eval(13), dangerous_call_function(9) |
| 23 | iconv-lite | 40 | 6 | high_entropy_string(53) |
| 24 | @prisma/client | 36 | 25 | js_obfuscation_pattern(20), env_charcode_reconstruction(10), dynamic_require(10) |
| 25 | mathjs | 36 | 60 | module_compile(389), module_compile_dynamic(29), obfuscation_detected(11) |
| 26 | moleculer | 35 | 15 | suspicious_dataflow(55), require_cache_poison(50), env_access(26) |
| 27 | eslint | 35 | 5 | dynamic_import(30), require_cache_poison(25), suspicious_dataflow(10) |
| 28 | vercel | 35 | 51 | known_malicious_package(25), env_access(13), suspicious_dataflow(10) |
| 29 | kue | 35 | 3 | staged_payload(25), dangerous_call_eval(10), dangerous_call_function(1) |
| 30 | oxlint | 34 | 15 | module_compile(10), module_compile_dynamic(10), dynamic_import(4) |
| 31 | sass-loader | 31 | 3 | known_malicious_package(25), lifecycle_script(3), dynamic_require(3) |
| 32 | puppeteer-core | 31 | 11 | suspicious_dataflow(26), env_access(12), dangerous_call_function(6) |
| 33 | aws-sdk | 29 | 35 | env_access(48), credential_tampering(25), suspicious_dataflow(13) |
| 34 | eslint-plugin-import | 28 | 2 | suspicious_dataflow(25), env_access(3) |
| 35 | release-it | 28 | 8 | suspicious_dataflow(26), dynamic_import(10), env_access(9) |
| 36 | postcss-loader | 27 | 5 | module_compile(10), module_compile_dynamic(10), lifecycle_script(3) |
| 37 | typeorm | 26 | 17 | dynamic_require(55), env_access(8), lifecycle_script(3) |
| 38 | moment | 26 | 3 | known_malicious_package(25), dynamic_require(2) |
| 39 | bluebird | 26 | 16 | dangerous_call_eval(21), suspicious_dataflow(21), dangerous_call_function(13) |
| 40 | fastify | 25 | 3 | require_cache_poison(25), suspicious_dataflow(10), curl_exfiltration(1) |
| 41 | mocha | 25 | 11 | dynamic_require(60), require_cache_poison(50), dynamic_import(10) |
| 42 | zod | 25 | 4 | obfuscation_detected(26), high_entropy_string(4) |
| 43 | storybook | 24 | 32 | suspicious_dataflow(22), dynamic_import(12), dangerous_call_function(10) |
| 44 | prettier | 24 | 39 | high_entropy_string(36), obfuscation_detected(23), dynamic_import(12) |
| 45 | webpack-dev-server | 23 | 6 | dynamic_require(10), suspicious_dataflow(10), lifecycle_script(3) |
| 46 | esbuild | 23 | 4 | suspicious_dataflow(20), dynamic_require(10), lifecycle_script(3) |
| 47 | mini-css-extract-plugin | 23 | 3 | module_compile(10), module_compile_dynamic(10), lifecycle_script(3) |

---

## 3. Rule Impact Analysis

### By total points contributed across all 47 FPs

| Rank | Rule | Hits | Points | Pkgs Affected | Severity Distribution |
|------|------|------|--------|--------------|----------------------|
| 1 | env_access | 157 | 719 | 26 | HIGH:50, MEDIUM:56, LOW:51 |
| 2 | suspicious_dataflow | 78 | 683 | 29 | CRITICAL:15, HIGH:27, LOW:35, MEDIUM:1 |
| 3 | module_compile | 43 | 577 | 13 | CRITICAL:20, HIGH:6, LOW:17 |
| 4 | dynamic_require | 81 | 442 | 23 | HIGH:39, LOW:37, MEDIUM:5 |
| 5 | prototype_hook | 128 | 353 | 5 | HIGH:13, MEDIUM:54, LOW:61 |
| 6 | high_entropy_string | 80 | 294 | 12 | HIGH:12, MEDIUM:53, LOW:15 |
| 7 | require_cache_poison | 13 | 286 | 11 | CRITICAL:11, HIGH:1, LOW:1 |
| 8 | obfuscation_detected | 47 | 257 | 15 | CRITICAL:8, HIGH:2, LOW:37 |
| 9 | module_compile_dynamic | 40 | 166 | 12 | CRITICAL:3, HIGH:6, LOW:31 |
| 10 | dynamic_import | 26 | 139 | 13 | HIGH:11, LOW:8, MEDIUM:7 |

### Single-rule elimination potential (if fully suppressed, how many FPs drop below 20?)

| Rule | FPs Eliminated | Notes |
|------|---------------|-------|
| suspicious_dataflow | **7** | Top single-rule fix |
| module_compile | 4 | Template engines, compilers, bundlers |
| dynamic_require | 3 | Test runners, module loaders |
| known_malicious_package | 3 | IOC false matches (see Section 5) |
| prototype_hook | 2 | undici, superagent |
| high_entropy_string | 2 | iconv-lite, npm |
| require_cache_poison | 2 | fastify, mocha |
| module_compile_dynamic | 2 | Overlaps with module_compile |

---

## 4. Pattern Deep Dives

### 4.1 suspicious_dataflow (29 pkgs, 7 eliminations)

The #1 FP contributor. The dataflow scanner flags when a "credential source" reaches a "network sink" in the same file.

**Problem patterns:**

1. **os.* telemetry sources treated as credentials** (14 hits across 10 pkgs):
   - `os.platform`, `os.arch`, `os.cpus`, `os.hostname`, `os.networkInterfaces` are flagged as credential reads
   - Legitimate use: esbuild downloads platform-specific binary, webpack-dev-server discovers network interfaces, eslint reports platform info
   - **Fix:** Exclude `os.platform`, `os.arch`, `os.cpus`, `os.totalmem` from credential sources (they are system telemetry, not credentials)

2. **process.env[dynamic] is a catch-all** (118 hits):
   - When the env var name is computed dynamically (`process.env[varName]`), the scanner can't distinguish safe config reads from credential access
   - Legitimate use: config loading (dotenv, @prisma/client), CI detection (storybook, nx)
   - Harder to fix without losing TP coverage

3. **npm_* env vars flagged** (e.g., `npm_config_user_agent`, `npm_config_registry`, `npm_command`):
   - Already in SAFE_ENV_PREFIXES but still flagged via dataflow
   - **Fix:** Ensure dataflow scanner respects SAFE_ENV_PREFIXES

4. **`get` sink is too broad** (3454 hits):
   - The `get` sink includes `http.get`, `https.get`, but likely also matches benign `.get()` calls on Maps, objects, and HTTP router methods
   - **Fix:** Tighten `get` sink to require http/https/fetch context

**Recommended priority fixes:**
- (a) Remove `os.platform`, `os.arch`, `os.cpus`, `os.totalmem` from credential sources -> eliminates ~14 safe-source dataflow hits
- (b) Demote `os.hostname`, `os.networkInterfaces` to LOW severity (they are machine identifiers, not secrets)
- (c) Downgrade dataflow findings where ALL sources are os.* or npm_* to LOW severity

### 4.2 module_compile / module_compile_dynamic (13/12 pkgs, 4+2 eliminations)

Flags `module._compile()` and dynamic `new Module()` patterns. These always appear together.

**Legitimate uses:**
- **Template engines:** nunjucks, art-template (compile templates to JS at runtime)
- **Compilers/transpilers:** @babel/core, @vue/compiler-sfc, playwright (Babel transform)
- **Bundlers:** vite, mini-css-extract-plugin, postcss-loader, storybook, webpack
- **Math engines:** mathjs (compiles expression nodes — 28 files flagged!)

**Observation:** module_compile is almost always used by packages that ARE compilers/transpilers/template engines. The pattern `module._compile(code, filename)` is standard Node.js for loading transformed source.

**Recommended fixes:**
- (a) Apply count-based downgrade: >3 `module_compile` hits in same package -> LOW (pattern matches mathjs, nunjucks, mathjs has 14 CRITICAL hits)
- (b) Downgrade module_compile in `dist/`, `lib/cjs/`, `lib/esm/` paths to LOW (bundled output, not hand-written attack code)

### 4.3 known_malicious_package (4 pkgs, 3 eliminations)

These flag **dependencies** of benign packages that appear in the IOC database.

| Package | Flagged Dependency | Source | Legit? |
|---------|--------------------|--------|--------|
| webpack | es5-ext@^0.10.53 | socket-dev | Disputed: es5-ext had protest-ware, but ^0.10.53 may include fixed version |
| sass-loader | bootstrap-sass@^3.4.1 | npm-removed | bootstrap-sass was deprecated, not malicious; npm-removed != malicious |
| vercel | @vercel-internals/constants@1.0.4 | IOC | Internal Vercel package, likely IOC false match on scoped package name |
| moment | typescript3@npm:typescript@^3.1.6 | IOC | npm alias for typescript; IOC likely flagging the alias name |

**Root cause:** The dependency scanner matches dependency names against the IOC database, but IOC entries can include protest-ware, deprecated packages, and alias names that are not truly malicious.

**Recommended fixes:**
- (a) Add `es5-ext`, `bootstrap-sass` to dep-scanner whitelist (protest-ware/deprecated, not actual malware)
- (b) Skip npm alias syntax (`pkg@npm:real-name@version`) — the alias name is not a real package
- (c) Skip `@vercel-internals/*` or add to internal scope whitelist
- (d) Alternatively: downgrade `known_malicious_package` from CRITICAL to HIGH when the dependency is an optional/dev dependency

### 4.4 require_cache_poison (11 pkgs, 2 eliminations)

Flags `require.cache` access. Legitimate uses:
- **fastify:** Plugin system uses `require.cache` to detect duplicate plugin loading
- **mocha:** File-unloader removes test files from cache between runs
- **moleculer:** Hot-reload middleware invalidates cache on file changes
- **eslint, webpack, @vue/compiler-sfc:** Module resolution cache management

**Recommended fix:** Apply count-based downgrade (already exists for >3, but CRITICAL->LOW is too harsh for 1-2 hits). Consider: single `require.cache` access in a plugin/loader/test-runner context -> HIGH instead of CRITICAL.

### 4.5 prototype_hook (5 pkgs, 2 eliminations)

Massive hit count (128) but only in 5 packages:
- **superagent** (78 threats, 181 pts): HTTP client that patches `.get`, `.post`, `.put` methods
- **undici** (90 pts): Node.js HTTP client, patches fetch/Request/Response prototypes
- **msw** (42 pts): Mock Service Worker, intercepts HTTP by hooking prototypes
- **yarn** (28 pts): Package manager, uses prototype extensions

These are all HTTP-related packages that legitimately extend prototypes as their core functionality.

**Recommended fix:** Expand the "framework prototype hook" FP reduction to cover HTTP client libraries (superagent, undici, msw). Current FP reduction only applies to Request/Response/App/Router prototypes but misses direct method patching patterns.

### 4.6 high_entropy_string (12 pkgs, 2 eliminations)

- **iconv-lite** (53 pts): Character encoding tables (legitimate high-entropy data)
- **npm** (59 pts): Bundled certificates/hashes
- **prettier, svelte, xlsx**: Bundled parser tables, Unicode data

**Recommended fix:** Skip entropy checks in files matching `**/encoding*`, `**/tables*`, `**/unicode*` patterns. Or apply existing dist/bundle downgrade more aggressively.

### 4.7 obfuscation_detected (15 pkgs)

Not a top eliminator on its own but contributes points in many packages. Main offenders:
- **prettier** (26 LOW hits): All plugin files flagged as "obfuscated" — they're minified bundles
- **zod** (25+1 pts): v3/types.cjs flagged CRITICAL
- **typescript** (50 pts): Bundled output flagged

**Already handled:** dist/build/*.bundle.js -> LOW. But `.cjs`, `.mjs`, and named bundles (types.cjs, index.mjs) are not matched.

**Recommended fix:** Extend bundle detection to `.cjs` and `.mjs` files that are over 100KB (clearly bundled output).

---

## 5. Recommended Fix Priority

Ranked by FP elimination impact and implementation difficulty:

| Priority | Fix | FPs Eliminated | Difficulty | Details |
|----------|-----|---------------|------------|---------|
| **P1** | Dataflow: exclude os.platform/arch/cpus/totalmem from credential sources | ~3-4 | Low | Simple list exclusion in dataflow scanner |
| **P1** | Dataflow: downgrade findings where ALL sources are os.*/npm_* to LOW | ~4-5 | Low | Post-processing severity rule |
| **P2** | known_malicious_package: whitelist es5-ext, bootstrap-sass; skip npm aliases | **3** | Low | Add to dep whitelist, regex for `@npm:` |
| **P2** | module_compile: count-based downgrade (>3 hits -> LOW) | ~3-4 | Low | Extend existing FP reduction pattern |
| **P2** | module_compile: downgrade in dist/lib paths | ~2-3 | Low | Path-based severity reduction |
| **P3** | require_cache_poison: downgrade single occurrence from CRITICAL to HIGH | ~2 | Low | Threshold adjustment |
| **P3** | prototype_hook: expand HTTP client whitelist | ~2 | Medium | Need to identify prototype target patterns |
| **P3** | obfuscation: extend bundle detection to .cjs/.mjs > 100KB | ~1-2 | Low | File extension + size check |
| **P4** | high_entropy: skip encoding table files | ~1-2 | Low | Filename pattern exclusion |
| **P4** | Dataflow: tighten `get` sink to http context | ~2-3 | High | Requires AST context analysis |

### Projected Impact

**Conservative (P1+P2 only):** Eliminate ~12-15 FPs -> FPR ~6.1-6.6% (32-35/527)
**Moderate (P1+P2+P3):** Eliminate ~16-20 FPs -> FPR ~5.1-5.9% (27-31/527)
**Aggressive (all P1-P4):** Eliminate ~20-25 FPs -> FPR ~4.2-5.1% (22-27/527)

---

## 6. Best Rule Combos (Elimination Analysis)

If we could fully suppress a combination of rules, how many FPs would drop below threshold?

### Best pairs:
| Combo | FPs Eliminated |
|-------|---------------|
| suspicious_dataflow + module_compile | **12** |
| suspicious_dataflow + module_compile_dynamic | 10 |
| suspicious_dataflow + known_malicious_package | 10 |
| suspicious_dataflow + prototype_hook | 10 |
| suspicious_dataflow + dynamic_require | 9 |
| suspicious_dataflow + require_cache_poison | 9 |
| suspicious_dataflow + high_entropy_string | 9 |

### Best triples:
| Combo | FPs Eliminated |
|-------|---------------|
| suspicious_dataflow + module_compile + known_malicious_package | **15** |
| suspicious_dataflow + module_compile + module_compile_dynamic | 15 |
| suspicious_dataflow + module_compile + dynamic_require | 14 |
| suspicious_dataflow + module_compile + require_cache_poison | 14 |
| suspicious_dataflow + module_compile + high_entropy_string | 14 |
| suspicious_dataflow + known_malicious_package + require_cache_poison | 13 |

**Key insight:** `suspicious_dataflow` is the single most impactful rule to improve. Every top combo includes it. Combined with `module_compile` fixes, we can eliminate 12+ FPs (25% of all FPs) with just two targeted rule improvements.

---

## 7. Methodology Notes

- Data source: `metrics/v2.2.28.json` (2026-02-24, 527 scanned, 2 skipped)
- Threshold: score >= 20 = flagged (consistent with `BENIGN_THRESHOLD` in evaluate.js)
- Scoring: per-file max model (`riskScore = min(100, max(file_scores) + package_level_score)`)
- Severity weights: CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1
- Elimination analysis: simulates removing all threats of a given type and recomputing per-file max score
- "FPs eliminated" = packages that drop from score >= 20 to score < 20 after rule removal
