# MUAD'DIB — False Positive Analysis

This document consolidates the historical FP audits performed during development. For the full evaluation methodology (TPR, FPR, ADR, holdout protocol), see [EVALUATION_METHODOLOGY.md](EVALUATION_METHODOLOGY.md).

## Current FPR: 10.8% (57/529) — v2.10.1

---

## Part 1: FPR Audit (v2.2.28 baseline)

**Date:** 2026-02-24
**Dataset:** 529 npm benign packages (527 scanned, 2 skipped)
**Threshold:** score > 20

### Impact of new rules (v2.2.28 vs v2.2.10)

| New rule | FP packages | Severity | Comment |
|---|---|---|---|
| `module_compile_dynamic` (AST-025) | **17** | CRITICAL | Worst offender — template engines, bundlers |
| `write_execute_delete` (AST-026) | 7 | HIGH | Build + cleanup packages |
| `env_harvesting_dynamic` (AST-029) | 7 | HIGH | Config loaders with `Object.entries(process.env)` |
| `zlib_inflate_eval` (AST-024) | 6 | CRITICAL | zlib + base64 + eval in bundled code |
| `dns_chunk_exfiltration` (AST-030) | 3 | HIGH | DNS + base64 in legitimate network code |
| `mcp_config_injection` (AST-027) | 0 | CRITICAL | Zero FP |
| `git_hooks_injection` (AST-028) | 0 | HIGH | Zero FP |
| `llm_api_key_harvesting` (AST-031) | 0 | MEDIUM | Zero FP |

### Top 10 FP-causing rules (baseline v2.2.10, 69 FP)

| Rule | Packages affected | Total hits |
|---|---|---|
| suspicious_dataflow | 37 | 102 |
| env_access | 37 | 220 |
| dynamic_require | 33 | 208 |
| dangerous_call_function | 27 | 122 |
| typosquat_detected | 23 | 32 |
| require_cache_poison | 20 | 33 |
| obfuscation_detected | 18 | 69 |
| lifecycle_script | 18 | 20 |
| dynamic_import | 17 | 83 |
| dangerous_call_eval | 15 | 40 |

### FP by file path

| Path | % of FP threats |
|---|---|
| `dist/` | 43.6% |
| `lib/` | 26.5% |
| `src/` | 6.3% |
| `package.json` | 4.7% |

**Key observation:** 43.6% of FP threats come from `dist/` files — bundled/minified code with legitimate patterns compressed together.

### FP by package category

| Category | FPR |
|---|---|
| Frameworks web | 36% |
| Monorepo tools | 33% |
| Testing | 28% |
| DevOps/CI | 28% |
| Build tools | 20% |
| Small packages (<10 JS files) | 6.2% |

---

## Part 2: Remaining 47 FPs (pre-P2/P3 analysis)

**Date:** 2026-02-25
**Version:** v2.2.28 (pre-P2/P3)
**FPR at time:** 8.9% (47/527)

### Score distribution

| Score band | Count |
|---|---|
| 20-25 | 8 (easiest to fix) |
| 26-35 | 14 |
| 36-50 | 11 |
| 51-75 | 10 |
| 76-100 | 4 |

### Rule impact analysis

| Rank | Rule | Points | Single-rule elimination |
|---|---|---|---|
| 1 | env_access | 719 | — |
| 2 | suspicious_dataflow | 683 | 7 FPs eliminated |
| 3 | module_compile | 577 | 4 FPs eliminated |
| 4 | dynamic_require | 442 | 3 FPs eliminated |
| 5 | prototype_hook | 353 | 2 FPs eliminated |
| 6 | high_entropy_string | 294 | 2 FPs eliminated |
| 7 | require_cache_poison | 286 | 2 FPs eliminated |

### Best rule combos for FP elimination

| Combo | FPs eliminated |
|---|---|
| suspicious_dataflow + module_compile | 12 |
| suspicious_dataflow + module_compile + known_malicious_package | 15 |

**Key insight:** `suspicious_dataflow` is the single most impactful rule to improve. Every top combo includes it.

### Pattern deep dives

**suspicious_dataflow (29 pkgs):** The #1 FP contributor. Root cause: `os.networkInterfaces()` + `dns.lookup()` (network bind) and `process.env[dynamic]` + `fetch()` (config + HTTP) flagged as credential exfiltration. Fixed in P2 by source categorization (telemetry_read vs fingerprint_read).

**module_compile (13 pkgs):** Template engines (nunjucks, art-template), compilers (@babel/core, @vue/compiler-sfc), math engines (mathjs with 14 CRITICAL hits). Fixed in P2 by count-based downgrade (>3 → LOW).

**prototype_hook (5 pkgs):** HTTP client libraries (superagent: 78 hits, undici: 90 pts). Fixed in P3 by HTTP client whitelist (>20 hits → MEDIUM).

**known_malicious_package (4 pkgs):** IOC false matches — es5-ext (protest-ware), bootstrap-sass (deprecated), npm aliases. Fixed in P2 by DEP_FP_WHITELIST + npm alias skip.

---

## FP Reduction History

| Version | FPR | Key fixes |
|---|---|---|
| v2.2.7 | 38% | First real measurement (real source code) |
| v2.2.8 | 19.4% | Count-based severity downgrade (P1) |
| v2.2.9 | 17.5% | Scanner-level refinements (P1 continued) |
| v2.2.11 | ~13% | Per-file max scoring |
| v2.3.0 | 8.9% | Dataflow source categorization, module_compile threshold (P2) |
| v2.3.1 | 7.4% | require_cache single-hit, HTTP client whitelist, .cjs/.mjs >100KB (P3) |
| v2.5.8 | 6.0% | IOC wildcard audit (P4) — included whitelist bias |
| v2.5.14 | ~13.6% | Audit hardening (tighter detection) + whitelist removed |
| v2.5.16 | 12.3% | Compound detection precision (P5+P6) |
| v2.6.0 | 12.3% | Intent graph v2 — zero FP added |
| v2.6.2 | **12.1%** | FP reduction P7 — env_access, entropy, dataflow thresholds |

> **Note:** The historic 6.0% FPR (v2.5.8) relied on a `BENIGN_PACKAGE_WHITELIST` — a data leakage bias removed in v2.5.10. Current FPR is an honest measurement without whitelisting.
