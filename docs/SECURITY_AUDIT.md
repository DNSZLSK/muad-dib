# MUAD'DIB Security Audit Report

**Date:** 2026-02-21
**Auditor:** AppSec Code Review (Claude)
**Scope:** Static scanners, sandbox, evaluation framework, bypass validation
**Version audited:** v2.2.12 (commit b4e27ce)

---

## Executive Summary

3 concrete bypass samples were created and validated against MUAD'DIB v2.2.12.
**All 3 score 0/100 (SAFE)** — well below the GT_THRESHOLD of 3.

Each sample implements a realistic credential stealer that reads SSH keys, AWS
credentials, and npm tokens, then exfiltrates them over HTTPS. These are not
contrived edge cases — they represent techniques observed in real supply chain
attacks (event-stream, ua-parser-js, Shai-Hulud).

| Sample | Score | Technique | Attacker Effort |
|--------|-------|-----------|-----------------|
| bypass-01-indirect-eval | **0/100** | Computed eval + SAFE_STRINGS | LOW |
| bypass-02-muaddib-ignore | **0/100** | muaddib-ignore + string split | LOW |
| bypass-03-mjs-extension | **0/100** | .mjs file extension | LOW |

---

## Bypass 01: Indirect eval via computed property access

**File:** `tests/audit-bypass/bypass-01-indirect-eval/index.js`
**Score:** 0/100 SAFE
**Expected real severity:** CRITICAL (staged remote code execution)

### Attack Description

The sample builds the string `"eval"` via `Array.join()` and calls it through
a computed member expression: `globalThis[k](payload)`. The payload is fetched
from a URL that contains `api.github.com` to exploit the SAFE_STRINGS shortcut.

### Root Causes

1. **`getCallName()` blind to computed properties** (`src/utils.js:171-179`):
   Returns `node.callee.property.name` which is undefined for computed access
   (`node.callee.property` is a Literal, not an Identifier). Returns `''`.

2. **Array.join() not handled by deobfuscator** (`src/scanner/deobfuscate.js`):
   Only handles `String.fromCharCode`, `Buffer.from`, `atob`, and BinaryExpression
   string concat. `['e','v','a','l'].join('')` passes through unchanged.

3. **SAFE_STRINGS early return** (`src/scanner/ast.js:806-808`):
   ```javascript
   if (SAFE_STRINGS.some(s => node.value.includes(s))) {
     return; // ← skips ALL subsequent checks including SENSITIVE_STRINGS
   }
   ```
   A URL containing `api.github.com` with a `.ssh` path is entirely ignored.

4. **No dataflow source detected**: `https.get()` with a callback that calls
   `g[k](payload)` — the eval is not detected, so no staged_payload finding.

### Bypassed Rules

- MUADDIB-AST-003 (dangerous_call_eval)
- MUADDIB-AST-021 (staged_eval_decode)
- MUADDIB-AST-001 (sensitive_string — via SAFE_STRINGS bypass)
- MUADDIB-FLOW-001 (suspicious_dataflow)

---

## Bypass 02: muaddib-ignore + string construction

**File:** `tests/audit-bypass/bypass-02-muaddib-ignore/index.js`
**Score:** 0/100 SAFE
**Expected real severity:** CRITICAL (credential theft + exfiltration)

### Attack Description

The sample uses `// muaddib-ignore` on line 1 to skip the dataflow scanner, and
`//# sourceMappingURL=` on line 2 to skip the entropy scanner. Sensitive path
strings are constructed via concatenation (`dot + 'ss' + 'h'`) to avoid AST
SENSITIVE_STRINGS matching on individual literals.

### Root Causes

1. **`muaddib-ignore` is attacker-accessible** (`src/scanner/dataflow.js:33-35`):
   ```javascript
   if (headerLines.some(line => line.includes('muaddib-ignore'))) {
     continue; // ← entire file skipped
   }
   ```
   An attacker who controls file contents can add this directive.

2. **Source map bypass** (`src/scanner/entropy.js:228`):
   ```javascript
   if (hasSourceMap(content)) continue;
   ```
   A single `//# sourceMappingURL=` line kills all entropy analysis.

3. **String concat evades SENSITIVE_STRINGS** (`src/scanner/ast.js:804-819`):
   `SENSITIVE_STRINGS` check only applies to `Literal` nodes with `typeof value === 'string'`.
   If `.ssh` is constructed via `'.' + 'ss' + 'h'`, each individual literal
   (`'.'`, `'ss'`, `'h'`) does not match any sensitive string.

4. **Deobfuscator would fold the concat** — but the deobfuscated code is only
   re-analyzed by the AST scanner (not independently by dataflow, which was
   already skipped by muaddib-ignore).

### Bypassed Rules

- MUADDIB-FLOW-001 (suspicious_dataflow — muaddib-ignore)
- MUADDIB-AST-001 (sensitive_string — string split)
- MUADDIB-ENTROPY-001 (high_entropy_string — source map bypass)
- MUADDIB-ENTROPY-003 (js_obfuscation_pattern — source map bypass)

---

## Bypass 03: .mjs file extension

**File:** `tests/audit-bypass/bypass-03-mjs-extension/stealer.mjs`
**Score:** 0/100 SAFE
**Expected real severity:** CRITICAL (full credential stealer + eval)

### Attack Description

The entire malicious payload is in a `.mjs` file. The package.json has
`"type": "module"` making this a valid ESM package. The stealer reads SSH keys,
npm tokens, AWS credentials, environment variables, and exfiltrates them via
HTTPS POST. It also uses `eval()` with a base64-decoded payload.

### Root Cause

**All scanners only process `.js` files** — a single, systemic gap:

- `src/utils.js:147-149`: `findJsFiles()` → `findFiles(dir, { extensions: ['.js'] })`
- `src/scanner/ast.js:103`: `findJsFiles(targetPath)`
- `src/scanner/dataflow.js:11`: `findJsFiles(targetPath)`
- `src/scanner/obfuscation.js:11`: `findFiles(targetPath, { extensions: ['.js'] })`
- `src/scanner/entropy.js:206`: `findFiles(targetPath, { extensions: ['.js'] })`
- `src/scanner/module-graph.js:34`: `findFiles(packagePath, { extensions: ['.js'] })`

Files with extensions `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts` are
completely invisible to every scanner.

### Bypassed Rules

ALL rules — no scanner processes the file.

---

## Additional Findings (Code Review)

### F01: Canary tokens trivially detectable (P1)

**Files:** `src/canary-tokens.js:8-17`, `src/sandbox.js:41-48`

All canary tokens contain `MUADDIB_CANARY_` prefix. Both dynamic tokens
(`ghp_MUADDIB_CANARY_<suffix>`) and static tokens (`MUADDIB_CANARY_GITHUB_f8k3t0k3n`)
are trivially identifiable. Any malware that checks `if (value.includes('CANARY'))`
before exfiltrating will bypass all canary detection.

Additionally, the token formats are unrealistic:
- Real GitHub PAT: `ghp_[a-zA-Z0-9]{36}` — canary: `ghp_MUADDIB_CANARY_<hex16>`
- Real AWS key: `AKIA[A-Z0-9]{16}` — canary: `AKIA_MUADDIB_CANARY_<hex16>`

### F02: Sandbox strict mode expands attack surface (P2)

**File:** `src/sandbox.js:179-183`

Strict mode adds `SYS_PTRACE`, `NET_RAW`, and `NET_ADMIN` capabilities.
`SYS_PTRACE` allows tracing other processes in the container, and combined
with `NET_ADMIN` could potentially be used for container escape in certain
kernel versions. No custom seccomp profile restricts the available syscalls.

### F03: isDevFile excludes scannable attack paths (P2)

**File:** `src/utils.js:29-46`

`DEV_PATTERNS` excludes `bin/`, `scripts/`, `build/`, `fixtures/`, and
`examples/`. While `bin/` is the main entry point of many npm packages, and
`scripts/` often contains lifecycle hook targets. A malware placing its
payload in `bin/malware.js` or `scripts/postinstall.js` would be excluded
from AST and dataflow scanning.

### F04: Evaluation threshold methodology (P2)

**File:** `src/commands/evaluate.js`

- `GT_THRESHOLD = 3`: A single MEDIUM finding counts as "detected." This may
  overstate detection quality when the scanner finds an incidental signal but
  misses the actual attack payload.
- Adversarial thresholds are per-sample tuned post-hoc, including holdout
  samples. The `callback-exfil` and `event-emitter-flow` thresholds are 3,
  meaning essentially any incidental finding counts.
- `silentScan` swallows errors as score 0, potentially masking parse failures.

### F05: SAFE_STRINGS / SENSITIVE_STRINGS order (P1)

**File:** `src/scanner/ast.js:806-808`

The check order creates a bypass: any string containing both a SAFE_STRING
(`api.github.com`, `registry.npmjs.org`) and a SENSITIVE_STRING (`.ssh`,
`.npmrc`, `/etc/passwd`) is entirely ignored. This is exploitable as shown
in bypass-01.

---

## Recommendations (Prioritized)

### P0 — Immediate (blocks active bypass techniques)

| ID | Fix | Impact | Effort |
|----|-----|--------|--------|
| P0-1 | **Detect indirect eval/Function**: add computed property, SequenceExpression, and Reflect.apply checks in `ast.js` CallExpression handler | Closes bypass-01 | ~30 LOC |
| P0-2 | **Remove or gate `muaddib-ignore`**: delete the directive from `dataflow.js:33-35`, or make it CLI-opt-in (`--allow-ignore`) | Closes bypass-02 | ~5 LOC |
| P0-3 | **Scan .mjs/.cjs files**: change `findJsFiles` and all scanner `findFiles` calls to include `.mjs` and `.cjs` extensions | Closes bypass-03 | ~10 LOC |

### P1 — High Priority (hardens detection significantly)

| ID | Fix | Impact | Effort |
|----|-----|--------|--------|
| P1-1 | **Fix SAFE_STRINGS order**: check SENSITIVE_STRINGS first, then only suppress if the string ONLY contains safe domains (not mixed) | Closes SAFE_STRINGS poisoning vector | ~15 LOC |
| P1-2 | **Realistic canary tokens**: generate tokens matching real format (ghp_ + 36 alnum for GitHub, AKIA + 16 uppercase for AWS). Remove all MUADDIB/CANARY markers | Eliminates trivial canary detection | ~40 LOC |
| P1-3 | **Don't skip entropy for source map files**: remove the `hasSourceMap` early return, or only skip the source map data URL string itself | Closes sourcemap injection bypass | ~5 LOC |

### P2 — Medium Priority (defense in depth)

| ID | Fix | Impact | Effort |
|----|-----|--------|--------|
| P2-1 | **Expand dataflow sinks**: add `axios`, `got`, `node-fetch`, `undici`, `http2.connect`, `dgram.send` to sink detection | Reduces FN for modern HTTP libs | ~20 LOC |
| P2-2 | **Handle Array.join in deobfuscator**: detect `[...].join('')` and `[...].join('')` patterns and fold to string literal | Closes join-based evasion | ~40 LOC |
| P2-3 | **Add seccomp profile to sandbox**: create a custom seccomp.json restricting to ~50 needed syscalls | Reduces container escape surface | ~50 LOC JSON |
| P2-4 | **Re-evaluate isDevFile exclusions**: remove `bin/` and `scripts/` from DEV_PATTERNS, or only skip them in very large packages | Prevents payload hiding in bin/ | ~5 LOC |
| P2-5 | **Expand sandbox evasion detection**: add checks for `DOCKER_HOST`, `KUBERNETES_SERVICE_HOST`, `/proc/version`, `os.cpus().length` | Catches more anti-analysis | ~20 LOC |

---

## Test Validation Summary

All scans run on 2026-02-21 against MUAD'DIB v2.2.12.

```
$ node bin/muaddib.js scan tests/audit-bypass/bypass-01-indirect-eval --json
→ riskScore: 0, riskLevel: SAFE, threats: []

$ node bin/muaddib.js scan tests/audit-bypass/bypass-02-muaddib-ignore --json
→ riskScore: 0, riskLevel: SAFE, threats: []

$ node bin/muaddib.js scan tests/audit-bypass/bypass-03-mjs-extension --json
→ riskScore: 0, riskLevel: SAFE, threats: []
```

**GT_THRESHOLD = 3. All bypasses score 0 < 3. Bypass confirmed.**

---

## Appendix: Files Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| `src/scanner/ast.js` | 989 | AST-based threat detection (20+ rules) |
| `src/scanner/dataflow.js` | 389 | Source→sink dataflow analysis |
| `src/scanner/obfuscation.js` | 144 | Code obfuscation detection |
| `src/scanner/entropy.js` | 261 | Shannon entropy + JS obfuscation patterns |
| `src/scanner/deobfuscate.js` | 606 | Static deobfuscation pre-processor |
| `src/scanner/module-graph.js` | 884 | Cross-file taint propagation |
| `src/index.js` | 980 | Main orchestration + FP reduction + scoring |
| `src/sandbox.js` | 621 | Docker sandbox dynamic analysis |
| `src/canary-tokens.js` | 185 | Canary token generation + detection |
| `src/utils.js` | 243 | File walking + helpers |
| `src/shared/download.js` | 172 | SSRF-safe downloads |
| `src/commands/evaluate.js` | 481 | TPR/FPR/ADR evaluation framework |
| `docker/Dockerfile` | 19 | Sandbox container image |
| `docker/sandbox-runner.sh` | 293 | Sandbox entrypoint script |
