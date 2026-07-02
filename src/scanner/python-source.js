'use strict';

/**
 * Python Source Scanner — detects import-time / install-time RCE patterns.
 *
 * Created v2.11.25 (TrapDoor PyPI gap, mai 2026). `python.js` is a manifest
 * parser (requirements.txt, setup.py, pyproject.toml — extracts dep names) ;
 * it never reads package source. `ast.js` / `dataflow.js` use acorn (JS only)
 * and skip `.py`. Only `ioc-strings.js` opens `.py` files, just for literal
 * IOC matching. → A malicious `__init__.py` that fetches + execs a payload at
 * import time was invisible to MUAD'DIB. This scanner closes that gap.
 *
 * Pas d'AST Python (CLAUDE.md interdit les deps runtime hors acorn / js-yaml /
 * adm-zip / @inquirer/prompts). Détection par regex ciblées sur les API
 * dangereuses, avec préprocessing :
 *  - strip des full-line comments (`^\s*#.*$`)
 *  - strip des triple-quoted strings (docstrings, block strings — réduit les
 *    FPs sur les docs qui mentionnent `exec`)
 *  - strip des chars Unicode invisibles via le helper partagé (mirror du fix
 *    AICONF-004 : empêche `e<ZWSP>xec(` de bypass — bien que Python rejette
 *    cet identifier comme SyntaxError, des invisibles dans des strings/comments
 *    restent un signal d'obfuscation valide).
 *
 * Rules : PYSRC-001 à PYSRC-008. Voir src/rules/index.js pour le détail.
 *
 * Références :
 *  - https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates (mai 2026)
 *  - https://attack.mitre.org/techniques/T1059/006/ (Command Scripting Interpreter: Python)
 */

const fs = require('fs');
const path = require('path');
const { countInvisibleUnicode, stripInvisibleUnicode } = require('../shared/unicode-invisibles.js');
const { detectAnalyzerHoneytoken } = require('./ast-detectors/anti-evasion.js');

const MAX_FILE_SIZE = 1024 * 1024; // 1 MB cap, cohérent avec ai-config.js

const PYSRC_UNICODE_THRESHOLD = 5;

// Dirs to skip when looking for __init__.py at depth-1. Couvre les patterns
// classiques (virtualenv, caches, tests, docs, build artifacts).
const EXCLUDED_DIRS = new Set([
  'tests', 'test', '__pycache__', '.pytest_cache', '.tox', '.nox',
  '.venv', 'venv', 'env', '.env',
  '.git', '.hg', '.svn',
  'node_modules',
  'examples', 'example', 'sample', 'samples',
  'docs', 'doc',
  'build', 'dist', 'site-packages',
  '.mypy_cache', '.ruff_cache', '.pytype', '.pyre',
  '.muaddib-cache', '.idea', '.vscode'
]);

// Files explicitly targeted at root (always scanned if present).
const ROOT_TARGET_FILES = ['__init__.py', 'setup.py'];

/**
 * Locate Python files that execute at import or install time.
 *
 * @param {string} targetPath
 * @returns {string[]} Absolute file paths, deduplicated.
 */
function findTargetPythonFiles(targetPath) {
  const targets = new Set();

  let rootEntries;
  try {
    rootEntries = fs.readdirSync(targetPath);
  } catch {
    return [];
  }

  // 1. ROOT_TARGET_FILES + every *.py at root (single-module packages)
  for (const entry of rootEntries) {
    if (!entry.endsWith('.py') && !ROOT_TARGET_FILES.includes(entry)) continue;
    const full = path.join(targetPath, entry);
    try {
      if (fs.statSync(full).isFile()) targets.add(full);
    } catch { /* ignore */ }
  }

  // 2. <subdir>/__init__.py at depth 1 (covers <pkg>/__init__.py layout)
  for (const entry of rootEntries) {
    if (EXCLUDED_DIRS.has(entry)) continue;
    if (entry.startsWith('.') && entry !== '.') continue; // skip hidden dirs by default
    const subdir = path.join(targetPath, entry);
    try {
      if (!fs.statSync(subdir).isDirectory()) continue;
    } catch { continue; }

    const initPy = path.join(subdir, '__init__.py');
    try {
      if (fs.statSync(initPy).isFile()) targets.add(initPy);
    } catch { /* not a file */ }

    // 3. src/<pkg>/__init__.py for PEP-518 src-layout
    if (entry === 'src') {
      let innerEntries;
      try {
        innerEntries = fs.readdirSync(subdir);
      } catch { continue; }
      for (const inner of innerEntries) {
        if (EXCLUDED_DIRS.has(inner)) continue;
        if (inner.startsWith('.')) continue;
        const innerDir = path.join(subdir, inner);
        try {
          if (!fs.statSync(innerDir).isDirectory()) continue;
        } catch { continue; }
        const innerInit = path.join(innerDir, '__init__.py');
        try {
          if (fs.statSync(innerInit).isFile()) targets.add(innerInit);
        } catch { /* not a file */ }
      }
    }
  }

  return [...targets];
}

/**
 * Strip full-line Python comments (lines whose first non-whitespace char is `#`).
 * Inline trailing comments are kept to avoid the complexity of a tokenizer.
 *
 * @param {string} content
 * @returns {string}
 */
function stripPythonComments(content) {
  return content.split(/\r?\n/).map(line => {
    const trimmed = line.trimStart();
    if (trimmed.startsWith('#')) return '';
    return line;
  }).join('\n');
}

/**
 * Strip triple-quoted strings (`"""..."""` and `'''...'''`). These are
 * typically docstrings or block-string literals containing free-form text
 * that may mention keywords like `exec` or `subprocess` without being a real
 * call site. Single-quoted strings are preserved (an attacker often hides
 * the payload inside `exec("import os; ...")`).
 *
 * @param {string} content
 * @returns {string}
 */
function stripTripleQuotedStrings(content) {
  return content
    .replace(/"""[\s\S]*?"""/g, '""')
    .replace(/'''[\s\S]*?'''/g, "''");
}

// --- Pattern detectors. All operate on a content string that has already
// been Unicode-normalized + comment-stripped + docstring-stripped.

function detectImportTimeExec(content) {
  // exec(...) or eval(...). Lookbehind excludes obj.exec(, ast.literal_eval(.
  return /(?<![.\w])(exec|eval)\s*\(/.test(content);
}

function detectImportTimeSubprocess(content) {
  return /\bsubprocess\.(Popen|run|call|check_output|check_call|getoutput|getstatusoutput)\s*\(/.test(content);
}

function detectImportTimeOsSystem(content) {
  // os.system, os.popen, os.spawn*, os.execv/exec*
  return /\bos\.(system|popen[234]?|spawn[a-z]+|exec[a-z]+)\s*\(/.test(content);
}

function detectNetworkFetch(content) {
  if (/\burllib\.request\.urlopen\s*\(/.test(content)) return true;
  if (/\burllib2\.urlopen\s*\(/.test(content)) return true;
  if (/\brequests\.(get|post|put|delete|patch|head|options|request)\s*\(/.test(content)) return true;
  if (/\bhttp\.client\.HTTPS?Connection\b/.test(content)) return true;
  if (/\bhttpx\.(get|post|put|delete|patch|head|options|request|Client|AsyncClient)\b/.test(content)) return true;
  if (/\baiohttp\.ClientSession\b/.test(content)) return true;
  return false;
}

function detectBase64Decode(content) {
  if (/\bbase64\.(b64|b32|b16|standard_b64|urlsafe_b64)decode\s*\(/.test(content)) return true;
  if (/\bcodecs\.decode\s*\(/.test(content)) return true;
  return false;
}

function detectDeserialization(content) {
  return /\b(pickle|cPickle|marshal|dill|cloudpickle|jsonpickle|shelve)\.loads?\s*\(/.test(content);
}

function detectDynamicDangerousImport(content) {
  return /__import__\s*\(\s*['"](subprocess|os|requests|urllib|urllib2|socket|http|ssl|ctypes|importlib)['"]/.test(content);
}

// PYSRC-009 — fork-exec d'un interpréteur inline. Pattern :
//   subprocess.{Popen,run,call,check_output,check_call,getoutput}(
//       [ "<interpreter>", "<inline-flag>", <code>, ... ], ...)
// Le premier élément de la liste est un nom d'interpréteur (literal string),
// le deuxième est un flag d'exécution inline (-e, -c, --eval, --command, -r).
// C'est le signe canonique d'un staging multi-langage (Python ouvre un
// interpréteur Node/Bash/Ruby/... et lui passe du code dans argv).
// Référence : TrapDoor (mai 2026) — `subprocess.run(["node", "-e", payload])`
// avec payload fetched depuis le C2 — pattern qui échappe à PYAST-005 parce
// qu'il n'y a pas d'`exec()`/`eval()` Python, l'exécution est côté interpréteur
// forked.
const FORK_EXEC_INLINE_INTERPRETER_RE = (() => {
  const SUBPROC_CALLEES = 'Popen|run|call|check_output|check_call|getoutput|getstatusoutput';
  const INTERPRETERS = 'node|nodejs|deno|bun|python|python2|python3|python3\\.\\d+|bash|sh|zsh|dash|ksh|ash|ruby|perl|php|lua|powershell|pwsh|cmd';
  const INLINE_FLAGS = '-e|-c|--eval|--command|-r';
  // All template inputs above are file-local constants — no user input flows
  // here, so the security/detect-non-literal-regexp warning is a false positive.
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(
    String.raw`\bsubprocess\.(?:${SUBPROC_CALLEES})\s*\(\s*\[\s*['"](?:${INTERPRETERS})['"]\s*,\s*['"](?:${INLINE_FLAGS})['"]`,
    'i'
  );
})();

function detectForkExecInlineInterpreter(content) {
  return FORK_EXEC_INLINE_INTERPRETER_RE.test(content);
}

// ── Python anti-evasion (M2 follow-up, 2026-07): PyPI parity for AST-096 ──
// analyzer_honeytoken_reference. Two FP-safe forms mirroring the JS side
// (ast-detectors/anti-evasion.js), BOTH reusing the existing CRITICAL AST-096
// rule (no new rule → rule count unchanged):
//   1. os.environ ENUMERATION (for-in / .keys() / .items()) coupled with a
//      MUADDIB-prefix key test (.startswith / == / in). NOT a direct read:
//      MUAD'DIB tooling reads specific MUADDIB_* config vars directly (verified
//      across the repo), while evasion enumerates the whole env looking for our
//      sandbox tripwire prefix. FP-safe by the distinctive marker + enumeration.
//   2. base64 / hex / charcode-encoded analyzer marker — handled by REUSING the
//      shared detectAnalyzerHoneytoken() (language-agnostic decoder; it already
//      matches Python byte-array, base64 and hex-escape encodings of the marker).
// Deliberately NOT covered (honest blind spots): plaintext direct reads of the
// honeytoken (legit security tooling references markers in the clear — same
// stance as the JS side); /proc fingerprinting such as reading the kernel
// version file (legit container-detection reads it — the Python equivalent of
// the gVisor FP); and shell/bash install hooks (this scanner only reads .py).
const PY_ENV_ENUM_RE = /\bfor\s+\w+\s+in\s+os\.environ\b|\bos\.environ\.(?:keys|items)\s*\(\s*\)/;
const PY_ENV_MARKER_TEST_RE = /\.startswith\s*\(\s*['"]MUADDIB|['"]MUADDIB\w*['"]\s*(?:==|!=)|(?:==|!=)\s*['"]MUADDIB|['"]MUADDIB\w*['"]\s+in\b/;

/**
 * Python parity for the JS detectEnvMarkerEnumeration. Returns 'MUADDIB' if the
 * file enumerates os.environ AND tests keys against the distinctive MUADDIB
 * prefix, else null. FP-safe: MUAD'DIB reads its own MUADDIB_* vars directly
 * (os.environ.get), never via enumerate+startswith (verified across the repo).
 */
function detectPythonEnvMarkerEnumeration(content) {
  if (!content || content.indexOf('os.environ') === -1) return null;
  if (!PY_ENV_ENUM_RE.test(content)) return null;
  return PY_ENV_MARKER_TEST_RE.test(content) ? 'MUADDIB' : null;
}

/**
 * Scan Python source files under targetPath for import-time / install-time RCE.
 *
 * @param {string} targetPath
 * @returns {Array<{type: string, severity: string, message: string, file: string}>}
 */
function scanPythonSource(targetPath) {
  const threats = [];

  const files = findTargetPythonFiles(targetPath);
  if (files.length === 0) return threats;

  for (const file of files) {
    let stat;
    try {
      stat = fs.statSync(file);
    } catch { continue; }
    if (!stat.isFile() || stat.size === 0 || stat.size > MAX_FILE_SIZE) continue;

    let rawContent;
    try {
      rawContent = fs.readFileSync(file, 'utf8');
    } catch { continue; }

    const relPath = path.relative(targetPath, file);

    // 1. PYSRC-008 — Unicode obfuscation (computed on raw content, before strip).
    const invisibleCount = countInvisibleUnicode(rawContent);
    if (invisibleCount >= PYSRC_UNICODE_THRESHOLD) {
      threats.push({
        type: 'python_source_unicode_obfuscation',
        severity: 'CRITICAL',
        message: `${relPath}: ${invisibleCount} invisible Unicode chars (zero-width / directional / variation selectors) — possible obfuscation hiding payload content from human review.`,
        file: relPath
      });
    }

    // 2. Normalize Unicode, strip docstrings + full-line comments.
    const normalized = invisibleCount > 0 ? stripInvisibleUnicode(rawContent) : rawContent;
    const cleaned = stripPythonComments(stripTripleQuotedStrings(normalized));

    // 3. Atomic detectors.
    const hasExec = detectImportTimeExec(cleaned);
    const hasSubprocess = detectImportTimeSubprocess(cleaned);
    const hasOsSystem = detectImportTimeOsSystem(cleaned);
    const hasFetch = detectNetworkFetch(cleaned);
    const hasBase64 = detectBase64Decode(cleaned);
    const hasDeser = detectDeserialization(cleaned);
    const hasDynImport = detectDynamicDangerousImport(cleaned);
    const hasForkExecInline = detectForkExecInlineInterpreter(cleaned);

    if (hasExec) {
      threats.push({
        type: 'import_time_exec',
        severity: 'CRITICAL',
        message: `${relPath}: exec()/eval() at module level — direct code execution on import or pip install (RCE).`,
        file: relPath
      });
    }
    if (hasSubprocess) {
      threats.push({
        type: 'import_time_subprocess',
        severity: 'CRITICAL',
        message: `${relPath}: subprocess.Popen/run/call/check_output — spawns external process on import or install.`,
        file: relPath
      });
    }
    if (hasOsSystem) {
      threats.push({
        type: 'import_time_os_system',
        severity: 'CRITICAL',
        message: `${relPath}: os.system()/os.popen()/os.spawn*()/os.exec*() — shell execution on import or install.`,
        file: relPath
      });
    }
    if (hasDeser) {
      threats.push({
        type: 'import_time_deserialization',
        severity: 'CRITICAL',
        message: `${relPath}: pickle/marshal/dill/cloudpickle/jsonpickle .loads() — unsafe deserialization, trivially RCE if input is attacker-controlled.`,
        file: relPath
      });
    }
    if (hasDynImport) {
      threats.push({
        type: 'dynamic_dangerous_import',
        severity: 'HIGH',
        message: `${relPath}: __import__() with hardcoded dangerous module name (subprocess/os/requests/urllib/socket/...) — obfuscation pattern to evade static analysis.`,
        file: relPath
      });
    }

    // 4. Compound detectors (in addition to individual fires).
    if (hasFetch && hasExec) {
      threats.push({
        type: 'import_time_fetch_exec',
        severity: 'CRITICAL',
        message: `${relPath}: network fetch (urllib/requests/http.client/httpx/aiohttp) AND exec/eval in same file — TrapDoor-style remote-payload-then-RCE.`,
        file: relPath
      });
    }
    if (hasBase64 && hasExec) {
      threats.push({
        type: 'import_time_base64_exec',
        severity: 'CRITICAL',
        message: `${relPath}: base64/codecs decode AND exec/eval in same file — obfuscated payload execution pattern.`,
        file: relPath
      });
    }
    // PYSRC-009: fork-exec inline interpreter — pattern transversal (node -e,
    // python -c, bash -c, ...). HIGH because it's structurally suspicious in
    // __init__.py / setup.py but has some legit uses (build scripts).
    if (hasForkExecInline) {
      threats.push({
        type: 'fork_exec_inline_interpreter',
        severity: 'HIGH',
        message: `${relPath}: subprocess.X(['<interpreter>', '-e|-c', ...]) — fork-exec of an inline interpreter (node/python/bash/ruby/perl/...). Canonical staging pattern for multi-language malware.`,
        file: relPath
      });
    }
    // PYSRC-010: fetch + fork-exec inline = TrapDoor signature exact. CRITICAL
    // because the file fetches remote bytes and feeds them to a forked
    // interpreter — RCE-equivalent without using Python's exec/eval.
    if (hasFetch && hasForkExecInline) {
      threats.push({
        type: 'fetch_to_fork_exec_inline',
        severity: 'CRITICAL',
        message: `${relPath}: network fetch (urllib/requests/...) AND subprocess.X(['<interpreter>', '-e', ...]) in same file — TrapDoor signature: fetch remote payload then fork-exec it through an inline interpreter. Escapes PYAST-005 (which only tracks Python exec/eval) because execution is on the forked interpreter side.`,
        file: relPath
      });
    }

    // Anti-evasion (AST-096 reused) — Python parity. Runs on cleaned content so
    // a base64 example inside a stripped docstring/comment cannot fire.
    const honeytokenMarker = detectAnalyzerHoneytoken(cleaned);
    const envEnumMarker = honeytokenMarker ? null : detectPythonEnvMarkerEnumeration(cleaned);
    if (honeytokenMarker || envEnumMarker) {
      threats.push({
        type: 'analyzer_honeytoken_reference',
        severity: 'CRITICAL',
        message: honeytokenMarker
          ? `${relPath}: obfuscated (base64/hex/charcode) reference to the analysis-environment honeytoken '${honeytokenMarker}' — sandbox-evasion reconnaissance. No legitimate PyPI package encodes a check for this tripwire.`
          : `${relPath}: os.environ enumeration testing keys against a MUADDIB prefix (marker-agnostic) — sandbox/analyzer evasion. No legitimate package scans the environment for this tripwire.`,
        file: relPath
      });
    }
  }

  return threats;
}

module.exports = {
  scanPythonSource,
  // Exported for unit testing of the helpers in isolation.
  _internal: {
    findTargetPythonFiles,
    stripPythonComments,
    stripTripleQuotedStrings,
    detectImportTimeExec,
    detectImportTimeSubprocess,
    detectImportTimeOsSystem,
    detectNetworkFetch,
    detectBase64Decode,
    detectDeserialization,
    detectDynamicDangerousImport,
    detectForkExecInlineInterpreter,
    detectPythonEnvMarkerEnumeration
  }
};
