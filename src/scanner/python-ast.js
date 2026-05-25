'use strict';

/**
 * Python AST Scanner (MUADDIB-PYAST-001 .. 008).
 *
 * Created v2.11.42+ to close the npm/PyPI parity gap on deep static analysis.
 * Until now the only Python coverage was:
 *  - `python.js` (manifest dependency parsing — requirements.txt, setup.py text,
 *    pyproject.toml — extracts dep NAMES, never reads source)
 *  - `python-source.js` (regex-based import-time RCE on __init__.py / setup.py)
 *  - `ioc-strings.js` (literal string IOC match in .py)
 *
 * None of these is AST-aware, so a malicious `setup.py` that puts the payload
 * inside `cmdclass.install.run()` (the canonical TrapDoor pattern) was caught
 * weakly at best (PYSRC-002 fires on subprocess, but with no scope-precision
 * on whether the subprocess actually executes at install time).
 *
 * This scanner parses `.py` files into a tree-sitter CST and walks it with
 * scope tracking. At depth 0 (module body) we flag patterns that execute on
 * import / pip install:
 *  - PYAST-001 `setup(cmdclass={...})` overrides on install-time commands
 *  - PYAST-002 `setup(entry_points=...)` with suspicious console_scripts
 *  - PYAST-003 `exec()` / `eval()` at module level
 *  - PYAST-004 `subprocess.*(..., shell=True)` at module level
 *  - PYAST-007 `pickle/marshal/dill .loads()` at module level
 *  - PYAST-008 `__import__('subprocess'|'os'|...)` (any scope)
 *
 * IDs 005, 006, 009, 010 are RESERVED for Phase 1b (taint-aware detectors:
 * fetch→exec, base64→exec, ctypes shellcode, env→network). Those require a
 * mini intra-procedural symbol table — separate PR.
 *
 * Coexistence with `python-source.js` regex-based detectors: BOTH scanners
 * run. Defense in depth. AST findings are more precise (scope-aware) ; regex
 * findings are a fast-path safety net.
 */

const fs = require('fs');
const path = require('path');

const { countInvisibleUnicode, stripInvisibleUnicode } = require('../shared/unicode-invisibles.js');
const { walk } = require('./python-ast-detectors/helpers.js');
const { visitors } = require('./python-ast-detectors/index.js');

const MAX_FILE_SIZE = 1024 * 1024; // 1 MB cap, identique python-source.js

const WASM_PATH = path.join(__dirname, '..', 'vendor', 'tree-sitter-python.wasm');

// Dirs to skip — identical set to python-source.js. The walker reuses
// findTargetPythonFiles() from python-source.js below.
const { _internal: pysrcInternal } = require('./python-source.js');
const { findTargetPythonFiles } = pysrcInternal;

// ---------------------------------------------------------------------------
// Async tree-sitter init (lazy, cached).
// Pattern: pre-analysis stage in pipeline executor calls initPythonParser()
// once before the parallel batch. That populates `parserInstance`. The actual
// scanPythonAST() function is sync from the caller's POV but pulls from the
// cached parser. If init failed (web-tree-sitter not installed, WASM missing),
// scanPythonAST() returns [] gracefully so the pipeline never crashes.
// ---------------------------------------------------------------------------

let parserInstance = null;
let initPromise = null;
let initError = null;

async function initPythonParser() {
  if (parserInstance) return parserInstance;
  if (initError) return null;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      // web-tree-sitter exports { Parser, Language } at module level.
      const tsModule = require('web-tree-sitter');
      const Parser = tsModule.Parser || tsModule.default?.Parser || tsModule;
      const Language = tsModule.Language || tsModule.default?.Language;
      if (!Parser || !Language) {
        throw new Error('web-tree-sitter exports missing Parser/Language');
      }
      await Parser.init();
      if (!fs.existsSync(WASM_PATH)) {
        throw new Error(`tree-sitter-python.wasm not found at ${WASM_PATH}`);
      }
      const lang = await Language.load(WASM_PATH);
      const parser = new Parser();
      parser.setLanguage(lang);
      parserInstance = parser;
      return parser;
    } catch (e) {
      initError = e;
      if (process.env.MUADDIB_DEBUG) {
        // eslint-disable-next-line no-console
        console.error('[python-ast] init failed — Python AST scanner disabled:', e.message);
      }
      return null;
    }
  })();

  return initPromise;
}

// ---------------------------------------------------------------------------
// Main scanner. Synchronous from the caller (`executor.js`) because the
// parser is initialised at pre-analysis stage. If the parser failed to init,
// returns [] silently.
// ---------------------------------------------------------------------------

function scanPythonAST(targetPath) {
  if (!parserInstance) return []; // init didn't run or failed — silently skip
  const threats = [];

  const files = findTargetPythonFiles(targetPath);
  if (files.length === 0) return threats;

  for (const file of files) {
    let stat;
    try {
      stat = fs.statSync(file);
    } catch { continue; }
    if (!stat.isFile() || stat.size === 0 || stat.size > MAX_FILE_SIZE) continue;

    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch { continue; }

    // Normalise invisible Unicode before parsing — same defense-in-depth as
    // python-source.js. ZW in identifiers actually breaks the Python parser
    // (PEP 3131), but it can hide payload content in strings/comments and
    // mislead the human reviewer. We strip ONLY if any invisibles present.
    const invisibleCount = countInvisibleUnicode(content);
    const source = invisibleCount > 0 ? stripInvisibleUnicode(content) : content;

    let tree;
    try {
      tree = parserInstance.parse(source);
    } catch (e) {
      if (process.env.MUADDIB_DEBUG) {
        // eslint-disable-next-line no-console
        console.error(`[python-ast] parse failed on ${file}:`, e.message);
      }
      continue;
    }
    if (!tree || !tree.rootNode) continue;

    const ctx = {
      threats,
      relFile: path.relative(targetPath, file),
      source,
      invisibleCount
    };

    walk(tree.rootNode, ctx, visitors);
  }

  return threats;
}

module.exports = {
  initPythonParser,
  scanPythonAST,
  // Exposed for tests + audit hook.
  _internal: {
    WASM_PATH,
    _resetForTests() {
      parserInstance = null;
      initPromise = null;
      initError = null;
    }
  }
};
