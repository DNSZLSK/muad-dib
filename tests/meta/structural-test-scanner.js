'use strict';

/**
 * structural-test-scanner.js — detects the "source-grep" test anti-pattern.
 *
 * The anti-pattern: a test reads an IMPLEMENTATION file (under src/, bin/, docker/,
 * deploy/) as text with readFileSync, then asserts that some string/identifier is
 * present in that text (assertIncludes / .includes / .match). Such tests are
 * structural, not behavioral: they break on a harmless rename and pass when the
 * logic is broken but the string is kept.
 *
 * This module is itself AST-based (acorn) so it is rename-safe — it does not match
 * on hardcoded variable names. It powers:
 *   - tests/meta/no-source-grep.test.js  (report mode → guard mode)
 *
 * Detection (per test file):
 *   1. Resolve simple path consts so identifier path args can be evaluated.
 *   2. Find variables bound from readFileSync(<impl-file>)  → the "tainted" set.
 *   3. Report every assertion that reads a tainted variable's text content.
 *
 * Returns an array of findings: { file, line, variable, target, substr, kind }.
 */

const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');

// A resolved path points at an implementation file if it sits under a src/ bin/ docker/
// deploy/ path segment AND is code: a .js/.mjs/.cjs or a .sh shell script. Declarative
// deploy/config files (systemd units, yaml/json/ini/toml/conf) are EXCLUDED — asserting
// that a deployed config contains required directives is a legitimate config-contract
// check, not the source-grep-of-CODE anti-pattern this scanner targets. Shell scripts
// (.sh) ARE code (sandbox-runner.sh, auto-update.sh), so they stay in scope.
const IMPL_SEGMENT_RE = /(^|[\\/])(src|bin|docker|deploy)[\\/]/;
const CONFIG_SUFFIX_RE = /\.(service|ya?ml|json|conf|ini|toml)$/i;
// Never treat fixtures / generated output / temp files as implementation.
const EXCLUDE_RE = /(samples|fixtures|node_modules|[\\/]tmp[\\/]|tmpdir|\.sarif|\.html\b)/i;

function listTestFiles(dir) {
  const out = [];
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(cur, e.name);
      if (e.isDirectory()) {
        // Skip the meta dir itself (the scanner & its test would self-flag) and node_modules.
        if (e.name === 'meta' || e.name === 'node_modules') continue;
        stack.push(full);
      } else if (e.isFile() && e.name.endsWith('.test.js')) {
        out.push(full);
      }
    }
  }
  return out.sort();
}

// Best-effort static evaluation of a path expression to a string.
// `dir` is the directory of the file being scanned (value of __dirname there).
// Returns a string (possibly with '..' segments) or null if not statically known.
function evalPathExpr(node, consts, dir) {
  if (!node) return null;
  switch (node.type) {
    case 'Literal':
      return typeof node.value === 'string' ? node.value : null;
    case 'TemplateLiteral': {
      let s = '';
      for (let i = 0; i < node.quasis.length; i++) {
        s += node.quasis[i].value.cooked || '';
        if (i < node.expressions.length) {
          const e = evalPathExpr(node.expressions[i], consts, dir);
          if (e == null) return null;
          s += e;
        }
      }
      return s;
    }
    case 'BinaryExpression': {
      if (node.operator !== '+') return null;
      const l = evalPathExpr(node.left, consts, dir);
      const r = evalPathExpr(node.right, consts, dir);
      if (l == null || r == null) return null;
      return l + r;
    }
    case 'Identifier':
      if (node.name === '__dirname') return dir;
      if (node.name === '__filename') return path.join(dir, 'file.js');
      if (consts.has(node.name)) return consts.get(node.name);
      return null;
    case 'CallExpression': {
      const c = node.callee;
      if (c.type === 'MemberExpression' && c.object.type === 'Identifier' &&
          c.property.type === 'Identifier') {
        // path.join(...) / path.resolve(...)
        if (c.object.name === 'path' && (c.property.name === 'join' || c.property.name === 'resolve')) {
          const parts = node.arguments.map(a => evalPathExpr(a, consts, dir));
          if (parts.some(p => p == null)) return null;
          return path.join(...parts);
        }
        // require.resolve('...')
        if (c.object.name === 'require' && c.property.name === 'resolve') {
          return evalPathExpr(node.arguments[0], consts, dir);
        }
      }
      return null;
    }
    default:
      return null;
  }
}

function isImplPath(s) {
  if (!s) return false;
  const norm = s.replace(/\\/g, '/');
  if (EXCLUDE_RE.test(norm) || CONFIG_SUFFIX_RE.test(norm)) return false;
  return IMPL_SEGMENT_RE.test(norm);
}

// Is this CallExpression a readFileSync(...) call (fs.readFileSync, require('fs').readFileSync, etc.)?
function isReadFileSyncCall(node) {
  if (!node || node.type !== 'CallExpression') return false;
  const c = node.callee;
  if (c.type === 'Identifier') return c.name === 'readFileSync';
  if (c.type === 'MemberExpression' && c.property.type === 'Identifier') {
    return c.property.name === 'readFileSync';
  }
  return false;
}

function literalArg(node) {
  return node && node.type === 'Literal' && typeof node.value === 'string' ? node.value : null;
}

/**
 * Scan a single test file. Returns an array of findings for that file.
 */
function scanFile(file) {
  let code;
  try {
    code = fs.readFileSync(file, 'utf8');
  } catch {
    return [];
  }
  let ast;
  try {
    ast = acorn.parse(code, { ecmaVersion: 'latest', locations: true, sourceType: 'script' });
  } catch {
    // Test files are CommonJS scripts; if one fails to parse, skip it (don't crash the suite).
    return [];
  }

  const dir = path.dirname(file);

  // Pass 1: resolve simple path consts (const X = path.join(...)/require.resolve(...)/'...').
  const consts = new Map();
  walk.simple(ast, {
    VariableDeclarator(node) {
      if (node.id.type !== 'Identifier' || !node.init) return;
      const v = evalPathExpr(node.init, consts, dir);
      if (v != null) consts.set(node.id.name, v);
    },
  });

  // Pass 2: collect tainted bindings (var = readFileSync(<impl file>)) and candidate
  // assertion usages, each tagged with its enclosing-function scope chain. This is so a
  // variable name reused in a different test — e.g. `content` holding a real function's
  // return value (createCanaryEnvFile(...)) in one test and a source read in another —
  // is NOT conflated. A usage only counts if a tainted binding of the same name is
  // visible in its scope.
  const isFn = (n) => n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression';
  const fnChain = (ancestors) => ancestors.filter(isFn).map(n => n.start);

  const bindings = []; // { name, scope, line, target }
  const usages = [];   // { name, chain:Set<number>, line, substr, kind }

  const considerBinding = (name, callNode, line, ancestors) => {
    const target = evalPathExpr(callNode.arguments[0], consts, dir);
    if (!isImplPath(target)) return;
    const chain = fnChain(ancestors);
    bindings.push({ name, scope: chain.length ? chain[chain.length - 1] : null, line, target: target.replace(/\\/g, '/') });
  };

  walk.ancestor(ast, {
    VariableDeclarator(node, _st, ancestors) {
      if (node.id.type === 'Identifier' && isReadFileSyncCall(node.init)) {
        considerBinding(node.id.name, node.init, node.loc.start.line, ancestors);
      }
    },
    AssignmentExpression(node, _st, ancestors) {
      if (node.left.type === 'Identifier' && isReadFileSyncCall(node.right)) {
        considerBinding(node.left.name, node.right, node.loc.start.line, ancestors);
      }
    },
    CallExpression(node, _st, ancestors) {
      const c = node.callee;
      // assertIncludes(var, 'substr') / assertNotIncludes(var, 'substr')
      if (c.type === 'Identifier' && (c.name === 'assertIncludes' || c.name === 'assertNotIncludes')) {
        const a0 = node.arguments[0];
        if (a0 && a0.type === 'Identifier') {
          usages.push({ name: a0.name, chain: new Set(fnChain(ancestors)), line: node.loc.start.line, substr: literalArg(node.arguments[1]), kind: c.name });
        }
        return;
      }
      // var.includes(...) / var.match(...) / var.indexOf(...)
      if (c.type === 'MemberExpression' && c.object.type === 'Identifier' &&
          c.property.type === 'Identifier' &&
          (c.property.name === 'includes' || c.property.name === 'match' || c.property.name === 'indexOf')) {
        usages.push({ name: c.object.name, chain: new Set(fnChain(ancestors)), line: node.loc.start.line, substr: literalArg(node.arguments[0]), kind: `.${c.property.name}()` });
      }
    },
  });

  if (bindings.length === 0) return [];

  // Pass 3: match each usage to a tainted binding of the same name that is visible in
  // its scope (binding's enclosing function is on the usage's ancestor chain) and
  // precedes it textually.
  const rel = path.relative(path.join(__dirname, '..', '..'), file).replace(/\\/g, '/');
  const findings = [];
  for (const u of usages) {
    const b = bindings.find(bd => bd.name === u.name && bd.line <= u.line &&
      (bd.scope === null || u.chain.has(bd.scope)));
    if (b) findings.push({ file: rel, line: u.line, variable: u.name, target: b.target, substr: u.substr, kind: u.kind });
  }
  return findings;
}

/**
 * Scan all *.test.js files under testsRoot (excluding tests/meta).
 * Returns a flat array of findings, sorted by file then line.
 */
function scanStructuralTests(testsRoot) {
  const files = listTestFiles(testsRoot);
  const all = [];
  for (const f of files) {
    for (const finding of scanFile(f)) all.push(finding);
  }
  return all.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

/**
 * Group findings by file → { file, count, findings[] }, sorted by count desc.
 */
function groupByFile(findings) {
  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }
  return [...byFile.entries()]
    .map(([file, fs_]) => ({ file, count: fs_.length, findings: fs_ }))
    .sort((a, b) => b.count - a.count || a.file.localeCompare(b.file));
}

module.exports = { scanStructuralTests, groupByFile, scanFile, listTestFiles };
