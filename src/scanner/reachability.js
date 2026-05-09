/**
 * Reachability analysis — determines which files are reachable from
 * package entry points (main, bin, exports, browser, module, lifecycle scripts).
 * Files not reachable from any entry point are likely tests, examples, or
 * internal utilities shipped in tarballs but never executed at install time.
 */
const fs = require('fs');
const path = require('path');
const { resolveLocal, extractLocalImports, parseFile, isLocalImport, toRel, isFileExists } = require('./module-graph');

/**
 * Recursively extract file paths from the package.json `exports` field.
 * Handles: string shorthand, condition objects, nested subpath objects, arrays.
 * @param {*} exportsField
 * @returns {string[]}
 */
function extractExportsPaths(exportsField) {
  if (!exportsField) return [];

  // String shorthand: "exports": "./index.js"
  if (typeof exportsField === 'string') {
    return isLocalPath(exportsField) ? [exportsField] : [];
  }

  // Array form: ["./a.js", "./b.js"]
  if (Array.isArray(exportsField)) {
    const paths = [];
    for (const item of exportsField) {
      paths.push(...extractExportsPaths(item));
    }
    return paths;
  }

  // Object form — could be condition keys or subpath keys
  if (typeof exportsField === 'object') {
    const paths = [];
    for (const value of Object.values(exportsField)) {
      paths.push(...extractExportsPaths(value));
    }
    return paths;
  }

  return [];
}

/**
 * Extract .js/.mjs/.cjs file paths referenced in lifecycle script commands.
 * Matches patterns like: node scripts/install.js, node ./lib/post.mjs
 * @param {string} scriptCmd
 * @returns {string[]}
 */
function extractScriptJsFiles(scriptCmd) {
  if (!scriptCmd || typeof scriptCmd !== 'string') return [];
  const matches = [];
  // Match: node <path>.js/mjs/cjs (but not node -e '...')
  const re = /\bnode\s+(?!-[a-z])([\w./_-]+\.(?:js|mjs|cjs))\b/g;
  let m;
  while ((m = re.exec(scriptCmd)) !== null) {
    matches.push(m[1]);
  }
  return matches;
}

/**
 * Check if a path is local (starts with ./ or ../ or has no protocol).
 */
function isLocalPath(p) {
  if (typeof p !== 'string') return false;
  if (p.startsWith('./') || p.startsWith('../')) return true;
  // Bare path without protocol (e.g., "index.js", "src/main.js")
  if (!p.includes('://') && !p.startsWith('#')) return true;
  return false;
}

/**
 * Resolve an entry point candidate against the filesystem.
 * Tries: exact, .js, .mjs, .cjs, /index.js
 * @param {string} candidate - Relative path from package root (e.g., "./src/index.js")
 * @param {string} packagePath - Absolute path to package root
 * @returns {string|null} Relative path (forward slashes) or null
 */
function resolveEntryPoint(candidate, packagePath) {
  // Strip leading ./ for path.resolve
  const clean = candidate.replace(/^\.\//, '');
  const abs = path.resolve(packagePath, clean);

  if (isFileExists(abs)) return toRel(abs, packagePath);
  if (isFileExists(abs + '.js')) return toRel(abs + '.js', packagePath);
  if (isFileExists(abs + '.mjs')) return toRel(abs + '.mjs', packagePath);
  if (isFileExists(abs + '.cjs')) return toRel(abs + '.cjs', packagePath);
  if (isFileExists(path.join(abs, 'index.js'))) return toRel(path.join(abs, 'index.js'), packagePath);
  return null;
}

/**
 * Extract entry points from package.json.
 * Sources: main, bin, exports, browser, module, lifecycle scripts.
 * @param {string} packagePath - Absolute path to package root
 * @returns {string[]} Resolved relative file paths (forward slashes)
 */
function getEntryPoints(packagePath) {
  const pkgJsonPath = path.join(packagePath, 'package.json');
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
  } catch {
    return [];
  }

  const candidates = [];

  // main
  if (typeof pkg.main === 'string') {
    candidates.push(pkg.main);
  }

  // bin (string or object)
  if (typeof pkg.bin === 'string') {
    candidates.push(pkg.bin);
  } else if (pkg.bin && typeof pkg.bin === 'object') {
    for (const v of Object.values(pkg.bin)) {
      if (typeof v === 'string') candidates.push(v);
    }
  }

  // exports (recursive)
  if (pkg.exports) {
    candidates.push(...extractExportsPaths(pkg.exports));
  }

  // browser (string or object)
  if (typeof pkg.browser === 'string') {
    candidates.push(pkg.browser);
  } else if (pkg.browser && typeof pkg.browser === 'object') {
    for (const v of Object.values(pkg.browser)) {
      if (typeof v === 'string') candidates.push(v);
    }
  }

  // module
  if (typeof pkg.module === 'string') {
    candidates.push(pkg.module);
  }

  // Lifecycle scripts: extract .js files from preinstall/install/postinstall/prepare
  const lifecycleKeys = ['preinstall', 'install', 'postinstall', 'prepare'];
  if (pkg.scripts) {
    for (const key of lifecycleKeys) {
      if (typeof pkg.scripts[key] === 'string') {
        candidates.push(...extractScriptJsFiles(pkg.scripts[key]));
      }
    }
  }

  // Resolve candidates against filesystem
  const resolved = new Set();
  for (const c of candidates) {
    if (!c || typeof c !== 'string') continue;
    const r = resolveEntryPoint(c, packagePath);
    if (r) resolved.add(r);
  }

  // Default fallback: try index.js
  if (resolved.size === 0) {
    const r = resolveEntryPoint('index.js', packagePath);
    if (r) resolved.add(r);
  }

  return [...resolved];
}

/**
 * Extract local .js file targets from child_process spawn/fork/execFile calls.
 * Handles patterns like:
 *   fork('./worker.js')
 *   spawn('node', [path.join(__dirname, 'worker.js')])
 *   spawn(process.execPath, ['./stealer.js'])
 * @param {string} absFile - Absolute path to the file to parse
 * @param {string} packagePath - Package root
 * @returns {string[]} Resolved relative paths of spawn targets
 */
function extractSpawnTargets(absFile, packagePath) {
  const ast = parseFile(absFile);
  if (!ast) return [];

  const fileDir = path.dirname(absFile);
  const targets = [];

  walkForSpawnTargets(ast, fileDir, packagePath, targets);
  return [...new Set(targets)];
}

function walkForSpawnTargets(node, fileDir, packagePath, targets) {
  if (!node || typeof node !== 'object') return;

  if (node.type === 'CallExpression' && node.callee) {
    const name = getSpawnCalleeName(node.callee);

    if (name === 'fork' && node.arguments.length >= 1) {
      // child_process.fork(modulePath) — first arg is a .js file
      const target = resolvePathArg(node.arguments[0], fileDir, packagePath);
      if (target) targets.push(target);
    } else if ((name === 'spawn' || name === 'execFile') && node.arguments.length >= 2) {
      // spawn('node', [filePath]) or spawn(process.execPath, [filePath])
      const argsNode = node.arguments[1];
      if (argsNode && argsNode.type === 'ArrayExpression' && argsNode.elements.length >= 1) {
        const target = resolvePathArg(argsNode.elements[0], fileDir, packagePath);
        if (target) targets.push(target);
      }
    }
  }

  for (const key of Object.keys(node)) {
    if (key === 'type') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object') walkForSpawnTargets(item, fileDir, packagePath, targets);
      }
    } else if (child && typeof child === 'object') {
      walkForSpawnTargets(child, fileDir, packagePath, targets);
    }
  }
}

/**
 * Get the function name from a callee node (spawn, fork, cp.spawn, child_process.fork, etc.)
 */
function getSpawnCalleeName(callee) {
  if (callee.type === 'Identifier') return callee.name;
  if (callee.type === 'MemberExpression' && callee.property) {
    return callee.property.name || callee.property.value || '';
  }
  return '';
}

/**
 * Resolve a path argument from AST node to a relative file path.
 * Handles: string literals, path.join(__dirname, 'file.js'), template literals.
 */
function resolvePathArg(argNode, fileDir, packagePath) {
  if (!argNode) return null;

  // Simple string literal: './worker.js' or 'worker.js'
  if (argNode.type === 'Literal' && typeof argNode.value === 'string') {
    const val = argNode.value;
    if (val.endsWith('.js') || val.endsWith('.mjs') || val.endsWith('.cjs')) {
      return resolveLocal(fileDir, val.startsWith('.') ? val : './' + val, packagePath);
    }
    return null;
  }

  // path.join(__dirname, 'worker.js') pattern
  if (argNode.type === 'CallExpression' && argNode.callee &&
      argNode.callee.type === 'MemberExpression' &&
      argNode.callee.object && argNode.callee.object.name === 'path' &&
      argNode.callee.property && argNode.callee.property.name === 'join') {
    // Look for __dirname as first arg + string literals for the rest
    const args = argNode.arguments;
    if (args.length >= 2 && args[0].type === 'Identifier' && args[0].name === '__dirname') {
      const parts = [];
      for (let i = 1; i < args.length; i++) {
        if (args[i].type === 'Literal' && typeof args[i].value === 'string') {
          parts.push(args[i].value);
        } else {
          return null; // Can't resolve dynamic parts
        }
      }
      const relPath = './' + parts.join('/');
      return resolveLocal(fileDir, relPath, packagePath);
    }
  }

  return null;
}

/**
 * BFS traversal from entry points through local imports and spawn targets.
 * @param {string} packagePath - Absolute path to package root
 * @returns {{ reachableFiles: Set<string>, entryPoints: string[], skipped: boolean }}
 */
function computeReachableFiles(packagePath) {
  const entryPoints = getEntryPoints(packagePath);

  if (entryPoints.length === 0) {
    return { reachableFiles: new Set(), entryPoints: [], skipped: true };
  }

  const reachable = new Set();
  const queue = [...entryPoints];

  // Seed with entry points
  for (const ep of entryPoints) {
    reachable.add(ep);
  }

  while (queue.length > 0) {
    const relFile = queue.shift();
    const absFile = path.resolve(packagePath, relFile);

    // Follow require/import edges
    let imports;
    try {
      imports = extractLocalImports(absFile, packagePath);
    } catch {
      imports = [];
    }

    // Follow child_process spawn/fork targets
    let spawnTargets;
    try {
      spawnTargets = extractSpawnTargets(absFile, packagePath);
    } catch {
      spawnTargets = [];
    }

    const allTargets = [...imports, ...spawnTargets];
    for (const target of allTargets) {
      if (!reachable.has(target)) {
        reachable.add(target);
        queue.push(target);
      }
    }
  }

  return { reachableFiles: reachable, entryPoints, skipped: false };
}

// =============================================================================
// FPR plan Chantier 2 - intra-file function-level reachability
// =============================================================================
//
// File-level reachability above answers "is this file ever loaded by entry?".
// Function-level reachability answers "is this code in a function that's ever
// called?". A reachable file (e.g. lib/utils.js) often ships dozens of helper
// functions where only a handful are actually called from exports - the rest
// are dead code that nevertheless contributes to the FPR baseline (lodash
// legacy modules, moment locales, framework polyfills).
//
// Bounded by design (CLAUDE.md "bounded resources") :
//   - MAX_FN_REACH_FILES files processed per package
//   - MAX_FN_REACH_BYTES per file
//   - Skips immediately on dynamic resolution (eval / Function / dynamic
//     require / globalThis[computed]) - fail-open to avoid TPR regression
//   - Only intra-file edges (inter-file already approximated by file-level
//     reachability above + treating all exports as seeds)
//
// Output : Map<relFile, { dynamic, deadRanges }> where deadRanges is an
// array of { startLine, endLine }. Threats with t.line falling inside any
// dead range are eligible for downgrade in src/scoring.js applyFPReductions.

const MAX_FN_REACH_FILES = 250;
const MAX_FN_REACH_BYTES = 1024 * 1024;

let _acornLazy = null;
function _acorn() {
  if (_acornLazy) return _acornLazy;
  _acornLazy = require('acorn');
  return _acornLazy;
}

const FN_REACH_ACORN_OPTIONS = {
  ecmaVersion: 2024,
  sourceType: 'module',
  allowReturnOutsideFunction: true,
  allowImportExportEverywhere: true,
  allowHashBang: true,
  locations: true
};

function _parseWithLocations(content) {
  const acorn = _acorn();
  try {
    return acorn.parse(content, FN_REACH_ACORN_OPTIONS);
  } catch {
    try {
      return acorn.parse(content, { ...FN_REACH_ACORN_OPTIONS, sourceType: 'script' });
    } catch {
      return null;
    }
  }
}

function _isFunctionNode(node) {
  return node && (
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression'
  );
}

/**
 * Walks an AST node tree, calling visitor(node) for every typed node.
 * Mirrors module-graph.walkAST but local to this file to keep imports tight.
 */
function _walk(node, visitor) {
  if (!node || typeof node !== 'object') return;
  if (node.type) visitor(node);
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'loc' || key === 'start' || key === 'end') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) _walk(item, visitor);
      }
    } else if (child && typeof child === 'object' && child.type) {
      _walk(child, visitor);
    }
  }
}

/**
 * Returns true when a single AST node is one of the dynamic-resolution
 * operations that defeat static call-graph analysis :
 *
 *   - eval(...) / Function(...) / new Function(...)
 *   - require(<non-literal>) / require(<template-with-expr>)
 *   - globalThis[<computed>] / global[<computed>] / window[<computed>]
 *
 * Single-node check ; combined with _walkBody to scope detection to a function
 * body or to the top-level program body.
 */
function _isDynamicNode(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'CallExpression') {
    const callee = node.callee;
    if (callee && callee.type === 'Identifier') {
      if (callee.name === 'eval' || callee.name === 'Function') return true;
      if (callee.name === 'require' && node.arguments.length >= 1) {
        const arg0 = node.arguments[0];
        const literalString = arg0 && arg0.type === 'Literal' && typeof arg0.value === 'string';
        const simpleTemplate = arg0 && arg0.type === 'TemplateLiteral' &&
          arg0.expressions.length === 0;
        if (!literalString && !simpleTemplate) return true;
      }
    }
  }
  if (node.type === 'NewExpression') {
    const callee = node.callee;
    if (callee && callee.type === 'Identifier' && callee.name === 'Function') return true;
  }
  if (node.type === 'MemberExpression' && node.computed) {
    const obj = node.object;
    if (obj && obj.type === 'Identifier' &&
        (obj.name === 'globalThis' || obj.name === 'global' || obj.name === 'window')) {
      if (node.property && node.property.type !== 'Literal') return true;
    }
  }
  return false;
}

/**
 * Walk a node and its descendants, calling visitor on each, but DO NOT
 * descend into nested function bodies or class bodies. Used both for
 * name-collection and dynamic-resolution detection scoped to one body.
 */
function _walkBody(node, visitor) {
  if (!node || typeof node !== 'object') return;
  if (node.type) visitor(node);
  if (_isFunctionNode(node) && node !== _walkBody._entry) return;
  if (node.type === 'ClassBody' && node !== _walkBody._entry) return;
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'loc' || key === 'start' || key === 'end') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const it of child) if (it && typeof it === 'object' && it.type) _walkBody(it, visitor);
    } else if (child && typeof child === 'object' && child.type) {
      _walkBody(child, visitor);
    }
  }
}

/**
 * Returns true if the body contains a dynamic-resolution op directly
 * (excluding nested function bodies, which count toward their own owner).
 */
function _bodyHasDynamic(bodyNode) {
  let found = false;
  _walkBody._entry = bodyNode;
  try {
    _walkBody(bodyNode, (n) => {
      if (found) return;
      if (_isDynamicNode(n)) found = true;
    });
  } finally {
    _walkBody._entry = null;
  }
  return found;
}

/**
 * Walk Program body and check whether any top-level (script-scope) statement
 * contains a dynamic-resolution op. Top-level eval can rebind globals so a
 * single hit forces full-file fail-open. Function bodies (declared at top
 * level but not invoked) are excluded from this check - they are evaluated
 * separately per-function.
 */
function _findTopLevelDynamic(ast) {
  for (const stmt of ast.body) {
    if (!stmt || !stmt.type) continue;
    // Pure declarations don't execute their bodies at top level.
    if (stmt.type === 'FunctionDeclaration') continue;
    if (stmt.type === 'ClassDeclaration') continue;
    if (stmt.type === 'ImportDeclaration') continue;
    if (stmt.type === 'ExportNamedDeclaration' &&
        stmt.declaration && (
          stmt.declaration.type === 'FunctionDeclaration' ||
          stmt.declaration.type === 'ClassDeclaration'
        )) continue;
    if (stmt.type === 'ExportDefaultDeclaration' && stmt.declaration && (
        stmt.declaration.type === 'FunctionDeclaration' ||
        stmt.declaration.type === 'ClassDeclaration'
      )) continue;
    // For variable declarators, only the init expression executes - a literal
    // function expression does not run unless invoked.
    if (stmt.type === 'VariableDeclaration') {
      for (const decl of stmt.declarations) {
        if (!decl.init) continue;
        if (_isFunctionNode(decl.init)) continue; // declared, not invoked
        if (_bodyHasDynamic(decl.init)) return true;
      }
      continue;
    }
    if (_bodyHasDynamic(stmt)) return true;
  }
  return false;
}

/**
 * Backwards-compatible wrapper kept for the unit tests that exercise the
 * coarse "any-dynamic-anywhere" check. New code path uses _findTopLevelDynamic
 * + per-function detection inside _analyzeFunctionReachability.
 */
function _hasDynamicResolution(ast) {
  let dynamic = false;
  _walk(ast, (node) => {
    if (dynamic) return;
    if (_isDynamicNode(node)) dynamic = true;
  });
  return dynamic;
}

/**
 * Collects every locally-named function declaration in the file.
 *   - function Foo() {}                               -> name='Foo'
 *   - const Foo = function() {} / const Foo = () => {} -> name='Foo'
 *   - class Foo { method() {} }                        -> all methods named '<class>.<method>'
 *
 * Returns Array<{ name, startLine, endLine, bodyNode }>. The bodyNode lets
 * the call-graph step walk the function body without re-finding it.
 */
function _collectNamedFunctions(ast) {
  const out = [];
  const seenStarts = new Set();
  _walk(ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id && node.id.name && node.loc) {
      if (seenStarts.has(node.start)) return;
      seenStarts.add(node.start);
      out.push({
        name: node.id.name,
        startLine: node.loc.start.line,
        endLine: node.loc.end.line,
        bodyNode: node.body,
        kind: 'function_decl'
      });
    } else if (node.type === 'VariableDeclarator' && node.id && node.id.type === 'Identifier' &&
               node.init && _isFunctionNode(node.init) && node.init.loc) {
      if (seenStarts.has(node.init.start)) return;
      seenStarts.add(node.init.start);
      out.push({
        name: node.id.name,
        startLine: node.init.loc.start.line,
        endLine: node.init.loc.end.line,
        bodyNode: node.init.body,
        kind: 'fn_const'
      });
    } else if (node.type === 'ClassDeclaration' && node.id && node.id.name &&
               node.body && node.body.type === 'ClassBody') {
      for (const member of node.body.body) {
        if ((member.type === 'MethodDefinition' || member.type === 'PropertyDefinition') &&
            member.value && _isFunctionNode(member.value) && member.value.loc) {
          if (seenStarts.has(member.value.start)) continue;
          seenStarts.add(member.value.start);
          const methodName = member.key && (member.key.name || member.key.value);
          out.push({
            name: `${node.id.name}.${methodName || '<anon>'}`,
            startLine: member.value.loc.start.line,
            endLine: member.value.loc.end.line,
            bodyNode: member.value.body,
            kind: 'class_method',
            className: node.id.name
          });
        }
      }
    }
  });
  return out;
}

/**
 * Collect every name-Identifier reference inside a node (excluding nested
 * function bodies - those are walked separately via the call-graph queue).
 * Captures three patterns equally :
 *
 *   foo()                                      // direct call
 *   arr.map(foo)                               // callback reference
 *   process.on('exit', cleanup)                // event handler reference
 *   const x = bar                              // alias creation
 *
 * Plus method names from non-computed MemberExpression callees (`obj.method`)
 * to keep class methods live behind imprecise dispatch. False-live is the
 * safe direction here ; the goal is to avoid TPR regression on dead-code
 * downgrade, not to be precise on which name is actually executed.
 *
 * Skips :
 *   - nested function bodies (handled via BFS queue)
 *   - declarators (a.id is not "referenced" by `function a() {}`)
 *   - non-computed MemberExpression .property side (only the .object Identifier)
 */
function _calleeIdentifierNames(node) {
  const names = new Set();
  function walkLight(n) {
    if (!n || typeof n !== 'object') return;

    // Track non-computed member callees so `obj.method()` keeps `method` live.
    if ((n.type === 'CallExpression' || n.type === 'NewExpression') && n.callee &&
        n.callee.type === 'MemberExpression' && !n.callee.computed &&
        n.callee.property && n.callee.property.type === 'Identifier') {
      names.add(n.callee.property.name);
    }

    if (n.type === 'Identifier') {
      names.add(n.name);
      return;
    }

    // Don't descend into NAMED nested functions - they're addressable via
    // collectNamedFunctions and BFS reaches them on their own. But anonymous
    // FunctionExpression / ArrowFunctionExpression (callbacks, object-method
    // shorthand, IIFE bodies) execute as part of the lexical parent and
    // their references count toward the parent's reachable name set.
    if (_isFunctionNode(n) && n.id && n.id.name) return;
    if (n.type === 'ClassBody') return; // descended via collectNamedFunctions

    // For MemberExpression, only walk the object side ; the property name is
    // already captured above for callees, and we never want to mark a name
    // live just because it appears as a property name (e.g. `pkg.foo` shouldn't
    // mark a local `foo` live unless `pkg` is the local's container - which
    // we cannot resolve statically here).
    if (n.type === 'MemberExpression' && !n.computed) {
      if (n.object) walkLight(n.object);
      return;
    }

    // Skip declarator id positions so a function's own name in
    // `function foo() {}` doesn't mark foo as referenced.
    if (n.type === 'VariableDeclarator') {
      if (n.init) walkLight(n.init);
      return;
    }
    if (n.type === 'FunctionDeclaration' || n.type === 'ClassDeclaration') {
      // The declaration itself doesn't reference its own name.
      if (n.body) walkLight(n.body);
      if (n.superClass) walkLight(n.superClass);
      return;
    }

    for (const key of Object.keys(n)) {
      if (key === 'type' || key === 'loc' || key === 'start' || key === 'end') continue;
      const child = n[key];
      if (Array.isArray(child)) {
        for (const it of child) if (it && typeof it === 'object' && it.type) walkLight(it);
      } else if (child && typeof child === 'object' && child.type) walkLight(child);
    }
  }
  walkLight(node);
  return names;
}

/**
 * Identify the seeds: names known to be live because they are exported, called
 * at top-level, or installed as event handlers / module entry points.
 *
 *   - module.exports = X / module.exports.Y = X / exports.Y = X      => X live
 *   - export function Foo                                            => Foo live
 *   - export default <Identifier|Function>                           => name live
 *   - export { Foo, Bar }                                            => Foo, Bar live
 *   - top-level CallExpression (Identifier callee)                   => name live
 *   - class Foo { ... } when Foo is exported                         => all methods live
 *
 * For each seed name, returns a Set<string>. Names that don't match a known
 * named function are simply ignored downstream.
 */
function _collectSeedNames(ast) {
  const seeds = new Set();
  const exportedClassNames = new Set();

  for (const stmt of ast.body) {
    if (!stmt || !stmt.type) continue;

    // Top-level: export named/default/declaration
    if (stmt.type === 'ExportNamedDeclaration') {
      if (stmt.declaration) {
        if (stmt.declaration.type === 'FunctionDeclaration' && stmt.declaration.id) {
          seeds.add(stmt.declaration.id.name);
        } else if (stmt.declaration.type === 'ClassDeclaration' && stmt.declaration.id) {
          seeds.add(stmt.declaration.id.name);
          exportedClassNames.add(stmt.declaration.id.name);
        } else if (stmt.declaration.type === 'VariableDeclaration') {
          for (const d of stmt.declaration.declarations) {
            if (d.id && d.id.type === 'Identifier') seeds.add(d.id.name);
          }
        }
      }
      if (stmt.specifiers) {
        for (const spec of stmt.specifiers) {
          if (spec.local && spec.local.type === 'Identifier') seeds.add(spec.local.name);
        }
      }
    } else if (stmt.type === 'ExportDefaultDeclaration') {
      const decl = stmt.declaration;
      if (decl) {
        if (decl.type === 'Identifier') seeds.add(decl.name);
        else if (decl.type === 'FunctionDeclaration' && decl.id) seeds.add(decl.id.name);
        else if (decl.type === 'ClassDeclaration' && decl.id) {
          seeds.add(decl.id.name);
          exportedClassNames.add(decl.id.name);
        }
      }
    }

    // Top-level: module.exports / exports / module.exports.X assignments
    if (stmt.type === 'ExpressionStatement' && stmt.expression &&
        stmt.expression.type === 'AssignmentExpression' && stmt.expression.operator === '=') {
      const left = stmt.expression.left;
      const right = stmt.expression.right;
      const isExportsAssign = left && left.type === 'MemberExpression' && (
        (left.object.type === 'Identifier' && left.object.name === 'exports') ||
        (left.object.type === 'Identifier' && left.object.name === 'module' &&
         left.property && left.property.name === 'exports') ||
        (left.object.type === 'MemberExpression' && left.object.object &&
         left.object.object.type === 'Identifier' && left.object.object.name === 'module' &&
         left.object.property && left.object.property.name === 'exports')
      );
      if (isExportsAssign && right) {
        if (right.type === 'Identifier') {
          seeds.add(right.name);
          // The exported identifier may resolve to a class - mark it as a
          // candidate so class_method entries with that className become
          // seeds. Non-class names are silently ignored downstream.
          exportedClassNames.add(right.name);
        }
        if (right.type === 'ObjectExpression') {
          for (const prop of right.properties) {
            if (prop.value && prop.value.type === 'Identifier') {
              seeds.add(prop.value.name);
              exportedClassNames.add(prop.value.name);
            }
          }
        }
      }
    }

    // Top-level: any CallExpression (statement-position or buried in expression)
    // adds its callee Identifier(s) to the seed set.
    const seedNames = _calleeIdentifierNames(stmt);
    for (const n of seedNames) seeds.add(n);
  }

  return { seeds, exportedClassNames };
}

/**
 * Build the dead-range table for a single AST. Returns null when the file is
 * dynamic (fail-open) ; otherwise returns { dynamic: false, deadRanges } where
 * deadRanges is an array of { startLine, endLine, name }.
 */
function _analyzeFunctionReachability(ast) {
  // Top-level dynamic ops (eval at script-level, dynamic require at script-
  // level) can rebind globals - we cannot reason about the call graph, so
  // fail-open the whole file. Same as the v1 behaviour.
  if (_findTopLevelDynamic(ast)) {
    return { dynamic: true, deadRanges: [] };
  }

  const namedFns = _collectNamedFunctions(ast);
  if (namedFns.length === 0) {
    return { dynamic: false, deadRanges: [] };
  }

  // Detect functions whose body contains dynamic ops. These functions stay
  // analyzable for reachability (a webpack chunk loader that's never called
  // from any export remains dead), but if any of them becomes live during
  // BFS we fail-open the rest of the file (we cannot follow into the eval).
  const dynamicFnSet = new Set();
  for (const fn of namedFns) {
    if (_bodyHasDynamic(fn.bodyNode)) dynamicFnSet.add(fn);
  }

  // Build name -> list of fn entries (a name can be redeclared, e.g. function
  // overloads in different scopes ; treating any match as live keeps fail-open).
  const byName = new Map();
  for (const fn of namedFns) {
    if (!byName.has(fn.name)) byName.set(fn.name, []);
    byName.get(fn.name).push(fn);
  }
  // Also expose class methods by their bare method name to cover obj.method()
  // calls without precise type tracking.
  for (const fn of namedFns) {
    if (fn.kind === 'class_method') {
      const dot = fn.name.lastIndexOf('.');
      const bare = dot >= 0 ? fn.name.slice(dot + 1) : fn.name;
      if (!byName.has(bare)) byName.set(bare, []);
      if (!byName.get(bare).includes(fn)) byName.get(bare).push(fn);
    }
  }

  const { seeds, exportedClassNames } = _collectSeedNames(ast);

  // Expand exported classes -> all their methods are live seeds
  for (const fn of namedFns) {
    if (fn.kind === 'class_method' && exportedClassNames.has(fn.className)) {
      seeds.add(fn.name);
    }
  }

  const live = new Set();
  const queue = [];
  let dynamicFailOpen = false; // a live function uses dynamic ops -> fail-open

  function activate(name) {
    const candidates = byName.get(name);
    if (!candidates) return;
    for (const fn of candidates) {
      if (live.has(fn)) continue;
      live.add(fn);
      queue.push(fn);
      // First time a dynamic-internal function becomes live : we can no
      // longer reason about which other locals it may invoke. Mark every
      // remaining named function live so deadRanges stays empty for them.
      if (dynamicFnSet.has(fn) && !dynamicFailOpen) {
        dynamicFailOpen = true;
        for (const other of namedFns) {
          if (live.has(other)) continue;
          live.add(other);
          queue.push(other);
        }
      }
    }
  }

  for (const seed of seeds) activate(seed);

  let safety = 0;
  while (queue.length > 0 && safety++ < 5000) {
    const fn = queue.shift();
    const calleeNames = _calleeIdentifierNames(fn.bodyNode);
    for (const name of calleeNames) activate(name);
  }

  const deadRanges = [];
  for (const fn of namedFns) {
    if (live.has(fn)) continue;
    deadRanges.push({
      startLine: fn.startLine,
      endLine: fn.endLine,
      name: fn.name
    });
  }
  return {
    dynamic: false,
    dynamicFailOpen,
    dynamicFnCount: dynamicFnSet.size,
    deadRanges
  };
}

/**
 * Compute function-level reachability for every reachable file in a package.
 * Returns Map<relFile, { dynamic, deadRanges }>. Files are skipped silently
 * (parse failure, IO error, byte cap, file count cap, non-JS extension) so
 * the caller can treat absence as "no info, do nothing".
 *
 * Bounded by MAX_FN_REACH_FILES and MAX_FN_REACH_BYTES per CLAUDE.md.
 */
function computeReachableFunctions(packagePath, reachableFiles) {
  const out = new Map();
  if (!reachableFiles || typeof reachableFiles[Symbol.iterator] !== 'function') return out;

  let processed = 0;
  for (const relFile of reachableFiles) {
    if (processed >= MAX_FN_REACH_FILES) break;
    if (typeof relFile !== 'string') continue;
    if (!/\.(js|mjs|cjs)$/i.test(relFile)) continue;

    const absFile = path.resolve(packagePath, relFile);
    let content;
    try {
      const stat = fs.statSync(absFile);
      if (!stat.isFile() || stat.size > MAX_FN_REACH_BYTES) continue;
      content = fs.readFileSync(absFile, 'utf8');
    } catch { continue; }

    const ast = _parseWithLocations(content);
    if (!ast) continue;
    processed++;

    const result = _analyzeFunctionReachability(ast);
    if (result) out.set(relFile, result);
  }

  return out;
}

module.exports = {
  computeReachableFiles,
  computeReachableFunctions,
  getEntryPoints,
  extractExportsPaths,
  extractScriptJsFiles,
  // Exported for tests
  _internals: {
    _hasDynamicResolution,
    _collectNamedFunctions,
    _collectSeedNames,
    _analyzeFunctionReachability,
    _parseWithLocations,
    MAX_FN_REACH_FILES,
    MAX_FN_REACH_BYTES
  }
};
