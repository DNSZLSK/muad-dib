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

module.exports = { computeReachableFiles, getEntryPoints, extractExportsPaths, extractScriptJsFiles };
