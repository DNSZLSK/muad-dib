const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const { findFiles, EXCLUDED_DIRS } = require('../utils');
const { ACORN_OPTIONS: BASE_ACORN_OPTIONS, safeParse } = require('../shared/constants.js');

// --- Sensitive source patterns ---
const SENSITIVE_MODULES = new Set(['fs', 'child_process', 'dns', 'os', 'dgram']);

const ACORN_OPTIONS = {
  ...BASE_ACORN_OPTIONS,
  allowReturnOutsideFunction: true,
  allowImportExportEverywhere: true,
};

// --- Sink patterns for cross-file detection ---
const SINK_CALLEE_NAMES = new Set(['fetch', 'eval', 'Function', 'WebSocket', 'XMLHttpRequest']);
const SINK_MEMBER_METHODS = new Set([
  'https.request', 'https.get', 'http.request', 'http.get',
  'child_process.exec', 'child_process.execSync', 'child_process.spawn',
]);
const SINK_INSTANCE_METHODS = new Set(['connect', 'write', 'send']);

// =============================================================================
// STEP 1 — Module dependency graph
// =============================================================================

/**
 * Build a dependency graph of local modules within a package.
 * Only tracks local imports (./  ../) — node_modules are ignored.
 */
function buildModuleGraph(packagePath) {
  const graph = {};
  const files = findFiles(packagePath, {
    extensions: ['.js', '.mjs', '.cjs'],
    excludedDirs: EXCLUDED_DIRS,
  });
  for (const absFile of files) {
    const relFile = toRel(absFile, packagePath);
    const imports = extractLocalImports(absFile, packagePath);
    graph[relFile] = imports;
  }
  return graph;
}

function extractLocalImports(filePath, packagePath) {
  const ast = parseFile(filePath);
  if (!ast) return [];

  const imports = [];
  const fileDir = path.dirname(filePath);

  for (const node of ast.body) {
    if (node.type === 'ImportDeclaration' && node.source && typeof node.source.value === 'string') {
      const spec = node.source.value;
      if (isLocalImport(spec)) {
        const resolved = resolveLocal(fileDir, spec, packagePath);
        if (resolved) imports.push(resolved);
      }
    }
  }
  walkForRequires(ast, fileDir, packagePath, imports);
  return [...new Set(imports)];
}

/**
 * Try to resolve string concatenation in require arguments.
 * require('./a' + '/b') → './a/b'
 * @param {Object} node - BinaryExpression AST node
 * @returns {string|null} Resolved string or null
 */
function tryResolveConcatRequire(node, depth) {
  if (depth === undefined) depth = 0;
  if (depth > 20) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = tryResolveConcatRequire(node.left, depth + 1);
    if (left === null) return null;
    const right = tryResolveConcatRequire(node.right, depth + 1);
    if (right === null) return null;
    return left + right;
  }
  return null;
}

function walkForRequires(node, fileDir, packagePath, imports) {
  if (!node || typeof node !== 'object') return;
  if (
    node.type === 'CallExpression' &&
    node.callee && node.callee.type === 'Identifier' &&
    node.callee.name === 'require' &&
    node.arguments.length === 1
  ) {
    const arg = node.arguments[0];
    let spec = null;
    if (arg.type === 'Literal' && typeof arg.value === 'string') {
      spec = arg.value;
    } else if (arg.type === 'BinaryExpression') {
      // Fix #25: Resolve simple string concatenation in require args
      spec = tryResolveConcatRequire(arg);
    }
    if (spec && isLocalImport(spec)) {
      const resolved = resolveLocal(fileDir, spec, packagePath);
      if (resolved) imports.push(resolved);
    }
  }
  for (const key of Object.keys(node)) {
    if (key === 'type') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) {
          walkForRequires(item, fileDir, packagePath, imports);
        }
      }
    } else if (child && typeof child === 'object' && child.type) {
      walkForRequires(child, fileDir, packagePath, imports);
    }
  }
}

// =============================================================================
// STEP 2 — Annotate tainted exports
// =============================================================================

/**
 * For each file in the graph, find exports and check if they depend on
 * sensitive sources (fs.readFileSync, process.env, os.homedir, etc.).
 *
 * Returns: { 'reader.js': { default: { tainted: true, source: '...', detail: '...' } }, ... }
 */
function annotateTaintedExports(graph, packagePath) {
  const result = {};
  for (const relFile of Object.keys(graph)) {
    const absFile = path.resolve(packagePath, relFile);
    result[relFile] = analyzeExports(absFile);
  }
  return result;
}

function analyzeExports(filePath) {
  const ast = parseFile(filePath);
  if (!ast) return {};

  // Track which local variables hold sensitive module references
  // e.g. const fs = require('fs') → moduleVars['fs'] = 'fs'
  const moduleVars = {};
  // Track which local variables hold tainted values
  // e.g. const data = fs.readFileSync(...) → taintedVars['data'] = { source, detail }
  const taintedVars = {};

  // Track class declarations: class Foo { ... }
  const classDefs = {};
  // Track function declarations: function foo() { ... }
  const funcDefs = {};
  walkAST(ast, (node) => {
    if (node.type === 'ClassDeclaration' && node.id && node.id.name) {
      classDefs[node.id.name] = node;
    }
    if (node.type === 'FunctionDeclaration' && node.id && node.id.name) {
      funcDefs[node.id.name] = node;
    }
  });

  // First pass: collect require assignments, ES imports, and tainted variable assignments
  walkAST(ast, (node) => {
    // import fs from 'fs' / import { readFileSync } from 'fs'
    if (node.type === 'ImportDeclaration' && node.source && typeof node.source.value === 'string') {
      const modName = node.source.value;
      if (SENSITIVE_MODULES.has(modName)) {
        for (const spec of node.specifiers) {
          if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
            moduleVars[spec.local.name] = modName;
          } else if (spec.type === 'ImportSpecifier') {
            moduleVars[spec.local.name] = modName;
          }
        }
      }
    }

    // const fs = require('fs')
    if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations) {
        if (!decl.init || !decl.id) continue;

        // const fs = require('fs')
        if (isRequireCall(decl.init) && SENSITIVE_MODULES.has(decl.init.arguments[0].value)) {
          if (decl.id.type === 'Identifier') {
            moduleVars[decl.id.name] = decl.init.arguments[0].value;
          }
        }

        // const data = fs.readFileSync(...) or const token = process.env.XXX
        if (decl.id.type === 'Identifier') {
          const taint = checkNodeTaint(decl.init, moduleVars);
          if (taint) {
            taintedVars[decl.id.name] = taint;
          }
        }
      }
    }

    // Also handle: let x; x = fs.readFileSync(...)
    if (node.type === 'ExpressionStatement' && node.expression.type === 'AssignmentExpression') {
      const left = node.expression.left;
      const right = node.expression.right;
      if (left.type === 'Identifier') {
        const taint = checkNodeTaint(right, moduleVars);
        if (taint) {
          taintedVars[left.name] = taint;
        }
      }
    }
  });

  // Second pass: find exports and check if they are tainted
  const exports = {};
  walkAST(ast, (node) => {
    // export function foo() {...} / export const foo = expr
    if (node.type === 'ExportNamedDeclaration' && node.declaration) {
      const decl = node.declaration;
      if (decl.type === 'FunctionDeclaration' && decl.id) {
        const funcBody = decl.body && decl.body.type === 'BlockStatement' ? decl.body.body : null;
        if (funcBody) {
          const bodyTaint = scanBodyForTaint(funcBody, moduleVars, taintedVars);
          if (bodyTaint) {
            exports[decl.id.name] = { tainted: true, source: bodyTaint.source, detail: bodyTaint.detail };
          }
        }
      }
      if (decl.type === 'VariableDeclaration') {
        for (const vDecl of decl.declarations) {
          if (!vDecl.id || vDecl.id.type !== 'Identifier') continue;
          if (vDecl.init) {
            const taint = checkNodeTaint(vDecl.init, moduleVars);
            if (taint) {
              exports[vDecl.id.name] = { tainted: true, source: taint.source, detail: taint.detail };
            } else if (vDecl.init.type === 'Identifier' && taintedVars[vDecl.init.name]) {
              const t = taintedVars[vDecl.init.name];
              exports[vDecl.id.name] = { tainted: true, source: t.source, detail: t.detail };
            } else {
              const funcBody = getFunctionBody(vDecl.init);
              if (funcBody) {
                const bodyTaint = scanBodyForTaint(funcBody, moduleVars, taintedVars);
                if (bodyTaint) {
                  exports[vDecl.id.name] = { tainted: true, source: bodyTaint.source, detail: bodyTaint.detail };
                }
              }
            }
          }
        }
      }
    }

    // export default function() {...} / export default expr
    if (node.type === 'ExportDefaultDeclaration' && node.declaration) {
      const decl = node.declaration;
      const taint = checkNodeTaint(decl, moduleVars);
      if (taint) {
        exports['default'] = { tainted: true, source: taint.source, detail: taint.detail };
      } else if (decl.type === 'Identifier' && taintedVars[decl.name]) {
        const t = taintedVars[decl.name];
        exports['default'] = { tainted: true, source: t.source, detail: t.detail };
      } else {
        const funcBody = (decl.type === 'FunctionDeclaration' || decl.type === 'FunctionExpression' || decl.type === 'ArrowFunctionExpression')
          ? (decl.body && decl.body.type === 'BlockStatement' ? decl.body.body : (decl.body ? [{ type: 'ReturnStatement', argument: decl.body }] : null))
          : getFunctionBody(decl);
        if (funcBody) {
          const bodyTaint = scanBodyForTaint(funcBody, moduleVars, taintedVars);
          if (bodyTaint) {
            exports['default'] = { tainted: true, source: bodyTaint.source, detail: bodyTaint.detail };
          }
        }
      }
    }

    // module.exports = value  OR  module.exports = { ... }
    if (isModuleExportsAssign(node)) {
      const value = node.expression.right;
      const exportName = getExportName(node.expression.left);

      // Direct taint on the value itself
      const taint = checkNodeTaint(value, moduleVars);
      if (taint) {
        exports[exportName] = { tainted: true, source: taint.source, detail: taint.detail };
        return;
      }

      // Variable reference → check taintedVars
      if (value.type === 'Identifier' && taintedVars[value.name]) {
        const t = taintedVars[value.name];
        exports[exportName] = { tainted: true, source: t.source, detail: t.detail };
        return;
      }

      // Object literal: module.exports = { read: function() { ... } }
      if (value.type === 'ObjectExpression' && exportName === 'default') {
        for (const prop of value.properties) {
          if (!prop.key) continue;
          const propName = prop.key.name || prop.key.value || 'unknown';

          // Check function body for taint
          const funcBody = getFunctionBody(prop.value);
          if (funcBody) {
            const bodyTaint = scanBodyForTaint(funcBody, moduleVars, taintedVars);
            if (bodyTaint) {
              exports[propName] = { tainted: true, source: bodyTaint.source, detail: bodyTaint.detail };
            }
          } else {
            // Value is a direct expression
            const vTaint = checkNodeTaint(prop.value, moduleVars);
            if (vTaint) {
              exports[propName] = { tainted: true, source: vTaint.source, detail: vTaint.detail };
            } else if (prop.value.type === 'Identifier' && taintedVars[prop.value.name]) {
              const t = taintedVars[prop.value.name];
              exports[propName] = { tainted: true, source: t.source, detail: t.detail };
            } else if (prop.value.type === 'Identifier' && funcDefs[prop.value.name]) {
              // Shorthand property referencing a FunctionDeclaration: { readConfig }
              const fnNode = funcDefs[prop.value.name];
              const fnBody = fnNode.body && fnNode.body.type === 'BlockStatement' ? fnNode.body.body : null;
              if (fnBody) {
                const bodyTaint = scanBodyForTaint(fnBody, moduleVars, taintedVars);
                if (bodyTaint) {
                  exports[propName] = { tainted: true, source: bodyTaint.source, detail: bodyTaint.detail };
                }
              }
            }
          }
        }
        return;
      }

      // Class expression: module.exports = class { ... }
      if (value.type === 'ClassExpression') {
        analyzeClassBody(value, moduleVars, taintedVars, exports);
        return;
      }

      // Class reference: module.exports = ClassName (where ClassName is a ClassDeclaration)
      if (value.type === 'Identifier' && classDefs[value.name]) {
        analyzeClassBody(classDefs[value.name], moduleVars, taintedVars, exports);
        return;
      }

      // Function/arrow: module.exports = function() { ... }
      const funcBody = getFunctionBody(value);
      if (funcBody) {
        const bodyTaint = scanBodyForTaint(funcBody, moduleVars, taintedVars);
        if (bodyTaint) {
          exports[exportName] = { tainted: true, source: bodyTaint.source, detail: bodyTaint.detail };
        }
      }
    }
  });

  return exports;
}

/**
 * Analyze class body methods for tainted sources.
 * Populates exports with named tainted methods.
 */
function analyzeClassBody(classNode, moduleVars, taintedVars, exports) {
  if (!classNode.body || !classNode.body.body) return;
  for (const member of classNode.body.body) {
    if (member.type !== 'MethodDefinition') continue;
    const methodName = member.key && (member.key.name || member.key.value);
    if (!methodName || methodName === 'constructor') continue;
    const funcBody = getFunctionBody(member.value);
    if (funcBody) {
      const bodyTaint = scanBodyForTaint(funcBody, moduleVars, taintedVars);
      if (bodyTaint) {
        exports[methodName] = { tainted: true, source: bodyTaint.source, detail: bodyTaint.detail };
      }
    }
  }
}

/**
 * Check if a single AST node represents a sensitive source call.
 */
function checkNodeTaint(node, moduleVars) {
  if (!node) return null;

  // process.env  or  process.env.XXX
  if (node.type === 'MemberExpression') {
    const chain = getMemberChain(node);
    if (chain.startsWith('process.env')) {
      const detail = chain.length > 'process.env'.length ? chain.slice('process.env.'.length) : '';
      return { source: 'process.env', detail };
    }
  }

  // require('fs').readFileSync(...)  (inline require)
  if (node.type === 'CallExpression' && node.callee.type === 'MemberExpression') {
    const obj = node.callee.object;
    const prop = node.callee.property;
    const methodName = prop.name || prop.value;

    // Check inline require: require('fs').readFileSync(...)
    if (isRequireCall(obj) && SENSITIVE_MODULES.has(obj.arguments[0].value)) {
      const mod = obj.arguments[0].value;
      return describeSensitiveCall(mod, methodName, node.arguments);
    }

    // Check variable-based: fs.readFileSync(...)
    if (obj.type === 'Identifier' && moduleVars[obj.name]) {
      const mod = moduleVars[obj.name];
      return describeSensitiveCall(mod, methodName, node.arguments);
    }
  }

  // Bare call: exec(...), spawn(...)
  if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
    const name = node.callee.name;
    if (name === 'exec' || name === 'execSync' || name === 'spawn' || name === 'spawnSync') {
      const detail = extractLiteralArg(node.arguments);
      return { source: `child_process.${name}`, detail };
    }
  }

  return null;
}

function describeSensitiveCall(mod, method, args) {
  const detail = extractLiteralArg(args);
  if (mod === 'fs' && (method === 'readFileSync' || method === 'readFile')) {
    return { source: `fs.${method}`, detail };
  }
  if (mod === 'os' && method === 'homedir') {
    return { source: 'os.homedir', detail: '' };
  }
  if (mod === 'child_process' && (method === 'exec' || method === 'execSync' || method === 'spawn')) {
    return { source: `child_process.${method}`, detail };
  }
  if (mod === 'dns' && method === 'resolveTxt') {
    return { source: 'dns.resolveTxt', detail };
  }
  return null;
}

/**
 * Scan a function body (array of statements) for any tainted expression.
 * Returns the first taint found, or null.
 */
function scanBodyForTaint(body, moduleVars, taintedVars) {
  // Collect local tainted vars within this function scope too
  const localTainted = { ...taintedVars };

  let found = null;
  walkAST({ type: 'Program', body }, (node) => {
    if (found) return;

    // Variable assignment inside function
    if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations) {
        if (!decl.init || !decl.id || decl.id.type !== 'Identifier') continue;
        if (isRequireCall(decl.init) && SENSITIVE_MODULES.has(decl.init.arguments[0].value)) {
          moduleVars[decl.id.name] = decl.init.arguments[0].value;
        }
        const t = checkNodeTaint(decl.init, moduleVars);
        if (t) localTainted[decl.id.name] = t;
      }
    }

    const taint = checkNodeTaint(node, moduleVars);
    if (taint) {
      found = taint;
      return;
    }

    // Return of a tainted variable
    if (node.type === 'ReturnStatement' && node.argument) {
      if (node.argument.type === 'Identifier' && localTainted[node.argument.name]) {
        found = localTainted[node.argument.name];
      }
    }
  });
  return found;
}

// =============================================================================
// STEP 3 — Cross-file flow detection
// =============================================================================

/**
 * Detect cross-file dataflows: a tainted export from one module reaches a
 * network/exec sink in another module.
 * Max 2 levels of re-export (A → B → C).
 */
function detectCrossFileFlows(graph, taintedExports, packagePath) {
  // Expand taint through re-exports (max 2 levels)
  const expandedTaint = expandTaintThroughReexports(graph, taintedExports, packagePath);

  const flows = [];

  for (const relFile of Object.keys(graph)) {
    const absFile = path.resolve(packagePath, relFile);
    const ast = parseFile(absFile);
    if (!ast) continue;

    // Find which local variables are tainted via imports
    const localTaint = collectImportTaint(ast, relFile, graph, expandedTaint, packagePath);
    if (Object.keys(localTaint).length === 0) continue;

    // Propagate taint through local variable assignments (e.g., const data = read())
    propagateLocalTaint(ast, localTaint);

    // Find sinks that use tainted variables
    const sinks = findSinksUsingTainted(ast, localTaint);
    for (const sink of sinks) {
      const taintInfo = localTaint[sink.taintedVar];
      flows.push({
        severity: 'CRITICAL',
        type: 'cross_file_dataflow',
        sourceFile: taintInfo.sourceFile,
        source: `${taintInfo.source}${taintInfo.detail ? '(' + taintInfo.detail + ')' : ''}`,
        sinkFile: relFile,
        sink: sink.sink,
        description: `Credential read in ${taintInfo.sourceFile} exported and sent to network in ${relFile}`,
      });
    }
  }

  return flows;
}

/**
 * Expand taint through re-exports: if module B imports from A and re-exports,
 * B's exports are also tainted. Max 2 levels.
 */
function expandTaintThroughReexports(graph, taintedExports, packagePath) {
  const expanded = {};
  for (const f of Object.keys(taintedExports)) {
    expanded[f] = { ...taintedExports[f] };
  }

  for (let level = 0; level < 4; level++) {
    let changed = false;
    for (const relFile of Object.keys(graph)) {
      const absFile = path.resolve(packagePath, relFile);
      const ast = parseFile(absFile);
      if (!ast) continue;

      const localTaint = collectImportTaint(ast, relFile, graph, expanded, packagePath);

      // Propagate taint through local variable assignments:
      // e.g. const encoded = Buffer.from(raw) where raw is tainted
      if (Object.keys(localTaint).length > 0) {
        propagateLocalTaint(ast, localTaint);
      }

      // Check if any export returns a tainted variable (or inline require)
      if (!expanded[relFile]) expanded[relFile] = {};
      const fileDir = path.dirname(absFile);
      walkAST(ast, (node) => {
        // ES re-export: export { foo } from './reader'
        if (node.type === 'ExportNamedDeclaration' && node.source && typeof node.source.value === 'string') {
          const spec = node.source.value;
          if (isLocalImport(spec)) {
            const resolved = resolveLocal(fileDir, spec, packagePath);
            if (resolved && expanded[resolved]) {
              for (const specifier of node.specifiers) {
                const importedName = specifier.exported.name || specifier.exported.value;
                const sourceName = specifier.local.name || specifier.local.value;
                const srcTaint = expanded[resolved][sourceName];
                if (srcTaint && srcTaint.tainted && !expanded[relFile][importedName]) {
                  expanded[relFile][importedName] = {
                    tainted: true,
                    source: srcTaint.source,
                    detail: srcTaint.detail,
                    sourceFile: srcTaint.sourceFile || resolved,
                  };
                  changed = true;
                }
              }
            }
          }
          return;
        }

        // ES export of tainted variable: export const x = taintedVar
        if (node.type === 'ExportNamedDeclaration' && node.declaration) {
          const decl = node.declaration;
          if (decl.type === 'VariableDeclaration') {
            for (const vDecl of decl.declarations) {
              if (vDecl.id?.type === 'Identifier' && vDecl.init?.type === 'Identifier' && localTaint[vDecl.init.name]) {
                if (!expanded[relFile][vDecl.id.name]) {
                  expanded[relFile][vDecl.id.name] = {
                    tainted: true,
                    source: localTaint[vDecl.init.name].source,
                    detail: localTaint[vDecl.init.name].detail,
                    sourceFile: localTaint[vDecl.init.name].sourceFile,
                  };
                  changed = true;
                }
              }
            }
          }
          return;
        }

        // ES export default of tainted variable
        if (node.type === 'ExportDefaultDeclaration' && node.declaration) {
          const decl = node.declaration;
          if (decl.type === 'Identifier' && localTaint[decl.name]) {
            if (!expanded[relFile]['default']) {
              expanded[relFile]['default'] = {
                tainted: true,
                source: localTaint[decl.name].source,
                detail: localTaint[decl.name].detail,
                sourceFile: localTaint[decl.name].sourceFile,
              };
              changed = true;
            }
          }
          return;
        }

        if (!isModuleExportsAssign(node)) return;
        const value = node.expression.right;
        const exportName = getExportName(node.expression.left);

        // Direct re-export: module.exports = taintedVar
        if (value.type === 'Identifier' && localTaint[value.name]) {
          if (!expanded[relFile][exportName]) {
            expanded[relFile][exportName] = {
              tainted: true,
              source: localTaint[value.name].source,
              detail: localTaint[value.name].detail,
              sourceFile: localTaint[value.name].sourceFile,
            };
            changed = true;
          }
          return;
        }

        // Inline re-export: module.exports = require('./x')
        if (isRequireCall(value) && isLocalImport(value.arguments[0].value)) {
          const spec = value.arguments[0].value;
          const resolved = resolveLocal(fileDir, spec, packagePath);
          if (resolved && expanded[resolved]) {
            const defTaint = expanded[resolved]['default'];
            if (defTaint && defTaint.tainted && !expanded[relFile][exportName]) {
              expanded[relFile][exportName] = {
                tainted: true,
                source: defTaint.source,
                detail: defTaint.detail,
                sourceFile: defTaint.sourceFile || resolved,
              };
              changed = true;
            }
          }
          return;
        }

        // Wrapped re-export: module.exports = fn(taintedVar)
        if (value.type === 'CallExpression') {
          const tArg = findFirstTaintedArg(value.arguments, localTaint);
          if (tArg && !expanded[relFile][exportName]) {
            expanded[relFile][exportName] = {
              tainted: true,
              source: localTaint[tArg].source,
              detail: localTaint[tArg].detail,
              sourceFile: localTaint[tArg].sourceFile,
            };
            changed = true;
          }
        }
      });
    }
    if (!changed) break;
  }

  return expanded;
}

/**
 * Propagate taint through local variable assignments.
 * If `const x = fn(taintedVar)`, then x is also tainted.
 */
function propagateLocalTaint(ast, localTaint) {
  walkAST(ast, (node) => {
    if (node.type !== 'VariableDeclaration') return;
    for (const decl of node.declarations) {
      if (!decl.init || !decl.id || decl.id.type !== 'Identifier') continue;
      if (localTaint[decl.id.name]) continue; // already tainted
      const tArg = findFirstTaintedArgInExpr(decl.init, localTaint);
      if (tArg) {
        localTaint[decl.id.name] = { ...localTaint[tArg] };
      }
    }
  });
}

/**
 * Find the first tainted identifier among function call arguments.
 */
function findFirstTaintedArg(args, taintMap) {
  if (!args) return null;
  for (const arg of args) {
    if (arg.type === 'Identifier' && taintMap[arg.name] && !arg.name.startsWith('__module__')) {
      return arg.name;
    }
  }
  return null;
}

/**
 * Recursively check if an expression uses a tainted variable as argument.
 * Handles: fn(tainted), fn(a, fn2(tainted)), fn(tainted).method()
 */
function findFirstTaintedArgInExpr(node, taintMap) {
  if (!node) return null;
  if (node.type === 'Identifier' && taintMap[node.name] && !node.name.startsWith('__module__')) {
    return node.name;
  }
  if (node.type === 'CallExpression') {
    const fromArgs = findFirstTaintedArg(node.arguments, taintMap);
    if (fromArgs) return fromArgs;
    // Check callee for chained calls: fn(x).method()
    return findFirstTaintedArgInExpr(node.callee, taintMap);
  }
  if (node.type === 'MemberExpression') {
    return findFirstTaintedArgInExpr(node.object, taintMap);
  }
  return null;
}

/**
 * For a given file's AST, find which local variables receive tainted values
 * via require('./...') imports.
 */
function collectImportTaint(ast, currentFile, graph, taintedExports, packagePath) {
  const localTaint = {};
  const fileDir = path.dirname(path.resolve(packagePath, currentFile));

  // Handle ES import declarations
  walkAST(ast, (node) => {
    if (node.type !== 'ImportDeclaration' || !node.source || typeof node.source.value !== 'string') return;
    const spec = node.source.value;
    if (!isLocalImport(spec)) return;
    const resolved = resolveLocal(fileDir, spec, packagePath);
    if (!resolved || !taintedExports[resolved]) return;
    const modTaint = taintedExports[resolved];

    for (const specifier of node.specifiers) {
      if (specifier.type === 'ImportDefaultSpecifier') {
        const defTaint = modTaint['default'];
        if (defTaint && defTaint.tainted) {
          localTaint[specifier.local.name] = {
            source: defTaint.source,
            detail: defTaint.detail || '',
            sourceFile: defTaint.sourceFile || resolved,
          };
        }
        localTaint['__module__' + specifier.local.name] = { resolved, modTaint };
      } else if (specifier.type === 'ImportNamespaceSpecifier') {
        localTaint['__module__' + specifier.local.name] = { resolved, modTaint };
      } else if (specifier.type === 'ImportSpecifier') {
        const importedName = specifier.imported.name || specifier.imported.value;
        if (modTaint[importedName] && modTaint[importedName].tainted) {
          localTaint[specifier.local.name] = {
            source: modTaint[importedName].source,
            detail: modTaint[importedName].detail || '',
            sourceFile: modTaint[importedName].sourceFile || resolved,
          };
        }
      }
    }
  });

  // Handle CommonJS require() imports
  walkAST(ast, (node) => {
    if (node.type !== 'VariableDeclaration') return;
    for (const decl of node.declarations) {
      if (!decl.init || !decl.id) continue;

      // const reader = require('./reader')
      if (isRequireCall(decl.init) && isLocalImport(decl.init.arguments[0].value)) {
        const spec = decl.init.arguments[0].value;
        const resolved = resolveLocal(fileDir, spec, packagePath);
        if (!resolved || !taintedExports[resolved]) continue;
        const modTaint = taintedExports[resolved];

        if (decl.id.type === 'Identifier') {
          // Whole module import — check 'default' export
          const defTaint = modTaint['default'];
          if (defTaint && defTaint.tainted) {
            localTaint[decl.id.name] = {
              source: defTaint.source,
              detail: defTaint.detail || '',
              sourceFile: defTaint.sourceFile || resolved,
            };
          }
          // Also mark any named-export access later via member expressions
          // Store the module reference for named export resolution
          localTaint['__module__' + decl.id.name] = { resolved, modTaint };
        }

        // const { getToken } = require('./utils')
        if (decl.id.type === 'ObjectPattern') {
          for (const prop of decl.id.properties) {
            const key = prop.key && (prop.key.name || prop.key.value);
            const localName = prop.value && prop.value.name;
            if (key && localName && modTaint[key] && modTaint[key].tainted) {
              localTaint[localName] = {
                source: modTaint[key].source,
                detail: modTaint[key].detail || '',
                sourceFile: modTaint[key].sourceFile || resolved,
              };
            }
          }
        }
      }
    }
  });

  // Resolve member access, class instances, and method calls
  walkAST(ast, (node) => {
    if (node.type !== 'VariableDeclaration') return;
    for (const decl of node.declarations) {
      if (!decl.init || !decl.id || decl.id.type !== 'Identifier') continue;

      // const c = new Collector() — propagate module ref to instance
      if (decl.init.type === 'NewExpression' && decl.init.callee.type === 'Identifier') {
        const modRef = localTaint['__module__' + decl.init.callee.name];
        if (modRef) {
          localTaint['__module__' + decl.id.name] = modRef;
        }
      }

      // const data = reader.getData()  or  const data = reader.data
      if (decl.init.type === 'MemberExpression' && decl.init.object.type === 'Identifier') {
        const modRef = localTaint['__module__' + decl.init.object.name];
        if (modRef) {
          const propName = decl.init.property.name || decl.init.property.value;
          if (modRef.modTaint[propName] && modRef.modTaint[propName].tainted) {
            const t = modRef.modTaint[propName];
            localTaint[decl.id.name] = {
              source: t.source,
              detail: t.detail || '',
              sourceFile: t.sourceFile || modRef.resolved,
            };
          }
        }
      }
      if (decl.init.type === 'CallExpression' && decl.init.callee.type === 'MemberExpression') {
        const callee = decl.init.callee;
        if (callee.object.type === 'Identifier') {
          const modRef = localTaint['__module__' + callee.object.name];
          if (modRef) {
            const propName = callee.property.name || callee.property.value;
            if (modRef.modTaint[propName] && modRef.modTaint[propName].tainted) {
              const t = modRef.modTaint[propName];
              localTaint[decl.id.name] = {
                source: t.source,
                detail: t.detail || '',
                sourceFile: t.sourceFile || modRef.resolved,
              };
            }
          }
        }
      }
    }
  });

  // Clean up internal markers
  for (const key of Object.keys(localTaint)) {
    if (key.startsWith('__module__')) delete localTaint[key];
  }

  return localTaint;
}

/**
 * Find sink calls in the AST that use a tainted variable as argument.
 */
function findSinksUsingTainted(ast, localTaint) {
  const taintedNames = new Set(Object.keys(localTaint));
  const sinks = [];

  walkAST(ast, (node) => {
    if (node.type !== 'CallExpression') return;

    const sinkName = getSinkName(node);
    if (!sinkName) return;

    // Check if any argument references a tainted variable
    const taintedArg = findTaintedArgument(node.arguments, taintedNames);
    if (taintedArg) {
      sinks.push({ sink: sinkName, taintedVar: taintedArg });
    }
  });

  return sinks;
}

function getSinkName(callNode) {
  const callee = callNode.callee;

  // fetch(url), eval(code), WebSocket(url)
  if (callee.type === 'Identifier' && SINK_CALLEE_NAMES.has(callee.name)) {
    return `${callee.name}()`;
  }

  // https.request(...), child_process.exec(...)
  if (callee.type === 'MemberExpression') {
    const chain = getMemberChain(callee);
    if (SINK_MEMBER_METHODS.has(chain)) {
      return `${chain}()`;
    }
    // instance.connect(), socket.write(), ws.send()
    const method = callee.property.name || callee.property.value;
    if (SINK_INSTANCE_METHODS.has(method)) {
      return `${method}()`;
    }
  }

  // new WebSocket(url), new XMLHttpRequest()
  if (callNode.type === 'NewExpression') {
    if (callee.type === 'Identifier' && (callee.name === 'WebSocket' || callee.name === 'XMLHttpRequest')) {
      return `new ${callee.name}()`;
    }
  }

  return null;
}

function findTaintedArgument(args, taintedNames) {
  if (!args) return null;
  for (const arg of args) {
    if (arg.type === 'Identifier' && taintedNames.has(arg.name)) {
      return arg.name;
    }
    // Template literal: `https://evil.com/?d=${data}`
    if (arg.type === 'TemplateLiteral') {
      for (const expr of arg.expressions) {
        if (expr.type === 'Identifier' && taintedNames.has(expr.name)) {
          return expr.name;
        }
      }
    }
    // Concatenation: 'url' + data
    if (arg.type === 'BinaryExpression' && arg.operator === '+') {
      const left = findTaintedInExpr(arg.left, taintedNames);
      if (left) return left;
      const right = findTaintedInExpr(arg.right, taintedNames);
      if (right) return right;
    }
    // Object: { body: data }
    if (arg.type === 'ObjectExpression') {
      for (const prop of arg.properties) {
        if (prop.value && prop.value.type === 'Identifier' && taintedNames.has(prop.value.name)) {
          return prop.value.name;
        }
        // Spread: { ...data }
        if (prop.type === 'SpreadElement' && prop.argument?.type === 'Identifier' && taintedNames.has(prop.argument.name)) {
          return prop.argument.name;
        }
      }
    }
  }
  return null;
}

function findTaintedInExpr(node, taintedNames) {
  if (node.type === 'Identifier' && taintedNames.has(node.name)) return node.name;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return findTaintedInExpr(node.left, taintedNames) || findTaintedInExpr(node.right, taintedNames);
  }
  return null;
}

// =============================================================================
// Shared helpers
// =============================================================================

function parseFile(filePath) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
  return safeParse(content, { allowReturnOutsideFunction: true, allowImportExportEverywhere: true });
}

function walkAST(node, visitor) {
  if (!node || typeof node !== 'object') return;
  if (node.type) visitor(node);
  for (const key of Object.keys(node)) {
    if (key === 'type') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) walkAST(item, visitor);
      }
    } else if (child && typeof child === 'object' && child.type) {
      walkAST(child, visitor);
    }
  }
}

function isRequireCall(node) {
  return (
    node && node.type === 'CallExpression' &&
    node.callee && node.callee.type === 'Identifier' &&
    node.callee.name === 'require' &&
    node.arguments.length === 1 &&
    node.arguments[0].type === 'Literal' &&
    typeof node.arguments[0].value === 'string'
  );
}

function isLocalImport(spec) {
  return spec.startsWith('./') || spec.startsWith('../');
}

function isModuleExportsAssign(node) {
  if (node.type !== 'ExpressionStatement') return false;
  const expr = node.expression;
  if (expr.type !== 'AssignmentExpression' || expr.operator !== '=') return false;
  const left = expr.left;
  // module.exports = ...
  if (left.type === 'MemberExpression' && left.object.type === 'Identifier' && left.object.name === 'module' &&
      left.property.name === 'exports') return true;
  // module.exports.foo = ...
  if (left.type === 'MemberExpression' && left.object.type === 'MemberExpression' &&
      left.object.object.type === 'Identifier' && left.object.object.name === 'module' &&
      left.object.property.name === 'exports') return true;
  // exports.foo = ...
  if (left.type === 'MemberExpression' && left.object.type === 'Identifier' && left.object.name === 'exports') return true;
  return false;
}

function getExportName(left) {
  // module.exports = ... → 'default'
  if (left.type === 'MemberExpression' && left.object.type === 'Identifier' && left.object.name === 'module') {
    if (left.property.name === 'exports') return 'default';
  }
  // module.exports.foo = ... → 'foo'
  if (left.type === 'MemberExpression' && left.object.type === 'MemberExpression') {
    return left.property.name || left.property.value || 'default';
  }
  // exports.foo = ... → 'foo'
  if (left.type === 'MemberExpression' && left.object.type === 'Identifier' && left.object.name === 'exports') {
    return left.property.name || left.property.value || 'default';
  }
  return 'default';
}

function getFunctionBody(node) {
  if (!node) return null;
  if (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
    if (node.body.type === 'BlockStatement') return node.body.body;
    // Arrow with expression body: () => expr
    return [{ type: 'ReturnStatement', argument: node.body }];
  }
  return null;
}

function getMemberChain(node) {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const obj = getMemberChain(node.object);
    const prop = node.property.name || node.property.value || '';
    return `${obj}.${prop}`;
  }
  return '';
}

function extractLiteralArg(args) {
  if (!args || args.length === 0) return '';
  const first = args[0];
  if (first.type === 'Literal' && typeof first.value === 'string') return first.value;
  if (first.type === 'TemplateLiteral' && first.quasis.length === 1) return first.quasis[0].value.raw;
  return '';
}

function resolveLocal(fileDir, spec, packagePath) {
  const abs = path.resolve(fileDir, spec);
  if (isFileExists(abs)) return toRel(abs, packagePath);
  if (isFileExists(abs + '.js')) return toRel(abs + '.js', packagePath);
  if (isFileExists(abs + '.mjs')) return toRel(abs + '.mjs', packagePath);
  if (isFileExists(abs + '.cjs')) return toRel(abs + '.cjs', packagePath);
  if (isFileExists(path.join(abs, 'index.js'))) return toRel(path.join(abs, 'index.js'), packagePath);
  return null;
}

function isFileExists(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

function toRel(abs, packagePath) {
  return path.relative(packagePath, abs).replace(/\\/g, '/');
}

// =============================================================================
// STEP 4 — Sink export annotation (for callback-based cross-file detection)
// =============================================================================

/**
 * Annotate exports that contain network/exec sinks in their function body.
 * This is the inverse of annotateTaintedExports — finds "where data goes out".
 * Used to detect callback-based cross-file exfiltration:
 *   reader.js exports readConfig() (tainted source)
 *   sender.js exports sendData() (sink export)
 *   index.js connects them via callback: readConfig((data) => sendData(data))
 */
function annotateSinkExports(graph, packagePath) {
  const result = {};
  for (const relFile of Object.keys(graph)) {
    const absFile = path.resolve(packagePath, relFile);
    result[relFile] = analyzeSinkExports(absFile);
  }
  return result;
}

function analyzeSinkExports(filePath) {
  const ast = parseFile(filePath);
  if (!ast) return {};

  const sinkExports = {};

  // Track function declarations for shorthand property resolution
  const localFuncDefs = {};
  walkAST(ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id && node.id.name) {
      localFuncDefs[node.id.name] = node;
    }
  });

  // Collect require assignments for sink module detection
  const sinkModuleVars = {};
  walkAST(ast, (node) => {
    if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations) {
        if (!decl.init || !decl.id || decl.id.type !== 'Identifier') continue;
        if (isRequireCall(decl.init)) {
          const mod = decl.init.arguments[0].value;
          if (mod === 'http' || mod === 'https' || mod === 'net' || mod === 'dgram') {
            sinkModuleVars[decl.id.name] = mod;
          }
        }
      }
    }
    if (node.type === 'ImportDeclaration' && node.source && typeof node.source.value === 'string') {
      const mod = node.source.value;
      if (mod === 'http' || mod === 'https' || mod === 'net' || mod === 'dgram') {
        for (const spec of node.specifiers) {
          sinkModuleVars[spec.local.name] = mod;
        }
      }
    }
  });

  function bodyHasSink(body) {
    let found = null;
    walkAST({ type: 'Program', body }, (node) => {
      if (found) return;
      if (node.type === 'CallExpression') {
        // fetch(), eval()
        if (node.callee.type === 'Identifier' && SINK_CALLEE_NAMES.has(node.callee.name)) {
          found = node.callee.name + '()';
          return;
        }
        // https.request(), http.get()
        if (node.callee.type === 'MemberExpression') {
          const chain = getMemberChain(node.callee);
          if (SINK_MEMBER_METHODS.has(chain)) {
            found = chain + '()';
            return;
          }
          // Variable-based: const h = require('https'); h.request()
          if (node.callee.object.type === 'Identifier' && sinkModuleVars[node.callee.object.name]) {
            const method = node.callee.property.name || node.callee.property.value;
            if (method === 'request' || method === 'get') {
              found = sinkModuleVars[node.callee.object.name] + '.' + method + '()';
              return;
            }
          }
          // .write(), .send(), .connect()
          const method = node.callee.property.name || node.callee.property.value;
          if (SINK_INSTANCE_METHODS.has(method)) {
            found = method + '()';
            return;
          }
        }
      }
    });
    return found;
  }

  // Check module.exports = { fn: function() { ... sink ... } }
  walkAST(ast, (node) => {
    if (isModuleExportsAssign(node)) {
      const value = node.expression.right;
      const exportName = getExportName(node.expression.left);

      if (value.type === 'ObjectExpression' && exportName === 'default') {
        for (const prop of value.properties) {
          if (!prop.key) continue;
          const propName = prop.key.name || prop.key.value || 'unknown';
          let funcBody = getFunctionBody(prop.value);
          // Shorthand property referencing a FunctionDeclaration: { reportData }
          if (!funcBody && prop.value.type === 'Identifier' && localFuncDefs[prop.value.name]) {
            const fnNode = localFuncDefs[prop.value.name];
            funcBody = fnNode.body && fnNode.body.type === 'BlockStatement' ? fnNode.body.body : null;
          }
          if (funcBody) {
            const sink = bodyHasSink(funcBody);
            if (sink) {
              sinkExports[propName] = { hasSink: true, sink };
            }
          }
        }
      } else {
        const funcBody = getFunctionBody(value);
        if (funcBody) {
          const sink = bodyHasSink(funcBody);
          if (sink) {
            sinkExports[exportName] = { hasSink: true, sink };
          }
        }
      }
    }

    // export function foo() { ... sink ... }
    if (node.type === 'ExportNamedDeclaration' && node.declaration) {
      const decl = node.declaration;
      if (decl.type === 'FunctionDeclaration' && decl.id) {
        const funcBody = decl.body && decl.body.type === 'BlockStatement' ? decl.body.body : null;
        if (funcBody) {
          const sink = bodyHasSink(funcBody);
          if (sink) {
            sinkExports[decl.id.name] = { hasSink: true, sink };
          }
        }
      }
    }
  });

  return sinkExports;
}

/**
 * Detect callback-based cross-file flows.
 * Pattern: file imports tainted source fn + sink fn, connects them via callback.
 * Example: readConfig((err, data) => { sendData(data); })
 * Also: const data = readConfig(); sendData(data);
 */
function detectCallbackCrossFileFlows(graph, taintedExports, sinkExports, packagePath) {
  const expandedTaint = expandTaintThroughReexports(graph, taintedExports, packagePath);
  const flows = [];

  for (const relFile of Object.keys(graph)) {
    const absFile = path.resolve(packagePath, relFile);
    const ast = parseFile(absFile);
    if (!ast) continue;

    const fileDir = path.dirname(absFile);

    // Collect imported tainted source functions and imported sink functions
    const importedSources = {}; // varName → { sourceFile, source, detail }
    const importedSinks = {};   // varName → { sinkFile, sink }

    walkAST(ast, (node) => {
      if (node.type !== 'VariableDeclaration') return;
      for (const decl of node.declarations) {
        if (!decl.init || !decl.id) continue;

        // const { readConfig } = require('./reader')
        if (isRequireCall(decl.init) && isLocalImport(decl.init.arguments[0].value)) {
          const spec = decl.init.arguments[0].value;
          const resolved = resolveLocal(fileDir, spec, packagePath);
          if (!resolved) continue;

          if (decl.id.type === 'ObjectPattern') {
            for (const prop of decl.id.properties) {
              const key = prop.key && (prop.key.name || prop.key.value);
              const localName = prop.value && prop.value.name;
              if (!key || !localName) continue;

              // Check if this is a tainted source export
              if (expandedTaint[resolved] && expandedTaint[resolved][key] && expandedTaint[resolved][key].tainted) {
                const t = expandedTaint[resolved][key];
                importedSources[localName] = {
                  sourceFile: t.sourceFile || resolved,
                  source: t.source,
                  detail: t.detail || ''
                };
              }

              // Check if this is a sink export
              if (sinkExports[resolved] && sinkExports[resolved][key] && sinkExports[resolved][key].hasSink) {
                importedSinks[localName] = {
                  sinkFile: resolved,
                  sink: sinkExports[resolved][key].sink
                };
              }
            }
          }

          if (decl.id.type === 'Identifier') {
            // Whole module import: const reader = require('./reader')
            // Check default taint
            if (expandedTaint[resolved] && expandedTaint[resolved]['default'] && expandedTaint[resolved]['default'].tainted) {
              const t = expandedTaint[resolved]['default'];
              importedSources[decl.id.name] = {
                sourceFile: t.sourceFile || resolved,
                source: t.source,
                detail: t.detail || ''
              };
            }
            // Check default sink
            if (sinkExports[resolved] && sinkExports[resolved]['default'] && sinkExports[resolved]['default'].hasSink) {
              importedSinks[decl.id.name] = {
                sinkFile: resolved,
                sink: sinkExports[resolved]['default'].sink
              };
            }
          }
        }
      }
    });

    // If we have both imported sources and sinks, check for callback connections
    if (Object.keys(importedSources).length === 0 || Object.keys(importedSinks).length === 0) continue;

    // Pattern 1: sourceFn(function(err, data) { sinkFn(data); })
    // Pattern 2: const result = sourceFn(); sinkFn(result);
    walkAST(ast, (node) => {
      if (node.type !== 'CallExpression') return;

      // Check if the call is to an imported source
      const calleeName = node.callee.type === 'Identifier' ? node.callee.name : null;
      if (!calleeName || !importedSources[calleeName]) return;

      // Check if any argument is a callback that calls an imported sink
      for (const arg of node.arguments) {
        if (arg.type === 'FunctionExpression' || arg.type === 'ArrowFunctionExpression') {
          const body = arg.body.type === 'BlockStatement' ? arg.body.body : [arg.body];
          walkAST({ type: 'Program', body }, (inner) => {
            if (inner.type !== 'CallExpression') return;
            const innerCallee = inner.callee.type === 'Identifier' ? inner.callee.name : null;
            if (innerCallee && importedSinks[innerCallee]) {
              const src = importedSources[calleeName];
              const snk = importedSinks[innerCallee];
              // Avoid duplicates
              const key = `${src.sourceFile}→${relFile}→${snk.sinkFile}`;
              if (!flows.some(f => `${f.sourceFile}→${f.sinkFile}→${snk.sinkFile}` === key)) {
                flows.push({
                  severity: 'CRITICAL',
                  type: 'cross_file_dataflow',
                  sourceFile: src.sourceFile,
                  source: `${src.source}${src.detail ? '(' + src.detail + ')' : ''}`,
                  sinkFile: relFile,
                  sink: snk.sink,
                  description: `Credential read in ${src.sourceFile} passed via callback to network sink (${snk.sink}) imported from ${snk.sinkFile} in ${relFile}`,
                });
              }
            }
          });
        }
      }
    });
  }

  return flows;
}

module.exports = {
  buildModuleGraph, annotateTaintedExports, detectCrossFileFlows,
  annotateSinkExports, detectCallbackCrossFileFlows,
  resolveLocal, extractLocalImports, parseFile, isLocalImport, toRel, isFileExists,
  tryResolveConcatRequire
};
