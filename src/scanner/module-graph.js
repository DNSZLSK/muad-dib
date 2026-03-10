const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const { findFiles, EXCLUDED_DIRS, debugLog } = require('../utils');
const { ACORN_OPTIONS: BASE_ACORN_OPTIONS, safeParse } = require('../shared/constants.js');

// --- Bounded path limits ---
const MAX_GRAPH_NODES = 50;   // Max files in dependency graph
const MAX_GRAPH_EDGES = 200;  // Max total import edges
const MAX_FLOWS = 20;         // Max cross-file flow findings per package

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
  'dns.resolveTxt', 'dns.resolve', 'dns.resolve4', 'dns.resolve6',
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

  // Bounded path: skip module graph for very large packages
  if (files.length > MAX_GRAPH_NODES) {
    debugLog(`[MODULE-GRAPH] Skipping: ${files.length} files exceeds MAX_GRAPH_NODES (${MAX_GRAPH_NODES})`);
    return graph;
  }

  let totalEdges = 0;
  for (const absFile of files) {
    const relFile = toRel(absFile, packagePath);
    const imports = extractLocalImports(absFile, packagePath);
    totalEdges += imports.length;
    if (totalEdges > MAX_GRAPH_EDGES) {
      debugLog(`[MODULE-GRAPH] Edge limit reached (${totalEdges} > ${MAX_GRAPH_EDGES}), returning partial graph`);
      graph[relFile] = imports;
      break;
    }
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
  if (mod === 'fs' && (method === 'readFileSync' || method === 'readFile' || method === 'createReadStream')) {
    return { source: `fs.${method}`, detail };
  }
  if (mod === 'os' && (method === 'homedir' || method === 'hostname' || method === 'userInfo' || method === 'networkInterfaces')) {
    return { source: `os.${method}`, detail: '' };
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
function detectCrossFileFlows(graph, taintedExports, sinkExportsOrPath, packagePath) {
  // Backward compat: old callers pass (graph, tainted, path) — 3 args
  let sinkExports = sinkExportsOrPath;
  if (typeof sinkExportsOrPath === 'string') {
    packagePath = sinkExportsOrPath;
    sinkExports = null;
  }
  // Expand taint through re-exports (max 2 levels)
  const expandedTaint = expandTaintThroughReexports(graph, taintedExports, packagePath);

  const flows = [];

  for (const relFile of Object.keys(graph)) {
    const absFile = path.resolve(packagePath, relFile);
    const ast = parseFile(absFile);
    if (!ast) continue;

    // Pipe chain cross-file flows (runs before localTaint check — doesn't need localTaint)
    if (sinkExports && flows.length < MAX_FLOWS) {
      const pipeFlows = findPipeChainCrossFileFlows(ast, relFile, graph, expandedTaint, sinkExports, packagePath);
      for (const flow of pipeFlows) {
        if (flows.length >= MAX_FLOWS) break;
        const key = `${flow.sourceFile}→${flow.sinkFile}`;
        if (!flows.some(f => `${f.sourceFile}→${f.sinkFile}` === key)) {
          flows.push(flow);
        }
      }
    }

    // Find which local variables are tainted via imports
    const localTaint = collectImportTaint(ast, relFile, graph, expandedTaint, packagePath);
    if (Object.keys(localTaint).length === 0) continue;

    // Propagate taint through local variable assignments (e.g., const data = read())
    propagateLocalTaint(ast, localTaint);

    // Find sinks that use tainted variables (direct sink calls at call site)
    const sinks = findSinksUsingTainted(ast, localTaint);
    for (const sink of sinks) {
      if (flows.length >= MAX_FLOWS) break;
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

    // Find imported methods that internally contain sinks and receive tainted args
    if (sinkExports && flows.length < MAX_FLOWS) {
      const importedSinkFlows = findImportedSinkMethodCalls(ast, localTaint, relFile, graph, sinkExports, packagePath);
      for (const flow of importedSinkFlows) {
        if (flows.length >= MAX_FLOWS) break;
        // Deduplicate: skip if same sourceFile→sinkFile already found
        const key = `${flow.sourceFile}→${flow.sinkFile}`;
        if (!flows.some(f => `${f.sourceFile}→${f.sinkFile}` === key)) {
          flows.push(flow);
        }
      }
    }

    if (flows.length >= MAX_FLOWS) {
      debugLog(`[MODULE-GRAPH] Flow limit reached (${MAX_FLOWS}), returning partial results`);
      break;
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

  // Resolve this.X = new Y() in class constructors, then this.X.method() in methods
  walkAST(ast, (node) => {
    if (node.type !== 'ClassDeclaration' && node.type !== 'ClassExpression') return;
    if (!node.body || node.body.type !== 'ClassBody') return;

    // Phase 1: scan constructor for this.X = new Y() assignments
    const thisRefs = {}; // propName → __module__ ref
    for (const method of node.body.body) {
      if (method.type !== 'MethodDefinition' || method.kind !== 'constructor') continue;
      const ctorBody = method.value && method.value.body;
      if (!ctorBody) continue;
      walkAST(ctorBody, (n) => {
        // this.reader = new Reader(...)
        if (n.type === 'ExpressionStatement' && n.expression.type === 'AssignmentExpression' &&
            n.expression.left.type === 'MemberExpression' &&
            n.expression.left.object.type === 'ThisExpression' &&
            n.expression.right.type === 'NewExpression' &&
            n.expression.right.callee.type === 'Identifier') {
          const prop = n.expression.left.property.name || n.expression.left.property.value;
          const className = n.expression.right.callee.name;
          const modRef = localTaint['__module__' + className];
          if (prop && modRef) {
            thisRefs[prop] = modRef;
          }
        }
      });
    }

    if (Object.keys(thisRefs).length === 0) return;

    // Phase 2: scan all methods for this.X.method() calls that return tainted data
    for (const method of node.body.body) {
      if (method.type !== 'MethodDefinition' || method.kind === 'constructor') continue;
      const methodBody = method.value && method.value.body;
      if (!methodBody) continue;
      walkAST(methodBody, (n) => {
        if (n.type !== 'VariableDeclaration') return;
        for (const decl of n.declarations) {
          if (!decl.init || !decl.id || decl.id.type !== 'Identifier') continue;
          // const data = this.reader.readAll()
          if (decl.init.type === 'CallExpression' &&
              decl.init.callee.type === 'MemberExpression' &&
              decl.init.callee.object.type === 'MemberExpression' &&
              decl.init.callee.object.object.type === 'ThisExpression') {
            const thisProp = decl.init.callee.object.property.name || decl.init.callee.object.property.value;
            const methodName = decl.init.callee.property.name || decl.init.callee.property.value;
            const modRef = thisRefs[thisProp];
            if (modRef && methodName && modRef.modTaint[methodName] && modRef.modTaint[methodName].tainted) {
              const t = modRef.modTaint[methodName];
              localTaint[decl.id.name] = {
                source: t.source,
                detail: t.detail || '',
                sourceFile: t.sourceFile || modRef.resolved,
              };
            }
          }
        }
      });
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
    if (sinkName) {
      // Check if any argument references a tainted variable
      const taintedArg = findTaintedArgument(node.arguments, taintedNames);
      if (taintedArg) {
        sinks.push({ sink: sinkName, taintedVar: taintedArg });
      }
    }

    // Pipe chain detection: tainted.pipe(transform).pipe(networkSink)
    // .pipe() returns the destination, so chains propagate taint.
    // Walk up to MAX_PIPE_DEPTH steps.
    if (node.callee && node.callee.type === 'MemberExpression') {
      const method = node.callee.property.name || node.callee.property.value;
      if (method === 'pipe') {
        const pipeSource = resolvePipeChainSource(node, taintedNames, 0);
        if (pipeSource) {
          // The final .pipe() destination — check if it's a known sink
          const destArg = node.arguments && node.arguments[0];
          if (destArg) {
            const destSink = getArgSinkName(destArg);
            if (destSink) {
              sinks.push({ sink: destSink, taintedVar: pipeSource });
            }
          }
        }
      }
    }
  });

  return sinks;
}

const MAX_PIPE_DEPTH = 5;

/**
 * Walk a .pipe() chain leftward to find the tainted source variable.
 * tainted.pipe(a).pipe(b) → check tainted, recurse through .pipe(a)
 */
function resolvePipeChainSource(pipeCallNode, taintedNames, depth) {
  if (depth > MAX_PIPE_DEPTH) return null;
  const obj = pipeCallNode.callee && pipeCallNode.callee.object;
  if (!obj) return null;

  // Base case: taintedVar.pipe(...)
  if (obj.type === 'Identifier' && taintedNames.has(obj.name)) {
    return obj.name;
  }

  // Recursive case: something.pipe(...).pipe(...)
  if (obj.type === 'CallExpression' && obj.callee && obj.callee.type === 'MemberExpression') {
    const method = obj.callee.property.name || obj.callee.property.value;
    if (method === 'pipe') {
      return resolvePipeChainSource(obj, taintedNames, depth + 1);
    }
  }

  return null;
}

/**
 * Check if a .pipe() destination argument is a network sink.
 * E.g., net.connect(...), http.request(...)
 */
function getArgSinkName(argNode) {
  // net.connect(...) as pipe destination
  if (argNode.type === 'CallExpression') {
    return getSinkName(argNode);
  }
  // Direct identifier that is a known sink instance (less common)
  return null;
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

/**
 * Find calls to imported methods whose bodies contain sinks, receiving tainted args.
 * Pattern: reporter.report(taintedData) where report() internally calls https.request().
 */
function findImportedSinkMethodCalls(ast, localTaint, relFile, graph, sinkExports, packagePath) {
  const flows = [];
  const taintedNames = new Set(Object.keys(localTaint));
  const fileDir = path.dirname(path.resolve(packagePath, relFile));

  // Build map: varName → resolved module path (for require-based imports)
  const moduleRefs = {};
  walkAST(ast, (node) => {
    if (node.type !== 'VariableDeclaration') return;
    for (const decl of node.declarations) {
      if (!decl.init || !decl.id) continue;
      // const reporter = require('./reporter')
      if (decl.id.type === 'Identifier' && isRequireCall(decl.init) && isLocalImport(decl.init.arguments[0].value)) {
        const resolved = resolveLocal(fileDir, decl.init.arguments[0].value, packagePath);
        if (resolved) moduleRefs[decl.id.name] = resolved;
      }
      // const r = new Reporter() where Reporter was required above
      if (decl.id.type === 'Identifier' && decl.init.type === 'NewExpression' && decl.init.callee.type === 'Identifier') {
        const ctorRef = moduleRefs[decl.init.callee.name];
        if (ctorRef) moduleRefs[decl.id.name] = ctorRef;
      }
    }
  });

  // Also handle ESM: import reporter from './reporter'
  for (const node of ast.body) {
    if (node.type === 'ImportDeclaration' && node.source && typeof node.source.value === 'string') {
      if (isLocalImport(node.source.value)) {
        const resolved = resolveLocal(fileDir, node.source.value, packagePath);
        if (!resolved) continue;
        for (const spec of node.specifiers) {
          moduleRefs[spec.local.name] = resolved;
        }
      }
    }
  }

  // Resolve this.X = new Y() in class constructors → thisRefs map
  const thisRefs = {}; // propName → resolved module path
  walkAST(ast, (node) => {
    if (node.type !== 'ClassDeclaration' && node.type !== 'ClassExpression') return;
    if (!node.body || node.body.type !== 'ClassBody') return;
    for (const method of node.body.body) {
      if (method.type !== 'MethodDefinition' || method.kind !== 'constructor') continue;
      const ctorBody = method.value && method.value.body;
      if (!ctorBody) continue;
      walkAST(ctorBody, (n) => {
        if (n.type === 'ExpressionStatement' && n.expression.type === 'AssignmentExpression' &&
            n.expression.left.type === 'MemberExpression' &&
            n.expression.left.object.type === 'ThisExpression' &&
            n.expression.right.type === 'NewExpression' &&
            n.expression.right.callee.type === 'Identifier') {
          const prop = n.expression.left.property.name || n.expression.left.property.value;
          const className = n.expression.right.callee.name;
          const resolved = moduleRefs[className];
          if (prop && resolved) {
            thisRefs[prop] = resolved;
          }
        }
      });
    }
  });

  // Find obj.method(taintedArg) where obj's module has sink exports
  walkAST(ast, (node) => {
    if (node.type !== 'CallExpression') return;
    const callee = node.callee;

    // Pattern: obj.method(taintedArg)
    if (callee.type === 'MemberExpression' && callee.object.type === 'Identifier') {
      const objName = callee.object.name;
      const methodName = callee.property.name || callee.property.value;
      const resolved = moduleRefs[objName];
      if (!resolved || !methodName) return;

      // Check if this method is a known sink export
      const moduleSinks = sinkExports[resolved];
      if (!moduleSinks) return;
      const sinkInfo = moduleSinks[methodName] || moduleSinks['default'];
      if (!sinkInfo || !sinkInfo.hasSink) return;

      // Check if any argument is tainted
      const taintedArg = findTaintedArgument(node.arguments, taintedNames);
      if (!taintedArg) return;

      const taintInfo = localTaint[taintedArg];
      if (!taintInfo) return;

      flows.push({
        severity: 'CRITICAL',
        type: 'cross_file_dataflow',
        sourceFile: taintInfo.sourceFile,
        source: `${taintInfo.source}${taintInfo.detail ? '(' + taintInfo.detail + ')' : ''}`,
        sinkFile: relFile,
        sink: sinkInfo.sink,
        description: `Credential read in ${taintInfo.sourceFile} flows to imported sink method ${objName}.${methodName}() (${sinkInfo.sink}) in ${relFile}`,
      });
    }

    // Pattern: this.transport.report(taintedArg) where transport's module has sink exports
    if (callee.type === 'MemberExpression' &&
        callee.object.type === 'MemberExpression' &&
        callee.object.object.type === 'ThisExpression') {
      const thisProp = callee.object.property.name || callee.object.property.value;
      const methodName = callee.property.name || callee.property.value;
      const resolved = thisRefs[thisProp];
      if (resolved && methodName) {
        const moduleSinks = sinkExports[resolved];
        if (moduleSinks) {
          const sinkInfo = moduleSinks[methodName] || moduleSinks['default'];
          if (sinkInfo && sinkInfo.hasSink) {
            const taintedArg = findTaintedArgument(node.arguments, taintedNames);
            if (taintedArg) {
              const taintInfo = localTaint[taintedArg];
              if (taintInfo) {
                flows.push({
                  severity: 'CRITICAL',
                  type: 'cross_file_dataflow',
                  sourceFile: taintInfo.sourceFile,
                  source: `${taintInfo.source}${taintInfo.detail ? '(' + taintInfo.detail + ')' : ''}`,
                  sinkFile: relFile,
                  sink: sinkInfo.sink,
                  description: `Credential read in ${taintInfo.sourceFile} flows via this.${thisProp}.${methodName}() (${sinkInfo.sink}) in ${relFile}`,
                });
              }
            }
          }
        }
      }
    }

    // Pattern: sinkFn(taintedArg) where sinkFn is a direct import of a sink function
    if (callee.type === 'Identifier') {
      const resolved = moduleRefs[callee.name];
      if (!resolved) return;
      const moduleSinks = sinkExports[resolved];
      if (!moduleSinks) return;
      const sinkInfo = moduleSinks['default'] || moduleSinks[callee.name];
      if (!sinkInfo || !sinkInfo.hasSink) return;

      const taintedArg = findTaintedArgument(node.arguments, taintedNames);
      if (!taintedArg) return;

      const taintInfo = localTaint[taintedArg];
      if (!taintInfo) return;

      flows.push({
        severity: 'CRITICAL',
        type: 'cross_file_dataflow',
        sourceFile: taintInfo.sourceFile,
        source: `${taintInfo.source}${taintInfo.detail ? '(' + taintInfo.detail + ')' : ''}`,
        sinkFile: relFile,
        sink: sinkInfo.sink,
        description: `Credential read in ${taintInfo.sourceFile} flows to imported sink function ${callee.name}() (${sinkInfo.sink}) in ${relFile}`,
      });
    }
  });

  return flows;
}

/**
 * Detect cross-file flows through .pipe() chains involving imported module instances.
 * Pattern: reader.stream().pipe(transform).pipe(sink.createWritable())
 * where reader and sink are instances of imported module classes.
 */
function findPipeChainCrossFileFlows(ast, relFile, graph, taintedExports, sinkExports, packagePath) {
  const flows = [];
  const fileDir = path.dirname(path.resolve(packagePath, relFile));

  // Build moduleRefs: varName → resolved module path
  const moduleRefs = {};
  walkAST(ast, (node) => {
    if (node.type !== 'VariableDeclaration') return;
    for (const decl of node.declarations) {
      if (!decl.init || !decl.id || decl.id.type !== 'Identifier') continue;
      if (isRequireCall(decl.init) && isLocalImport(decl.init.arguments[0].value)) {
        const resolved = resolveLocal(fileDir, decl.init.arguments[0].value, packagePath);
        if (resolved) moduleRefs[decl.id.name] = resolved;
      }
      if (decl.init.type === 'NewExpression' && decl.init.callee.type === 'Identifier') {
        const ctorRef = moduleRefs[decl.init.callee.name];
        if (ctorRef) moduleRefs[decl.id.name] = ctorRef;
      }
    }
  });

  // Walk AST for .pipe() chains
  walkAST(ast, (node) => {
    if (node.type !== 'CallExpression') return;
    if (!node.callee || node.callee.type !== 'MemberExpression') return;
    const method = node.callee.property.name || node.callee.property.value;
    if (method !== 'pipe') return;

    // Walk leftward to find the source of the pipe chain
    let sourceInfo = null;
    let current = node;
    let depth = 0;
    while (current && depth < MAX_PIPE_DEPTH) {
      const obj = current.callee && current.callee.object;
      if (!obj) break;

      if (obj.type === 'CallExpression' && obj.callee && obj.callee.type === 'MemberExpression') {
        const innerMethod = obj.callee.property.name || obj.callee.property.value;
        // Another .pipe() (intermediate step) — keep walking regardless of sub-object type
        if (innerMethod === 'pipe') {
          current = obj;
          depth++;
          continue;
        }
        // Non-pipe method call on an Identifier: instance.method() from a tainted module
        if (obj.callee.object.type === 'Identifier') {
          const objName = obj.callee.object.name;
          const resolved = moduleRefs[objName];
          if (resolved && taintedExports[resolved]) {
            const modTaint = taintedExports[resolved];
            if (modTaint[innerMethod] && modTaint[innerMethod].tainted) {
              const t = modTaint[innerMethod];
              sourceInfo = {
                source: `${t.source}${t.detail ? '(' + t.detail + ')' : ''}`,
                sourceFile: t.sourceFile || resolved,
              };
            }
          }
        }
      }
      break;
    }

    if (!sourceInfo) return;

    // Check ALL pipe destinations in the chain (walk outward)
    // For the current (outermost) .pipe(), check its argument
    const checkPipeDest = (pipeNode) => {
      const destArg = pipeNode.arguments && pipeNode.arguments[0];
      if (!destArg) return null;

      // Direct sink: net.connect(), https.request()
      const directSink = getSinkName(destArg);
      if (directSink) return { sink: directSink, sinkFile: relFile };

      // Module method sink: sink.createWritable() where sink module has sink exports
      if (destArg.type === 'CallExpression' && destArg.callee && destArg.callee.type === 'MemberExpression' &&
          destArg.callee.object.type === 'Identifier') {
        const destObj = destArg.callee.object.name;
        const destMethod = destArg.callee.property.name || destArg.callee.property.value;
        const destResolved = moduleRefs[destObj];
        if (destResolved && sinkExports[destResolved]) {
          const sInfo = sinkExports[destResolved][destMethod] || sinkExports[destResolved]['default'];
          if (sInfo && sInfo.hasSink) {
            return { sink: sInfo.sink, sinkFile: destResolved };
          }
        }
      }
      return null;
    };

    // Check the outermost .pipe() destination
    let sinkResult = checkPipeDest(node);

    // Also walk inward through intermediate .pipe() steps to check their destinations
    if (!sinkResult) {
      let inner = node.callee && node.callee.object;
      let d = 0;
      while (inner && d < MAX_PIPE_DEPTH && !sinkResult) {
        if (inner.type === 'CallExpression' && inner.callee && inner.callee.type === 'MemberExpression') {
          const m = inner.callee.property.name || inner.callee.property.value;
          if (m === 'pipe') {
            sinkResult = checkPipeDest(inner);
            inner = inner.callee.object;
            d++;
            continue;
          }
        }
        break;
      }
    }

    if (sinkResult) {
      flows.push({
        severity: 'CRITICAL',
        type: 'cross_file_dataflow',
        sourceFile: sourceInfo.sourceFile,
        source: sourceInfo.source,
        sinkFile: relFile,
        sink: sinkResult.sink,
        description: `${sourceInfo.source} in ${sourceInfo.sourceFile} piped to ${sinkResult.sink} in ${relFile}`,
      });
    }
  });

  return flows;
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
          if (mod === 'http' || mod === 'https' || mod === 'net' || mod === 'dgram' || mod === 'dns') {
            sinkModuleVars[decl.id.name] = mod;
          }
        }
      }
    }
    if (node.type === 'ImportDeclaration' && node.source && typeof node.source.value === 'string') {
      const mod = node.source.value;
      if (mod === 'http' || mod === 'https' || mod === 'net' || mod === 'dgram' || mod === 'dns') {
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
            if (method === 'request' || method === 'get' || method === 'resolveTxt' || method === 'resolve' || method === 'resolve4' || method === 'resolve6') {
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
      } else if ((value.type === 'ClassExpression' || value.type === 'Identifier') && exportName === 'default') {
        // module.exports = ClassName — resolve class from local declarations
        let classNode = value;
        if (value.type === 'Identifier') {
          // Find class declaration in AST
          walkAST(ast, (n) => {
            if (n.type === 'ClassDeclaration' && n.id && n.id.name === value.name) {
              classNode = n;
            }
          });
        }
        if (classNode.body && classNode.body.type === 'ClassBody') {
          for (const method of classNode.body.body) {
            if (method.type !== 'MethodDefinition' || method.kind === 'constructor') continue;
            const methodName = method.key && (method.key.name || method.key.value);
            const funcBody = method.value && method.value.body;
            if (!methodName || !funcBody) continue;
            const body = funcBody.type === 'BlockStatement' ? funcBody.body : null;
            if (body) {
              const sink = bodyHasSink(body);
              if (sink) {
                sinkExports[methodName] = { hasSink: true, sink };
              }
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

// =============================================================================
// STEP 5 — EventEmitter cross-module detection
// =============================================================================

// Standard Node.js event names that are NOT indicative of malicious intent
const BENIGN_EVENT_NAMES = new Set([
  'error', 'end', 'close', 'data', 'finish', 'readable', 'drain',
  'connect', 'listening', 'message', 'timeout', 'response', 'request',
  'open', 'pause', 'resume', 'pipe', 'unpipe', 'exit', 'disconnect',
]);

const MAX_EMITTER_FLOWS = 2; // Cap per package to prevent explosion on event-heavy libs

/**
 * Detect cross-file EventEmitter flows.
 * Pattern: file A does emitter.emit('event', taintedData),
 *          file B does emitter.on('event', (data) => networkSink(data))
 * where the emitter is shared via a common imported module.
 */
function detectEventEmitterFlows(graph, taintedExports, sinkExports, packagePath) {
  const expandedTaint = expandTaintThroughReexports(graph, taintedExports, packagePath);
  const flows = [];

  // Phase 1: collect all emit() and on() calls across files
  const emitCalls = []; // { file, eventName, taintedSource, emitterVar }
  const onCalls = [];   // { file, eventName, hasSink, sinkName, emitterVar }

  for (const relFile of Object.keys(graph)) {
    const absFile = path.resolve(packagePath, relFile);
    const ast = parseFile(absFile);
    if (!ast) continue;

    // Build taint map for this file (imports + local sources)
    const localTaint = collectImportTaint(ast, relFile, graph, expandedTaint, packagePath);

    // Also detect local taint sources (process.env, fs.readFileSync, os.homedir)
    // collectImportTaint only handles cross-file imports; we need intra-file sources too
    const moduleVars = {};
    walkAST(ast, (n) => {
      if (n.type === 'VariableDeclaration') {
        for (const decl of n.declarations) {
          if (!decl.init || !decl.id || decl.id.type !== 'Identifier') continue;
          if (isRequireCall(decl.init) && SENSITIVE_MODULES.has(decl.init.arguments[0].value)) {
            moduleVars[decl.id.name] = decl.init.arguments[0].value;
          }
          const t = checkNodeTaint(decl.init, moduleVars);
          if (t && !localTaint[decl.id.name]) {
            localTaint[decl.id.name] = { source: t.source, detail: t.detail || '', sourceFile: relFile };
          }
          // ObjectExpression: const metrics = { hostname: os.hostname(), ... }
          // If any property value is tainted, the whole object is tainted
          if (!t && !localTaint[decl.id.name] && decl.init.type === 'ObjectExpression') {
            for (const prop of decl.init.properties) {
              if (!prop.value) continue;
              const pt = checkNodeTaint(prop.value, moduleVars);
              if (pt) {
                localTaint[decl.id.name] = { source: pt.source, detail: pt.detail || '', sourceFile: relFile };
                break;
              }
            }
          }
        }
      }
    });

    propagateLocalTaint(ast, localTaint);
    const taintedNames = new Set(Object.keys(localTaint));

    // Collect class method bodies for resolving this.method() calls in handlers
    const classMethodBodies = Object.create(null);
    walkAST(ast, (n) => {
      if (n.type !== 'ClassDeclaration' && n.type !== 'ClassExpression') return;
      if (!n.body || n.body.type !== 'ClassBody') return;
      for (const member of n.body.body) {
        if (member.type !== 'MethodDefinition') continue;
        const name = member.key && (member.key.name || member.key.value);
        if (!name || name === 'constructor') continue;
        const body = member.value && member.value.body;
        if (body && body.type === 'BlockStatement') {
          if (!classMethodBodies[name]) classMethodBodies[name] = [];
          classMethodBodies[name].push(body.body);
        }
      }
    });

    walkAST(ast, (node) => {
      if (node.type !== 'CallExpression' || !node.callee || node.callee.type !== 'MemberExpression') return;
      const method = node.callee.property.name || node.callee.property.value;
      if (!method) return;

      const emitterVar = getEmitterVarName(node.callee.object);

      // emitter.emit('eventName', data)
      if (method === 'emit' && node.arguments.length >= 2) {
        const eventNameNode = node.arguments[0];
        const eventName = (eventNameNode.type === 'Literal' && typeof eventNameNode.value === 'string') ? eventNameNode.value : null;
        if (!eventName || BENIGN_EVENT_NAMES.has(eventName)) return;

        // Check if any data argument (2nd+) is tainted
        const dataArgs = node.arguments.slice(1);
        const taintedArg = findTaintedArgument(dataArgs, taintedNames);
        if (!taintedArg) return;

        emitCalls.push({
          file: relFile,
          eventName,
          taintedSource: localTaint[taintedArg],
          emitterVar,
        });
      }

      // emitter.on('eventName', handler) — check if handler has a network sink
      if ((method === 'on' || method === 'addListener' || method === 'once') && node.arguments.length >= 2) {
        const eventNameNode = node.arguments[0];
        const eventName = (eventNameNode.type === 'Literal' && typeof eventNameNode.value === 'string') ? eventNameNode.value : null;
        if (!eventName || BENIGN_EVENT_NAMES.has(eventName)) return;

        const handler = node.arguments[1];
        if (handler.type !== 'FunctionExpression' && handler.type !== 'ArrowFunctionExpression') return;

        // Check if handler body contains a network sink
        const handlerBody = handler.body.type === 'BlockStatement' ? handler.body.body : [handler.body];
        let sinkFound = null;
        walkAST({ type: 'Program', body: handlerBody }, (inner) => {
          if (sinkFound) return;
          if (inner.type === 'CallExpression') {
            const sName = getSinkName(inner);
            if (sName) sinkFound = sName;
          }
        });

        // If no direct sink, check this.method() calls → resolve to class method bodies
        if (!sinkFound && Object.keys(classMethodBodies).length > 0) {
          walkAST({ type: 'Program', body: handlerBody }, (inner) => {
            if (sinkFound) return;
            if (inner.type === 'CallExpression' &&
                inner.callee.type === 'MemberExpression' &&
                inner.callee.object.type === 'ThisExpression') {
              const methodName = inner.callee.property.name || inner.callee.property.value;
              if (methodName && classMethodBodies[methodName]) {
                for (const methodBody of classMethodBodies[methodName]) {
                  walkAST({ type: 'Program', body: methodBody }, (n2) => {
                    if (sinkFound) return;
                    if (n2.type === 'CallExpression') {
                      const sName = getSinkName(n2);
                      if (sName) sinkFound = sName;
                    }
                  });
                  if (sinkFound) return;
                }
              }
            }
          });
        }

        if (sinkFound) {
          onCalls.push({
            file: relFile,
            eventName,
            hasSink: true,
            sinkName: sinkFound,
            emitterVar,
          });
        }
      }
    });
  }

  // Phase 2: match emit + on by event name (cross-file only)
  for (const emit of emitCalls) {
    if (flows.length >= MAX_EMITTER_FLOWS) break;
    for (const on of onCalls) {
      if (flows.length >= MAX_EMITTER_FLOWS) break;
      if (emit.eventName !== on.eventName) continue;
      if (emit.file === on.file) continue; // intra-file handled by dataflow scanner

      // Dedup by event name
      if (flows.some(f => f.description.includes(emit.eventName))) continue;

      const taintInfo = emit.taintedSource;
      flows.push({
        severity: 'CRITICAL',
        type: 'cross_file_dataflow',
        sourceFile: taintInfo.sourceFile || emit.file,
        source: `${taintInfo.source}${taintInfo.detail ? '(' + taintInfo.detail + ')' : ''}`,
        sinkFile: on.file,
        sink: on.sinkName,
        description: `Credential emitted via EventEmitter '${emit.eventName}' in ${emit.file} → handler with ${on.sinkName} in ${on.file}`,
      });
    }
  }

  return flows;
}

/**
 * Extract the variable name from an emitter expression.
 * Handles: emitter.emit(), this.emitter.emit(), bus.emit()
 */
function getEmitterVarName(node) {
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression' && node.object.type === 'ThisExpression') {
    return 'this.' + (node.property.name || node.property.value);
  }
  return null;
}

module.exports = {
  buildModuleGraph, annotateTaintedExports, detectCrossFileFlows,
  annotateSinkExports, detectCallbackCrossFileFlows, detectEventEmitterFlows,
  resolveLocal, extractLocalImports, parseFile, isLocalImport, toRel, isFileExists,
  tryResolveConcatRequire,
  MAX_GRAPH_NODES, MAX_GRAPH_EDGES, MAX_FLOWS
};
