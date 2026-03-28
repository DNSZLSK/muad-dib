'use strict';

const path = require('path');
const { debugLog } = require('../../utils');
const { MAX_FLOWS, MAX_TAINT_DEPTH, SINK_CALLEE_NAMES, SINK_MEMBER_METHODS, SINK_INSTANCE_METHODS } = require('./constants.js');
const {
  parseFile, walkAST, isRequireCall, isLocalImport, isModuleExportsAssign,
  getExportName, getMemberChain, resolveLocal
} = require('./parse-utils.js');

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


module.exports = { detectCrossFileFlows, expandTaintThroughReexports, collectImportTaint, propagateLocalTaint, getSinkName, findTaintedArgument };
