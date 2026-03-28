'use strict';

const path = require('path');
const { MAX_FLOWS, SENSITIVE_MODULES, SINK_CALLEE_NAMES, SINK_MEMBER_METHODS } = require('./constants.js');
const { parseFile, walkAST, isRequireCall } = require('./parse-utils.js');
const { expandTaintThroughReexports, collectImportTaint, propagateLocalTaint, getSinkName, findTaintedArgument } = require('./detect-cross-file.js');
const { checkNodeTaint } = require('./annotate-tainted.js');

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


module.exports = { detectEventEmitterFlows };
