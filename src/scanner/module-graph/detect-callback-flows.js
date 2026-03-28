'use strict';

const path = require('path');
const { MAX_FLOWS, SINK_CALLEE_NAMES, SINK_MEMBER_METHODS } = require('./constants.js');
const { parseFile, walkAST, isRequireCall, isLocalImport, resolveLocal } = require('./parse-utils.js');
const { expandTaintThroughReexports } = require('./detect-cross-file.js');

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


module.exports = { detectCallbackCrossFileFlows };
