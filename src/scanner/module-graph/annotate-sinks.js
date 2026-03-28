'use strict';

const fs = require('fs');
const path = require('path');
const { SINK_CALLEE_NAMES, SINK_MEMBER_METHODS, SINK_INSTANCE_METHODS, ACORN_OPTIONS } = require('./constants.js');
const {
  parseFile, walkAST, isRequireCall, isModuleExportsAssign,
  getExportName, getFunctionBody, getMemberChain
} = require('./parse-utils.js');

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

module.exports = { annotateSinkExports };
