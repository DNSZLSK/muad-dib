'use strict';

const fs = require('fs');
const path = require('path');
const { SENSITIVE_MODULES, ACORN_OPTIONS } = require('./constants.js');
const {
  parseFile, walkAST, isRequireCall, isModuleExportsAssign,
  getExportName, getFunctionBody, getMemberChain, extractLiteralArg
} = require('./parse-utils.js');

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
  // Object.create(null) prevents prototype pollution via __proto__/constructor keys
  const moduleVars = Object.create(null);
  // Track which local variables hold tainted values
  // e.g. const data = fs.readFileSync(...) → taintedVars['data'] = { source, detail }
  const taintedVars = Object.create(null);

  // Track class declarations: class Foo { ... }
  const classDefs = Object.create(null);
  // Track function declarations: function foo() { ... }
  const funcDefs = Object.create(null);
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
  const localTainted = Object.assign(Object.create(null), taintedVars);

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


module.exports = { annotateTaintedExports, checkNodeTaint };
