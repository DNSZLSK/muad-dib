'use strict';

const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const { ACORN_OPTIONS, MAX_TAINT_DEPTH } = require('./constants.js');
const { safeParse } = require('../../shared/constants.js');

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

function walkAST(node, visitor, depth) {
  if (depth === undefined) depth = 0;
  if (depth > MAX_TAINT_DEPTH) return;
  if (!node || typeof node !== 'object') return;
  if (node.type) visitor(node);
  for (const key of Object.keys(node)) {
    if (key === 'type') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) walkAST(item, visitor, depth + 1);
      }
    } else if (child && typeof child === 'object' && child.type) {
      walkAST(child, visitor, depth + 1);
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

function getMemberChain(node, depth) {
  if (depth === undefined) depth = 0;
  if (depth > MAX_TAINT_DEPTH) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const obj = getMemberChain(node.object, depth + 1);
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


module.exports = {
  parseFile, walkAST, isRequireCall, isLocalImport, isModuleExportsAssign,
  getExportName, getFunctionBody, getMemberChain, extractLiteralArg,
  resolveLocal, isFileExists, toRel
};
