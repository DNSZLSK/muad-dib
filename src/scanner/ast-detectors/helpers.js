'use strict';

const {
  ENV_SENSITIVE_KEYWORDS,
  ENV_NON_SENSITIVE_QUALIFIERS
} = require('./constants.js');

/**
 * Check if an env var name contains a sensitive keyword as a full _-delimited segment,
 * not preceded by a non-sensitive qualifier.
 * e.g., NPM_TOKEN → TOKEN is full segment → true
 *       PUBLIC_KEY → KEY preceded by PUBLIC → false
 *       CACHE_KEY → KEY preceded by CACHE → false
 *       GITHUB_TOKEN → TOKEN is full segment, preceded by GITHUB (not a qualifier) → true
 */
function isEnvSensitive(envVar) {
  const upper = envVar.toUpperCase();
  const segments = upper.split('_');
  for (let i = 0; i < segments.length; i++) {
    if (ENV_SENSITIVE_KEYWORDS.includes(segments[i])) {
      // Check if preceded by a non-sensitive qualifier
      if (i > 0 && ENV_NON_SENSITIVE_QUALIFIERS.has(segments[i - 1])) {
        continue;
      }
      return true;
    }
  }
  return false;
}

/**
 * Extract string value from a node if it's a Literal or TemplateLiteral with no expressions.
 */
function extractStringValue(node) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map(q => q.value.raw).join('');
  }
  // Template literal with expressions — concatenate what we can
  if (node.type === 'TemplateLiteral') {
    return node.quasis.map(q => q.value.raw).join('***');
  }
  return null;
}

/**
 * Audit v3 B2: Shannon entropy calculation for split-entropy detection.
 * Replicates the algorithm from entropy.js for inline use in AST scanner.
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = Object.create(null);
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Audit v3 B2: Count the number of leaf string operands in a BinaryExpression chain.
 * Used to identify split payloads (≥3 chunks concatenated).
 */
function countConcatOperands(node) {
  if (!node) return 0;
  if (node.type === 'Literal' && typeof node.value === 'string') return 1;
  if (node.type === 'Identifier') return 1;
  if (node.type === 'TemplateLiteral') return 1;
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return countConcatOperands(node.left) + countConcatOperands(node.right);
  }
  return 0;
}

/**
 * Recursively resolve BinaryExpression with '+' operator to reconstruct
 * concatenated strings like '.gi' + 't' → '.git' or 'ho' + 'oks' → 'hooks'.
 * Returns null if any part is non-literal.
 */
function resolveStringConcat(node) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map(q => q.value.raw).join('');
  }
  // TemplateLiteral with resolvable expressions
  if (node.type === 'TemplateLiteral' && node.expressions.length > 0) {
    const parts = [];
    for (let i = 0; i < node.quasis.length; i++) {
      parts.push(node.quasis[i].value.raw);
      if (i < node.expressions.length) {
        const resolved = resolveStringConcat(node.expressions[i]);
        if (resolved === null) return null;
        parts.push(resolved);
      }
    }
    return parts.join('');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = resolveStringConcat(node.left);
    const right = resolveStringConcat(node.right);
    if (left !== null && right !== null) return left + right;
  }
  // ConditionalExpression — either branch is enough for detection
  if (node.type === 'ConditionalExpression') {
    const consequent = resolveStringConcat(node.consequent);
    const alternate = resolveStringConcat(node.alternate);
    return consequent !== null ? consequent : alternate;
  }
  return null;
}

/**
 * Like resolveStringConcat, but additionally resolves Identifier nodes via
 * a stringVarValues Map (variable name → known string value).
 * Used for double-indirection patterns: var a='ev',b='al'; globalThis[a+b]()
 */
function resolveStringConcatWithVars(node, stringVarValues) {
  if (!node) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'Identifier' && stringVarValues && stringVarValues.has(node.name)) {
    return stringVarValues.get(node.name);
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map(q => q.value.raw).join('');
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length > 0) {
    const parts = [];
    for (let i = 0; i < node.quasis.length; i++) {
      parts.push(node.quasis[i].value.raw);
      if (i < node.expressions.length) {
        const resolved = resolveStringConcatWithVars(node.expressions[i], stringVarValues);
        if (resolved === null) return null;
        parts.push(resolved);
      }
    }
    return parts.join('');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = resolveStringConcatWithVars(node.left, stringVarValues);
    const right = resolveStringConcatWithVars(node.right, stringVarValues);
    if (left !== null && right !== null) return left + right;
  }
  return null;
}

/**
 * Extract string value from a node, including BinaryExpression resolution.
 * Falls back to extractStringValue if concat resolution fails.
 */
function extractStringValueDeep(node) {
  const concat = resolveStringConcat(node);
  let result = concat !== null ? concat : extractStringValue(node);
  // Batch 2: strip node: prefix so require('node:child_process') normalizes to 'child_process'
  if (typeof result === 'string' && result.startsWith('node:')) {
    result = result.slice(5);
  }
  return result;
}

/**
 * Returns true if all arguments of a call/new expression are string literals.
 * Used to distinguish safe patterns like eval('1+2') or Function('return this')
 * from dangerous dynamic patterns like eval(userInput).
 */
function hasOnlyStringLiteralArgs(node) {
  if (!node.arguments || node.arguments.length === 0) return false;
  return node.arguments.every(arg => arg.type === 'Literal' && typeof arg.value === 'string');
}

/**
 * Returns true if a node is a decode call: atob(str) or Buffer.from(str,'base64').toString()
 * Used to detect staged eval/Function decode patterns.
 */
function hasDecodeArg(node) {
  if (!node || typeof node !== 'object') return false;
  // atob('...')
  if (node.type === 'CallExpression' &&
      node.callee?.type === 'Identifier' && node.callee.name === 'atob') {
    return true;
  }
  // Buffer.from('...', 'base64').toString()
  if (node.type === 'CallExpression' &&
      node.callee?.type === 'MemberExpression' &&
      node.callee.property?.name === 'toString') {
    const inner = node.callee.object;
    if (inner?.type === 'CallExpression' &&
        inner.callee?.type === 'MemberExpression' &&
        inner.callee.object?.name === 'Buffer' &&
        inner.callee.property?.name === 'from' &&
        inner.arguments?.length >= 2 &&
        inner.arguments[1]?.value === 'base64') {
      return true;
    }
  }
  return false;
}

/**
 * Checks if an AST subtree contains decode patterns (base64, atob, fromCharCode).
 */
function containsDecodePattern(node) {
  if (!node || typeof node !== 'object') return false;
  if (node.type === 'Literal' && node.value === 'base64') return true;
  if (node.type === 'Identifier' && (node.name === 'atob' || node.name === 'fromCharCode')) return true;
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item.type === 'string' && containsDecodePattern(item)) return true;
      }
    } else if (child && typeof child === 'object' && typeof child.type === 'string') {
      if (containsDecodePattern(child)) return true;
    }
  }
  return false;
}

// ============================================
// VISITOR HANDLERS
// ============================================
// Each handler receives (node, ctx) where ctx contains:
//   threats, relFile, dynamicRequireVars, dangerousCmdVars,
//   workflowPathVars, execPathVars, globalThisAliases,
//   hasFromCharCode, hasEvalInFile (mutable)

function isStaticValue(node) {
  if (!node) return false;
  if (node.type === 'Literal' && typeof node.value === 'string') return true;
  if (node.type === 'ArrayExpression') {
    return node.elements.every(el => el && el.type === 'Literal' && typeof el.value === 'string');
  }
  if (node.type === 'ObjectExpression') {
    return node.properties.every(p =>
      p.value && p.value.type === 'Literal' && typeof p.value.value === 'string'
    );
  }
  return false;
}

module.exports = {
  isEnvSensitive,
  extractStringValue,
  calculateShannonEntropy,
  countConcatOperands,
  resolveStringConcat,
  resolveStringConcatWithVars,
  extractStringValueDeep,
  hasOnlyStringLiteralArgs,
  hasDecodeArg,
  containsDecodePattern,
  isStaticValue
};
