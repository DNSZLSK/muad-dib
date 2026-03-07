'use strict';

const acorn = require('acorn');
const walk = require('acorn-walk');
const { ACORN_OPTIONS, safeParse } = require('../shared/constants.js');

/**
 * Lightweight static deobfuscation pre-processor.
 * Resolves common JS obfuscation patterns via AST rewriting (no eval).
 *
 * @param {string} sourceCode — raw JS source
 * @returns {{ code: string, transforms: Array<{type: string, start: number, end: number, before: string, after: string}> }}
 */
function deobfuscate(sourceCode) {
  const transforms = [];

  // Parse AST — if parsing fails, return source unchanged (fail-safe)
  let ast = safeParse(sourceCode, { ranges: true });
  if (!ast) return { code: sourceCode, transforms };

  // Collect replacements as { start, end, value, type, before }
  const replacements = [];

  walk.simple(ast, {
    // ---- 1. STRING CONCAT FOLDING ----
    // 'ch' + 'il' + 'd_' + 'process' → 'child_process'
    BinaryExpression(node) {
      if (node.operator !== '+') return;
      const folded = tryFoldConcat(node);
      if (folded === null) return;
      // Avoid folding single literals (no transformation needed)
      if (node.left.type === 'Literal' && node.right.type === 'Literal' &&
          typeof node.left.value === 'string' && typeof node.right.value === 'string') {
        // Simple two-literal concat — always fold
      } else if (node.type === 'BinaryExpression') {
        // Nested concat — only fold if top-level (not already inside a folded parent)
        // We check this by not folding if parent already covers this range
      }
      const before = sourceCode.slice(node.start, node.end);
      const after = quoteString(folded);
      replacements.push({
        start: node.start,
        end: node.end,
        value: after,
        type: 'string_concat',
        before
      });
    },

    // ---- 1b. TEMPLATE LITERAL FOLDING ----
    // `child_process` → 'child_process' (no expression templates)
    // `child_${'process'}` → 'child_process' (with resolvable expressions)
    TemplateLiteral(node) {
      const folded = tryFoldConcat(node);
      if (folded === null) return;
      const before = sourceCode.slice(node.start, node.end);
      const after = quoteString(folded);
      if (before === after) return; // no change
      replacements.push({
        start: node.start,
        end: node.end,
        value: after,
        type: 'template_literal',
        before
      });
    },

    // ---- 2. CHARCODE REBUILD + 3. BASE64 DECODE ----
    CallExpression(node) {
      // String.fromCharCode(99, 104, 105, 108, 100) → "child"
      if (isStringFromCharCode(node)) {
        const nums = extractNumericArgs(node);
        if (nums === null) return;
        try {
          const decoded = String.fromCharCode(...nums);
          const before = sourceCode.slice(node.start, node.end);
          const after = quoteString(decoded);
          replacements.push({
            start: node.start,
            end: node.end,
            value: after,
            type: 'charcode',
            before
          });
        } catch { /* invalid char codes — skip */ }
        return;
      }

      // Buffer.from('...', 'base64').toString() → decoded string
      if (isBufferBase64ToString(node)) {
        const b64str = extractBufferBase64Arg(node);
        if (b64str === null) return;
        try {
          const decoded = Buffer.from(b64str, 'base64').toString();
          // Sanity: only replace if decoded is printable ASCII/UTF-8
          if (!isPrintable(decoded)) return;
          const before = sourceCode.slice(node.start, node.end);
          const after = quoteString(decoded);
          replacements.push({
            start: node.start,
            end: node.end,
            value: after,
            type: 'base64',
            before
          });
        } catch { /* decode failure — skip */ }
        return;
      }

      // Buffer.from('...', 'hex').toString() → decoded string
      if (isBufferHexToString(node)) {
        const hexStr = extractBufferHexArg(node);
        if (hexStr === null) return;
        try {
          const decoded = Buffer.from(hexStr, 'hex').toString();
          if (!isPrintable(decoded)) return;
          const before = sourceCode.slice(node.start, node.end);
          const after = quoteString(decoded);
          replacements.push({
            start: node.start,
            end: node.end,
            value: after,
            type: 'hex',
            before
          });
        } catch { /* decode failure — skip */ }
        return;
      }

      // atob('...') → decoded string
      if (isAtobCall(node)) {
        const b64str = node.arguments[0]?.value;
        if (typeof b64str !== 'string') return;
        try {
          const decoded = Buffer.from(b64str, 'base64').toString();
          if (!isPrintable(decoded)) return;
          const before = sourceCode.slice(node.start, node.end);
          const after = quoteString(decoded);
          replacements.push({
            start: node.start,
            end: node.end,
            value: after,
            type: 'base64',
            before
          });
        } catch { /* skip */ }
        return;
      }

      // ---- 4. HEX ARRAY MAP ----
      // [0x63, 0x68, ...].map(c => String.fromCharCode(c)).join('')
      const hexResult = tryResolveHexArrayMap(node, sourceCode);
      if (hexResult !== null) {
        replacements.push(hexResult);
      }
    }
  });

  // De-duplicate: nested BinaryExpression nodes produce overlapping replacements.
  // Keep only the outermost (widest) replacement for each overlapping range.
  replacements.sort((a, b) => a.start - b.start || b.end - a.end);
  const filtered = [];
  let lastEnd = -1;
  for (const r of replacements) {
    if (r.start < lastEnd) continue; // nested inside a wider replacement — skip
    filtered.push(r);
    lastEnd = r.end;
  }

  // Apply replacements from end to start to preserve positions
  filtered.sort((a, b) => b.start - a.start);

  let code = sourceCode;
  for (const r of filtered) {
    code = code.slice(0, r.start) + r.value + code.slice(r.end);
    transforms.push({
      type: r.type,
      start: r.start,
      end: r.end,
      before: r.before,
      after: r.value
    });
  }

  // Reverse transforms so they're in source order (start ascending)
  transforms.reverse();

  // ---- PHASE 2: CONST PROPAGATION ----
  // If phase 1 produced transforms, re-parse and propagate const string assignments.
  // const a = 'child_'; const b = 'process'; require(a + b) → require('child_' + 'process') → require('child_process')
  if (transforms.length > 0) {
    const phase2 = propagateConsts(code);
    if (phase2.transforms.length > 0) {
      code = phase2.code;
      transforms.push(...phase2.transforms);
    }
  }

  return { code, transforms };
}

/**
 * Phase 2: Propagate const string literal assignments into identifier references,
 * then fold any resulting string concatenations.
 */
function propagateConsts(sourceCode) {
  const transforms = [];
  let ast = safeParse(sourceCode, { ranges: true });
  if (!ast) return { code: sourceCode, transforms };

  // Collect const declarations: name → { value, initStart, initEnd }
  const constMap = new Map();
  // Track which names are assigned more than once (not safe to propagate)
  const reassigned = new Set();

  walk.simple(ast, {
    VariableDeclaration(node) {
      if (node.kind !== 'const') return;
      for (const decl of node.declarations) {
        if (!decl.init) continue;
        // Standard: const x = 'literal'
        if (decl.id?.type === 'Identifier') {
          if (decl.init.type === 'Literal' && typeof decl.init.value === 'string') {
            constMap.set(decl.id.name, {
              value: decl.init.value,
              declStart: decl.init.start,
              declEnd: decl.init.end
            });
          }
        }
        // Array destructuring: const [a, b] = ['child_', 'process']
        if (decl.id?.type === 'ArrayPattern' && decl.init?.type === 'ArrayExpression') {
          for (let i = 0; i < decl.id.elements.length && i < decl.init.elements.length; i++) {
            if (decl.id.elements[i]?.type === 'Identifier' &&
                decl.init.elements[i]?.type === 'Literal' &&
                typeof decl.init.elements[i].value === 'string') {
              constMap.set(decl.id.elements[i].name, {
                value: decl.init.elements[i].value,
                declStart: decl.init.elements[i].start,
                declEnd: decl.init.elements[i].end
              });
            }
          }
        }
      }
    },
    AssignmentExpression(node) {
      if (node.left?.type === 'Identifier') {
        reassigned.add(node.left.name);
      }
    }
  });

  // Remove reassigned names from constMap (not safe)
  for (const name of reassigned) {
    constMap.delete(name);
  }

  if (constMap.size === 0) {
    return { code: sourceCode, transforms };
  }

  // Find all Identifier references to propagate (excluding declarations and property names)
  const replacements = [];
  walk.simple(ast, {
    Identifier(node) {
      if (!constMap.has(node.name)) return;
      const info = constMap.get(node.name);
      // Skip the declaration site itself
      if (node.start === info.declStart || (node.start >= info.declStart && node.end <= info.declEnd)) return;
      replacements.push({
        start: node.start,
        end: node.end,
        value: quoteString(info.value),
        type: 'const_propagation',
        before: sourceCode.slice(node.start, node.end)
      });
    }
  });

  // Filter: skip property access identifiers (obj.prop — prop is not a variable ref)
  // We detect this by checking if the identifier is a property of a MemberExpression
  const propPositions = new Set();
  walk.simple(ast, {
    MemberExpression(node) {
      if (!node.computed && node.property?.type === 'Identifier') {
        propPositions.add(node.property.start);
      }
    },
    VariableDeclarator(node) {
      // Skip the declaration name itself
      if (node.id?.type === 'Identifier') {
        propPositions.add(node.id.start);
      }
    }
  });

  const validReplacements = replacements.filter(r => !propPositions.has(r.start));

  if (validReplacements.length === 0) {
    return { code: sourceCode, transforms };
  }

  // Apply replacements from end to start
  validReplacements.sort((a, b) => b.start - a.start);
  let code = sourceCode;
  for (const r of validReplacements) {
    code = code.slice(0, r.start) + r.value + code.slice(r.end);
    transforms.push({
      type: r.type,
      start: r.start,
      end: r.end,
      before: r.before,
      after: r.value
    });
  }

  // Now re-run concat folding on the propagated code
  const phase3 = foldConcatsOnly(code);
  if (phase3.transforms.length > 0) {
    code = phase3.code;
    transforms.push(...phase3.transforms);
  }

  transforms.reverse();
  return { code, transforms };
}

/**
 * Run only string concat folding on code (phase 3 after const propagation).
 */
function foldConcatsOnly(sourceCode) {
  const transforms = [];
  let ast = safeParse(sourceCode, { ranges: true });
  if (!ast) return { code: sourceCode, transforms };

  const replacements = [];
  walk.simple(ast, {
    BinaryExpression(node) {
      if (node.operator !== '+') return;
      const folded = tryFoldConcat(node);
      if (folded === null) return;
      const before = sourceCode.slice(node.start, node.end);
      const after = quoteString(folded);
      replacements.push({ start: node.start, end: node.end, value: after, type: 'string_concat', before });
    }
  });

  // De-duplicate overlapping
  replacements.sort((a, b) => a.start - b.start || b.end - a.end);
  const filtered = [];
  let lastEnd = -1;
  for (const r of replacements) {
    if (r.start < lastEnd) continue;
    filtered.push(r);
    lastEnd = r.end;
  }

  filtered.sort((a, b) => b.start - a.start);
  let code = sourceCode;
  for (const r of filtered) {
    code = code.slice(0, r.start) + r.value + code.slice(r.end);
    transforms.push({ type: r.type, start: r.start, end: r.end, before: r.before, after: r.value });
  }

  return { code, transforms };
}

// ============================================================
// HELPERS
// ============================================================

/**
 * Recursively fold string concat BinaryExpression.
 * Returns the concatenated string, or null if any part is not a string literal.
 * Depth limit prevents stack overflow DoS on deeply nested expressions.
 */
const MAX_FOLD_DEPTH = 100;

function tryFoldConcat(node, depth) {
  if (depth === undefined) depth = 0;
  if (depth > MAX_FOLD_DEPTH) return null;
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }
  // TemplateLiteral without expressions → direct string
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map(q => q.value.cooked).join('');
  }
  // TemplateLiteral with resolvable expressions
  if (node.type === 'TemplateLiteral' && node.expressions.length > 0) {
    const parts = [];
    for (let i = 0; i < node.quasis.length; i++) {
      parts.push(node.quasis[i].value.cooked);
      if (i < node.expressions.length) {
        const v = tryFoldConcat(node.expressions[i], depth + 1);
        if (v === null) return null;
        parts.push(v);
      }
    }
    return parts.join('');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = tryFoldConcat(node.left, depth + 1);
    if (left === null) return null;
    const right = tryFoldConcat(node.right, depth + 1);
    if (right === null) return null;
    return left + right;
  }
  return null;
}

/**
 * Check if node is String.fromCharCode(...)
 */
function isStringFromCharCode(node) {
  if (node.type !== 'CallExpression') return false;
  const c = node.callee;
  if (c.type !== 'MemberExpression') return false;
  // String.fromCharCode
  if (c.object?.type === 'Identifier' && c.object.name === 'String' &&
      c.property?.type === 'Identifier' && c.property.name === 'fromCharCode') {
    return true;
  }
  return false;
}

/**
 * Extract numeric arguments from a call (handles direct numbers and spread of array).
 * Returns array of numbers, or null if any argument is non-numeric.
 */
function extractNumericArgs(node) {
  const nums = [];
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement' && arg.argument?.type === 'ArrayExpression') {
      for (const el of arg.argument.elements) {
        if (el?.type === 'Literal' && typeof el.value === 'number') {
          nums.push(el.value);
        } else {
          return null; // non-numeric — abort
        }
      }
    } else if (arg.type === 'Literal' && typeof arg.value === 'number') {
      nums.push(arg.value);
    } else {
      return null; // non-numeric argument (variable, expression) — abort
    }
  }
  return nums.length > 0 ? nums : null;
}

/**
 * Check if node is Buffer.from('...', 'base64').toString()
 */
function isBufferBase64ToString(node) {
  if (node.type !== 'CallExpression') return false;
  const callee = node.callee;
  // .toString() call
  if (callee.type !== 'MemberExpression') return false;
  if (callee.property?.type !== 'Identifier' || callee.property.name !== 'toString') return false;
  // The object is Buffer.from(str, 'base64')
  const inner = callee.object;
  if (inner?.type !== 'CallExpression') return false;
  const innerCallee = inner.callee;
  if (innerCallee?.type !== 'MemberExpression') return false;
  if (innerCallee.object?.type !== 'Identifier' || innerCallee.object.name !== 'Buffer') return false;
  if (innerCallee.property?.type !== 'Identifier' || innerCallee.property.name !== 'from') return false;
  // Args: (string, 'base64')
  if (inner.arguments.length < 2) return false;
  if (inner.arguments[1]?.type !== 'Literal' || inner.arguments[1].value !== 'base64') return false;
  if (inner.arguments[0]?.type !== 'Literal' || typeof inner.arguments[0].value !== 'string') return false;
  return true;
}

/**
 * Extract the base64 string argument from Buffer.from(str, 'base64').toString()
 */
function extractBufferBase64Arg(node) {
  const inner = node.callee.object;
  return inner.arguments[0].value;
}

/**
 * Check if node is Buffer.from('...', 'hex').toString()
 */
function isBufferHexToString(node) {
  if (node.type !== 'CallExpression') return false;
  const callee = node.callee;
  if (callee.type !== 'MemberExpression') return false;
  if (callee.property?.type !== 'Identifier' || callee.property.name !== 'toString') return false;
  const inner = callee.object;
  if (inner?.type !== 'CallExpression') return false;
  const innerCallee = inner.callee;
  if (innerCallee?.type !== 'MemberExpression') return false;
  if (innerCallee.object?.type !== 'Identifier' || innerCallee.object.name !== 'Buffer') return false;
  if (innerCallee.property?.type !== 'Identifier' || innerCallee.property.name !== 'from') return false;
  if (inner.arguments.length < 2) return false;
  if (inner.arguments[1]?.type !== 'Literal' || inner.arguments[1].value !== 'hex') return false;
  if (inner.arguments[0]?.type !== 'Literal' || typeof inner.arguments[0].value !== 'string') return false;
  return true;
}

/**
 * Extract the hex string argument from Buffer.from(str, 'hex').toString()
 */
function extractBufferHexArg(node) {
  const inner = node.callee.object;
  return inner.arguments[0].value;
}

/**
 * Check if node is atob('...')
 */
function isAtobCall(node) {
  if (node.type !== 'CallExpression') return false;
  if (node.callee?.type !== 'Identifier' || node.callee.name !== 'atob') return false;
  if (node.arguments.length !== 1) return false;
  if (node.arguments[0]?.type !== 'Literal' || typeof node.arguments[0].value !== 'string') return false;
  return true;
}

/**
 * Try to resolve [0x63, ...].map(c => String.fromCharCode(c)).join('')
 * Returns a replacement object or null.
 */
function tryResolveHexArrayMap(node, source) {
  // Pattern: <expr>.join('') where <expr> is <array>.map(<fn>)
  // node is the .join('') call
  if (node.type !== 'CallExpression') return null;
  const callee = node.callee;
  if (callee?.type !== 'MemberExpression') return null;
  if (callee.property?.type !== 'Identifier' || callee.property.name !== 'join') return null;
  // Verify .join('') or .join("")
  if (node.arguments.length !== 1) return null;
  if (node.arguments[0]?.type !== 'Literal' || node.arguments[0].value !== '') return null;

  // The object of .join should be a .map(...) call
  const mapCall = callee.object;
  if (mapCall?.type !== 'CallExpression') return null;
  if (mapCall.callee?.type !== 'MemberExpression') return null;
  if (mapCall.callee.property?.type !== 'Identifier' || mapCall.callee.property.name !== 'map') return null;

  // The map callback should reference String.fromCharCode
  if (mapCall.arguments.length < 1) return null;
  const mapFn = mapCall.arguments[0];
  if (!containsFromCharCode(mapFn)) return null;

  // The object of .map should be an ArrayExpression of numbers
  const arr = mapCall.callee.object;
  if (arr?.type !== 'ArrayExpression') return null;
  const nums = [];
  for (const el of arr.elements) {
    if (el?.type === 'Literal' && typeof el.value === 'number') {
      nums.push(el.value);
    } else {
      return null; // non-numeric element — abort
    }
  }
  if (nums.length === 0) return null;

  try {
    const decoded = String.fromCharCode(...nums);
    const before = source.slice(node.start, node.end);
    return {
      start: node.start,
      end: node.end,
      value: quoteString(decoded),
      type: 'hex_array',
      before
    };
  } catch {
    return null;
  }
}

/**
 * Check if an AST node (a function/arrow function) contains a reference to String.fromCharCode.
 */
function containsFromCharCode(node) {
  if (!node || typeof node !== 'object') return false;

  // Direct check on this node
  if (node.type === 'MemberExpression' &&
      node.object?.type === 'Identifier' && node.object.name === 'String' &&
      node.property?.type === 'Identifier' && node.property.name === 'fromCharCode') {
    return true;
  }

  // Recurse into child nodes
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'range') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const c of child) {
        if (c && typeof c === 'object' && containsFromCharCode(c)) return true;
      }
    } else if (child && typeof child === 'object' && child.type) {
      if (containsFromCharCode(child)) return true;
    }
  }
  return false;
}

/**
 * Quote a string value as a JS single-quoted string literal.
 */
function quoteString(str) {
  const escaped = str
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
  return `'${escaped}'`;
}

/**
 * Check if a decoded string is "printable" (no control chars except whitespace).
 * Prevents replacing base64 that decodes to binary garbage.
 */
function isPrintable(str) {
  // Allow printable ASCII + common unicode + whitespace
  // Reject if more than 20% of chars are control characters
  let controlCount = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
      controlCount++;
    }
  }
  if (str.length === 0) return false;
  return (controlCount / str.length) < 0.2;
}

/**
 * Detect control flow flattening obfuscation pattern.
 * Pattern: while(true/1) { switch(var) { case N: ...; var = M; break; ... } }
 * Returns true if the pattern is detected.
 * @param {string} sourceCode — raw JS source
 * @returns {boolean}
 */
function detectControlFlowFlattening(sourceCode) {
  const ast = safeParse(sourceCode, { ranges: true });
  if (!ast) return false;

  let found = false;
  walk.simple(ast, {
    WhileStatement(node) {
      if (found) return;
      // Check for while(true) or while(1)
      const test = node.test;
      const isInfinite = (test.type === 'Literal' && (test.value === true || test.value === 1))
        || (test.type === 'Identifier' && test.name === 'true');
      if (!isInfinite) return;

      // Body should contain a SwitchStatement
      const body = node.body;
      let switchNode = null;
      if (body.type === 'SwitchStatement') {
        switchNode = body;
      } else if (body.type === 'BlockStatement' && body.body) {
        switchNode = body.body.find(s => s.type === 'SwitchStatement');
      }
      if (!switchNode || !switchNode.cases) return;

      // Need at least 3 cases for CFF pattern
      if (switchNode.cases.length < 3) return;

      // Check for state variable reassignment in at least 2 cases
      const discriminant = switchNode.discriminant;
      if (!discriminant) return;
      let stateVarName = null;
      if (discriminant.type === 'Identifier') {
        stateVarName = discriminant.name;
      } else if (discriminant.type === 'MemberExpression' && discriminant.property?.type === 'Identifier') {
        stateVarName = discriminant.property.name;
      }
      if (!stateVarName) return;

      // Count cases that reassign the state variable
      let reassignCount = 0;
      for (const c of switchNode.cases) {
        if (!c.consequent) continue;
        const caseSource = sourceCode.slice(c.start, c.end);
        // Look for stateVar = <number> pattern
        const reassignRe = new RegExp('\\b' + stateVarName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*=\\s*\\d+');
        if (reassignRe.test(caseSource)) {
          reassignCount++;
        }
      }

      // CFF pattern: at least 2 cases reassign the state variable
      if (reassignCount >= 2) {
        found = true;
      }
    }
  });

  return found;
}

module.exports = { deobfuscate, detectControlFlowFlattening };
