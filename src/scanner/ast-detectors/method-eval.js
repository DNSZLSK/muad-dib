/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

'use strict';

/**
 * Method calls named `eval` on a non-global object (`client.eval(script, ...)`).
 *
 * `getCallName` returns the property name of a member call, so a Redis/Lua
 * `client.eval(SCRIPT, keys...)` used to be reported as the JavaScript global
 * eval (HIGH), and intent coherence then paired it with any credential read in
 * the same file (CRITICAL credential -> exec_sink).
 *
 * Threat model. To run code through `X.eval(...)`, X must hold the global eval.
 * The only ways to get that value into a non-global object are:
 *   - the bare identifier `eval` used as a value (`{eval}`, `o.eval = eval`,
 *     `Reflect.apply(eval, ...)`),
 *   - a `.eval` member read that is not a call (`o.run = globalThis.eval`),
 *   - the string 'eval' (`Reflect.get(globalThis, 'eval')`, `g['eval']`),
 *   - a global object used as a value (`f(globalThis)`, `{...window}`,
 *     `const g = self`), after which any `.eval` may be the global one.
 * When the file shows none of these, `X.eval(...)` on a non-global receiver
 * cannot be the global eval: the finding is kept, at LOW (which also keeps it
 * out of intent coherence and of the dynamic-exec compounds). When the file
 * shows any of them, the call stays HIGH, exactly as before.
 * Receivers that may be the global object (`globalThis.eval`, `window.top.eval`,
 * `this.eval`, a tracked alias, a call result such as `Function('return this')()`,
 * a computed access) are never downgraded.
 */

const GLOBAL_NAMES = new Set(['globalThis', 'global', 'window', 'self', 'top', 'parent', 'frames']);

function newMethodEvalState() {
  return {
    evalIdent: 0,        // Identifier `eval` in an expression position
    evalCallee: 0,       // ... of which the callee of a call (`eval(x)`)
    evalTypeof: 0,       // ... of which the operand of `typeof`
    evalMember: 0,       // non-computed `.eval` member expressions
    evalMemberCallee: 0, // ... of which the callee of a call (`x.eval(y)`)
    evalString: false,   // string literal exactly 'eval'
    globalIdent: 0,      // Identifier globalThis/window/... in an expression position
    globalMemberObj: 0,  // ... of which the object of a member expression (`window.x`)
    globalTypeof: 0,     // ... of which the operand of `typeof`
    candidates: []       // { threat, dynamic } awaiting the end of the walk
  };
}

function isEvalProperty(member) {
  return member.type === 'MemberExpression' && !member.computed &&
    member.property?.type === 'Identifier' && member.property.name === 'eval';
}

function noteIdentifier(node, ctx) {
  const st = ctx.methodEval;
  if (node.name === 'eval') st.evalIdent++;
  else if (GLOBAL_NAMES.has(node.name)) st.globalIdent++;
}

function noteUnary(node, ctx) {
  if (node.operator !== 'typeof' || node.argument?.type !== 'Identifier') return;
  const st = ctx.methodEval;
  if (node.argument.name === 'eval') st.evalTypeof++;
  else if (GLOBAL_NAMES.has(node.argument.name)) st.globalTypeof++;
}

function noteMember(node, ctx) {
  const st = ctx.methodEval;
  if (isEvalProperty(node)) st.evalMember++;
  if (node.object?.type === 'Identifier' && GLOBAL_NAMES.has(node.object.name)) st.globalMemberObj++;
}

function noteLiteral(node, ctx) {
  if (node.value === 'eval') ctx.methodEval.evalString = true;
}

function noteCall(node, ctx) {
  const st = ctx.methodEval;
  if (node.callee.type === 'Identifier' && node.callee.name === 'eval') st.evalCallee++;
  else if (isEvalProperty(node.callee)) st.evalMemberCallee++;
}

/**
 * True when `node` is `receiver.eval(...)` (non-computed) and the receiver
 * cannot be the global object by its syntax alone.
 */
function isNonGlobalMethodEval(node, ctx) {
  if (!isEvalProperty(node.callee)) return false;
  let obj = node.callee.object;
  let depth = 0;
  for (;;) {
    if (obj.type === 'Identifier') {
      return !GLOBAL_NAMES.has(obj.name) && !ctx.globalThisAliases.has(obj.name);
    }
    if (obj.type === 'ThisExpression') return depth > 0; // this.eval may be global; this.client.eval not
    if (obj.type !== 'MemberExpression' || obj.computed || obj.property?.type !== 'Identifier') return false;
    if (GLOBAL_NAMES.has(obj.property.name)) return false;
    obj = obj.object;
    depth++;
  }
}

function receiverText(member) {
  const parts = [];
  let obj = member.object;
  while (obj.type === 'MemberExpression') { parts.unshift(obj.property.name); obj = obj.object; }
  parts.unshift(obj.type === 'ThisExpression' ? 'this' : obj.name);
  return parts.join('.');
}

/**
 * Called once after the walk. Applies the deferred flags of kept candidates,
 * or downgrades every candidate when the file never exposes eval as a value.
 */
function resolveMethodEvalCandidates(ctx) {
  const st = ctx.methodEval;
  if (st.candidates.length === 0) return;
  const evalAsValue = st.evalIdent > st.evalCallee + st.evalTypeof ||
    st.evalMember > st.evalMemberCallee || st.evalString;
  const globalAsValue = st.globalIdent > st.globalMemberObj + st.globalTypeof;
  for (const c of st.candidates) {
    if (evalAsValue || globalAsValue) {
      ctx.hasEvalInFile = true;
      if (c.dynamic) ctx.hasDynamicExec = true;
    } else {
      c.threat.severity = 'LOW';
      c.threat.message = `Method "${c.receiver}.eval()" on a non-global object (e.g. Redis/Lua scripting API); ` +
        'the file never exposes the global eval as a value, so this is not JavaScript eval.';
    }
  }
}

module.exports = {
  GLOBAL_NAMES,
  newMethodEvalState,
  noteIdentifier,
  noteUnary,
  noteMember,
  noteLiteral,
  noteCall,
  isNonGlobalMethodEval,
  receiverText,
  resolveMethodEvalCandidates
};
