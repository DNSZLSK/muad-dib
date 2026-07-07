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

const {
  SUSPICIOUS_DOMAINS_HIGH,
  SUSPICIOUS_DOMAINS_MEDIUM
} = require('./constants.js');
const {
  extractStringValueDeep,
  hasOnlyStringLiteralArgs
} = require('./helpers.js');

function handleNewExpression(node, ctx) {
  if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
    // v2.10.94: detect new Function('require', '__dirname', '__filename', <dynamic>)
    // csec-crypto-toolkit pattern. Gated by obfuscation signal to avoid FP on
    // legitimate CommonJS module wrappers used by babel-register, ts-node, pirates,
    // jest, nyc, vitest etc. which call new Function('module', 'exports', 'require',
    // compiledCode). Those transpilers DO NOT have fromCharCode/base64 decode loops
    // in the same file — csec does.
    if (node.arguments.length >= 3) {
      const RUNTIME_ARG_NAMES = new Set(['require', '__dirname', '__filename', 'module', 'exports', 'process']);
      const bodyArg = node.arguments[node.arguments.length - 1];
      const argNameLiterals = node.arguments.slice(0, -1)
        .map(a => (a.type === 'Literal' && typeof a.value === 'string') ? a.value : null);
      const runtimeArgCount = argNameLiterals.filter(v => v !== null && RUNTIME_ARG_NAMES.has(v)).length;
      const bodyIsDynamic = bodyArg.type !== 'Literal';
      // FP gate: require an obfuscation/decode signal in the same file.
      // ctx.hasFromCharCode catches XOR/charcode loops (csec).
      // ctx.hasBase64Decode catches Buffer.from(..., 'base64') patterns.
      // ctx.hasZlibInflate catches zlib + base64 payloads.
      const hasObfuscationContext = ctx.hasFromCharCode || ctx.hasBase64Decode || ctx.hasZlibInflate;
      if (runtimeArgCount >= 2 && bodyIsDynamic && hasObfuscationContext) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'function_runtime_args',
          severity: 'CRITICAL',
          message: `new Function() passes runtime identifiers (${argNameLiterals.filter(Boolean).join(', ')}) to a dynamic body in a file containing decode/obfuscation patterns — csec-style obfuscated payload with full Node.js context.`,
          file: ctx.relFile
        });
        return;
      }
    }
    // Skip string literal args — zero-risk globalThis polyfills used by every bundler
    if (!hasOnlyStringLiteralArgs(node)) {
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'dangerous_call_function',
        severity: 'MEDIUM',
        message: 'new Function() with dynamic expression (template/factory pattern).',
        file: ctx.relFile
      });
    }
  }

  // v2.10.89: new Function.constructor("require", code) — RCE evasion
  // Catches: chai-as-inserted (score 10→CRITICAL), cookie-parseflow (score 10→CRITICAL)
  // Pattern: new Function.constructor("require", s); handler(require) — passes real require to dynamic code
  if (node.callee.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'constructor' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'Function' &&
      node.arguments.length >= 1) {
    const hasRequireArg = node.arguments.some(arg =>
      arg.type === 'Literal' && typeof arg.value === 'string' && arg.value === 'require'
    );
    if (hasRequireArg) {
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'function_constructor_require',
        severity: 'CRITICAL',
        message: 'new Function.constructor("require", ...) — dynamic code execution bypassing require() detection. Attacker passes real require to execute arbitrary code.',
        file: ctx.relFile
      });
    }
  }

  // Batch 1: new vm.Script(code) — dynamic code compilation via vm module
  if (node.callee.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'Script' &&
      node.arguments.length >= 1 && !hasOnlyStringLiteralArgs(node)) {
    // NOTE: Do NOT set ctx.hasDynamicExec — same rationale as vm.runInThisContext above.
    ctx.threats.push({
      type: 'vm_code_execution',
      severity: 'HIGH',
      message: 'new vm.Script() with dynamic code — vm module code compilation bypasses eval detection.',
      file: ctx.relFile
    });
  }

  // Detect new Proxy(process.env, handler)
  if (node.callee.type === 'Identifier' && node.callee.name === 'Proxy' && node.arguments.length >= 2) {
    const target = node.arguments[0];
    if (target.type === 'MemberExpression' &&
        target.object?.name === 'process' &&
        target.property?.name === 'env') {
      ctx.threats.push({
        type: 'env_proxy_intercept',
        severity: 'CRITICAL',
        message: 'new Proxy(process.env) detected — intercepts all environment variable access.',
        file: ctx.relFile
      });
    }
    // Detect new Proxy(require, handler) — intercept module loading
    if (target.type === 'Identifier' && target.name === 'require') {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: 'new Proxy(require) — proxy wrapping require to intercept/redirect module loading.',
        file: ctx.relFile
      });
    }
    // Detect new Proxy(globalThis/global/window/self, handler) — intercepts all global access
    if (target.type === 'Identifier' &&
        (target.name === 'globalThis' || target.name === 'global' ||
         target.name === 'window' || target.name === 'self' ||
         ctx.globalThisAliases.has(target.name))) {
      ctx.threats.push({
        type: 'proxy_globalthis_intercept',
        severity: 'CRITICAL',
        message: `new Proxy(${target.name}, handler) — intercepts all global object access. Attacker can hook eval/Function/require transparently.`,
        file: ctx.relFile
      });
    }
    // Detect new Proxy(obj, handler) where handler has set/get traps — data interception
    // Real-world technique: export a Proxy that intercepts all property sets/gets to exfiltrate
    // data flowing through the module. Combined with network (hasNetworkInFile) → credential theft.
    if (!target.type?.includes('MemberExpression') || target.property?.name !== 'env') {
      const handler = node.arguments[1];
      if (handler?.type === 'ObjectExpression') {
        const hasTrap = handler.properties?.some(p =>
          p.key?.type === 'Identifier' && ['set', 'get', 'apply', 'construct'].includes(p.key.name)
        );
        if (hasTrap) {
          ctx.hasProxyTrap = true;
          const hasSetTrap = handler.properties?.some(p =>
            p.key?.type === 'Identifier' && p.key.name === 'set'
          );
          if (hasSetTrap) ctx.hasProxySetTrap = true;
        }
      }
      // Also detect when handler is a variable reference that was tracked as having trap properties
      if (handler?.type === 'Identifier' && ctx.proxyHandlerVars?.has(handler.name)) {
        ctx.hasProxyTrap = true;
        ctx.hasProxySetTrap = true; // proxyHandlerVars tracks objects with any trap including set
      }
    }
  }

  // Batch 2: new Worker(code, { eval: true }) — worker_threads code execution
  if (node.callee.type === 'Identifier' && node.callee.name === 'Worker' &&
      node.arguments.length >= 1) {
    ctx.hasWorkerThread = true;
    if (node.arguments.length >= 2) {
      const opts = node.arguments[1];
      if (opts?.type === 'ObjectExpression') {
        const evalProp = opts.properties?.find(p =>
          p.key?.name === 'eval' && p.value?.value === true);
        if (evalProp) {
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'worker_thread_exec',
            severity: 'HIGH',
            message: 'new Worker() with eval:true — executes arbitrary code in worker thread, bypasses main thread detection.',
            file: ctx.relFile
          });
        }
      }
    }
    // Blue Team v8: new Worker('data:...') — data URL code injection into worker
    const firstArg = node.arguments[0];
    if (firstArg?.type === 'Literal' && typeof firstArg.value === 'string' &&
        firstArg.value.startsWith('data:')) {
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'worker_thread_exec',
        severity: 'HIGH',
        message: 'new Worker() with data: URL — inline code injection into worker thread.',
        file: ctx.relFile
      });
    }
  }

  // Blue Team v8: new SharedArrayBuffer() — shared memory for covert IPC
  if (node.callee.type === 'Identifier' && node.callee.name === 'SharedArrayBuffer') {
    ctx.hasSharedArrayBuffer = true;
  }

  // Blue Team v8: new WebSocket(url) — track for C2 compound detection
  if (node.callee.type === 'Identifier' && node.callee.name === 'WebSocket' &&
      node.arguments.length >= 1) {
    ctx.hasWebSocketNew = true;
    // Check if URL points to suspicious domain
    const wsArg = node.arguments[0];
    const wsUrl = extractStringValueDeep(wsArg);
    if (wsUrl) {
      const wsLower = wsUrl.toLowerCase();
      const isSuspiciousWs = SUSPICIOUS_DOMAINS_HIGH.some(d => wsLower.includes(d)) ||
                             SUSPICIOUS_DOMAINS_MEDIUM.some(d => wsLower.includes(d));
      if (isSuspiciousWs) {
        ctx.threats.push({
          type: 'websocket_c2',
          severity: 'HIGH',
          message: `new WebSocket() connecting to suspicious domain: "${wsUrl.substring(0, 80)}" — potential C2 channel.`,
          file: ctx.relFile
        });
      }
    }
  }

  // B2: new FinalizationRegistry(callback) — deferred execution after GC
  // Malicious pattern: callback contains require('child_process') or exec/spawn
  if (node.callee.type === 'Identifier' && node.callee.name === 'FinalizationRegistry' &&
      node.arguments.length >= 1) {
    const callback = node.arguments[0];
    if (callback) {
      // Check if callback body contains dangerous patterns
      let hasDangerousBody = false;
      const cbSource = callback.start !== undefined && callback.end !== undefined
        ? ctx._sourceCode?.slice(callback.start, callback.end) : null;
      if (cbSource && /\b(child_process|exec|execSync|spawn|spawnSync)\b/.test(cbSource)) {
        hasDangerousBody = true;
      }
      // Also flag if the callback is a variable known to be dangerous
      if (callback.type === 'Identifier' && ctx.evalAliases?.has(callback.name)) {
        hasDangerousBody = true;
      }
      if (hasDangerousBody) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'finalization_registry_exec',
          severity: 'CRITICAL',
          message: 'new FinalizationRegistry() with dangerous callback — deferred code execution triggered by garbage collection, evades synchronous analysis.',
          file: ctx.relFile
        });
      } else {
        ctx.hasFinalizationRegistry = true;
      }
    }
  }
}


module.exports = { handleNewExpression };
