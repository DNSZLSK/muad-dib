'use strict';

const { getCallName } = require('../../utils.js');
const {
  DANGEROUS_CMD_PATTERNS,
  HOOKABLE_NATIVES,
  NODE_HOOKABLE_MODULES,
  NODE_HOOKABLE_CLASSES
} = require('./constants.js');
const {
  extractStringValue,
  resolveStringConcat,
  extractStringValueDeep
} = require('./helpers.js');

function handleAssignmentExpression(node, ctx) {
  // Variable reassignment: x += 'process' or x = x + 'process'
  if (node.left?.type === 'Identifier') {
    if (node.operator === '+=' && ctx.stringVarValues.has(node.left.name)) {
      const rightVal = extractStringValueDeep(node.right);
      if (rightVal !== null) {
        const combined = ctx.stringVarValues.get(node.left.name) + rightVal;
        ctx.stringVarValues.set(node.left.name, combined);
        if (DANGEROUS_CMD_PATTERNS.some(p => p.test(combined))) {
          ctx.dangerousCmdVars.set(node.left.name, combined);
        }
      }
    }
    if (node.operator === '=' && node.right?.type === 'BinaryExpression') {
      const resolved = resolveStringConcat(node.right);
      if (resolved) {
        ctx.stringVarValues.set(node.left.name, resolved);
        if (DANGEROUS_CMD_PATTERNS.some(p => p.test(resolved))) {
          ctx.dangerousCmdVars.set(node.left.name, resolved);
        }
      }
    }
  }

  // B6: Symbol property hiding — obj[Symbol(...)] = require('child_process')
  if (node.left?.type === 'MemberExpression' && node.left.computed &&
      node.left.property?.type === 'CallExpression' &&
      node.left.property.callee?.type === 'Identifier' && node.left.property.callee.name === 'Symbol') {
    // Check if the right side is require('child_process') or similar dangerous module
    let isDangerous = false;
    let modName = null;
    if (node.right?.type === 'CallExpression' && getCallName(node.right) === 'require' &&
        node.right.arguments?.[0]?.type === 'Literal') {
      const rawMod = node.right.arguments[0].value;
      modName = typeof rawMod === 'string' && rawMod.startsWith('node:') ? rawMod.slice(5) : rawMod;
      if (['child_process', 'fs', 'net', 'dns', 'http', 'https'].includes(modName)) {
        isDangerous = true;
      }
    }
    // Also detect: obj[Symbol('x')] = eval / Function / exec
    if (node.right?.type === 'Identifier' && ['eval', 'Function'].includes(node.right.name)) {
      isDangerous = true;
    }
    if (isDangerous) {
      ctx.threats.push({
        type: 'symbol_property_hiding',
        severity: 'HIGH',
        message: `Dangerous module/function hidden behind Symbol property — obj[Symbol(...)] = ${modName ? "require('" + modName + "')" : node.right?.name || '...'}, evades string-based property enumeration.`,
        file: ctx.relFile
      });
    }
  }

  // B5: Module.wrap = ... or require('module').wrap = ... — module wrapper override
  if (node.left?.type === 'MemberExpression' &&
      node.left.property?.type === 'Identifier' && node.left.property.name === 'wrap') {
    const obj = node.left.object;
    // Direct: Module.wrap = ... (where Module was imported via require('module'))
    const isModuleObj = (obj?.type === 'Identifier' && ctx.moduleAliases?.has(obj.name)) ||
      (obj?.type === 'Identifier' && obj.name === 'Module');
    // Inline: require('module').wrap = ...
    const isInlineRequire = obj?.type === 'CallExpression' && getCallName(obj) === 'require' &&
      obj.arguments?.[0]?.type === 'Literal' && obj.arguments[0].value === 'module';
    if (isModuleObj || isInlineRequire) {
      ctx.threats.push({
        type: 'module_wrap_override',
        severity: 'CRITICAL',
        message: 'Module.wrap overridden — module wrapper function hijacked, allows injecting code into every loaded module.',
        file: ctx.relFile
      });
    }
  }

  // Blue Team v8b (A4): Module._resolveFilename / _compile / _extensions hijack
  // Any assignment to these private Module APIs is a supply-chain attack vector
  if (node.left?.type === 'MemberExpression' && !node.left.computed &&
      node.left.property?.type === 'Identifier' &&
      ['_resolveFilename', '_compile', '_extensions', '_findPath', '_nodeModulePaths'].includes(node.left.property.name)) {
    // Check if the object is Module, a module alias, or a constructor chain
    const obj = node.left.object;
    const isModuleRef = (obj?.type === 'Identifier' && (ctx.moduleAliases?.has(obj.name) || obj.name === 'Module')) ||
      // require('module')._resolveFilename = ...
      (obj?.type === 'CallExpression' && getCallName(obj) === 'require' && obj.arguments?.[0]?.value === 'module') ||
      // x.constructor._resolveFilename = ... (any .constructor chain)
      (obj?.type === 'MemberExpression' && obj.property?.type === 'Identifier' && obj.property.name === 'constructor');
    // Also match: proc.mainModule.constructor._resolveFilename (deeper chain)
    const isDeepChain = obj?.type === 'MemberExpression' && obj.property?.type === 'Identifier' &&
      ['_resolveFilename', '_compile', '_extensions', '_findPath', '_nodeModulePaths'].includes(node.left.property.name);
    if (isModuleRef || isDeepChain || (obj?.type === 'MemberExpression' && obj.property?.name === 'constructor')) {
      ctx.hasModuleInternalsHijack = true;
      ctx.threats.push({
        type: 'module_internals_hijack',
        severity: 'CRITICAL',
        message: `Assignment to Module.${node.left.property.name} — module system internals hijacked. All subsequent require() calls can be intercepted.`,
        file: ctx.relFile
      });
    }
  }

  // Detect object property indirection: obj.exec = require('child_process').exec
  // or obj.fn = eval — stashing dangerous functions in object properties
  if (node.left?.type === 'MemberExpression' && node.right) {
    const propName = node.left.property?.type === 'Identifier' ? node.left.property.name :
                     (node.left.property?.type === 'Literal' ? String(node.left.property.value) : null);

    if (propName) {
      // Assigning require('child_process') or its methods to an object property
      if (node.right.type === 'CallExpression' && getCallName(node.right) === 'require' &&
          node.right.arguments.length > 0 && node.right.arguments[0]?.type === 'Literal') {
        const rawMod = node.right.arguments[0].value;
        // Batch 2: strip node: prefix
        const mod = typeof rawMod === 'string' && rawMod.startsWith('node:') ? rawMod.slice(5) : rawMod;
        if (mod === 'child_process' || mod === 'fs' || mod === 'net' || mod === 'dns') {
          ctx.threats.push({
            type: 'dynamic_require',
            severity: 'HIGH',
            message: `Object property indirection: ${propName} = require('${mod}') — hiding dangerous module in object property.`,
            file: ctx.relFile
          });
        }
      }
      // Assigning require('child_process').exec to an object property
      if (node.right.type === 'MemberExpression' && node.right.object?.type === 'CallExpression' &&
          getCallName(node.right.object) === 'require' &&
          node.right.object.arguments.length > 0 && node.right.object.arguments[0]?.type === 'Literal') {
        const reqModRaw = node.right.object.arguments[0].value;
        // Batch 2: strip node: prefix
        const reqMod = typeof reqModRaw === 'string' && reqModRaw.startsWith('node:') ? reqModRaw.slice(5) : reqModRaw;
        if (reqMod === 'child_process') {
          const method = node.right.property?.type === 'Identifier' ? node.right.property.name : null;
          if (method && ['exec', 'execSync', 'spawn', 'execFile'].includes(method)) {
            ctx.threats.push({
              type: 'dangerous_exec',
              severity: 'HIGH',
              message: `Object property indirection: ${propName} = require('child_process').${method} — hiding exec in object property.`,
              file: ctx.relFile
            });
          }
        }
      }
      // Assigning eval or Function to an object property
      if (node.right.type === 'Identifier' && (node.right.name === 'eval' || node.right.name === 'Function')) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: node.right.name === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
          severity: 'HIGH',
          message: `Object property indirection: ${propName} = ${node.right.name} — stashing dangerous function in object property.`,
          file: ctx.relFile
        });
      }
    }
  }

  // B4: Prototype pollution — __proto__ assignment
  if (node.left?.type === 'MemberExpression' && !node.left.computed &&
      node.left.property?.type === 'Identifier' && node.left.property.name === '__proto__') {
    ctx.threats.push({
      type: 'prototype_pollution',
      severity: 'HIGH',
      message: `__proto__ assignment on ${node.left.object?.name || 'object'} — prototype pollution can hijack inherited properties across all objects.`,
      file: ctx.relFile
    });
  }

  if (node.left?.type === 'MemberExpression') {
    const left = node.left;

    // require.cache[...].exports = ... — module cache poisoning WRITE (not just read)
    // This is always malicious: replacing a core module's exports to intercept all usage.
    // Also detects: mod.exports.X = ... where mod is from require.cache[...]
    if (left.property?.type === 'Identifier' && left.property.name === 'exports') {
      // Direct pattern: require.cache[...].exports = ...
      const obj = left.object;
      if (obj?.type === 'MemberExpression' && obj.computed) {
        const deep = obj.object;
        if (deep?.type === 'MemberExpression' &&
            deep.object?.type === 'Identifier' && deep.object.name === 'require' &&
            deep.property?.type === 'Identifier' && deep.property.name === 'cache') {
          ctx.hasRequireCacheWrite = true;
        }
      }
    }
    // Indirect pattern: mod.exports.X = ... where mod = require.cache[...]
    if (left.object?.type === 'MemberExpression' &&
        left.object.property?.type === 'Identifier' && left.object.property.name === 'exports' &&
        left.object.object?.type === 'Identifier' &&
        ctx.requireCacheVars?.has(left.object.object.name)) {
      ctx.hasRequireCacheWrite = true;
    }

    // globalThis.fetch = ... or globalThis.XMLHttpRequest = ... (B2: include aliases)
    if (left.object?.type === 'Identifier' &&
        (left.object.name === 'globalThis' || left.object.name === 'global' ||
         left.object.name === 'window' || left.object.name === 'self' ||
         ctx.globalThisAliases.has(left.object.name)) &&
        left.property?.type === 'Identifier') {
      if (HOOKABLE_NATIVES.includes(left.property.name)) {
        ctx.threats.push({
          type: 'prototype_hook',
          severity: 'HIGH',
          message: `${left.object.name}.${left.property.name} overridden — native API hooking for traffic interception.`,
          file: ctx.relFile
        });
      }
    }

    // JSON.stringify = ... or JSON.parse = ... — global API hooking
    // Real-world technique: override JSON.stringify to intercept all serialization and exfiltrate data
    if (left.object?.type === 'Identifier' && left.object.name === 'JSON' &&
        left.property?.type === 'Identifier' &&
        ['stringify', 'parse'].includes(left.property.name)) {
      ctx.threats.push({
        type: 'prototype_hook',
        severity: 'HIGH',
        message: `JSON.${left.property.name} overridden — global API hooking to intercept all JSON serialization/deserialization.`,
        file: ctx.relFile
      });
    }

    // XMLHttpRequest.prototype.send = ... or Response.prototype.json = ...
    if (left.object?.type === 'MemberExpression' &&
        left.object.property?.type === 'Identifier' &&
        left.object.property.name === 'prototype' &&
        left.object.object?.type === 'Identifier') {
      if (HOOKABLE_NATIVES.includes(left.object.object.name)) {
        ctx.threats.push({
          type: 'prototype_hook',
          severity: 'HIGH',
          message: `${left.object.object.name}.prototype.${left.property?.name || '?'} overridden — native API hooking for traffic interception.`,
          file: ctx.relFile
        });
      }
    }

    // http.request = ... or https.get = ...
    if (left.object?.type === 'Identifier' &&
        ['http', 'https'].includes(left.object.name) &&
        left.property?.type === 'Identifier' &&
        ['request', 'get', 'createServer'].includes(left.property.name) &&
        node.right?.type === 'FunctionExpression') {
      ctx.threats.push({
        type: 'prototype_hook',
        severity: 'HIGH',
        message: `${left.object.name}.${left.property.name} overridden — Node.js network module hooking for traffic interception.`,
        file: ctx.relFile
      });
    }

    // <module>.<Class>.prototype.<method> = ...
    if (left.object?.type === 'MemberExpression' &&
        left.object.property?.type === 'Identifier' && left.object.property.name === 'prototype' &&
        left.object.object?.type === 'MemberExpression' &&
        left.object.object.object?.type === 'Identifier' &&
        left.object.object.property?.type === 'Identifier') {
      const moduleName = left.object.object.object.name;
      const className = left.object.object.property.name;
      if (NODE_HOOKABLE_MODULES.includes(moduleName) && NODE_HOOKABLE_CLASSES.includes(className)) {
        ctx.threats.push({
          type: 'prototype_hook',
          severity: 'CRITICAL',
          message: `${moduleName}.${className}.prototype.${left.property?.name || '?'} overridden — Node.js core module prototype hooking for traffic interception.`,
          file: ctx.relFile
        });
      }
    }
  }
}


module.exports = { handleAssignmentExpression };
