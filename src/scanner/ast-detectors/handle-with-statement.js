'use strict';

const { getCallName } = require('../../utils.js');

function handleWithStatement(node, ctx) {
  // with(require('child_process')) exec(cmd) — scope injection evasion
  // The with() statement makes all properties of the object available as local variables.
  // When used with require(), it allows calling exec(), spawn() etc. without explicit reference.
  if (node.object?.type === 'CallExpression' && getCallName(node.object) === 'require') {
    const arg = node.object.arguments[0];
    const rawModName = arg?.type === 'Literal' ? arg.value : null;
    // Batch 2: strip node: prefix
    const modName = typeof rawModName === 'string' && rawModName.startsWith('node:') ? rawModName.slice(5) : rawModName;
    const dangerousModules = ['child_process', 'fs', 'http', 'https', 'net', 'dns', 'worker_threads'];
    if (modName && dangerousModules.includes(modName)) {
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'dangerous_exec',
        severity: 'CRITICAL',
        message: `with(require('${modName}')) — scope injection evasion: all module methods available as local variables.`,
        file: ctx.relFile
      });
    } else if (!modName) {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: 'with(require(...)) — scope injection with dynamic module. Evasion technique.',
        file: ctx.relFile
      });
    }
    return; // Already handled as direct with(require(...))
  }

  // B7: with(obj) { ... require('child_process') ... } — body contains dangerous require/exec
  // The with statement itself is rare in modern code; combined with dangerous APIs in body = evasion
  if (node.body) {
    const bodySource = node.body.start !== undefined && node.body.end !== undefined
      ? ctx._sourceCode?.slice(node.body.start, node.body.end) : null;
    if (bodySource && /\b(require\s*\(\s*['"]child_process['"]\s*\)|child_process|exec\s*\(|execSync\s*\(|spawn\s*\()/.test(bodySource)) {
      // Blue Team v8: Elevate to CRITICAL when with() scope object is a known Proxy variable
      const isProxyScope = node.object?.type === 'Identifier' && ctx.proxyHandlerVars?.has(node.object.name);
      ctx.threats.push({
        type: 'with_body_dangerous',
        severity: isProxyScope ? 'CRITICAL' : 'HIGH',
        message: isProxyScope
          ? `with(Proxy) + exec/require in body — Proxy trap intercepts all name resolution, enabling complete API hijacking.`
          : 'with() statement body contains require/exec/spawn — scope injection used to obscure dangerous API calls.',
        file: ctx.relFile
      });
    }
  }
}


module.exports = { handleWithStatement };
