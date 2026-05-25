'use strict';

const {
  calleeDottedName,
  hasKeywordArg,
  firstPositionalArg,
  stringLiteralValue,
  isTruthyLiteral,
  lineOf
} = require('./helpers.js');

/**
 * Visitor for `call` nodes. Emits PYAST-003, PYAST-004, PYAST-007, PYAST-008.
 *
 * PYAST-001 / PYAST-002 are emitted by `handle-setup-call.js` which is a
 * specialised pass over the same node type — it only fires on `setup(...)`.
 */

const MODULE_EXEC_CALLEES = new Set(['exec', 'eval']);

const SUBPROCESS_SHELL_CALLEES = new Set([
  'subprocess.Popen',
  'subprocess.run',
  'subprocess.call',
  'subprocess.check_output',
  'subprocess.check_call',
  'subprocess.getoutput',
  'subprocess.getstatusoutput'
]);

const DESERIALIZATION_CALLEES = new Set([
  'pickle.loads',
  'pickle.load',
  'cPickle.loads',
  'cPickle.load',
  'marshal.loads',
  'marshal.load',
  'dill.loads',
  'dill.load',
  'cloudpickle.loads',
  'cloudpickle.load',
  'jsonpickle.loads',
  'shelve.open'  // shelve.open returns an unpickling object
]);

const DANGEROUS_DYNAMIC_IMPORTS = new Set([
  'subprocess',
  'os',
  'requests',
  'urllib',
  'urllib2',
  'urllib.request',
  'socket',
  'http',
  'http.client',
  'ssl',
  'ctypes',
  'importlib'
]);

function handleCallExpression(node, ctx, scopeDepth) {
  const callee = calleeDottedName(node);
  if (!callee) return;

  // PYAST-003: exec()/eval() at module level — direct RCE on import.
  if (MODULE_EXEC_CALLEES.has(callee) && scopeDepth === 0) {
    ctx.threats.push({
      type: 'pyast_module_level_exec',
      severity: 'CRITICAL',
      message: `${ctx.relFile}:${lineOf(node)}: ${callee}() at module level — executes on import or pip install (RCE).`,
      file: ctx.relFile,
      line: lineOf(node)
    });
  }

  // PYAST-004: subprocess.X(..., shell=True) at module level.
  if (SUBPROCESS_SHELL_CALLEES.has(callee) && scopeDepth === 0) {
    if (hasKeywordArg(node, 'shell', isTruthyLiteral)) {
      ctx.threats.push({
        type: 'pyast_module_level_subprocess_shell',
        severity: 'CRITICAL',
        message: `${ctx.relFile}:${lineOf(node)}: ${callee}(..., shell=True) at module level — shell command injection surface, executes on import.`,
        file: ctx.relFile,
        line: lineOf(node)
      });
    }
  }

  // PYAST-007: unsafe deserialization at module level.
  if (DESERIALIZATION_CALLEES.has(callee) && scopeDepth === 0) {
    ctx.threats.push({
      type: 'pyast_module_level_unsafe_deserialization',
      severity: 'CRITICAL',
      message: `${ctx.relFile}:${lineOf(node)}: ${callee}() at module level — pickle/marshal deserialization is trivially RCE if input is attacker-controlled, and runs on import.`,
      file: ctx.relFile,
      line: lineOf(node)
    });
  }

  // PYAST-008: __import__('subprocess'|'os'|...) with hardcoded dangerous name.
  // The string literal arg is checked at ANY scope depth — the obfuscation
  // intent is independent of whether it runs at import or later.
  if (callee === '__import__') {
    const firstArg = firstPositionalArg(node);
    const name = stringLiteralValue(firstArg);
    if (name && DANGEROUS_DYNAMIC_IMPORTS.has(name)) {
      ctx.threats.push({
        type: 'pyast_dynamic_dangerous_import',
        severity: 'HIGH',
        message: `${ctx.relFile}:${lineOf(node)}: __import__('${name}') — dynamic import of a dangerous module is an obfuscation pattern (evades static "import X" tracking).`,
        file: ctx.relFile,
        line: lineOf(node)
      });
    }
  }
}

module.exports = { handleCallExpression };
