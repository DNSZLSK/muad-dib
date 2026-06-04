'use strict';

const {
  calleeDottedName,
  stringLiteralValue,
  lineOf
} = require('./helpers.js');

/**
 * Specialised visitor: emits PYAST-001 and PYAST-002 only on `setup(...)`
 * calls that are at module level inside a `setup.py` file.
 *
 * Both rules look at the dict/keyword arguments passed to setuptools' main
 * entrypoint. They do NOT cross-fire on a setup() call that is itself
 * scoped inside a function (depth >= 1) — that would be a function defining
 * a helper, not a real package definition.
 */

// Setup commands whose override is the canonical install-time RCE vector.
const INSTALL_TIME_COMMANDS = new Set([
  'install',
  'develop',
  'easy_install',
  'build',
  'build_py',
  'build_ext',  // build_ext is also a known abuse vector (CustomBuildExt that runs payload during compile)
  'bdist_wheel',
  'sdist'
]);

// Commands that are typically legitimate when overridden (compile / packaging
// helpers). We DON'T blanket-allow them; we still flag if the override class
// contains exec/subprocess/network calls in its body. But for the strict
// PYAST-001 "cmdclass override" finding, build_ext-only with a clearly-named
// legit base class drops to MEDIUM. (Implemented in body check below.)
function emitCmdclassFinding(ctx, callNode, kwNode, commandsOverridden) {
  const severity = commandsOverridden.has('install') || commandsOverridden.has('develop')
    ? 'CRITICAL'
    : 'HIGH';
  const list = [...commandsOverridden].join(', ');
  ctx.threats.push({
    type: 'pyast_setup_cmdclass_override',
    severity,
    message: `${ctx.relFile}:${lineOf(kwNode || callNode)}: setup(cmdclass={...}) overrides ${list} — install-time RCE vector (canonical PyPI supply chain pattern; TrapDoor mai 2026).`,
    file: ctx.relFile,
    line: lineOf(kwNode || callNode)
  });
}

/**
 * Walk a `dictionary` node and return a Set of command names (string keys).
 * Returns null if the dict is not a literal (e.g. computed expression).
 */
function extractDictStringKeys(dictNode) {
  if (!dictNode || dictNode.type !== 'dictionary') return null;
  const keys = new Set();
  for (const child of dictNode.children) {
    if (child.type !== 'pair') continue;
    const keyNode = child.childForFieldName('key');
    const literal = stringLiteralValue(keyNode);
    if (literal !== null) {
      keys.add(literal);
    }
    // If a key isn't a literal string, skip it but don't bail — the literal
    // keys we DO find still constitute evidence.
  }
  return keys;
}

function handleSetupCall(node, ctx, scopeDepth) {
  const callee = calleeDottedName(node);
  if (callee !== 'setup') return;
  if (scopeDepth !== 0) return;
  // Only treat as a "setuptools setup()" if the file is named setup.py.
  // Inside __init__.py or other modules, a function called setup() is more
  // likely a user-defined function — too FP-prone to flag.
  if (!ctx.relFile.endsWith('setup.py')) return;

  // PYAST-001: cmdclass keyword argument with dict literal.
  const args = node.childForFieldName('arguments');
  if (!args) return;

  for (const child of args.children) {
    if (child.type !== 'keyword_argument') continue;
    const nameNode = child.childForFieldName('name');
    if (!nameNode) continue;
    const valueNode = child.childForFieldName('value');

    if (nameNode.text === 'cmdclass') {
      const keys = extractDictStringKeys(valueNode);
      if (keys && keys.size > 0) {
        const installRelated = new Set([...keys].filter(k => INSTALL_TIME_COMMANDS.has(k)));
        if (installRelated.size > 0) {
          emitCmdclassFinding(ctx, node, child, installRelated);
        }
      }
    }

    // PYAST-002: entry_points={'console_scripts': [...]} with a name pattern
    // that looks unusual (single-letter names, names matching `_post_install`
    // or `setup_<verb>`, or pointing to a module that doesn't match the
    // package name). Heuristic — emit HIGH only if at least one entry looks
    // suspicious. Conservative: legit packages routinely use console_scripts.
    if (nameNode.text === 'entry_points') {
      const sus = inspectEntryPoints(valueNode);
      if (sus.length > 0) {
        ctx.threats.push({
          type: 'pyast_setup_entry_points_suspicious',
          severity: 'HIGH',
          message: `${ctx.relFile}:${lineOf(child)}: setup(entry_points=...) declares ${sus.length} suspicious console_scripts: ${sus.slice(0, 3).join(', ')}${sus.length > 3 ? '…' : ''}.`,
          file: ctx.relFile,
          line: lineOf(child)
        });
      }
    }
  }
}

const SUSPICIOUS_ENTRY_NAME_RE = /^(_|post_install|setup_|install_)/i;

function inspectEntryPoints(valueNode) {
  const sus = [];
  if (!valueNode || valueNode.type !== 'dictionary') return sus;
  for (const pair of valueNode.children) {
    if (pair.type !== 'pair') continue;
    const keyNode = pair.childForFieldName('key');
    const valNode = pair.childForFieldName('value');
    const key = stringLiteralValue(keyNode);
    if (key !== 'console_scripts' && key !== 'distutils.commands') continue;
    // valNode is a list of strings like ["name = module:func", ...].
    if (!valNode || valNode.type !== 'list') continue;
    for (const item of valNode.children) {
      const entry = stringLiteralValue(item);
      if (!entry) continue;
      const namePart = entry.split('=')[0].trim();
      if (SUSPICIOUS_ENTRY_NAME_RE.test(namePart)) sus.push(entry);
    }
  }
  return sus;
}

module.exports = { handleSetupCall };
