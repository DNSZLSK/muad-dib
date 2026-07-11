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

/**
 * install_native_drop_exec compound correlator (MUADDIB-COMPOUND-020).
 *
 * Threat model — the jscrambler@8.14.0 shape (Socket, 2026-07-11): a `preinstall`
 * hook (`node dist/setup.js`) reads a package-BUNDLED blob (`readFileSync(intro.js)`),
 * decompresses it (`gunzipSync`), writes it to a hidden temp file with an EXECUTABLE
 * mode (`writeFileSync(…, {mode: 0o755})`), and spawns THAT written path detached
 * (`spawn(target, [], {detached:true, stdio:'ignore', windowsHide:true}); unref()`).
 * A native infostealer runs on `npm install` before any application code — and the
 * loader itself trips ZERO existing AST/dataflow rules (only PKG-001 `lifecycle_script`
 * fires, capped as base behavior). This closes that gap.
 *
 * Why a compound and not a lone detector: the invariant we key on is
 *   (BUNDLED_SOURCE) the executable's bytes originate from WITHIN the package —
 *                    a local fs read, a zlib/brotli decompress, or an inline
 *                    base64/hex Buffer — NOT from the network; AND
 *   (DROP_EXEC)      a file is written with an exec bit / chmod +x / an .exe-class
 *                    name; AND
 *   (EXEC_COMPUTED)  child_process spawn/exec/execFile/fork runs a COMPUTED path
 *                    (a variable/expression, not a bare "git"/"node" literal).
 * Any one of these alone is legitimate somewhere. The three together, reached from an
 * install hook, is the "drop-and-run a bundled native binary at install time" pattern,
 * which legitimate native-module installers never do: they DOWNLOAD prebuilt binaries
 * from a URL (network, not bundled — so BUNDLED_SOURCE is absent), COMPILE via
 * `node-gyp`/`make`/`cc` invoked by NAME (a literal command — EXEC_COMPUTED absent), or
 * ship a prebuilt `.node` addon loaded with `require()` (never spawned). Gating on the
 * install hook + requiring all three signals ⇒ FP≈0 by construction.
 *
 * Variant-robust, not a jscrambler signature: renaming the carrier, changing the custom
 * container magic, swapping gzip→brotli/base64, `spawn`→`exec`/`fork`, tmpdir→cache, or
 * dropping the `.exe` obfuscation all preserve the three invariants and still fire. The
 * one evasion this does NOT cover — fetching the binary from a URL at install — is a
 * different, noisier pattern (network egress + URL IOC surface) detected elsewhere.
 *
 * Runs as a post-processor (like phantom-gyp.js): it re-reads package.json and the
 * invoked loader directly rather than relying on any per-file finding, so a benign
 * package carries no intermediate signal and gains zero findings.
 */
'use strict';

const fs = require('fs');
const path = require('path');

let acorn = null;
let walk = null;
try {
  acorn = require('acorn');
  walk = require('acorn-walk');
} catch { /* acorn unavailable → correlator is a no-op */ }

// Install hooks that npm runs on the CONSUMER from a published registry tarball.
// Same set package.js escalates on (preinstall/install/postinstall). `prepare` is
// intentionally excluded: it runs only for git/directory installs, not registry
// tarballs, and would widen the surface without the coupling gaining precision.
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];

// child_process execution sinks.
const EXEC_MEMBERS = new Set(['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']);
// zlib decompression of a bundled payload.
const DECOMPRESS_MEMBERS = new Set(['gunzipSync', 'gunzip', 'brotliDecompressSync', 'brotliDecompress', 'inflateSync', 'inflate', 'inflateRawSync', 'inflateRaw', 'unzipSync', 'unzip']);
// fs reads / writes / chmod.
const READ_MEMBERS = new Set(['readFileSync', 'readFile']);
const WRITE_MEMBERS = new Set(['writeFileSync', 'writeFile']);
const CHMOD_MEMBERS = new Set(['chmodSync', 'chmod', 'fchmodSync', 'fchmod', 'lchmodSync', 'lchmod']);

const MODULE_CP = new Set(['child_process', 'node:child_process']);
const MODULE_ZLIB = new Set(['zlib', 'node:zlib']);
const MODULE_FS = new Set(['fs', 'node:fs', 'fs/promises', 'node:fs/promises']);
// HTTP download modules. Their presence means the loader FETCHES its bytes — the
// download-and-execute pattern (network egress + URL IOC surface), handled by other
// detectors. This compound is intentionally scoped to the STEALTHY no-network variant
// where the payload is bundled inside the package, so we suppress when any appears.
const NETWORK_MODULES = new Set([
  'http', 'https', 'node:http', 'node:https', 'http2', 'node:http2',
  'axios', 'node-fetch', 'got', 'undici', 'request', 'follow-redirects',
  'needle', 'superagent', 'phin', 'bent', 'cross-fetch', 'isomorphic-fetch',
  'make-fetch-happen', 'minipass-fetch'
]);

const EXEC_EXT_RE = /\.(?:exe|cmd|bat|com|scr|ps1|msi)$/i;
const ENCODINGS = new Set(['base64', 'base64url', 'hex']);

// Loaders are tiny. Skip pathological files (a huge minified index is never an
// install loader) to bound parse cost.
const MAX_SCRIPT_BYTES = 1024 * 1024;

/** Normalize a relative path for comparison: backslashes→/, strip leading ./ and /. */
function _normRel(f) {
  return String(f || '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '');
}

/**
 * Extract the local .js/.cjs/.mjs files invoked by `node <file>` in a lifecycle
 * command line. Splits on shell separators so `node a.js && echo ok` yields a.js.
 * Inline-eval forms (`node -e "…"`) and non-node commands yield nothing.
 * @param {string} cmd - raw script command from package.json scripts[hook]
 * @returns {string[]} invoked script file paths (as written in the command)
 */
function extractInvokedScriptFiles(cmd) {
  const out = [];
  if (!cmd || typeof cmd !== 'string') return out;
  const segments = cmd.split(/&&|\|\||[;&|\n]/);
  for (const seg of segments) {
    const toks = seg.trim().split(/\s+/).filter(Boolean);
    if (!toks.length) continue;
    const bin = toks[0].replace(/^.*[/\\]/, '').toLowerCase();
    if (bin !== 'node' && bin !== 'nodejs') continue;
    for (let i = 1; i < toks.length; i++) {
      const tok = toks[i];
      if (tok.startsWith('-')) {
        // An inline-eval flag means there is no script file in this invocation.
        if (/^--?(?:e|p|c|eval|print|require)$/i.test(tok)) break;
        continue; // some other flag (e.g. --experimental-*) — keep scanning
      }
      const clean = tok.replace(/^['"]+|['"]+$/g, '');
      if (/\.(?:c|m)?js$/i.test(clean)) { out.push(clean); break; }
      break; // first non-flag token is not a script file → nothing to analyze
    }
  }
  return out;
}

/** Try module then script source type. Returns AST or null (obfuscated/non-JS). */
function _parse(code) {
  if (!acorn) return null;
  for (const sourceType of ['module', 'script']) {
    try {
      return acorn.parse(code, {
        ecmaVersion: 'latest',
        sourceType,
        allowHashBang: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true
      });
    } catch { /* try next */ }
  }
  return null;
}

/** True when a spawn/exec first argument is a COMPUTED path (not a bare command literal). */
function _isComputedArg(arg) {
  if (!arg) return false;
  if (arg.type === 'Literal') return typeof arg.value !== 'string' ? false : false; // literal command → not our pattern
  if (arg.type === 'TemplateLiteral') return (arg.expressions && arg.expressions.length > 0);
  // Identifier / MemberExpression / CallExpression / BinaryExpression / ConditionalExpression …
  return true;
}

/** True when the read source is an explicit http(s) URL literal (network, not bundled). */
function _isUrlArg(arg) {
  if (!arg) return false;
  if (arg.type === 'Literal' && typeof arg.value === 'string') return /^https?:\/\//i.test(arg.value);
  if (arg.type === 'TemplateLiteral' && arg.quasis && arg.quasis[0]) {
    return /^https?:\/\//i.test(arg.quasis[0].value.cooked || arg.quasis[0].value.raw || '');
  }
  // `new URL('./x', import.meta.url)` is the canonical ESM LOCAL-file idiom — only an
  // http(s) first argument makes it a network URL.
  if (arg.type === 'NewExpression' && arg.callee && arg.callee.name === 'URL') {
    const u = arg.arguments && arg.arguments[0];
    return !!(u && u.type === 'Literal' && typeof u.value === 'string' && /^https?:\/\//i.test(u.value));
  }
  return false;
}

/** True when a numeric/string/ternary mode value carries any exec bit (0o111 mask). */
function _modeHasExecBit(node) {
  if (!node) return false;
  if (node.type === 'Literal') {
    if (typeof node.value === 'number') return (node.value & 0o111) !== 0;
    if (typeof node.value === 'string') {
      const v = parseInt(node.value, 8);
      return Number.isInteger(v) && (v & 0o111) !== 0;
    }
    return false;
  }
  // { mode: platform === 1 ? 0o644 : 0o755 } — check both branches.
  if (node.type === 'ConditionalExpression') {
    return _modeHasExecBit(node.consequent) || _modeHasExecBit(node.alternate);
  }
  return false;
}

/** writeFile(file, data, options?): executable if options.mode has an exec bit, or the target is an .exe-class literal. */
function _writeIsExecutable(callNode) {
  const args = callNode.arguments || [];
  const opts = args[2];
  if (opts && opts.type === 'ObjectExpression') {
    for (const p of opts.properties) {
      if (p.type === 'Property' && !p.computed && p.key &&
          (p.key.name === 'mode' || p.key.value === 'mode') && _modeHasExecBit(p.value)) {
        return true;
      }
    }
  }
  const target = args[0];
  if (target && target.type === 'Literal' && typeof target.value === 'string' && EXEC_EXT_RE.test(target.value)) {
    return true;
  }
  return false;
}

/** Buffer.from(<string literal>, 'base64'|'hex') — an inline-encoded payload. */
function _isEncodingArg(arg) {
  return !!(arg && arg.type === 'Literal' && typeof arg.value === 'string' && ENCODINGS.has(arg.value.toLowerCase()));
}

/** True when `node` is `require('<module in set>')`. */
function _isRequireOf(node, moduleSet) {
  return !!(node && node.type === 'CallExpression' && node.callee && node.callee.type === 'Identifier' &&
    node.callee.name === 'require' && node.arguments && node.arguments[0] &&
    node.arguments[0].type === 'Literal' && moduleSet.has(node.arguments[0].value));
}

/**
 * Collect local binding names imported/required from child_process, zlib and fs.
 * Handles ESM named/namespace imports and CJS require destructuring/namespace, plus
 * `const spawn = require('child_process').spawn`.
 */
function _collectBindings(ast) {
  const b = {
    execFns: new Set(), cpNs: new Set(),
    decompressFns: new Set(), zlibNs: new Set(),
    readFns: new Set(), writeFns: new Set(), chmodFns: new Set(), fsNs: new Set(),
    network: false
  };
  const addNamed = (src, importedName, localName) => {
    if (MODULE_CP.has(src)) {
      if (EXEC_MEMBERS.has(importedName)) b.execFns.add(localName);
    } else if (MODULE_ZLIB.has(src)) {
      if (DECOMPRESS_MEMBERS.has(importedName)) b.decompressFns.add(localName);
    } else if (MODULE_FS.has(src)) {
      if (READ_MEMBERS.has(importedName)) b.readFns.add(localName);
      else if (WRITE_MEMBERS.has(importedName)) b.writeFns.add(localName);
      else if (CHMOD_MEMBERS.has(importedName)) b.chmodFns.add(localName);
    }
  };
  const addNs = (src, localName) => {
    if (MODULE_CP.has(src)) b.cpNs.add(localName);
    else if (MODULE_ZLIB.has(src)) b.zlibNs.add(localName);
    else if (MODULE_FS.has(src)) b.fsNs.add(localName);
  };

  walk.simple(ast, {
    ImportDeclaration(node) {
      const src = node.source && node.source.value;
      if (!src) return;
      if (NETWORK_MODULES.has(src)) b.network = true;
      for (const spec of node.specifiers || []) {
        if (spec.type === 'ImportSpecifier') addNamed(src, spec.imported.name, spec.local.name);
        else if (spec.type === 'ImportNamespaceSpecifier' || spec.type === 'ImportDefaultSpecifier') addNs(src, spec.local.name);
      }
    },
    VariableDeclarator(node) {
      const init = node.init;
      if (!init) return;
      // const X = require('mod')  |  const {a,b} = require('mod')
      if (init.type === 'CallExpression' && init.callee && init.callee.type === 'Identifier' &&
          init.callee.name === 'require' && init.arguments[0] && init.arguments[0].type === 'Literal') {
        const src = init.arguments[0].value;
        if (NETWORK_MODULES.has(src)) b.network = true;
        if (node.id.type === 'Identifier') addNs(src, node.id.name);
        else if (node.id.type === 'ObjectPattern') {
          for (const p of node.id.properties) {
            if (p.type === 'Property' && p.key && p.value && p.value.type === 'Identifier') {
              addNamed(src, p.key.name || p.key.value, p.value.name);
            }
          }
        }
        return;
      }
      // const spawn = require('child_process').spawn
      if (init.type === 'MemberExpression' && !init.computed && init.property.type === 'Identifier' &&
          node.id.type === 'Identifier') {
        const prop = init.property.name;
        if (_isRequireOf(init.object, MODULE_CP) && EXEC_MEMBERS.has(prop)) b.execFns.add(node.id.name);
        else if (_isRequireOf(init.object, MODULE_ZLIB) && DECOMPRESS_MEMBERS.has(prop)) b.decompressFns.add(node.id.name);
        else if (_isRequireOf(init.object, MODULE_FS) && READ_MEMBERS.has(prop)) b.readFns.add(node.id.name);
        else if (_isRequireOf(init.object, MODULE_FS) && WRITE_MEMBERS.has(prop)) b.writeFns.add(node.id.name);
        else if (_isRequireOf(init.object, MODULE_FS) && CHMOD_MEMBERS.has(prop)) b.chmodFns.add(node.id.name);
      }
    }
  });
  return b;
}

/** Record spawn/exec option boosters (not required for firing — they enrich the message). */
function _spawnBoosters(callNode, sig) {
  const opts = (callNode.arguments || []).find(a => a && a.type === 'ObjectExpression');
  if (!opts) return;
  for (const p of opts.properties) {
    if (p.type !== 'Property' || p.computed || !p.key) continue;
    const k = p.key.name || p.key.value;
    if (k === 'detached' && p.value.type === 'Literal' && p.value.value === true) sig.boosters.add('detached');
    else if (k === 'stdio' && p.value.type === 'Literal' && p.value.value === 'ignore') sig.boosters.add("stdio:'ignore'");
    else if (k === 'windowsHide' && p.value.type === 'Literal' && p.value.value === true) sig.boosters.add('windowsHide');
  }
}

/** Classify one CallExpression against the module bindings, updating the signal set. */
function _classifyCall(node, b, sig) {
  const callee = node.callee;
  const args = node.arguments || [];
  if (!callee) return;

  if (callee.type === 'Identifier') {
    const n = callee.name;
    if (n === 'fetch') { sig.network = true; return; }
    if (b.execFns.has(n)) { if (_isComputedArg(args[0])) { sig.exec = true; _spawnBoosters(node, sig); } }
    else if (b.decompressFns.has(n)) sig.boosters.add('decompress');
    else if (b.readFns.has(n)) { if (!_isUrlArg(args[0])) sig.source = true; }
    else if (b.writeFns.has(n)) { if (_writeIsExecutable(node)) sig.drop = true; }
    else if (b.chmodFns.has(n)) { if (_modeHasExecBit(args[1])) sig.drop = true; }
    return;
  }

  if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
    const prop = callee.property.name;
    const obj = callee.object;
    const objName = obj.type === 'Identifier' ? obj.name : null;
    if (objName === 'Buffer' && prop === 'from' && _isEncodingArg(args[1])) { sig.source = true; return; }
    if (prop === 'unref') { sig.boosters.add('unref'); return; }

    const objIsCP = (objName && b.cpNs.has(objName)) || _isRequireOf(obj, MODULE_CP);
    const objIsZ = (objName && b.zlibNs.has(objName)) || _isRequireOf(obj, MODULE_ZLIB);
    const objIsFS = (objName && b.fsNs.has(objName)) || _isRequireOf(obj, MODULE_FS);

    if (objIsCP && EXEC_MEMBERS.has(prop)) { if (_isComputedArg(args[0])) { sig.exec = true; _spawnBoosters(node, sig); } }
    else if (objIsZ && DECOMPRESS_MEMBERS.has(prop)) sig.boosters.add('decompress');
    else if (objIsFS && READ_MEMBERS.has(prop)) { if (!_isUrlArg(args[0])) sig.source = true; }
    else if (objIsFS && WRITE_MEMBERS.has(prop)) { if (_writeIsExecutable(node)) sig.drop = true; }
    else if (objIsFS && CHMOD_MEMBERS.has(prop)) { if (_modeHasExecBit(args[1])) sig.drop = true; }
  }
}

/** Conservative textual scan — only reached when the loader does not parse as JS. */
function _textualFallback(code) {
  // Network present → download-exec pattern, not our bundled variant. Suppress.
  if (/\bhttps?\b|\bfetch\s*\(|\b(?:axios|node-fetch|got|undici|follow-redirects)\b/.test(code)) {
    return { fired: false, reason: '' };
  }
  const hasCP = /(?:require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"])/.test(code);
  const hasExec = /\b(?:spawn|spawnSync|execFile|execFileSync|fork)\s*\(/.test(code);
  // Bundled source = local file read or inline base64/hex (a bare decompress could be on
  // a network stream, so it is a booster, not a source qualifier).
  const hasSource = /\breadFileSync?\s*\(|Buffer\.from\([^)]*['"](?:base64|hex)['"]/.test(code);
  const hasDrop = /\bchmod\w*\s*\(|mode\s*:\s*0o?[0-7]*[1357]|['"][^'"]*\.exe['"]/.test(code);
  const fired = hasCP && hasExec && hasSource && hasDrop;
  return { fired, reason: fired ? 'reads bundled bytes, writes an executable file and spawns it (textual match on an unparsable loader)' : '' };
}

/** Compose a static human-readable reason from the fired signals + boosters. */
function _buildReason(sig) {
  const boosters = sig.boosters.size ? ` (${Array.from(sig.boosters).join(', ')})` : '';
  return 'reads package-bundled bytes (local read / decompress / inline base64), writes them to an executable file ' +
    '(exec-bit mode, chmod +x, or .exe) and spawns that written path' + boosters;
}

/**
 * Analyze one install-hook-invoked loader for the drop-exec conjunction.
 * @returns {{fired:boolean, reason?:string}|null} null when the file can't be read/resolved
 */
function analyzeScriptForDropExec(targetPath, file) {
  const rel = _normRel(file);
  const root = path.resolve(targetPath);
  const abs = path.resolve(root, rel);
  // Contain within the package (no ../ traversal out of the scan root).
  if (abs !== root && !abs.startsWith(root + path.sep)) return null;

  let code;
  try {
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > MAX_SCRIPT_BYTES) return null;
    code = fs.readFileSync(abs, 'utf8');
  } catch { return null; }

  const ast = _parse(code);
  if (!ast) return _textualFallback(code);

  const bindings = _collectBindings(ast);
  const sig = { exec: false, drop: false, source: false, network: false, boosters: new Set() };
  walk.simple(ast, { CallExpression(node) { _classifyCall(node, bindings, sig); } });

  // Suppress when the loader fetches its bytes from the network: that is the
  // download-and-execute pattern (network egress + URL IOC surface, handled by other
  // detectors), not the stealthy bundled variant this compound targets.
  if (bindings.network || sig.network) return { fired: false };
  if (!(sig.exec && sig.drop && sig.source)) return { fired: false };
  return { fired: true, reason: _buildReason(sig) };
}

/**
 * install_native_drop_exec compound: for each preinstall/install/postinstall that runs
 * `node x.js`, if x.js bundles+drops+executes a native binary, push one CRITICAL threat.
 * Mutates `threats` in place; idempotent; no-op (no findings added) on benign packages.
 *
 * @param {Array<object>} threats - deduplicated, post-scan threats array
 * @param {string} targetPath - scan target directory (where package.json lives)
 * @returns {object|null} the pushed compound threat, or null if nothing fired
 */
function correlateInstallNativeDropExec(threats, targetPath) {
  if (!Array.isArray(threats) || !targetPath || !acorn) return null;
  if (threats.some(t => t && t.type === 'install_native_drop_exec')) return null; // idempotent

  let pkg;
  try {
    const p = path.join(targetPath, 'package.json');
    if (!fs.existsSync(p)) return null;
    pkg = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch { return null; }

  const scripts = pkg && pkg.scripts;
  if (!scripts || typeof scripts !== 'object') return null;

  for (const hook of INSTALL_HOOKS) {
    for (const file of extractInvokedScriptFiles(scripts[hook])) {
      const analysis = analyzeScriptForDropExec(targetPath, file);
      if (analysis && analysis.fired) {
        const compound = {
          type: 'install_native_drop_exec',
          severity: 'CRITICAL',
          message: `package.json "${hook}" runs \`node ${file}\`, which ${analysis.reason} — install-time native-binary drop-and-execute: the payload runs on \`npm install\` before any application code, no import required (compound).`,
          file: _normRel(file),
          compound: true,
          count: 1
        };
        threats.push(compound);
        return compound; // one compound per package is enough
      }
    }
  }
  return null;
}

module.exports = {
  correlateInstallNativeDropExec,
  extractInvokedScriptFiles,
  analyzeScriptForDropExec,
  _normRel
};
