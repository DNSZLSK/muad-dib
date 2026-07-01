'use strict';

const {
  calleeDottedName,
  hasKeywordArg,
  firstPositionalArg,
  stringLiteralValue,
  isTruthyLiteral,
  lineOf
} = require('./helpers.js');
const { lookupTaint, isEnvSensitive, isCryptoEncryptCall, isSensitiveFileOpen, nodeReadsSensitiveEnv } = require('./taint-tracker.js');

/**
 * Visitor for `call` nodes. Emits PYAST-003, PYAST-004, PYAST-005, PYAST-006,
 * PYAST-007, PYAST-008, PYAST-009, PYAST-010.
 *
 * PYAST-001 / PYAST-002 are emitted by `handle-setup-call.js` which is a
 * specialised pass over the same node type — it only fires on `setup(...)`.
 *
 * Taint-aware detectors (005/006/009/010) read `ctx.moduleTaint` populated
 * by `handle-assignment.js`. They only fire at scope_depth === 0 (module-level
 * sinks paired with module-level sources — see plan Phase 1b for the
 * intra-procedural / single-hop restrictions).
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

// Network "write" sinks for PYAST-010. POST/PUT/PATCH-style sends.
const NETWORK_WRITE_CALLEES = new Set([
  'requests.post',
  'requests.put',
  'requests.patch',
  'requests.delete',
  'requests.request',
  'httpx.post',
  'httpx.put',
  'httpx.patch',
  'httpx.delete',
  'httpx.request',
  'urllib.request.urlopen',  // can send body when called on a Request object
  'urllib.request.Request'
]);

const NETWORK_DATA_KWARGS = new Set(['data', 'json', 'body', 'files', 'params']);

// ctypes loaders for PYAST-009.
const CTYPES_LOAD_CALLEES = new Set([
  'ctypes.CDLL',
  'ctypes.WinDLL',
  'ctypes.cdll.LoadLibrary',
  'ctypes.windll.LoadLibrary',
  'ctypes.PyDLL'
]);

const SUSPICIOUS_PATH_RE = /^(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|~\/|\$HOME\/|C:\\Users\\Public\\|C:\\Windows\\Temp\\|\.\/_?cache\/)/i;

// ---------------------------------------------------------------------------
// Helper: iterate positional args of a call, skipping syntax noise.
// ---------------------------------------------------------------------------
function* positionalArgs(callNode) {
  const args = callNode.childForFieldName('arguments');
  if (!args) return;
  for (const child of args.children) {
    if (child.type === 'keyword_argument' || child.type === ','
        || child.type === '(' || child.type === ')') continue;
    yield child;
  }
}

// Returns the value node of a kwarg with the given name, or null.
function getKwargValue(callNode, kwName) {
  const args = callNode.childForFieldName('arguments');
  if (!args) return null;
  for (const child of args.children) {
    if (child.type !== 'keyword_argument') continue;
    const nameNode = child.childForFieldName('name');
    if (nameNode && nameNode.text === kwName) {
      return child.childForFieldName('value');
    }
  }
  return null;
}

// crypto_exfil harvest helper: true if any argument (positional or kwarg value)
// reads a sensitive env var, e.g. requests.post(url, data=os.environ['AWS_SECRET']).
function _callHasSensitiveEnvArg(callNode) {
  const args = callNode.childForFieldName('arguments');
  if (!args) return false;
  for (const child of args.children) {
    if (child.type === 'keyword_argument') {
      const v = child.childForFieldName('value');
      if (v && nodeReadsSensitiveEnv(v)) return true;
    } else if (nodeReadsSensitiveEnv(child)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Main visitor
// ---------------------------------------------------------------------------

function handleCallExpression(node, ctx, scopeDepth) {
  const callee = calleeDottedName(node);

  // crypto_exfil (PyPI mirror of MUADDIB-COMPOUND-019): accumulate file-level flags consumed by
  // the post-walk same-file compound in python-ast.js. Runs for EVERY call (before the !callee
  // early return) and at ANY scope — the compound is file-level, like the JS handle-post-walk one.
  // AST-call based, so a string/comment that merely contains "AES.new(" cannot trip it (JS self-FP lesson).
  if (isCryptoEncryptCall(node)) ctx.hasCryptoEncryptPy = true;
  if (callee && NETWORK_WRITE_CALLEES.has(callee)) ctx.hasNetworkWritePy = true;
  if (!ctx.hasSensitiveHarvestPy &&
      (nodeReadsSensitiveEnv(node) || isSensitiveFileOpen(node) || _callHasSensitiveEnvArg(node))) {
    ctx.hasSensitiveHarvestPy = true;
  }

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

    // PYAST-005 / PYAST-006: taint-aware compounds layered on top of PYAST-003.
    // Walk the positional args; if any is a tainted identifier we fire the
    // appropriate compound. Multiple sources in the same call → multiple emits.
    for (const arg of positionalArgs(node)) {
      const taint = lookupTaint(ctx, arg);
      if (!taint) continue;
      if (taint.sourceType === 'fetch') {
        ctx.threats.push({
          type: 'pyast_fetch_to_exec_taint',
          severity: 'CRITICAL',
          message: `${ctx.relFile}:${lineOf(node)}: ${callee}(${arg.text}) — argument was assigned earlier from a network fetch (urllib / requests / http.client / httpx / aiohttp). TrapDoor-style remote-payload-then-RCE.`,
          file: ctx.relFile,
          line: lineOf(node)
        });
      } else if (taint.sourceType === 'base64') {
        ctx.threats.push({
          type: 'pyast_base64_to_exec_taint',
          severity: 'CRITICAL',
          message: `${ctx.relFile}:${lineOf(node)}: ${callee}(${arg.text}) — argument was assigned earlier from a decode call (base64 / codecs / zlib / gzip / binascii). Obfuscated payload execution pattern.`,
          file: ctx.relFile,
          line: lineOf(node)
        });
      }
    }
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

  // PYAST-009: ctypes.CDLL / WinDLL / LoadLibrary with suspicious path OR
  // tainted argument. Fires at any scope depth (loading shellcode is dangerous
  // wherever it runs, but module-level is the worst).
  if (CTYPES_LOAD_CALLEES.has(callee)) {
    const firstArg = firstPositionalArg(node);
    if (firstArg) {
      const litPath = stringLiteralValue(firstArg);
      if (litPath && SUSPICIOUS_PATH_RE.test(litPath)) {
        ctx.threats.push({
          type: 'pyast_ctypes_shellcode_load',
          severity: 'HIGH',
          message: `${ctx.relFile}:${lineOf(node)}: ${callee}('${litPath}') — loads a native library from a suspicious path (temp / world-writable / user-cache). Common shellcode loader pattern.`,
          file: ctx.relFile,
          line: lineOf(node)
        });
      } else {
        const taint = lookupTaint(ctx, firstArg);
        if (taint && (taint.sourceType === 'fetch' || taint.sourceType === 'base64')) {
          ctx.threats.push({
            type: 'pyast_ctypes_shellcode_load',
            severity: 'HIGH',
            message: `${ctx.relFile}:${lineOf(node)}: ${callee}(${firstArg.text}) — native library loaded from a tainted argument (assigned from ${taint.sourceType === 'fetch' ? 'network fetch' : 'base64/decode chain'}). Shellcode loader pattern.`,
            file: ctx.relFile,
            line: lineOf(node)
          });
        }
      }
    }
  }

  // PYAST-010: env var read → network POST/PUT/etc. sink at module level.
  // Walks the call's positional args + sensitive kwargs (data, json, body, ...)
  // looking for a tainted identifier with sourceType === 'env'. Severity
  // escalates to CRITICAL if the env var name matches the sensitive pattern.
  if (NETWORK_WRITE_CALLEES.has(callee) && scopeDepth === 0) {
    const candidates = [];
    for (const arg of positionalArgs(node)) candidates.push(arg);
    for (const kwName of NETWORK_DATA_KWARGS) {
      const v = getKwargValue(node, kwName);
      if (v) candidates.push(v);
    }
    for (const arg of candidates) {
      // Direct identifier: data=token
      if (arg.type === 'identifier') {
        const taint = lookupTaint(ctx, arg);
        if (taint && taint.sourceType === 'env') {
          emitEnvNetwork(ctx, node, callee, arg.text, taint.envVarName);
          break; // one finding per call
        }
      }
      // Container literal: data={"t": token}, json=[token]
      // Walk one level deep looking for tainted identifiers.
      if (arg.type === 'dictionary' || arg.type === 'list' || arg.type === 'tuple') {
        const tainted = findTaintedIdentifierIn(arg, ctx);
        if (tainted) {
          emitEnvNetwork(ctx, node, callee, tainted.text, tainted.taint.envVarName);
          break;
        }
      }
    }
  }
}

function emitEnvNetwork(ctx, callNode, callee, varName, envVarName) {
  const sensitive = isEnvSensitive(envVarName);
  ctx.threats.push({
    type: 'pyast_env_to_network_write',
    severity: sensitive ? 'CRITICAL' : 'HIGH',
    message: `${ctx.relFile}:${lineOf(callNode)}: ${callee}(...) at module level receives '${varName}' which was assigned from os.environ['${envVarName}']${sensitive ? ' — sensitive env var name matches credential pattern, credential exfil suspected.' : ' — env-to-network exfil pattern.'}`,
    file: ctx.relFile,
    line: lineOf(callNode)
  });
}

// Walks one level inside a dict / list / tuple looking for an identifier whose
// taint sourceType === 'env'. Returns { text, taint } or null. Single hop only
// — does not recurse into nested containers (V1 limitation, matches plan).
function findTaintedIdentifierIn(containerNode, ctx) {
  for (const child of containerNode.children) {
    if (child.type === 'identifier') {
      const taint = lookupTaint(ctx, child);
      if (taint && taint.sourceType === 'env') return { text: child.text, taint };
    }
    if (child.type === 'pair') {
      const v = child.childForFieldName('value');
      if (v && v.type === 'identifier') {
        const taint = lookupTaint(ctx, v);
        if (taint && taint.sourceType === 'env') return { text: v.text, taint };
      }
    }
  }
  return null;
}

module.exports = { handleCallExpression };
