'use strict';

/**
 * Mini taint tracker — Phase 1b of the PYAST roadmap.
 *
 * Scope (V1, deliberately minimal — see plan file for the full design):
 *  - intra-procedural, module-level only (scope_depth === 0)
 *  - single assignment hop : `var = source_expr` then `sink(..., var, ...)`
 *  - reassignment clears taint
 *  - bare identifiers only (no attribute / subscript LHS)
 *  - no multi-hop chains (`a = src(); b = a; sink(b)` is NOT tracked — Phase 3)
 *
 * Sources :
 *  - 'fetch'  : network reads (urllib, requests, httpx, aiohttp, http.client)
 *  - 'base64' : decoders (base64.*, codecs.decode, zlib.decompress, gzip.decompress, binascii.unhexlify, bytes.fromhex)
 *  - 'env'    : os.environ access (subscript + .get + os.getenv)
 *
 * Sinks are NOT defined here — they live in handle-call-expression.js. This
 * module is the pure-source-classifier + lookup helper.
 */

const { dottedName, stringLiteralValue } = require('./helpers.js');

// ---------------------------------------------------------------------------
// FETCH source detection
// ---------------------------------------------------------------------------

const FETCH_DOTTED_CALLEES = new Set([
  'urllib.request.urlopen',
  'urllib2.urlopen',
  'requests.get',
  'requests.post',
  'requests.put',
  'requests.delete',
  'requests.patch',
  'requests.head',
  'requests.options',
  'requests.request',
  'httpx.get',
  'httpx.post',
  'httpx.put',
  'httpx.delete',
  'httpx.patch',
  'httpx.head',
  'httpx.options',
  'httpx.request'
]);

// Returns true if the call node is one of the http-class instantiations
// (`http.client.HTTPSConnection(...)`, `http.client.HTTPConnection(...)`).
function isHttpClientConnectionCall(callNode) {
  const name = dottedName(callNode.childForFieldName('function'));
  return name === 'http.client.HTTPSConnection' || name === 'http.client.HTTPConnection';
}

// Returns true if the expression is a "fetch" source, i.e. its evaluation
// produces attacker-controlled bytes. Handles chains like `.read()` / `.text`
// / `.content` / `.json()` applied to the fetch result.
function isFetchSource(node) {
  if (!node) return false;

  // Direct call: requests.get(...) , urllib.request.urlopen(...)
  if (node.type === 'call') {
    const name = dottedName(node.childForFieldName('function'));
    if (name && FETCH_DOTTED_CALLEES.has(name)) return true;
    if (isHttpClientConnectionCall(node)) return true; // produces a connection object — treated as fetch
    // Method call on a fetch result: requests.get(...).text, urlopen(...).read()
    // The .read() / .json() form is itself a `call` node whose function is an
    // `attribute` whose object is the inner call. Walk one level.
    const fn = node.childForFieldName('function');
    if (fn && fn.type === 'attribute') {
      const inner = fn.childForFieldName('object');
      const methodNode = fn.childForFieldName('attribute');
      const methodName = methodNode && methodNode.text;
      if (['read', 'json', 'text', 'content', 'iter_content', 'iter_lines'].includes(methodName)) {
        if (isFetchSource(inner)) return true;
      }
    }
  }

  // Attribute access on a fetch result: `r.text`, `r.content`, `r.json` (no call)
  if (node.type === 'attribute') {
    const inner = node.childForFieldName('object');
    const attr = node.childForFieldName('attribute');
    if (attr && ['text', 'content', 'json'].includes(attr.text)) {
      if (isFetchSource(inner)) return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// BASE64 / decode source detection
// ---------------------------------------------------------------------------

const DECODE_DOTTED_CALLEES = new Set([
  'base64.b64decode',
  'base64.b32decode',
  'base64.b16decode',
  'base64.standard_b64decode',
  'base64.urlsafe_b64decode',
  'base64.a85decode',
  'base64.b85decode',
  'codecs.decode',
  'zlib.decompress',
  'gzip.decompress',
  'bz2.decompress',
  'lzma.decompress',
  'binascii.unhexlify',
  'binascii.a2b_base64',
  'binascii.a2b_hex',
  'bytes.fromhex' // `bytes.fromhex("...")` decodes a hex string
]);

function isBase64Source(node) {
  if (!node || node.type !== 'call') return false;
  const name = dottedName(node.childForFieldName('function'));
  if (name && DECODE_DOTTED_CALLEES.has(name)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// ENV source detection — returns { sourceType: 'env', envVarName }
// ---------------------------------------------------------------------------

// Sensitive env var name patterns — match triggers severity escalation
// for PYAST-010. Conservative list (substring match, case-insensitive).
const SENSITIVE_ENV_RE = /(TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|CRED|NPM_|AWS_|SSH|API|GITHUB_|GH_|HF_|ANTHROPIC|OPENAI|SLACK|DISCORD|TELEGRAM|STRIPE|GCP|AZURE|DATABASE_URL|DB_PASS)/i;

function isEnvSensitive(envVarName) {
  return typeof envVarName === 'string' && SENSITIVE_ENV_RE.test(envVarName);
}

// Returns the env var name (string) if `node` reads from os.environ / os.getenv,
// or null. For subscript access like `os.environ['X']` returns 'X'.
// For `os.environ[X]` (computed key) returns '<computed>'.
function classifyEnvSource(node) {
  if (!node) return null;

  // subscript: os.environ['X'] or os.environ[X]
  if (node.type === 'subscript') {
    const obj = node.childForFieldName('value');
    if (obj && dottedName(obj) === 'os.environ') {
      const subscript = node.childForFieldName('subscript');
      const lit = stringLiteralValue(subscript);
      return lit !== null ? lit : '<computed>';
    }
  }

  // call: os.environ.get('X', ...) or os.getenv('X', ...)
  if (node.type === 'call') {
    const name = dottedName(node.childForFieldName('function'));
    if (name === 'os.environ.get' || name === 'os.getenv') {
      const args = node.childForFieldName('arguments');
      if (args) {
        for (const child of args.children) {
          if (child.type === 'keyword_argument' || child.type === ',' ||
              child.type === '(' || child.type === ')') continue;
          const lit = stringLiteralValue(child);
          if (lit !== null) return lit;
          return '<computed>';
        }
      }
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Classify the taint of an RHS expression node. Returns:
 *   { sourceType: 'fetch'|'base64'|'env', envVarName?: string }
 * or null if the node is not a recognised tainted source.
 */
function classifyTaintSource(node) {
  if (!node) return null;
  if (isFetchSource(node)) return { sourceType: 'fetch' };
  if (isBase64Source(node)) return { sourceType: 'base64' };
  const envVarName = classifyEnvSource(node);
  if (envVarName !== null) return { sourceType: 'env', envVarName };
  return null;
}

/**
 * Returns the taint record for a variable, or null.
 * Caller filters on sourceType if needed.
 */
function lookupTaint(ctx, identifierNode) {
  if (!identifierNode || identifierNode.type !== 'identifier') return null;
  if (!ctx.moduleTaint) return null;
  return ctx.moduleTaint.get(identifierNode.text) || null;
}

module.exports = {
  classifyTaintSource,
  lookupTaint,
  isEnvSensitive,
  // Exposed for unit tests
  _internal: {
    isFetchSource,
    isBase64Source,
    classifyEnvSource,
    SENSITIVE_ENV_RE
  }
};
