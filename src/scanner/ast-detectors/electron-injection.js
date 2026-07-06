'use strict';

// MUADDIB-AST-097 — electron_app_injection shared detection helpers.
//
// Threat model: an install-time hook LOCATES a third-party Electron desktop app already
// installed on the victim (Discord, Atomic Wallet, Slack, ...) by resolving the user's home
// directory, matching an Electron signature path (.asar / *_desktop_core / an electron core
// module), and probing it with fs.existsSync — then OVERWRITES that app's code with an injected
// JavaScript payload, so the payload runs with the target app's identity and permissions.
//   GT-036 (discord-electron-inject): overwrites Discord's discord_desktop_core/index.js with a
//     webContents.debugger network hook that exfiltrates login/MFA responses to bada-stealer.com.
//   GT-044 (atomic-wallet-patch): patches Atomic Wallet's app.asar bundle with an
//     XMLHttpRequest.prototype.send hook that swaps crypto recipient addresses.
//
// The DISCRIMINATOR (why this beats a file-level co-occurrence proxy): the malice is not that a
// file *mentions* BrowserWindow/.asar — a legitimate Electron app's own main process mentions all
// of those. The malice is that a filesystem WRITE writes CONTENT that IS injected Electron code
// into a FOREIGN app. So we couple, at AST level:
//   (1) the write's CONTENT resolves to injected-Electron-code markers (the payload), AND
//   (2) module context proves foreign-app discovery: os.homedir() + Electron-sig path + existsSync.
// A legit Electron app writes JSON *config* (settings.json), never source that hooks another app's
// internals — so coupling the payload to the write is what separates injection from an app writing
// its own settings, WITHOUT the evadable "is this file itself an Electron main?" heuristic.
//
// Consumed by: handle-call-expression.js (write-sink + fact collection), handle-variable-declarator.js
// & handle-assignment-expression.js (injected-code variable tracking), handle-post-walk.js (emit).

const { extractStringValueDeep } = require('./helpers.js');

// An Electron *target path* signature: an installed app's packed archive or a native core module.
//   app.asar / core.asar / *.asar(.unpacked)   — Electron ASAR archive
//   discord_desktop_core / betterdiscord         — Discord's swappable core module (well-known target)
//   modules/<x>_core / *_desktop_core            — Electron "<app>_core" native module convention
const ELECTRON_SIG_RE = /\.asar\b|discord_desktop_core|betterdiscord|[\\/]modules[\\/][A-Za-z0-9_.-]*_core\b|_desktop_core\b/i;

// Injected-Electron-code markers — tokens that make written CONTENT an injection payload, not config.
//   HOOK markers (interception / tamper): near-zero in benign written content.
const ELECTRON_HOOK_MARKERS =
  /\bwebContents\b|\bdebugger\s*\.\s*(?:attach|on|sendCommand)\b|\bNetwork\s*\.\s*(?:enable|responseReceived|getResponseBody)\b|\bipcRenderer\b|\.\s*prototype\s*\.\s*[A-Za-z_$][\w$]*\s*=/;
//   APP markers (electron surface): boilerplate-ish, weaker alone but a payload signal in write content.
const ELECTRON_APP_MARKERS =
  /\bBrowserWindow\b|require\s*\(\s*['"]electron['"]\s*\)|module\s*\.\s*exports\s*=\s*require\s*\(/;
// A write's content is a payload when it carries a HOOK marker OR an APP marker.
const ELECTRON_PAYLOAD_MARKERS = new RegExp(ELECTRON_HOOK_MARKERS.source + '|' + ELECTRON_APP_MARKERS.source);

const HOME_PATH_STR_RE = /[\\/]home[\\/]|[\\/]Users[\\/]|appdata|localappdata|userprofile|[\\/]\.config[\\/]|^~[\\/]/i;

// Best-effort: collect all string-literal fragments reachable from a node subtree (array
// elements, `.join()`/`.concat()` receivers+args, `+` concatenation, template quasis, conditional
// branches). Bounded in depth and total length. Used to test whether a write's CONTENT argument
// (or a variable initializer) carries injected-Electron-code markers even when it is built as
// `[ ...lines ].join("\n")` or `"...hook..." + fileContent`.
function collectCodeString(node, depth, acc) {
  if (!node || depth > 6 || acc.budget <= 0) return acc.s;
  switch (node.type) {
    case 'Literal':
      if (typeof node.value === 'string') { acc.s += node.value + '\n'; acc.budget -= node.value.length + 1; }
      break;
    case 'TemplateLiteral':
      for (const q of node.quasis || []) { const raw = q.value.raw; acc.s += raw + '\n'; acc.budget -= raw.length + 1; }
      for (const e of node.expressions || []) collectCodeString(e, depth + 1, acc);
      break;
    case 'BinaryExpression':
      if (node.operator === '+') { collectCodeString(node.left, depth + 1, acc); collectCodeString(node.right, depth + 1, acc); }
      break;
    case 'ArrayExpression':
      for (const el of node.elements || []) collectCodeString(el, depth + 1, acc);
      break;
    case 'CallExpression': {
      const m = node.callee && node.callee.type === 'MemberExpression' && node.callee.property
        ? node.callee.property.name : null;
      if (m === 'join' || m === 'concat') {
        collectCodeString(node.callee.object, depth + 1, acc);
        for (const a of node.arguments || []) collectCodeString(a, depth + 1, acc);
      }
      break;
    }
    case 'ConditionalExpression':
      collectCodeString(node.consequent, depth + 1, acc);
      collectCodeString(node.alternate, depth + 1, acc);
      break;
    default:
      break;
  }
  return acc.s;
}

function resolveCodeString(node) {
  return collectCodeString(node, 0, { s: '', budget: 20000 });
}

// Does this subtree reference a variable already known to hold injected Electron code?
// Handles `hook + "\n" + fileContent` (BinaryExpression), templates, and array joins.
function referencesInjectedVar(node, ctx, depth) {
  if (!node || depth > 6 || !ctx.injectedCodeVars) return false;
  switch (node.type) {
    case 'Identifier':
      return ctx.injectedCodeVars.has(node.name);
    case 'BinaryExpression':
      return node.operator === '+' &&
        (referencesInjectedVar(node.left, ctx, depth + 1) || referencesInjectedVar(node.right, ctx, depth + 1));
    case 'TemplateLiteral':
      return (node.expressions || []).some(e => referencesInjectedVar(e, ctx, depth + 1));
    case 'ConditionalExpression':
      return referencesInjectedVar(node.consequent, ctx, depth + 1) || referencesInjectedVar(node.alternate, ctx, depth + 1);
    case 'CallExpression': {
      const m = node.callee && node.callee.type === 'MemberExpression' && node.callee.property
        ? node.callee.property.name : null;
      if (m === 'join' || m === 'concat') {
        return referencesInjectedVar(node.callee.object, ctx, depth + 1) ||
          (node.arguments || []).some(a => referencesInjectedVar(a, ctx, depth + 1));
      }
      return false;
    }
    default:
      return false;
  }
}

// True if a node (a variable initializer or a write's content arg) carries an injected payload:
// it references a tracked injected-code variable, or it statically resolves to code with markers.
function carriesInjectedPayload(node, ctx) {
  if (!node) return false;
  if (node.type === 'Identifier') return !!(ctx.injectedCodeVars && ctx.injectedCodeVars.has(node.name));
  if (referencesInjectedVar(node, ctx, 0)) return true;
  return ELECTRON_PAYLOAD_MARKERS.test(resolveCodeString(node));
}

// An argument that roots a path in the user's HOME (where a victim's apps are installed):
//   os.homedir() | process.env.{HOME,APPDATA,LOCALAPPDATA,USERPROFILE,XDG_CONFIG_HOME}
//   | "~"/"~/..." | absolute "/home/..", "/Users/..", "C:\Users\.." literal
function isHomeRootArg(node) {
  if (!node) return false;
  if (node.type === 'CallExpression' && node.callee && node.callee.type === 'MemberExpression' &&
      node.callee.object && node.callee.object.type === 'Identifier' && node.callee.object.name === 'os' &&
      node.callee.property && node.callee.property.type === 'Identifier' && node.callee.property.name === 'homedir') {
    return true;
  }
  if (node.type === 'MemberExpression' &&
      node.object && node.object.type === 'MemberExpression' &&
      node.object.object && node.object.object.type === 'Identifier' && node.object.object.name === 'process' &&
      node.object.property && node.object.property.type === 'Identifier' && node.object.property.name === 'env' &&
      node.property && node.property.type === 'Identifier' &&
      ['HOME', 'APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'XDG_CONFIG_HOME'].includes(node.property.name)) {
    return true;
  }
  if (node.type === 'Literal' && typeof node.value === 'string') {
    if (/^~(?:[\\/]|$)/.test(node.value)) return true;
    if (/^\/home\/|^\/Users\/|:[\\/]Users[\\/]/i.test(node.value)) return true;
  }
  return false;
}

function _scanPathArgForSig(arg, ctx) {
  if (!arg) return;
  const s = extractStringValueDeep(arg);
  if (s && ELECTRON_SIG_RE.test(s)) ctx.hasElectronAppSig = true;
  if (arg.type === 'CallExpression' && arg.callee && arg.callee.type === 'MemberExpression' &&
      arg.callee.object && arg.callee.object.type === 'Identifier' && arg.callee.object.name === 'path' &&
      arg.callee.property && arg.callee.property.type === 'Identifier' &&
      (arg.callee.property.name === 'join' || arg.callee.property.name === 'resolve')) {
    const joined = (arg.arguments || []).map(a => extractStringValueDeep(a) || '').join('/');
    if (ELECTRON_SIG_RE.test(joined)) ctx.hasElectronAppSig = true;
    if ((arg.arguments || []).some(isHomeRootArg)) ctx.hasHomedirResolve = true;
  }
}

// Collect the foreign-app-discovery corroboration facts from a CallExpression:
//   os.homedir()                                → hasHomedirResolve
//   fs.existsSync/accessSync/statSync/lstatSync → hasFsExistsProbe (+ sig/home from the probed path)
//   path.join/path.resolve                      → hasElectronAppSig / hasHomedirResolve
//   app.whenReady/app.getPath/.loadURL/.loadFile → hasOwnElectronMain (the file IS an Electron main;
//                                                   gates the HIGH tier so a real app's self-writes
//                                                   are not flagged as tampering).
function scanElectronFacts(node, ctx) {
  const callee = node.callee;
  if (!callee || callee.type !== 'MemberExpression' || !callee.property || callee.property.type !== 'Identifier') return;
  const prop = callee.property.name;
  const objName = callee.object && callee.object.type === 'Identifier' ? callee.object.name : null;

  if (objName === 'os' && prop === 'homedir') ctx.hasHomedirResolve = true;

  if (prop === 'existsSync' || prop === 'accessSync' || prop === 'statSync' || prop === 'lstatSync') {
    ctx.hasFsExistsProbe = true;
    _scanPathArgForSig(node.arguments && node.arguments[0], ctx);
  }

  if (objName === 'path' && (prop === 'join' || prop === 'resolve')) {
    const joined = (node.arguments || []).map(a => extractStringValueDeep(a) || '').join('/');
    if (ELECTRON_SIG_RE.test(joined)) ctx.hasElectronAppSig = true;
    if ((node.arguments || []).some(isHomeRootArg)) ctx.hasHomedirResolve = true;
  }

  if ((prop === 'whenReady' && (objName === 'app' || objName === 'electron')) ||
      (prop === 'getPath' && objName === 'app') ||
      prop === 'loadURL' || prop === 'loadFile') {
    ctx.hasOwnElectronMain = true;
  }
}

// For the HIGH tier: does a write TARGET resolve to a home-rooted Electron file? Handles an inline
// path.join/path.resolve, a bare literal, or an Identifier bound to a tracked path.join result
// (ctx.electronTargetVars — the common `const target = path.join(os.homedir(), ..., 'app.asar')`).
function resolveElectronTarget(node, ctx) {
  if (node && node.type === 'Identifier' && ctx && ctx.electronTargetVars && ctx.electronTargetVars.has(node.name)) {
    return ctx.electronTargetVars.get(node.name);
  }
  let pathStr = '';
  let home = false;
  if (node && node.type === 'CallExpression' && node.callee && node.callee.type === 'MemberExpression' &&
      node.callee.object && node.callee.object.type === 'Identifier' && node.callee.object.name === 'path' &&
      node.callee.property && node.callee.property.type === 'Identifier' &&
      (node.callee.property.name === 'join' || node.callee.property.name === 'resolve')) {
    pathStr = (node.arguments || []).map(a => extractStringValueDeep(a) || '').join('/');
    if ((node.arguments || []).some(isHomeRootArg)) home = true;
  } else {
    pathStr = extractStringValueDeep(node) || '';
  }
  if (HOME_PATH_STR_RE.test(pathStr)) home = true;
  return { sig: ELECTRON_SIG_RE.test(pathStr), home, pathStr: pathStr.slice(0, 120) };
}

module.exports = {
  ELECTRON_SIG_RE,
  ELECTRON_PAYLOAD_MARKERS,
  ELECTRON_HOOK_MARKERS,
  resolveCodeString,
  carriesInjectedPayload,
  referencesInjectedVar,
  isHomeRootArg,
  scanElectronFacts,
  resolveElectronTarget
};
