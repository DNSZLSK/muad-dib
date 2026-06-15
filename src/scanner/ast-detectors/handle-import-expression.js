'use strict';

const {
  SOLANA_PACKAGES
} = require('./constants.js');
const { containsDecodePattern } = require('./helpers.js');

// Gate #2 (FPR 2026-06-15 — Étape 0 adjudication): a computed dynamic import() is only
// remote-code-loading when there is positive evidence of a remote/decoded/env-driven target
// (URL literal, .replace() URL manipulation, atob/Buffer decode, or a process.env-sourced
// specifier). Bounded-local imports — CLI subcommand dispatchers (import(MAP[cmd])), layout/i18n
// loaders (import(`../x/${name}.js`)), dep-resolve / own-dist shims (import(join(dir,'dist/main.js')))
// — were ~19% of the band-20-49 false positives with 0 TP. Without evidence, computed imports
// stay HIGH (still fires, but ~25→10 pts: sub-threshold alone) instead of CRITICAL. Flag-gated;
// when the flag is off the legacy CRITICAL-on-Identifier/TemplateLiteral behavior is preserved.
function _importStaticText(node) {
  if (!node) return '';
  if (node.type === 'Literal') return typeof node.value === 'string' ? node.value : '';
  if (node.type === 'TemplateLiteral') {
    return (node.quasis || [])
      .map(q => (q.value && (q.value.cooked != null ? q.value.cooked : q.value.raw)) || '')
      .join(' ');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return _importStaticText(node.left) + ' ' + _importStaticText(node.right);
  }
  return '';
}

function _isProcessEnvMember(node) {
  return !!node && node.type === 'MemberExpression' &&
    node.object && node.object.type === 'MemberExpression' &&
    node.object.object && node.object.object.type === 'Identifier' && node.object.object.name === 'process' &&
    node.object.property && node.object.property.type === 'Identifier' && node.object.property.name === 'env';
}

function _importRemoteEvidence(src, ctx) {
  // URL manipulation (GlassWorm): import(x.replace(...))
  if (src.type === 'CallExpression' && src.callee && src.callee.type === 'MemberExpression' &&
      src.callee.property && src.callee.property.name === 'replace') return true;
  // env-driven specifier: import(process.env.X), or import(v) where v was assigned from process.env.X
  if (_isProcessEnvMember(src)) return true;
  if (src.type === 'Identifier' && ctx.varSource && ctx.varSource.get(src.name) === 'env_var') return true;
  // identifier resolving to a URL string literal: const u = 'https://evil/x.js'; import(u)
  if (src.type === 'Identifier' && ctx.stringVarValues) {
    const resolved = ctx.stringVarValues.get(src.name);
    if (resolved && /https?:|:\/\//i.test(resolved)) return true;
  }
  // runtime decode: import(atob(...)) / import(Buffer.from(...).toString())
  if (containsDecodePattern(src)) return true;
  // explicit URL scheme in the static parts of the specifier
  if (/https?:|:\/\//i.test(_importStaticText(src))) return true;
  return false;
}

function handleImportExpression(node, ctx) {
  if (node.source) {
    const src = node.source;
    if (src.type === 'Literal' && typeof src.value === 'string') {
      const dangerousModules = ['child_process', 'fs', 'http', 'https', 'net', 'dns', 'tls', 'worker_threads'];
      // Batch 2: strip node: prefix so import('node:child_process') normalizes
      const modName = src.value.startsWith('node:') ? src.value.slice(5) : src.value;
      if (dangerousModules.includes(modName)) {
        // Audit v3: dynamic import of code execution modules → CRITICAL (evasion technique)
        const CRITICAL_IMPORTS = ['child_process', 'net', 'dns', 'worker_threads'];
        ctx.threats.push({
          type: 'dynamic_import',
          severity: CRITICAL_IMPORTS.includes(modName) ? 'CRITICAL' : 'HIGH',
          message: `Dynamic import() of dangerous module "${src.value}".`,
          file: ctx.relFile
        });
      }
      // GlassWorm: track Solana/Web3 dynamic import for compound blockchain C2 detection
      if (SOLANA_PACKAGES.some(pkg => src.value === pkg)) {
        ctx.hasSolanaImport = true;
      }
    } else if (process.env.MUADDIB_DYNIMPORT_BOUNDED === '1') {
      // Gate #2 (downgrade-only — never escalates above legacy severity, so it cannot raise FPR):
      // a legacy-CRITICAL computed import (Identifier / TemplateLiteral / .replace URL) drops to HIGH
      // when there is NO remote/decode/env evidence (bounded/local: CLI dispatchers, layout/i18n
      // loaders, dep-resolve shims). With evidence it stays CRITICAL; a legacy-HIGH argument stays HIGH.
      const legacyCritical = src.type === 'Identifier' || src.type === 'TemplateLiteral' ||
        (src.type === 'CallExpression' && src.callee?.property?.name === 'replace');
      const bounded = legacyCritical && !_importRemoteEvidence(src, ctx);
      ctx.threats.push({
        type: 'dynamic_import',
        severity: bounded ? 'HIGH' : (legacyCritical ? 'CRITICAL' : 'HIGH'),
        message: bounded
          ? 'Dynamic import() with computed (bounded/local) argument — possible obfuscation.'
          : (legacyCritical
              ? 'Dynamic import() with computed URL argument — remote code loading from dynamically constructed URL.'
              : 'Dynamic import() with computed argument (possible obfuscation).'),
        file: ctx.relFile
      });
    } else {
      // Legacy behavior (gate off): Blue Team v8b (C6) — non-literal arg is CRITICAL when it
      // looks like a constructed URL (Identifier / TemplateLiteral / .replace()).
      const isCritical = src.type === 'Identifier' || src.type === 'TemplateLiteral' ||
        (src.type === 'CallExpression' && src.callee?.property?.name === 'replace');
      ctx.threats.push({
        type: 'dynamic_import',
        severity: isCritical ? 'CRITICAL' : 'HIGH',
        message: isCritical
          ? 'Dynamic import() with computed URL argument — remote code loading from dynamically constructed URL.'
          : 'Dynamic import() with computed argument (possible obfuscation).',
        file: ctx.relFile
      });
    }
  }
}


module.exports = { handleImportExpression };
