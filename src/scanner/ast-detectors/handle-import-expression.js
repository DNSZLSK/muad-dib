'use strict';

const {
  SOLANA_PACKAGES
} = require('./constants.js');

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
    } else {
      // Blue Team v8b (C6): Dynamic import with non-literal arg — if it's a variable
      // built from URL manipulation, this is remote code loading
      const isCritical = node.source.type === 'Identifier' || node.source.type === 'TemplateLiteral' ||
        (node.source.type === 'CallExpression' && node.source.callee?.property?.name === 'replace');
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
