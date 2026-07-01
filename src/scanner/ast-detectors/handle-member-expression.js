'use strict';

const {
  SAFE_ENV_VARS,
  SAFE_ENV_PREFIXES,
  LLM_API_KEY_VARS,
  SOLANA_C2_METHODS
} = require('./constants.js');
const {
  isEnvSensitive
} = require('./helpers.js');

function handleMemberExpression(node, ctx) {
  // Detect require.cache access — set flag, defer threat emission to handlePostWalk
  // FP fix: distinguish READ (hot-reload, delete, introspection) from WRITE (.exports = ...)
  if (node.object?.type === 'Identifier' && node.object.name === 'require' &&
      node.property?.type === 'Identifier' && node.property.name === 'cache') {
    ctx.hasRequireCacheRead = true;
  }

  // GlassWorm: track .codePointAt() calls (variation selector decoder pattern)
  if (node.property?.type === 'Identifier' && node.property.name === 'codePointAt') {
    ctx.hasCodePointAt = true;
  }

  // GlassWorm: track Solana C2 method calls (e.g., connection.getSignaturesForAddress)
  if (node.property?.type === 'Identifier' && SOLANA_C2_METHODS.includes(node.property.name)) {
    ctx.hasSolanaC2Method = true;
  }

  if (
    node.object?.object?.name === 'process' &&
    node.object?.property?.name === 'env'
  ) {
    // Dynamic access: process.env[variable]
    if (node.computed) {
      if (ctx.hasFromCharCode) {
        ctx.threats.push({
          type: 'env_charcode_reconstruction',
          severity: 'HIGH',
          message: 'process.env accessed with dynamically reconstructed key (String.fromCharCode obfuscation).',
          file: ctx.relFile
        });
      }
      ctx.threats.push({
        type: 'env_access',
        severity: 'MEDIUM',
        message: 'Dynamic access to process.env (variable key).',
        file: ctx.relFile
      });
      return;
    }

    const envVar = node.property?.name;
    if (envVar) {
      if (SAFE_ENV_VARS.includes(envVar)) {
        return;
      }
      const envLower = envVar.toLowerCase();
      if (SAFE_ENV_PREFIXES.some(p => envLower.startsWith(p))) {
        return;
      }
      if (isEnvSensitive(envVar)) {
        ctx.threats.push({
          type: 'env_access',
          severity: 'HIGH',
          message: `Access to sensitive variable process.env.${envVar}.`,
          file: ctx.relFile
        });
      }
      // SANDWORM_MODE R9: Count LLM API key accesses
      if (LLM_API_KEY_VARS.includes(envVar)) {
        ctx.llmApiKeyCount++;
      }
    }
  }

  // AST-018 alias fix (@longzy): `var env = process.env; env[_decode([...])]` reaches env via
  // an alias, so the direct `process.env[x]` match above misses it. Close ONLY the
  // charcode-reconstruction signal for aliases (computed access + String.fromCharCode in the
  // file) — we deliberately do NOT emit the generic env_access MEDIUM for aliases, keeping FPR
  // flat; the HIGH signal fires only on the malicious obfuscated-key shape.
  if (
    node.computed &&
    ctx.hasFromCharCode &&
    node.object?.type === 'Identifier' &&
    ctx.envAliases && ctx.envAliases.has(node.object.name)
  ) {
    ctx.threats.push({
      type: 'env_charcode_reconstruction',
      severity: 'HIGH',
      message: 'process.env (accessed via an alias) reads a dynamically reconstructed key (String.fromCharCode obfuscation).',
      file: ctx.relFile
    });
  }
}


module.exports = { handleMemberExpression };
