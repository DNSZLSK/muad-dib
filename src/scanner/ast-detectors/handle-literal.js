'use strict';

const {
  SENSITIVE_STRINGS,
  AI_AGENT_DANGEROUS_FLAGS,
  SAFE_STRINGS,
  SUSPICIOUS_DOMAINS_HIGH,
  SUSPICIOUS_DOMAINS_MEDIUM,
  BLOCKCHAIN_RPC_ENDPOINTS,
  SOLANA_C2_METHODS,
  VARIATION_SELECTOR_CONSTS
} = require('./constants.js');

function handleLiteral(node, ctx) {
  if (typeof node.value === 'string') {
    // Ignore safe strings
    if (SAFE_STRINGS.some(s => node.value.includes(s))) {
      return;
    }

    for (const sensitive of SENSITIVE_STRINGS) {
      if (node.value.includes(sensitive)) {
        ctx.threats.push({
          type: 'sensitive_string',
          severity: 'HIGH',
          message: `Reference to "${sensitive}" detected.`,
          file: ctx.relFile
        });
      }
    }

    // Detect AI agent dangerous flags as string literals (MEDIUM signal only —
    // CRITICAL reserved for CallExpression context where flag is actually used in exec/spawn)
    for (const flag of AI_AGENT_DANGEROUS_FLAGS) {
      if (node.value === flag) {
        // Skip if already detected in a CallExpression context (avoid double-counting)
        const alreadyDetected = ctx.threats.some(t =>
          t.type === 'ai_agent_abuse' && t.severity === 'CRITICAL' && t.file === ctx.relFile
        );
        if (!alreadyDetected) {
          ctx.threats.push({
            type: 'ai_agent_abuse',
            severity: 'MEDIUM',
            message: `AI agent security bypass flag "${flag}" referenced in code — verify it is not used in exec/spawn invocations.`,
            file: ctx.relFile
          });
        }
      }
    }

    // Detect suspicious C2/exfiltration domains in string literals
    const lowerVal = node.value.toLowerCase();
    for (const domain of SUSPICIOUS_DOMAINS_HIGH) {
      if (lowerVal.includes(domain)) {
        ctx.threats.push({
          type: 'suspicious_domain',
          severity: 'HIGH',
          message: `Suspicious C2/exfiltration domain "${domain}" found in string literal.`,
          file: ctx.relFile
        });
        break;
      }
    }
    for (const domain of SUSPICIOUS_DOMAINS_MEDIUM) {
      if (lowerVal.includes(domain)) {
        ctx.threats.push({
          type: 'suspicious_domain',
          severity: 'MEDIUM',
          message: `Suspicious tunnel/proxy domain "${domain}" found in string literal.`,
          file: ctx.relFile
        });
        break;
      }
    }

    // AST-NNN: direct_ip_exfil (Track D, v2.11.48+) — IPv4 literal used as
    // C2 endpoint (URL form `http://1.2.3.4:port/path` OR bare IP literal
    // outside the safe ranges). Pattern observed on marginfi cluster
    // (72.62.71.201), design-system-coopeuch GT-095 (direct IP exfil, no
    // OAST cover), and similar manual-review MALWARE. HIGH alone — combined
    // with linux_fingerprint_exec in the same file, escalates to CRITICAL
    // via `recon_exfil_direct_ip` compound.
    //
    // Safe ranges (skipped, no fire):
    //   0.0.0.0           bind-all / server listen address (fastify/express default)
    //   127.0.0.0/8       localhost
    //   169.254.0.0/16    link-local (incl. cloud IMDS — separate rules cover abuse)
    //   10.0.0.0/8        RFC 1918 private
    //   172.16.0.0/12     RFC 1918 private
    //   192.168.0.0/16    RFC 1918 private
    //   255.255.255.255   broadcast
    // RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x)
    // are intentionally flagged — no legitimate runtime use, lets our GT
    // reconstruction fixtures exercise the rule.
    const IP_SAFE_RE = /^(0\.0\.0\.0$|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|255\.255\.255\.255$)/;
    const urlIpMatch = node.value.match(/^https?:\/\/((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:\/|$)/);
    const bareIpMatch = node.value.match(/^((?:\d{1,3}\.){3}\d{1,3})$/);
    const candidateIp = (urlIpMatch && urlIpMatch[1]) || (bareIpMatch && bareIpMatch[1]) || null;
    if (candidateIp && !IP_SAFE_RE.test(candidateIp)) {
      // Validate each octet ≤ 255 to avoid matching '999.999.999.999' style noise
      const octets = candidateIp.split('.').map(n => parseInt(n, 10));
      if (octets.every(o => o >= 0 && o <= 255)) {
        const form = urlIpMatch ? 'URL' : 'bare IPv4 literal';
        ctx.threats.push({
          type: 'direct_ip_exfil',
          severity: 'HIGH',
          message: `Hardcoded ${form} ${candidateIp} — direct-IP exfil endpoint (no DNS, no OAST cover). Classic C2 / dep-confusion pattern.`,
          file: ctx.relFile
        });
      }
    }

    // Ollama LLM local: polymorphic engine indicator (PhantomRaven Wave 4)
    // Port 11434 is Ollama's default port. Legitimate packages don't call local LLMs.
    if (/(?:localhost|127\.0\.0\.1):11434/.test(node.value)) {
      ctx.threats.push({
        type: 'ollama_local_llm',
        severity: 'HIGH',
        message: `Reference to Ollama LLM API (${node.value.slice(0, 60)}) — polymorphic malware engine: uses local LLM to rewrite code and evade detection.`,
        file: ctx.relFile
      });
    }

    // Blockchain RPC endpoints — potential C2 channel (GlassWorm)
    for (const endpoint of BLOCKCHAIN_RPC_ENDPOINTS) {
      if (lowerVal.includes(endpoint)) {
        ctx.threats.push({
          type: 'blockchain_rpc_endpoint',
          severity: 'MEDIUM',
          message: `Hardcoded blockchain RPC endpoint "${endpoint}" — potential blockchain C2 channel.`,
          file: ctx.relFile
        });
        break;
      }
    }

    // Track Solana C2 method names in string literals (for compound detection)
    for (const method of SOLANA_C2_METHODS) {
      if (node.value === method || node.value.includes(method)) {
        ctx.hasSolanaC2Method = true;
        break;
      }
    }
  }

  // Track variation selector constants in numeric literals (GlassWorm decoder)
  if (typeof node.value === 'number') {
    if (VARIATION_SELECTOR_CONSTS.includes(node.value)) {
      ctx.hasVariationSelectorConst = true;
    }
  }
}


module.exports = { handleLiteral };
