'use strict';

// Sandbox-friendly compound triggers.
// Surgical activation of the Docker sandbox only on threat patterns where
// dynamic observation provides signal beyond static AST/regex analysis.
// Targets 2026 attacks: Shai-Hulud, Axios 2026 (OrDeR_7077), GlassWorm,
// PhantomRaven, CanisterWorm, ltidi chain.
//
// Activation rule: a compound matches AND preliminary score in [15, 35].
//   score < 15  -> clean, no need to sandbox
//   score > 35  -> already definitive, no second-tier verdict needed

const SANDBOX_TRIGGER_MIN_SCORE = 15;
const SANDBOX_TRIGGER_MAX_SCORE = 35;

const TRIGGERS = [
  {
    name: 'lifecycle_install_chain',
    description: 'Lifecycle script + credential tampering or harvest pattern',
    target: 'Shai-Hulud, PhantomRaven',
    watchpoints: ['honey_npmrc_read', 'honey_ssh_read', 'execve_chain_depth', 'outbound_non_registry'],
    matches(threats) {
      const hasLifecycle = threats.some(t =>
        t.type === 'lifecycle_script' ||
        t.type === 'lifecycle_added_critical' ||
        t.type === 'lifecycle_added_high' ||
        t.type === 'lifecycle_modified' ||
        t.type === 'lifecycle_inline_exec' ||
        t.type === 'lifecycle_remote_require' ||
        t.type === 'lifecycle_dataflow' ||
        t.type === 'lifecycle_dangerous_exec' ||
        t.type === 'obfuscated_lifecycle_env' ||
        t.type === 'lifecycle_typosquat' ||
        t.type === 'lifecycle_shell_pipe' ||
        t.type === 'lifecycle_hidden_payload'
      );
      const hasCredHarvest = threats.some(t =>
        t.type === 'credential_regex_harvest' ||
        t.type === 'credential_tampering' ||
        t.type === 'credential_command_exec' ||
        t.type === 'env_harvesting_dynamic' ||
        t.type === 'curl_env_exfil' ||
        t.type === 'env_proxy_intercept' ||
        t.type === 'npmrc_access' ||
        t.type === 'github_token_access' ||
        t.type === 'aws_credential_access' ||
        t.type === 'ssh_access'
      );
      return hasLifecycle && hasCredHarvest;
    }
  },
  {
    name: 'stub_with_external_dep',
    description: 'Stub package with external HTTPS dep (ltidi chain)',
    target: 'ltidi chain attack',
    watchpoints: ['outbound_non_registry', 'fs_created_outside_install', 'execve_chain_depth'],
    matches(threats) {
      const hasStub = threats.some(t =>
        t.type === 'stub_package_external_payload' ||
        t.type === 'stub_package_external_dep' ||
        t.type === 'stub_with_string_ioc'
      );
      const hasExternalDep = threats.some(t =>
        t.type === 'external_tarball_dep' ||
        t.type === 'dependency_url_suspicious' ||
        t.type === 'git_dependency_rce' ||
        t.type === 'lifecycle_script_dependency'
      );
      return hasStub && hasExternalDep;
    }
  },
  {
    name: 'obfuscated_oversize',
    description: 'Obfuscation + large file + execution path',
    target: 'Shai-Hulud bun_environment.js (10MB)',
    watchpoints: ['runtime_deobfuscation_executed', 'execve_chain_depth', 'outbound_non_registry'],
    matches(threats, fileSizes) {
      const hasObf = threats.some(t =>
        t.type === 'obfuscation_detected' ||
        t.type === 'js_obfuscation_pattern' ||
        t.type === 'possible_obfuscation' ||
        t.type === 'split_entropy_payload' ||
        t.type === 'fragmented_high_entropy_cluster' ||
        t.type === 'high_entropy_string'
      );
      const hasExec = threats.some(t =>
        t.type === 'dangerous_call_exec' ||
        t.type === 'dangerous_exec' ||
        t.type === 'detached_process' ||
        t.type === 'staged_payload' ||
        t.type === 'staged_binary_payload' ||
        t.type === 'binary_dropper' ||
        t.type === 'bun_runtime_evasion'
      );
      if (!hasObf || !hasExec) return false;
      // Specificity gate: this compound only matches when at least one file
      // exceeds 1MB. Without that, decrypt_then_execute below is more
      // appropriate. Returns false (not undefined) when no size info to keep
      // the more specific decrypt_then_execute match available.
      if (!fileSizes || Object.keys(fileSizes).length === 0) return false;
      return Object.values(fileSizes).some(size => typeof size === 'number' && size > 1024 * 1024);
    }
  },
  {
    name: 'decrypt_then_execute',
    description: 'Obfuscation or XOR decoding + new Function or eval',
    target: 'Axios 2026 OrDeR_7077',
    watchpoints: ['runtime_deobfuscation_executed', 'outbound_non_registry'],
    matches(threats) {
      const hasDecrypt = threats.some(t =>
        t.type === 'base64_decode' ||
        t.type === 'base64_decode_exec' ||
        t.type === 'obfuscation_detected' ||
        t.type === 'js_obfuscation_pattern' ||
        t.type === 'crypto_decipher' ||
        t.type === 'staged_eval_decode' ||
        t.type === 'env_charcode_reconstruction' ||
        t.type === 'string_mutation_obfuscation' ||
        t.type === 'self_destruct_eval' ||
        t.type === 'anti_forensic_xor_autodelete' ||
        t.type === 'anti_forensic_partial' ||
        t.type === 'wget_base64_decode'
      );
      const hasExec = threats.some(t =>
        t.type === 'dangerous_call_eval' ||
        t.type === 'dangerous_call_function' ||
        t.type === 'dangerous_constructor' ||
        t.type === 'function_runtime_args' ||
        t.type === 'function_constructor_require' ||
        t.type === 'staged_payload' ||
        t.type === 'fetch_decrypt_exec' ||
        t.type === 'vm_dynamic_code' ||
        t.type === 'vm_code_execution' ||
        t.type === 'reflect_code_execution' ||
        t.type === 'callback_exec_rce' ||
        t.type === 'eval_usage'
      );
      return hasDecrypt && hasExec;
    }
  },
  {
    name: 'invisible_blockchain',
    description: 'Unicode invisible decoder + blockchain RPC endpoint',
    target: 'GlassWorm',
    watchpoints: ['outbound_blockchain_rpc', 'runtime_deobfuscation_executed'],
    matches(threats) {
      const hasInvisible = threats.some(t =>
        t.type === 'unicode_invisible_injection' ||
        t.type === 'unicode_variation_decoder'
      );
      const hasBlockchain = threats.some(t =>
        t.type === 'blockchain_c2_resolution' ||
        t.type === 'blockchain_rpc_endpoint'
      );
      return hasInvisible && hasBlockchain;
    }
  },
  {
    name: 'npm_token_self_use',
    description: 'npmrc access + outbound HTTP or npm CLI invocation pattern',
    target: 'CanisterWorm',
    watchpoints: ['npm_self_invoke', 'honey_npmrc_read', 'outbound_non_registry'],
    matches(threats) {
      const hasNpmrc = threats.some(t =>
        t.type === 'npmrc_access' ||
        t.type === 'npmrc_git_override' ||
        t.type === 'npm_token_steal' ||
        t.type === 'npm_publish_worm'
      );
      const hasOutbound = threats.some(t =>
        t.type === 'curl_exfiltration' ||
        t.type === 'curl_env_exfil' ||
        t.type === 'github_api_call' ||
        t.type === 'remote_code_load' ||
        t.type === 'network_require' ||
        t.type === 'websocket_credential_exfil' ||
        t.type === 'websocket_c2' ||
        t.type === 'dns_chunk_exfiltration' ||
        t.type === 'staged_payload' ||
        t.type === 'fetch_decrypt_exec'
      );
      return hasNpmrc && hasOutbound;
    }
  }
];

/**
 * Evaluate whether the static threat set warrants sandbox activation.
 *
 * @param {Array<{type:string,severity:string}>} threats - Deduplicated static threats.
 * @param {number} score - Preliminary static score.
 * @param {object} [fileSizes] - Map relative-path -> bytes (used by obfuscated_oversize).
 * @returns {{shouldRun:boolean, compound:string|null, watchpoints:string[], reason:string}}
 */
function evaluateSandboxTrigger(threats, score, fileSizes) {
  if (!Array.isArray(threats)) {
    return { shouldRun: false, compound: null, watchpoints: [], reason: 'no threats array' };
  }
  if (typeof score !== 'number' || Number.isNaN(score)) {
    return { shouldRun: false, compound: null, watchpoints: [], reason: 'invalid score' };
  }
  if (score < SANDBOX_TRIGGER_MIN_SCORE) {
    return { shouldRun: false, compound: null, watchpoints: [], reason: 'score below window' };
  }
  if (score > SANDBOX_TRIGGER_MAX_SCORE) {
    return { shouldRun: false, compound: null, watchpoints: [], reason: 'score above window' };
  }
  for (const trigger of TRIGGERS) {
    let matched;
    try {
      matched = trigger.matches(threats, fileSizes || {});
    } catch {
      matched = false;
    }
    if (matched) {
      return {
        shouldRun: true,
        compound: trigger.name,
        watchpoints: trigger.watchpoints.slice(),
        reason: trigger.description
      };
    }
  }
  return { shouldRun: false, compound: null, watchpoints: [], reason: 'no compound matched' };
}

module.exports = {
  evaluateSandboxTrigger,
  TRIGGERS,
  SANDBOX_TRIGGER_MIN_SCORE,
  SANDBOX_TRIGGER_MAX_SCORE
};
