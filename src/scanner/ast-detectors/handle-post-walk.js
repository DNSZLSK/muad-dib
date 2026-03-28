'use strict';

function handlePostWalk(ctx) {
  // SANDWORM_MODE: zlib inflate + base64 decode + eval/Function/Module._compile = obfuscated payload
  if (ctx.hasZlibInflate && ctx.hasBase64Decode && ctx.hasDynamicExec) {
    // FIX 4: dist/build files get LOW severity (bundlers legitimately use zlib+base64+eval)
    const isDistFile = /^(dist|build)[/\\]/i.test(ctx.relFile) || /\.bundle\.js$/i.test(ctx.relFile);
    ctx.threats.push({
      type: 'zlib_inflate_eval',
      severity: isDistFile ? 'LOW' : 'CRITICAL',
      message: 'Obfuscated payload: zlib inflate + base64 decode + dynamic execution. No legitimate package uses this pattern.',
      file: ctx.relFile
    });
  }

  // SANDWORM_MODE: write + execute + delete = anti-forensics staging
  if (ctx.hasTempFileWrite && ctx.hasTempFileExec && ctx.hasFileDelete) {
    ctx.threats.push({
      type: 'write_execute_delete',
      severity: 'HIGH',
      message: 'Anti-forensics: write, execute, then delete. Typical malware staging pattern.',
      file: ctx.relFile
    });
  }

  // SANDWORM_MODE R7: env harvesting = Object.entries/keys/values(process.env) + sensitive pattern in file
  if (ctx.hasEnvEnumeration && ctx.hasEnvHarvestPattern && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'env_harvesting_dynamic',
      severity: 'HIGH',
      message: 'Dynamic environment variable harvesting with sensitive pattern matching. Credential theft technique.',
      file: ctx.relFile
    });
  }

  // SANDWORM_MODE R8: DNS exfiltration = dns require + base64 encode + dns call (loop implied by co-occurrence)
  if (ctx.hasDnsLoop) {
    ctx.threats.push({
      type: 'dns_chunk_exfiltration',
      severity: 'HIGH',
      message: 'DNS exfiltration: data encoded in DNS queries. Covert channel for firewall bypass.',
      file: ctx.relFile
    });
  }

  // SANDWORM_MODE R9: LLM API key harvesting (3+ different providers = harvesting)
  if (ctx.llmApiKeyCount >= 3) {
    ctx.threats.push({
      type: 'llm_api_key_harvesting',
      severity: 'MEDIUM',
      message: `LLM API key harvesting: accessing ${ctx.llmApiKeyCount} AI provider keys. Monetization vector.`,
      file: ctx.relFile
    });
  }

  // JS reverse shell pattern
  if (ctx.hasJsReverseShell) {
    ctx.threats.push({
      type: 'reverse_shell',
      severity: 'CRITICAL',
      message: 'JavaScript reverse shell: net.Socket + connect() + pipe to shell process stdin/stdout.',
      file: ctx.relFile
    });
  }

  // Binary dropper: chmod executable + exec/spawn in same file = CRITICAL
  if (ctx.hasChmodExecutable) {
    const execTypes = ['dangerous_exec', 'dangerous_call_exec', 'detached_process'];
    const hasExecInFile = ctx.threats.some(t =>
      t.file === ctx.relFile && execTypes.includes(t.type)
    );
    if (hasExecInFile) {
      ctx.threats.push({
        type: 'binary_dropper',
        severity: 'CRITICAL',
        message: `${ctx.chmodMessage} + exec/spawn in same file — binary dropper pattern.`,
        file: ctx.relFile
      });
    }
  }

  // Steganographic/binary payload execution
  if (ctx.hasBinaryFileLiteral && ctx.hasEvalInFile) {
    ctx.threats.push({
      type: 'staged_binary_payload',
      severity: 'HIGH',
      message: 'Binary file reference (.png/.jpg/.wasm/etc.) + eval() in same file — possible steganographic payload execution.',
      file: ctx.relFile
    });
  }

  // Remote code loading: fetch + eval/Function in same file = multi-stage payload
  // Distinct from fetch_decrypt_exec which also requires crypto. This catches SVG/HTML payload extraction.
  if (ctx.hasRemoteFetch && ctx.hasDynamicExec && !ctx.hasCryptoDecipher) {
    ctx.threats.push({
      type: 'remote_code_load',
      severity: 'CRITICAL',
      message: 'Remote code loading: network fetch + dynamic eval/Function in same file — multi-stage payload execution.',
      file: ctx.relFile
    });
  }

  // Wave 4: Remote fetch + crypto decrypt + dynamic eval = steganographic payload chain
  if (ctx.hasRemoteFetch && ctx.hasCryptoDecipher && ctx.hasDynamicExec) {
    ctx.threats.push({
      type: 'fetch_decrypt_exec',
      severity: 'CRITICAL',
      message: 'Steganographic payload chain: remote fetch + crypto decryption + dynamic execution. No legitimate package uses this pattern.',
      file: ctx.relFile
    });
  }

  // Wave 4: Download-execute-cleanup — https download + chmod executable + execSync + unlink
  // Exclude when all URLs in the file point to safe registries (npm, GitHub, nodejs.org)
  // B4: removed fetchOnlySafeDomains guard — compound requires fetch+chmod+exec, which is never legitimate
  // C10: If file also contains hash/checksum verification, downgrade to HIGH — real droppers
  // don't verify payload integrity; legitimate installers (esbuild, sharp) do.
  if (ctx.hasRemoteFetch && ctx.hasChmodExecutable && ctx.hasExecSyncCall) {
    ctx.threats.push({
      type: 'download_exec_binary',
      severity: ctx.hasHashVerification ? 'HIGH' : 'CRITICAL',
      message: 'Download-execute pattern: remote fetch + chmod executable + execSync in same file.' +
        (ctx.hasHashVerification ? ' Hash verification detected — likely legitimate binary installer.' : ' Binary dropper camouflaged as native addon build.'),
      file: ctx.relFile
    });
  }

  // Wave 4: IDE persistence via content co-occurrence — tasks.json + runOn + writeFileSync
  if (!ctx.hasIdePersistenceWrite && ctx.hasTasksJsonInContent && ctx.hasRunOnInContent && ctx.hasWriteFileSyncInContent) {
    ctx.hasIdePersistenceWrite = true;
    ctx.threats.push({
      type: 'ide_persistence',
      severity: 'HIGH',
      message: 'IDE persistence: writes tasks.json with auto-execution trigger (runOn/folderOpen). VS Code task persistence technique.',
      file: ctx.relFile
    });
  }

  // WASM payload detection: WebAssembly.compile/instantiate + network in same file
  // C5+C6: Only emit CRITICAL wasm_host_sink if corroborating exfil signals exist
  // (env_access, sensitive_string, credential reads). WASM + fetch alone is likely
  // just WASM module loading via fetch() (standard pattern: fetch('mod.wasm').then(WebAssembly.instantiateStreaming))
  if (ctx.hasWasmLoad && ctx.hasNetworkCallInFile) {
    // C5/C6: Distinguish fetch-for-WASM-loading from independent network channels
    // https.request, http.get, dns.resolve are NEVER used for WASM loading — they indicate
    // an independent network channel (e.g., WASM host callbacks for C2 exfiltration)
    const hasExfilSignal = ctx.threats.some(t =>
      t.file === ctx.relFile && (
        t.type === 'env_access' || t.type === 'sensitive_string' ||
        t.type === 'suspicious_dataflow' || t.type === 'credential_regex_harvest'
      )
    );
    if (ctx.hasNonFetchNetworkCall || hasExfilSignal) {
      ctx.threats.push({
        type: 'wasm_host_sink',
        severity: 'CRITICAL',
        message: 'WebAssembly module with network-capable host imports and credential/env access. WASM can invoke host callbacks to exfiltrate data while hiding control flow.',
        file: ctx.relFile
      });
    } else {
      // WASM + network but no credential/env signals → standalone MEDIUM (likely fetch for WASM loading)
      ctx.threats.push({
        type: 'wasm_standalone',
        severity: 'MEDIUM',
        message: 'WebAssembly module with network calls but no credential/env access signals. Likely WASM loading via fetch(). Verify .wasm file purpose.',
        file: ctx.relFile
      });
    }
  }

  // WASM standalone: WebAssembly.compile/instantiate WITHOUT network sinks.
  // Legitimate: crypto, image processing, codecs. Still warrants investigation
  // because WASM hides control flow from static analysis.
  if (ctx.hasWasmLoad && !ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'wasm_standalone',
      severity: 'MEDIUM',
      message: 'WebAssembly module loaded without detectable network sinks. WASM hides control flow — verify .wasm file purpose.',
      file: ctx.relFile
    });
  }

  // Credential regex harvesting: credential-matching regex + network call in same file
  // Real-world pattern: Transform/stream that scans data for tokens/passwords and exfiltrates
  if (ctx.hasCredentialRegex && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'credential_regex_harvest',
      severity: 'HIGH',
      message: 'Credential regex patterns (token/password/secret/Bearer) + network call in same file — stream data credential harvesting.',
      file: ctx.relFile
    });
  }

  // Built-in method override + network: console.X = function or Object.defineProperty = function
  // combined with network calls. Monkey-patching built-in APIs for data interception.
  // CRITICAL when Object.defineProperty itself is reassigned (global hook on all property defs).
  if (ctx.hasBuiltinOverride && ctx.hasNetworkCallInFile) {
    const isGlobalHook = ctx.hasBuiltinGlobalHook;
    ctx.threats.push({
      type: 'builtin_override_exfil',
      severity: isGlobalHook ? 'CRITICAL' : 'HIGH',
      message: isGlobalHook
        ? 'Object.defineProperty reassigned + network call — global hook intercepts all property definitions for credential exfiltration.'
        : 'Built-in method override (console/Object.defineProperty) + network call — runtime API hijacking for data interception and exfiltration.',
      file: ctx.relFile
    });
  }

  // Stream credential interception: Transform/Duplex/Writable stream + credential regex + network
  // Wiretap pattern: intercepts data in transit, scans for credentials, exfiltrates matches.
  if (ctx.hasStreamInterceptor && ctx.hasCredentialRegex && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'stream_credential_intercept',
      severity: 'HIGH',
      message: 'Stream class (Transform/Duplex/Writable) with credential regex scanning + network call — data-in-transit credential wiretap.',
      file: ctx.relFile
    });
  }

  // Proxy data interception: new Proxy(obj, { set/get }) + network in same file
  // Real-world pattern: export a Proxy that exfiltrates all property assignments via network
  // CRITICAL only when credential signals co-occur (env_access, suspicious_dataflow),
  // otherwise HIGH — bare Proxy + fetch is insufficient evidence.
  if (ctx.hasProxyTrap && ctx.hasNetworkCallInFile) {
    const hasCredentialSignal = ctx.threats.some(t =>
      t.type === 'env_access' || t.type === 'suspicious_dataflow'
    );
    // CRITICAL when: credential signals co-occur, OR set trap (intercepts all property writes)
    // A set trap with network call = universal data capture + exfiltration
    const isCritical = hasCredentialSignal || ctx.hasProxySetTrap;
    ctx.threats.push({
      type: 'proxy_data_intercept',
      severity: isCritical ? 'CRITICAL' : 'HIGH',
      message: ctx.hasProxySetTrap
        ? 'Proxy set trap with network call — intercepts ALL property writes for exfiltration via Proxy handler.'
        : 'Proxy trap (set/get/apply) with network call in same file — data interception and exfiltration via Proxy handler.',
      file: ctx.relFile
    });
  }

  // Wave 4: MCP content keywords in file with writeFileSync = MCP injection signal
  if (ctx.hasMcpContentKeywords && !ctx.threats.some(t => t.type === 'mcp_config_injection')) {
    ctx.threats.push({
      type: 'mcp_config_injection',
      severity: 'CRITICAL',
      message: 'MCP config injection: code contains MCP server configuration keywords (mcpServers/mcp.json/claude_desktop_config) with filesystem writes. AI toolchain poisoning.',
      file: ctx.relFile
    });
  }

  // require.cache: distinguish WRITE (actual poisoning) from READ-only (hot-reload, introspection)
  // FP fix: READ-only emits LOW (informational), WRITE emits CRITICAL (malicious module replacement).
  if (ctx.hasRequireCacheWrite) {
    ctx.threats.push({
      type: 'require_cache_poison',
      severity: 'CRITICAL',
      message: 'require.cache[...].exports = ... — module cache write: replaces core module exports to intercept all callers.',
      file: ctx.relFile
    });
  } else if (ctx.hasRequireCacheRead) {
    ctx.threats.push({
      type: 'require_cache_poison',
      severity: 'LOW',
      message: 'require.cache accessed — module cache read (hot-reload/introspection pattern).',
      file: ctx.relFile
    });
  }

  // DPRK/Lazarus compound: detached background process + credential env access + network
  // Pattern: spawn({detached:true}) reads secrets then exfils via network.
  // This combination is never legitimate — daemons don't read API keys and send them out.
  const hasDetachedInFile = ctx.threats.some(t =>
    t.file === ctx.relFile && t.type === 'detached_process'
  );
  const hasSensitiveEnvInFile = ctx.threats.some(t =>
    t.file === ctx.relFile && t.type === 'env_access' && t.severity === 'HIGH'
  );
  if (hasDetachedInFile && hasSensitiveEnvInFile && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'detached_credential_exfil',
      severity: 'CRITICAL',
      message: 'Detached process + sensitive env access + network call — credential exfiltration via background process (DPRK/Lazarus evasion pattern).',
      file: ctx.relFile
    });
  }

  // Audit v3 bypass fix: uncaughtException + env access + network = silent exfiltration
  // Pattern: process.on('uncaughtException', handler) that reads env vars and sends to network.
  // Never legitimate — error handlers don't need to send credentials to external servers.
  if (ctx.hasUncaughtExceptionHandler && hasSensitiveEnvInFile && ctx.hasNetworkCallInFile) {
    ctx.threats.push({
      type: 'uncaught_exception_exfil',
      severity: 'CRITICAL',
      message: 'process.on("uncaughtException") + sensitive env access + network — silent credential exfiltration via error handler hijacking.',
      file: ctx.relFile
    });
  }
  // Also: uncaughtException + env enumeration (Object.entries/keys(process.env)) + network
  if (ctx.hasUncaughtExceptionHandler && ctx.hasEnvEnumeration && ctx.hasNetworkCallInFile) {
    if (!ctx.threats.some(t => t.type === 'uncaught_exception_exfil' && t.file === ctx.relFile)) {
      ctx.threats.push({
        type: 'uncaught_exception_exfil',
        severity: 'CRITICAL',
        message: 'process.on("uncaughtException") + bulk env enumeration + network — silent credential exfiltration via error handler hijacking.',
        file: ctx.relFile
      });
    }
  }

  // GlassWorm: Unicode variation selector decoder = .codePointAt + variation selector constants
  // CRITICAL if combined with eval/exec (GlassWorm always uses dynamic execution),
  // MEDIUM otherwise (.codePointAt + 0xFE00 is legitimate Unicode processing in fonts/text libs)
  if (ctx.hasCodePointAt && ctx.hasVariationSelectorConst) {
    ctx.threats.push({
      type: 'unicode_variation_decoder',
      severity: ctx.hasDynamicExec ? 'CRITICAL' : 'MEDIUM',
      message: ctx.hasDynamicExec
        ? 'Unicode variation selector decoder: .codePointAt() + 0xFE00/0xE0100 constants + dynamic execution — GlassWorm payload reconstruction from invisible characters.'
        : 'Unicode variation selector decoder: .codePointAt() + 0xFE00/0xE0100 constants — likely legitimate Unicode processing (text formatting, font rendering).',
      file: ctx.relFile
    });
  }

  // GlassWorm: Blockchain C2 resolution = Solana import + C2 method
  // CRITICAL if combined with eval/exec, HIGH otherwise
  if (ctx.hasSolanaImport && ctx.hasSolanaC2Method) {
    ctx.threats.push({
      type: 'blockchain_c2_resolution',
      severity: ctx.hasDynamicExec ? 'CRITICAL' : 'HIGH',
      message: 'Solana/Web3 import + blockchain C2 method (getSignaturesForAddress/getTransaction) — ' +
        (ctx.hasDynamicExec
          ? 'dead drop resolver with dynamic execution. GlassWorm blockchain C2 pattern confirmed.'
          : 'potential dead drop resolver. GlassWorm technique: C2 address rotated via Solana memo field.'),
      file: ctx.relFile
    });
  }

  // B2 compound: FinalizationRegistry + exec/network in same file = deferred malicious execution
  if (ctx.hasFinalizationRegistry && ctx.hasDynamicExec) {
    ctx.threats.push({
      type: 'finalization_registry_exec',
      severity: 'CRITICAL',
      message: 'FinalizationRegistry + dynamic execution in same file — deferred code execution triggered by garbage collection.',
      file: ctx.relFile
    });
  }

  // Blue Team v8: SharedArrayBuffer + Worker = covert shared memory IPC
  // Pattern: SharedArrayBuffer enables worker-to-main-thread communication
  // that bypasses message channel monitoring. Alone = MEDIUM, with exec = HIGH.
  if (ctx.hasSharedArrayBuffer && ctx.hasWorkerThread) {
    ctx.threats.push({
      type: 'shared_memory_ipc',
      severity: ctx.hasDynamicExec ? 'HIGH' : 'MEDIUM',
      message: ctx.hasDynamicExec
        ? 'SharedArrayBuffer + Worker + dynamic execution — covert shared memory IPC with code execution.'
        : 'SharedArrayBuffer + Worker — shared memory IPC channel bypasses standard message monitoring.',
      file: ctx.relFile
    });
  }

  // Blue Team v8: dgram/UDP exfiltration — dgram import + send in same file
  if (ctx.hasDgramImport && ctx.hasDgramSend) {
    const hasExfilSignal = ctx.threats.some(t =>
      t.file === ctx.relFile && (t.type === 'env_access' || t.type === 'sensitive_string')
    );
    ctx.threats.push({
      type: 'udp_exfiltration',
      severity: hasExfilSignal ? 'CRITICAL' : 'HIGH',
      message: hasExfilSignal
        ? 'UDP socket (dgram) with credential/env access — data exfiltration via UDP bypasses HTTP-level monitoring.'
        : 'UDP socket (dgram) createSocket + send — non-HTTP data channel. UDP exfiltration bypasses HTTP firewalls.',
      file: ctx.relFile
    });
  }

  // Blue Team v8: WebSocket C2 compound — WebSocket + exec/spawn in same file
  if (ctx.hasWebSocketNew && ctx.hasDynamicExec) {
    // Only emit if no websocket_c2 already emitted (from suspicious domain detection)
    if (!ctx.threats.some(t => t.type === 'websocket_c2' && t.file === ctx.relFile)) {
      ctx.threats.push({
        type: 'websocket_c2',
        severity: 'HIGH',
        message: 'WebSocket connection + dynamic execution in same file — potential WebSocket C2 channel for remote command execution.',
        file: ctx.relFile
      });
    }
  }

  // Blue Team v8: Extended blockchain C2 — Ethereum/Web3 import + C2 methods
  // Extends GlassWorm detection to cover ethers.js/web3.js patterns
  if (!ctx.hasSolanaImport && ctx.hasSolanaC2Method) {
    // C2 method detected without Solana import — check if Ethereum packages are used
    const hasEthImport = /\brequire\s*\(\s*['"](?:ethers|web3|@ethersproject)/i.test(ctx._sourceCode || '');
    if (hasEthImport) {
      ctx.threats.push({
        type: 'blockchain_c2_resolution',
        severity: ctx.hasDynamicExec ? 'CRITICAL' : 'HIGH',
        message: 'Ethereum/Web3 import + blockchain C2 method — ' +
          (ctx.hasDynamicExec
            ? 'dead drop resolver with dynamic execution. Blockchain C2 pattern confirmed.'
            : 'potential dead drop resolver. Technique: C2 commands stored in blockchain transactions.'),
        file: ctx.relFile
      });
    }
  }

  // Blue Team v8b (A6): with statement + Proxy + require/exec in same file = sandbox escape compound
  // Boost: if with_body_dangerous AND proxy trap detected → ensure minimum CRITICAL score
  const hasWithDangerous = ctx.threats.some(t => t.type === 'with_body_dangerous' && t.file === ctx.relFile);
  const hasProxyInFile = ctx.hasProxyTrap || ctx.proxyHandlerVars?.size > 0;
  if (hasWithDangerous && hasProxyInFile) {
    // Elevate existing with_body_dangerous to CRITICAL if not already
    for (const t of ctx.threats) {
      if (t.type === 'with_body_dangerous' && t.file === ctx.relFile && t.severity !== 'CRITICAL') {
        t.severity = 'CRITICAL';
        t.message = 'with() + Proxy compound: Proxy trap intercepts all scope resolution inside with block — complete API hijacking for sandbox escape.';
      }
    }
  }

  // Blue Team v8b (B7): Binary file read + new Function/eval = steganographic payload
  if (ctx.hasBinaryFileRead && ctx.hasDynamicExec) {
    ctx.threats.push({
      type: 'stego_binary_exec',
      severity: 'CRITICAL',
      message: 'Binary/image file read + dynamic execution (eval/Function) — steganographic payload extraction and execution.',
      file: ctx.relFile
    });
  } else if (ctx.hasImageFileRef && ctx.hasDynamicExec && ctx.hasWriteFileSyncInContent) {
    // Fallback: image reference + eval in same file (may not directly readFile the image)
    ctx.threats.push({
      type: 'stego_binary_exec',
      severity: 'HIGH',
      message: 'Image file reference + dynamic execution + file I/O in same file — potential steganographic payload pattern.',
      file: ctx.relFile
    });
  }

  // Blue Team v8b (C1): AsyncLocalStorage + credential file read + exec/network
  // Trigger on hasDynamicExec OR when dynamic_require is present (require('child_' + 'process') stored in context)
  const hasDynReqInFile = ctx.threats.some(t => t.type === 'dynamic_require' && t.file === ctx.relFile);
  if (ctx.hasAsyncLocalStorage && (ctx.hasDynamicExec || hasDynReqInFile)) {
    ctx.threats.push({
      type: 'asynclocal_context_exec',
      severity: 'HIGH',
      message: 'AsyncLocalStorage + dynamic execution/require — code execution hidden in async context, evades synchronous call-stack analysis.',
      file: ctx.relFile
    });
  }

  // Blue Team v8b (C10): net.Socket + exec = WebSocket/TCP C2
  // Trigger on callbackExec (exec in .on('message') callback) OR hasDynamicExec (exec anywhere in file)
  if (ctx.hasNetSocketCreate && (ctx.hasCallbackExec || ctx.hasDynamicExec)) {
    if (!ctx.threats.some(t => t.type === 'websocket_c2' && t.file === ctx.relFile)) {
      ctx.threats.push({
        type: 'websocket_c2',
        severity: 'CRITICAL',
        message: 'net.Socket + exec in same file — persistent TCP/WebSocket C2 with remote command execution.',
        file: ctx.relFile
      });
    }
  }

  // Blue Team v8b (B2): CI environment fingerprinting probe — 3+ CI provider env vars in same file
  // Indicates multi-provider CI detection for conditional payload activation
  if (ctx.ciProviderCount >= 3) {
    ctx.threats.push({
      type: 'ci_environment_probe',
      severity: 'HIGH',
      message: `File references ${ctx.ciProviderCount} CI provider environment variables (GITHUB_ACTIONS, GITLAB_CI, etc.) — CI environment fingerprinting for targeted execution.`,
      file: ctx.relFile
    });
  }

  // Blue Team v8: Hardcoded contract address (40-char hex) + blockchain import = C2 address
  if ((ctx.hasSolanaImport || /\brequire\s*\(\s*['"](?:ethers|web3|@ethersproject|@solana)/i.test(ctx._sourceCode || '')) &&
      /\b0x[0-9a-fA-F]{40}\b/.test(ctx._sourceCode || '')) {
    const existingBlockchain = ctx.threats.some(t =>
      t.type === 'blockchain_c2_resolution' && t.file === ctx.relFile
    );
    if (!existingBlockchain) {
      ctx.threats.push({
        type: 'blockchain_c2_resolution',
        severity: 'MEDIUM',
        message: 'Blockchain import + hardcoded contract address (0x...) — potential smart contract C2 endpoint.',
        file: ctx.relFile
      });
    }
  }
}


module.exports = { handlePostWalk };
