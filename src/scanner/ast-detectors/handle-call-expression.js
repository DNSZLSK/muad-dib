'use strict';

/**
 * AST CallExpression handler — the largest single detection module.
 *
 * Architecture note (ANSSI audit m3):
 * This file detects ~95 distinct threat patterns across 7 categories:
 *   1. Dynamic require/import (lines ~36-163)   — 8 patterns
 *   2. Process.mainModule bypasses (~166-215)    — 2 patterns
 *   3. Shell execution variants (~217-404)       — 8+ patterns (exec, spawn, npm worm, token steal)
 *   4. File write interception (~449-700)        — 7 patterns (workflows, node_modules, systemd, MCP, git hooks, IDE)
 *   5. Credential access (~700-1200)             — 15+ patterns (env harvest, regex harvest, CLI steal)
 *   6. Network/eval combos (~1200-1600)          — 10+ patterns (fetch+eval, download+exec, WASM)
 *   7. Prototype/proxy hooks (~1600-1842)        — 10+ patterns (globalThis, Reflect, defineProperty)
 *
 * Why monolithic: Each pattern shares AST context (ctx.moduleAliases, ctx.stringVarValues,
 * ctx.trackedVars) built incrementally during the walk. Splitting into separate files would
 * require passing a large mutable context object, adding complexity without reducing LOC.
 *
 * Refactoring TODO: If the file exceeds ~2500 lines, extract categories 4-7 into
 * handle-call-expression-fs.js and handle-call-expression-network.js with shared ctx.
 */

const path = require('path');
const { getCallName } = require('../../utils.js');
const {
  AI_AGENT_DANGEROUS_FLAGS,
  AI_AGENT_BINARIES,
  CREDENTIAL_CLI_COMMANDS,
  DANGEROUS_CMD_PATTERNS,
  MCP_CONFIG_PATHS,
  MCP_CONTENT_PATTERNS,
  SENSITIVE_AI_CONFIG_FILES_UNIQUE,
  SENSITIVE_AI_CONFIG_FILES_ROOT_ONLY,
  GIT_HOOKS,
  SANDBOX_INDICATORS,
  ETHEREUM_PACKAGES,
  SOLANA_PACKAGES,
  SAFE_FETCH_DOMAINS
} = require('./constants.js');
const {
  extractStringValue,
  calculateShannonEntropy,
  countConcatOperands,
  resolveStringConcat,
  resolveStringConcatWithVars,
  extractStringValueDeep,
  hasOnlyStringLiteralArgs,
  hasDecodeArg,
  containsDecodePattern
} = require('./helpers.js');

function handleCallExpression(node, ctx) {
  const callName = getCallName(node);

  // Detect require() with non-literal argument (obfuscation)
  if (callName === 'require' && node.arguments.length > 0) {
    const arg = node.arguments[0];
    if (arg.type === 'BinaryExpression' && arg.operator === '+') {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: 'Dynamic require() with string concatenation (module name obfuscation).',
        file: ctx.relFile
      });
    } else if (arg.type === 'TemplateLiteral' && arg.expressions.length > 0) {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: 'Dynamic require() with template literal (module name obfuscation).',
        file: ctx.relFile
      });
    } else if (arg.type === 'CallExpression') {
      const argCallName = getCallName(arg);
      // Skip safe patterns: require(path.join(...)), require(path.resolve(...))
      if (argCallName !== 'path.join' && argCallName !== 'path.resolve') {
        const hasDecode = containsDecodePattern(arg);
        ctx.threats.push({
          type: 'dynamic_require',
          severity: hasDecode ? 'CRITICAL' : 'HIGH',
          message: hasDecode
            ? 'Dynamic require() with runtime decode (base64/atob obfuscation).'
            : 'Dynamic require() with computed argument (possible decode obfuscation).',
          file: ctx.relFile
        });
      }
    } else if (arg.type === 'Identifier') {
      // Check if variable was reassignment-tracked to a dangerous module
      const DANGEROUS_MODS_REQ = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
      const resolvedVal = ctx.stringVarValues?.get(arg.name);
      if (resolvedVal) {
        const norm = resolvedVal.startsWith('node:') ? resolvedVal.slice(5) : resolvedVal;
        if (DANGEROUS_MODS_REQ.includes(norm)) {
          ctx.threats.push({
            type: 'dynamic_require', severity: 'CRITICAL',
            message: `require(${arg.name}) resolves to "${norm}" via variable reassignment — module name obfuscation.`,
            file: ctx.relFile
          });
        } else {
          // If the variable was assigned from a static value (string literal,
          // array of strings, object with string values), it's a plugin loader pattern
          const severity = ctx.staticAssignments.has(arg.name) ? 'LOW' : 'HIGH';
          ctx.threats.push({
            type: 'dynamic_require',
            severity,
            message: severity === 'LOW'
              ? `Dynamic require() with statically-assigned variable "${arg.name}" (plugin loader pattern).`
              : 'Dynamic require() with variable argument (module name obfuscation).',
            file: ctx.relFile
          });
        }
      } else {
        // If the variable was assigned from a static value (string literal,
        // array of strings, object with string values), it's a plugin loader pattern
        const severity = ctx.staticAssignments.has(arg.name) ? 'LOW' : 'HIGH';
        ctx.threats.push({
          type: 'dynamic_require',
          severity,
          message: severity === 'LOW'
            ? `Dynamic require() with statically-assigned variable "${arg.name}" (plugin loader pattern).`
            : 'Dynamic require() with variable argument (module name obfuscation).',
          file: ctx.relFile
        });
      }
    }
    // B3 fix: require(/child_process/.source) — RegExpLiteral.source resolution
    else if (arg.type === 'MemberExpression' &&
             arg.object?.type === 'Literal' && arg.object.regex &&
             arg.property?.type === 'Identifier' && arg.property.name === 'source') {
      const regexSource = arg.object.regex.pattern;
      const DANGEROUS_MODS = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
      const norm = regexSource.startsWith('node:') ? regexSource.slice(5) : regexSource;
      if (DANGEROUS_MODS.includes(norm)) {
        ctx.threats.push({ type: 'dynamic_require', severity: 'CRITICAL',
          message: `require(/${regexSource}/.source) resolves to "${norm}" — regex .source evasion.`,
          file: ctx.relFile });
      } else {
        ctx.threats.push({ type: 'dynamic_require', severity: 'HIGH',
          message: `require() with regex .source argument (/${regexSource}/.source) — obfuscation technique.`,
          file: ctx.relFile });
      }
    }
    // B5: require(obj.prop) — MemberExpression argument
    else if (arg.type === 'MemberExpression') {
      const objName = arg.object?.type === 'Identifier' ? arg.object.name : null;
      const propName = arg.property?.type === 'Identifier' ? arg.property.name :
                       (arg.property?.type === 'Literal' ? String(arg.property.value) : null);
      const DANGEROUS_MODS = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
      let resolved = false;
      if (objName && propName && ctx.objectPropertyMap?.has(objName)) {
        const val = ctx.objectPropertyMap.get(objName).get(propName);
        if (val) {
          const norm = val.startsWith('node:') ? val.slice(5) : val;
          if (DANGEROUS_MODS.includes(norm)) {
            ctx.threats.push({ type: 'dynamic_require', severity: 'CRITICAL',
              message: `require(${objName}.${propName}) resolves to "${norm}" — object property indirection.`,
              file: ctx.relFile });
            resolved = true;
          }
        }
      }
      if (!resolved) {
        ctx.threats.push({ type: 'dynamic_require', severity: 'MEDIUM',
          message: 'Dynamic require() with member expression argument (object property obfuscation).',
          file: ctx.relFile });
      }
    }
    // Wave 4: detect require() of .node binary files (native addon camouflage)
    const reqStr = extractStringValueDeep(arg);
    if (reqStr && /\.node\s*$/.test(reqStr)) {
      ctx.hasRequireNodeFile = true;
    }
    // GlassWorm: track Solana/Web3 require imports for compound blockchain C2 detection
    if (reqStr && SOLANA_PACKAGES.some(pkg => reqStr === pkg)) {
      ctx.hasSolanaImport = true;
    }
    // Blue Team v8: track Ethereum/Web3 imports
    if (reqStr && ETHEREUM_PACKAGES.some(pkg => reqStr === pkg || reqStr.startsWith(pkg))) {
      ctx.hasSolanaImport = true; // reuse flag — both indicate blockchain SDK usage
    }
    // Blue Team v8: track require('ws') for WebSocket C2 detection
    if (reqStr === 'ws' || reqStr === 'websocket') {
      ctx.hasWebSocketNew = true; // ws module provides WebSocket functionality
    }
  }

  // Detect process.mainModule.require('child_process') — module system bypass
  if (node.callee.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'require' &&
      node.callee.object?.type === 'MemberExpression' &&
      node.callee.object.object?.type === 'Identifier' &&
      node.callee.object.object.name === 'process' &&
      node.callee.object.property?.type === 'Identifier' &&
      node.callee.object.property.name === 'mainModule' &&
      node.arguments.length > 0) {
    const arg = node.arguments[0];
    const modName = extractStringValueDeep(arg);
    const DANGEROUS_MODS = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
    if (modName && DANGEROUS_MODS.includes(modName)) {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'CRITICAL',
        message: `process.mainModule.require('${modName}') — bypasses module system restrictions.`,
        file: ctx.relFile
      });
    } else {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'HIGH',
        message: `process.mainModule.require() detected — module system bypass.`,
        file: ctx.relFile
      });
    }
  }

  // B8: require('process').mainModule.require('child_process') — indirect process access
  // Pattern: require('process').mainModule.require(mod)
  if (node.callee.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'require' &&
      node.callee.object?.type === 'MemberExpression' &&
      node.callee.object.property?.type === 'Identifier' && node.callee.object.property.name === 'mainModule' &&
      node.callee.object.object?.type === 'CallExpression' &&
      getCallName(node.callee.object.object) === 'require' &&
      node.callee.object.object.arguments?.[0]?.type === 'Literal' &&
      node.callee.object.object.arguments[0].value === 'process') {
    const arg = node.arguments?.[0];
    const modName = arg ? extractStringValueDeep(arg) : null;
    const DANGEROUS_MODS = ['child_process', 'fs', 'net', 'dns', 'http', 'https', 'tls'];
    const severity = modName && DANGEROUS_MODS.includes(modName) ? 'CRITICAL' : 'HIGH';
    ctx.threats.push({
      type: 'require_process_mainmodule',
      severity,
      message: `require('process').mainModule.require(${modName ? "'" + modName + "'" : '...'}) — indirect process access bypasses direct process.mainModule detection.`,
      file: ctx.relFile
    });
  }

  // Detect exec/execSync with dangerous shell commands (direct or via MemberExpression)
  const execName = callName === 'exec' || callName === 'execSync' ? callName : null;
  const memberExec = !execName && node.callee.type === 'MemberExpression' &&
    node.callee.property?.type === 'Identifier' &&
    (node.callee.property.name === 'exec' || node.callee.property.name === 'execSync')
    ? node.callee.property.name : null;
  if ((execName || memberExec) && node.arguments.length > 0) {
    // Wave 4: track any execSync/exec call for compound detection
    ctx.hasExecSyncCall = true;
    const arg = node.arguments[0];
    let cmdStr = null;
    if (arg.type === 'Literal' && typeof arg.value === 'string') {
      cmdStr = arg.value;
    } else if (arg.type === 'Identifier' && ctx.dangerousCmdVars.has(arg.name)) {
      // Variable was assigned a dangerous command string
      cmdStr = ctx.dangerousCmdVars.get(arg.name);
    } else if (arg.type === 'Identifier' && ctx.execPathVars.has(arg.name)) {
      // Variable was assigned a temp/executable file path
      cmdStr = ctx.execPathVars.get(arg.name);
    } else if (arg.type === 'TemplateLiteral') {
      cmdStr = arg.quasis.map(q => q.value.raw).join('***');
    }

    if (cmdStr) {
      // Check for dangerous shell patterns
      if (/\|\s*(sh|bash)\b/.test(cmdStr) || /nc\s+-[elp]/.test(cmdStr) || /\/dev\/tcp\//.test(cmdStr) || /bash\s+-i/.test(cmdStr) || /\bcurl\b/.test(cmdStr) || /\bwget\b/.test(cmdStr) || /\bpowershell\b/.test(cmdStr) || /\bpwsh\b/.test(cmdStr) || /\bnslookup\b/.test(cmdStr) || /\bdig\s+/.test(cmdStr) || /\bhost\s+\S+\.\S+/.test(cmdStr)) {
        ctx.threats.push({
          type: 'dangerous_exec',
          severity: 'CRITICAL',
          message: `Dangerous shell command in exec(): "${cmdStr.substring(0, 80)}"`,
          file: ctx.relFile
        });
      }

      // Check for temp file execution (binary dropper pattern)
      if (/^\/tmp\/|^\/var\/tmp\//i.test(cmdStr)) {
        ctx.threats.push({
          type: 'dangerous_exec',
          severity: 'CRITICAL',
          message: `Execution of temp file "${cmdStr.substring(0, 80)}" — binary dropper pattern.`,
          file: ctx.relFile
        });
      }

      // Check for credential-stealing CLI commands
      for (const credCmd of CREDENTIAL_CLI_COMMANDS) {
        if (cmdStr.includes(credCmd)) {
          ctx.threats.push({
            type: 'credential_command_exec',
            severity: 'CRITICAL',
            message: `Credential theft via CLI tool: exec("${credCmd}") — steals auth tokens from installed tools.`,
            file: ctx.relFile
          });
          break;
        }
      }

      // Bun runtime evasion: exec/spawn using bun instead of node (Shai-Hulud 2.0)
      if (/\bbun\s+(run|exec|install|x)\b/.test(cmdStr)) {
        ctx.threats.push({
          type: 'bun_runtime_evasion',
          severity: 'HIGH',
          message: `Bun runtime invocation detected: "${cmdStr.slice(0, 80)}" — alternative runtime to evade Node.js monitoring/sandboxing.`,
          file: ctx.relFile
        });
      }

      // Worm propagation: npm publish / npm adduser / npm token create (Shai-Hulud)
      if (/\bnpm\s+(publish|adduser|token\s+create|login)\b/.test(cmdStr)) {
        ctx.threats.push({
          type: 'npm_publish_worm',
          severity: 'CRITICAL',
          message: `exec("${cmdStr.slice(0, 80)}") — worm propagation: publishing packages with stolen credentials.`,
          file: ctx.relFile
        });
      }

      // Token theft: npm config get _authToken / npm whoami (CanisterWorm findNpmTokens)
      if (/\bnpm\s+(config\s+get\b.*authToken|whoami)\b/i.test(cmdStr)) {
        ctx.threats.push({
          type: 'npm_token_steal',
          severity: 'CRITICAL',
          message: `exec("${cmdStr.slice(0, 80)}") — npm credential extraction (CanisterWorm findNpmTokens pattern).`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect exec/execSync called on a dynamically-required module variable
  if ((execName || memberExec) && node.callee.type === 'MemberExpression' && node.callee.object?.type === 'Identifier') {
    if (ctx.dynamicRequireVars.has(node.callee.object.name)) {
      const method = execName || memberExec;
      ctx.threats.push({
        type: 'dynamic_require_exec',
        severity: 'CRITICAL',
        message: `${method}() called on dynamically-required module "${node.callee.object.name}" — obfuscated command execution.`,
        file: ctx.relFile
      });
    }
  }

  // Detect chained: require(non-literal).exec(...) — direct dynamic require + exec
  if ((execName || memberExec) && node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'CallExpression') {
    const innerCall = node.callee.object;
    const innerName = getCallName(innerCall);
    if (innerName === 'require' && innerCall.arguments.length > 0 &&
        innerCall.arguments[0]?.type !== 'Literal') {
      const method = execName || memberExec;
      ctx.threats.push({
        type: 'dynamic_require_exec',
        severity: 'CRITICAL',
        message: `${method}() chained on dynamic require() — obfuscated module + command execution.`,
        file: ctx.relFile
      });
    }
  }

  // Blue Team v8b (C10): require('child_process').execSync/exec(variable) — inline require + variable command
  // When require is literal 'child_process' but the command argument is not resolvable (MemberExpression, Identifier),
  // this is a hidden exec with runtime-determined command (C2 pattern: cmd from network data)
  if ((execName || memberExec) && node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'CallExpression') {
    const innerCall = node.callee.object;
    const innerName = getCallName(innerCall);
    if (innerName === 'require' && innerCall.arguments.length > 0 &&
        innerCall.arguments[0]?.type === 'Literal' && innerCall.arguments[0].value === 'child_process') {
      const cmdArg = node.arguments[0];
      if (cmdArg && cmdArg.type !== 'Literal') {
        // Non-literal command argument with inline require — opaque shell execution
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'dangerous_exec',
          severity: 'HIGH',
          message: `Inline require('child_process').${execName || memberExec}(variable) — hidden import with runtime-determined command. Typical C2 or RCE payload pattern.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect sandbox/container evasion
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const fsMethod = node.callee.property.name;
    if (['accessSync', 'existsSync', 'statSync', 'lstatSync', 'access', 'stat'].includes(fsMethod)) {
      const arg = node.arguments[0];
      if (arg?.type === 'Literal' && typeof arg.value === 'string') {
        if (SANDBOX_INDICATORS.some(ind => arg.value.includes(ind))) {
          ctx.threats.push({
            type: 'sandbox_evasion',
            severity: 'HIGH',
            message: `Sandbox/container detection via ${fsMethod}("${arg.value}") — anti-analysis technique.`,
            file: ctx.relFile
          });
        }
      }
    }
  }

  // Detect spawn/execFile of shell processes
  if ((callName === 'spawn' || callName === 'execFile') && node.arguments.length >= 1) {
    const shellArg = node.arguments[0];
    if (shellArg.type === 'Literal' && typeof shellArg.value === 'string') {
      const shellBin = shellArg.value.toLowerCase();
      if (['/bin/sh', '/bin/bash', 'sh', 'bash', 'cmd.exe', 'powershell', 'pwsh', 'cmd'].includes(shellBin)) {
        ctx.threats.push({
          type: 'dangerous_call_exec',
          severity: 'MEDIUM',
          message: `${callName}('${shellArg.value}') — direct shell process spawn detected.`,
          file: ctx.relFile
        });
      }
    }
    // Also check when shell is computed via os.platform() ternary
    if (shellArg.type === 'ConditionalExpression') {
      const checkLiteral = (n) => n.type === 'Literal' && typeof n.value === 'string' &&
        ['/bin/sh', '/bin/bash', 'sh', 'bash', 'cmd.exe', 'powershell', 'pwsh', 'cmd'].includes(n.value.toLowerCase());
      if (checkLiteral(shellArg.consequent) || checkLiteral(shellArg.alternate)) {
        ctx.threats.push({
          type: 'dangerous_call_exec',
          severity: 'MEDIUM',
          message: `${callName}() with conditional shell binary (platform-aware) — direct shell process spawn detected.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect spawn('bun', ['run', ...]) — Bun runtime evasion via spawn
  if ((callName === 'spawn' || callName === 'execFile') && node.arguments.length >= 1) {
    const bunArg = node.arguments[0];
    if (bunArg.type === 'Literal' && typeof bunArg.value === 'string' && bunArg.value === 'bun') {
      // Check the args array for run/exec/install/x
      const argsArr = node.arguments[1];
      let bunCmd = 'bun';
      if (argsArr?.type === 'ArrayExpression' && argsArr.elements.length > 0) {
        const firstEl = argsArr.elements[0];
        if (firstEl?.type === 'Literal' && typeof firstEl.value === 'string') {
          bunCmd = `bun ${firstEl.value}`;
        }
      }
      if (/\bbun\s*(run|exec|install|x)?$/.test(bunCmd) || bunCmd === 'bun') {
        ctx.threats.push({
          type: 'bun_runtime_evasion',
          severity: 'HIGH',
          message: `spawn("bun", [...]) — Bun runtime invocation to evade Node.js monitoring/sandboxing.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect spawn/fork with {detached: true}
  if ((callName === 'spawn' || callName === 'fork') && node.arguments.length >= 2) {
    const lastArg = node.arguments[node.arguments.length - 1];
    if (lastArg.type === 'ObjectExpression') {
      const hasDetached = lastArg.properties.some(p =>
        p.key?.type === 'Identifier' && p.key.name === 'detached' &&
        p.value?.type === 'Literal' && p.value.value === true
      );
      if (hasDetached) {
        ctx.threats.push({
          type: 'detached_process',
          severity: 'HIGH',
          message: `${callName}() with {detached: true} — background process survives parent exit (evasion technique).`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect fs.writeFileSync/writeFile to .github/workflows
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const writeMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile'].includes(writeMethod) && node.arguments.length > 0) {
      const pathArg = node.arguments[0];
      const pathStr = extractStringValue(pathArg);
      let joinedPath = null;
      let hasWorkflowVar = false;
      if (pathArg?.type === 'CallExpression' && pathArg.arguments) {
        joinedPath = pathArg.arguments.map(a => {
          if (a.type === 'Identifier' && ctx.workflowPathVars.has(a.name)) {
            hasWorkflowVar = true;
            return '.github/workflows';
          }
          return extractStringValue(a) || '';
        }).join('/');
      }
      if (pathArg?.type === 'Identifier' && ctx.workflowPathVars.has(pathArg.name)) {
        hasWorkflowVar = true;
      }
      const checkPath = pathStr || joinedPath || '';
      if (hasWorkflowVar || /\.github[\\/]workflows/i.test(checkPath) || /\.github[\\/]actions/i.test(checkPath)) {
        ctx.threats.push({
          type: 'workflow_write',
          severity: 'CRITICAL',
          message: `${writeMethod}() writes to .github/workflows — GitHub Actions injection/persistence technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect writes to node_modules/ — worm propagation / package patching (Shai-Hulud 2.0)
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const nmWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile', 'appendFileSync'].includes(nmWriteMethod) && node.arguments.length >= 2) {
      const nmPathArg = node.arguments[0];
      let nmPathStr = extractStringValueDeep(nmPathArg);
      // Also resolve variable indirection
      if (!nmPathStr && nmPathArg?.type === 'Identifier' && ctx.stringVarValues?.has(nmPathArg.name)) {
        nmPathStr = ctx.stringVarValues.get(nmPathArg.name);
      }
      if (nmPathStr && /node_modules[/\\]/.test(nmPathStr)) {
        ctx.threats.push({
          type: 'node_modules_write',
          severity: 'CRITICAL',
          message: `${nmWriteMethod}() targeting node_modules/ path: "${nmPathStr.substring(0, 80)}" — package patching / worm propagation technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect writes to systemd service paths — persistence technique (CanisterWorm/TeamPCP T1543.002)
  // No legitimate npm package creates systemd services.
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const sdWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile', 'appendFileSync'].includes(sdWriteMethod) && node.arguments.length >= 2) {
      const sdPathArg = node.arguments[0];
      let sdPathStr = extractStringValueDeep(sdPathArg);
      if (!sdPathStr && sdPathArg?.type === 'Identifier' && ctx.stringVarValues?.has(sdPathArg.name)) {
        sdPathStr = ctx.stringVarValues.get(sdPathArg.name);
      }
      if (sdPathStr && (/systemd[/\\]/i.test(sdPathStr) || /\.service$/i.test(sdPathStr))) {
        ctx.threats.push({
          type: 'systemd_persistence',
          severity: 'CRITICAL',
          message: `${sdWriteMethod}() writes to systemd path: "${sdPathStr.substring(0, 80)}" — persistence technique (CanisterWorm/TeamPCP).`,
          file: ctx.relFile
        });
      }
      // Detect writes to .pth files — Python auto-exec persistence (LiteLLM/Checkmarx T1546.004)
      // .pth files in site-packages/ are executed automatically by the Python interpreter at startup.
      // No legitimate npm package creates .pth files.
      if (sdPathStr && /\.pth$/i.test(sdPathStr)) {
        ctx.threats.push({
          type: 'pth_persistence',
          severity: 'CRITICAL',
          message: `${sdWriteMethod}() writes to Python .pth file: "${sdPathStr.substring(0, 80)}" — auto-exec persistence technique (LiteLLM/Checkmarx).`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect fs.mkdirSync creating .github/workflows
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const mkdirMethod = node.callee.property.name;
    if ((mkdirMethod === 'mkdirSync' || mkdirMethod === 'mkdir') && node.arguments.length > 0) {
      const pathArg = node.arguments[0];
      if (pathArg?.type === 'Identifier' && ctx.workflowPathVars.has(pathArg.name)) {
        ctx.threats.push({
          type: 'workflow_write',
          severity: 'CRITICAL',
          message: `${mkdirMethod}() creates .github/workflows directory — GitHub Actions persistence technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect fs.readdirSync on .github/workflows
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const readDirMethod = node.callee.property.name;
    if ((readDirMethod === 'readdirSync' || readDirMethod === 'readdir') && node.arguments.length > 0) {
      const pathArg = node.arguments[0];
      if (pathArg?.type === 'Identifier' && ctx.workflowPathVars.has(pathArg.name)) {
        ctx.threats.push({
          type: 'workflow_write',
          severity: 'CRITICAL',
          message: `${readDirMethod}() enumerates .github/workflows — workflow modification/injection technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // SANDWORM_MODE R5: MCP config injection — writeFileSync to AI config paths
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const mcpWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile'].includes(mcpWriteMethod) && node.arguments.length >= 2) {
      const mcpPathArg = node.arguments[0];
      const mcpPathStr = extractStringValueDeep(mcpPathArg);
      // Also check path.join() calls — resolve concat fragments in each argument
      let mcpJoinedPath = '';
      if (mcpPathArg?.type === 'CallExpression' && mcpPathArg.arguments) {
        mcpJoinedPath = mcpPathArg.arguments.map(a => extractStringValueDeep(a) || '').join('/');
      }
      // Also check if path arg is a variable tracked as MCP/IDE config path
      let mcpVarPath = '';
      if (mcpPathArg?.type === 'Identifier' && ctx.ideConfigPathVars.has(mcpPathArg.name)) {
        mcpVarPath = ctx.ideConfigPathVars.get(mcpPathArg.name);
      }
      const mcpCheckPath = (mcpPathStr || mcpJoinedPath || mcpVarPath).toLowerCase();
      const isMcpPath = MCP_CONFIG_PATHS.some(p => mcpCheckPath.includes(p.toLowerCase()));
      if (isMcpPath) {
        // Check content argument for MCP-related patterns
        const contentArg = node.arguments[1];
        const contentStr = extractStringValue(contentArg);
        // Extract filename from path to distinguish sensitive config files from plugin state
        const mcpFileName = mcpCheckPath.split(/[/\\]/).filter(Boolean).pop() || '';
        const isUniqueSensitive = SENSITIVE_AI_CONFIG_FILES_UNIQUE.some(f => mcpFileName === f);
        // For generic names (settings.json), only sensitive at config dir root (1 level deep)
        // e.g. .claude/settings.json → sensitive, .claude/plugin/settings.json → not sensitive
        let isRootOnlySensitive = false;
        if (SENSITIVE_AI_CONFIG_FILES_ROOT_ONLY.some(f => mcpFileName === f)) {
          const matchedDir = MCP_CONFIG_PATHS.find(p => mcpCheckPath.includes(p.toLowerCase()));
          if (matchedDir) {
            const idx = mcpCheckPath.indexOf(matchedDir.toLowerCase());
            const afterDir = mcpCheckPath.slice(idx + matchedDir.length);
            // Direct child: no further path separators (e.g. "settings.json", not "sub/settings.json")
            isRootOnlySensitive = !afterDir.includes('/') && !afterDir.includes('\\');
          }
        }
        const isSensitiveConfigFile = isUniqueSensitive || isRootOnlySensitive;
        const hasContentPattern = contentStr
          ? MCP_CONTENT_PATTERNS.some(p => contentStr.includes(p.replace(/"/g, '')))
          : isSensitiveConfigFile; // dynamic content only suspicious for known config files
        if (hasContentPattern) {
          ctx.threats.push({
            type: 'mcp_config_injection',
            severity: 'CRITICAL',
            message: `MCP config injection: ${mcpWriteMethod}() writes to AI assistant configuration (${mcpCheckPath}). SANDWORM_MODE technique for AI toolchain poisoning.`,
            file: ctx.relFile
          });
        }
      }
    }
  }

  // SANDWORM_MODE R6: Git hooks injection — writeFileSync to .git/hooks/
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const gitWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile'].includes(gitWriteMethod) && node.arguments.length >= 1) {
      const gitPathArg = node.arguments[0];
      const gitPathStr = extractStringValueDeep(gitPathArg);
      let gitJoinedPath = '';
      if (gitPathArg?.type === 'CallExpression' && gitPathArg.arguments) {
        gitJoinedPath = gitPathArg.arguments.map(a => extractStringValueDeep(a) || '').join('/');
      }
      // Also check if path arg is a variable tracked as git hooks path
      let gitVarPath = '';
      if (gitPathArg?.type === 'Identifier' && ctx.gitHooksPathVars.has(gitPathArg.name)) {
        gitVarPath = ctx.gitHooksPathVars.get(gitPathArg.name);
      }
      const gitCheckPath = gitPathStr || gitJoinedPath || gitVarPath;
      if (/\.git[\\/]hooks[\\/]/i.test(gitCheckPath) ||
          GIT_HOOKS.some(h => gitCheckPath.includes(h) && (gitCheckPath.includes('.git') || gitCheckPath.includes('hooks')))) {
        ctx.threats.push({
          type: 'git_hooks_injection',
          severity: 'HIGH',
          message: `Git hook injection: ${gitWriteMethod}() writes to .git/hooks/. Persistence technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // SANDWORM_MODE R6: Git hooks injection via exec — git config --global init.templateDir or git config hooks
  if ((execName || memberExec) && node.arguments.length > 0) {
    const gitExecArg = node.arguments[0];
    const gitExecStr = extractStringValue(gitExecArg);
    if (gitExecStr) {
      if (/git\s+config\s+.*init\.templateDir/i.test(gitExecStr)) {
        ctx.threats.push({
          type: 'git_hooks_injection',
          severity: 'HIGH',
          message: 'Git hook injection: modifying global git template directory via "git config init.templateDir". Persistence technique.',
          file: ctx.relFile
        });
      } else if (/git\s+config\b/.test(gitExecStr) && /hooks/i.test(gitExecStr)) {
        ctx.threats.push({
          type: 'git_hooks_injection',
          severity: 'HIGH',
          message: 'Git hook injection: modifying git hooks configuration. Persistence technique.',
          file: ctx.relFile
        });
      }
    }
  }

  // Wave 4: IDE persistence — writeFileSync to VS Code tasks.json or Code/User/ paths
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const ideWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile'].includes(ideWriteMethod) && node.arguments.length >= 1) {
      const idePathArg = node.arguments[0];
      const idePathStr = extractStringValueDeep(idePathArg);
      let ideJoinedPath = '';
      if (idePathArg?.type === 'CallExpression' && idePathArg.arguments) {
        ideJoinedPath = idePathArg.arguments.map(a => extractStringValueDeep(a) || '').join('/');
      }
      let ideVarPath = '';
      if (idePathArg?.type === 'Identifier' && ctx.ideConfigPathVars.has(idePathArg.name)) {
        ideVarPath = ctx.ideConfigPathVars.get(idePathArg.name);
      }
      const ideCheckPath = (idePathStr || ideJoinedPath || ideVarPath).toLowerCase();
      if ((ideCheckPath.includes('tasks.json') || ideCheckPath.includes('code/user/') || ideCheckPath.includes('.vscode/')) &&
          !ctx.hasIdePersistenceWrite) {
        // Check content for task runner persistence patterns (runOn, folderOpen)
        const ideContentArg = node.arguments[1];
        const ideContentStr = extractStringValue(ideContentArg);
        const hasPersistencePattern = ideContentStr
          ? /runOn|folderOpen|reveal.*silent/.test(ideContentStr)
          : true; // dynamic content targeting IDE task paths = suspicious
        if (hasPersistencePattern) {
          ctx.hasIdePersistenceWrite = true;
          ctx.threats.push({
            type: 'ide_persistence',
            severity: 'HIGH',
            message: `IDE persistence: ${ideWriteMethod}() writes to IDE task configuration (${ideCheckPath}). Auto-execution on folder open.`,
            file: ctx.relFile
          });
        }
      }
    }
  }


  // Detect fs.chmodSync with executable permissions (deferred to postWalk for compound check)
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const chmodMethod = node.callee.property.name;
    if ((chmodMethod === 'chmodSync' || chmodMethod === 'chmod') && node.arguments.length >= 2) {
      const modeArg = node.arguments[1];
      if (modeArg?.type === 'Literal' && typeof modeArg.value === 'number') {
        // 0o755=493, 0o777=511, 0o700=448, 0o775=509
        if (modeArg.value === 493 || modeArg.value === 511 || modeArg.value === 448 || modeArg.value === 509) {
          ctx.hasChmodExecutable = true;
          ctx.chmodMessage = `${chmodMethod}() with executable permissions (0o${modeArg.value.toString(8)})`;
        }
      }
    }
  }

  // Detect AI agent weaponization
  if ((callName === 'spawn' || callName === 'exec' || callName === 'execSync' ||
       callName === 'execFile' || callName === 'execFileSync' || memberExec) &&
      node.arguments.length > 0) {
    const argStrings = [];
    for (const arg of node.arguments) {
      if (arg.type === 'Literal' && typeof arg.value === 'string') {
        argStrings.push(arg.value);
      } else if (arg.type === 'ArrayExpression') {
        for (const el of arg.elements) {
          if (el && el.type === 'Literal' && typeof el.value === 'string') {
            argStrings.push(el.value);
          }
        }
      }
    }

    const allArgText = argStrings.join(' ');
    const hasDangerousFlag = AI_AGENT_DANGEROUS_FLAGS.some(flag => allArgText.includes(flag));
    const firstArg = node.arguments[0];
    const cmdName = firstArg?.type === 'Literal' && typeof firstArg.value === 'string'
      ? firstArg.value.toLowerCase() : '';
    const cmdBasename = cmdName ? path.basename(cmdName) : '';
    const isAIAgent = AI_AGENT_BINARIES.some(bin => cmdBasename === bin);

    if (hasDangerousFlag) {
      const matchedFlag = AI_AGENT_DANGEROUS_FLAGS.find(flag => allArgText.includes(flag));
      ctx.threats.push({
        type: 'ai_agent_abuse',
        severity: 'CRITICAL',
        message: `AI agent invoked with security bypass flag "${matchedFlag}"${isAIAgent ? ` (agent: ${cmdName})` : ''} — weaponized AI coding assistant (s1ngularity/Nx pattern).`,
        file: ctx.relFile
      });
    } else if (isAIAgent) {
      ctx.threats.push({
        type: 'ai_agent_abuse',
        severity: 'HIGH',
        message: `AI coding agent "${cmdName}" invoked from package — potential AI agent weaponization.`,
        file: ctx.relFile
      });
    }
  }

  // Detect Object.defineProperty(process.env, ...) — env interception
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'Object' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'defineProperty' &&
      node.arguments.length >= 2) {
    const target = node.arguments[0];
    if (target.type === 'MemberExpression' &&
        target.object?.name === 'process' &&
        target.property?.name === 'env') {
      ctx.threats.push({
        type: 'env_proxy_intercept',
        severity: 'CRITICAL',
        message: 'Object.defineProperty(process.env) detected — intercepts environment variable access for credential theft.',
        file: ctx.relFile
      });
    }
  }

  // B1: Alias call — E('code') where E = eval or F = Function
  if (node.callee.type === 'Identifier' && ctx.evalAliases?.has(node.callee.name)) {
    const aliased = ctx.evalAliases.get(node.callee.name);
    if (aliased.endsWith('_factory')) {
      // Factory pattern: getEval()('code') — the callee is detected at outer CallExpression level
      // Mark the identifier so we can detect the outer call
    } else {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      // Audit v3: elevate to CRITICAL when argument contains dangerous API calls
      let aliasSev = 'HIGH';
      let aliasMsg = `Indirect ${aliased} via alias "${node.callee.name}" — eval wrapper evasion.`;
      if (node.arguments.length >= 1) {
        const aliasArg = node.arguments[0];
        if (aliasArg?.type === 'Literal' && typeof aliasArg.value === 'string' &&
            /\b(require|import|exec|execSync|spawn|child_process|process\.env)\b/.test(aliasArg.value)) {
          aliasSev = 'CRITICAL';
          aliasMsg = `Indirect ${aliased} via alias "${node.callee.name}" with dangerous payload: "${aliasArg.value.substring(0, 80)}" — eval evasion + code execution.`;
        }
      }
      ctx.threats.push({
        type: aliased === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
        severity: aliasSev,
        message: aliasMsg,
        file: ctx.relFile
      });
    }
  }

  // B1 fix: Factory call — getEval()('code') where getEval = () => eval
  if (node.callee.type === 'CallExpression' &&
      node.callee.callee?.type === 'Identifier' &&
      ctx.evalAliases?.has(node.callee.callee.name)) {
    const aliased = ctx.evalAliases.get(node.callee.callee.name);
    if (aliased.endsWith('_factory')) {
      const baseName = aliased.replace('_factory', '');
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: baseName === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
        severity: 'HIGH',
        message: `Indirect ${baseName} via factory function "${node.callee.callee.name}()" — eval factory evasion.`,
        file: ctx.relFile
      });
    }
  }

  // Audit v3 B3: Bare call to destructured _load — e.g. const { _load } = require('module'); _load('child_process')
  if (node.callee.type === 'Identifier' && ctx.moduleLoadDirectAliases?.has(node.callee.name)) {
    ctx.threats.push({
      type: 'module_load_bypass',
      severity: 'CRITICAL',
      message: `Module._load() via destructured alias "${node.callee.name}" — internal module loader bypass.`,
      file: ctx.relFile
    });
  }

  if (callName === 'eval') {
    ctx.hasEvalInFile = true;
    // Detect staged eval decode
    if (node.arguments.length === 1 && hasDecodeArg(node.arguments[0])) {
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'staged_eval_decode',
        severity: 'CRITICAL',
        message: 'eval() with decode argument (atob/Buffer.from base64) — staged payload execution.',
        file: ctx.relFile
      });
    } else {
      const isConstant = hasOnlyStringLiteralArgs(node);
      let severity = isConstant ? 'LOW' : 'HIGH';
      let message = isConstant
        ? 'eval() with constant string literal (low risk, globalThis polyfill pattern).'
        : 'Dangerous call "eval" with dynamic expression detected.';

      // Audit fix: even string-literal eval is dangerous if content contains dangerous APIs
      if (isConstant && node.arguments[0]?.value) {
        const val = node.arguments[0].value;
        if (/\b(require|import|exec|execSync|spawn|child_process|\.readFile|\.writeFile|process\.env|\.homedir)\b/.test(val)) {
          severity = 'HIGH';
          message = `eval() with dangerous API in string literal: "${val.substring(0, 100)}"`;
          ctx.hasDynamicExec = true;
        }
      }

      // Only set hasDynamicExec for non-constant (dynamic) eval
      if (!isConstant) {
        ctx.hasDynamicExec = true;
      }

      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity,
        message,
        file: ctx.relFile
      });
    }
  } else if (callName === 'Function') {
    ctx.hasDynamicExec = true;
    // Detect staged Function decode
    if (node.arguments.length >= 1 && hasDecodeArg(node.arguments[node.arguments.length - 1])) {
      ctx.threats.push({
        type: 'staged_eval_decode',
        severity: 'CRITICAL',
        message: 'Function() with decode argument (atob/Buffer.from base64) — staged payload execution.',
        file: ctx.relFile
      });
    } else if (!hasOnlyStringLiteralArgs(node)) {
      // Only flag dynamic Function() calls — string literal args (e.g. Function('return this'))
      // are zero-risk globalThis polyfills used by every bundler
      ctx.threats.push({
        type: 'dangerous_call_function',
        severity: 'MEDIUM',
        message: 'Function() with dynamic expression (template/factory pattern).',
        file: ctx.relFile
      });
    }
  }

  // Audit v3 B2: Split entropy detection — concatenated strings passed to eval/Function/decode
  // Detects payloads split across ≥3 chunks to bypass per-string entropy thresholds.
  if (callName === 'eval' || callName === 'Function' || callName === 'atob') {
    // Threshold lower than standard (5.5) because the triple signal
    // (concat ≥3 + eval/decode + entropy) provides high confidence at 4.5.
    const SPLIT_ENTROPY_THRESHOLD = 4.5;
    const SPLIT_ENTROPY_MIN_OPERANDS = 3;
    for (const arg of node.arguments) {
      // Direct concat: eval('ch1' + 'ch2' + 'ch3')
      if (arg.type === 'BinaryExpression' && arg.operator === '+') {
        const operands = countConcatOperands(arg);
        if (operands >= SPLIT_ENTROPY_MIN_OPERANDS) {
          const resolved = resolveStringConcatWithVars(arg, ctx.stringVarValues);
          if (resolved && resolved.length >= 20 && calculateShannonEntropy(resolved) > SPLIT_ENTROPY_THRESHOLD) {
            ctx.threats.push({
              type: 'split_entropy_payload',
              severity: 'CRITICAL',
              message: `Split high-entropy string (${operands} chunks, ${calculateShannonEntropy(resolved).toFixed(2)} bits) passed to ${callName}() — payload fragmentation evasion.`,
              file: ctx.relFile
            });
            break;
          }
        }
      }
      // Variable indirection: eval(payload) where payload was built from concat
      if (arg.type === 'Identifier' && ctx.concatValues?.has(arg.name)) {
        const cv = ctx.concatValues.get(arg.name);
        if (calculateShannonEntropy(cv.value) > SPLIT_ENTROPY_THRESHOLD) {
          ctx.threats.push({
            type: 'split_entropy_payload',
            severity: 'CRITICAL',
            message: `Split high-entropy variable "${arg.name}" (${cv.operands} chunks, ${calculateShannonEntropy(cv.value).toFixed(2)} bits) passed to ${callName}() — payload fragmentation evasion.`,
            file: ctx.relFile
          });
          break;
        }
      }
    }
  }

  // Also check Buffer.from arguments for split entropy (decode context)
  if (node.callee?.type === 'MemberExpression' &&
      node.callee.object?.name === 'Buffer' && node.callee.property?.name === 'from') {
    const SPLIT_ENTROPY_THRESHOLD = 4.5;
    const arg = node.arguments?.[0];
    if (arg?.type === 'BinaryExpression' && arg.operator === '+') {
      const operands = countConcatOperands(arg);
      if (operands >= 3) {
        const resolved = resolveStringConcatWithVars(arg, ctx.stringVarValues);
        if (resolved && resolved.length >= 20 && calculateShannonEntropy(resolved) > SPLIT_ENTROPY_THRESHOLD) {
          ctx.threats.push({
            type: 'split_entropy_payload',
            severity: 'CRITICAL',
            message: `Split high-entropy string (${operands} chunks, ${calculateShannonEntropy(resolved).toFixed(2)} bits) in Buffer.from() — payload fragmentation evasion.`,
            file: ctx.relFile
          });
        }
      }
    }
    if (arg?.type === 'Identifier' && ctx.concatValues?.has(arg.name)) {
      const cv = ctx.concatValues.get(arg.name);
      if (calculateShannonEntropy(cv.value) > SPLIT_ENTROPY_THRESHOLD) {
        ctx.threats.push({
          type: 'split_entropy_payload',
          severity: 'CRITICAL',
          message: `Split high-entropy variable "${arg.name}" (${cv.operands} chunks, ${calculateShannonEntropy(cv.value).toFixed(2)} bits) in Buffer.from() — payload fragmentation evasion.`,
          file: ctx.relFile
        });
      }
    }
  }

  // setTimeout/setInterval with string argument = eval equivalent
  // setTimeout("require('child_process').exec('whoami')", 100) executes the string as code
  // Only string Literal and TemplateLiteral are eval-equivalent; Identifier/MemberExpression
  // are function references (callbacks), not code strings.
  if ((callName === 'setTimeout' || callName === 'setInterval') && node.arguments.length >= 1) {
    const firstArg = node.arguments[0];
    if ((firstArg.type === 'Literal' && typeof firstArg.value === 'string') ||
        firstArg.type === 'TemplateLiteral') {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      // Audit v3: elevate to CRITICAL when string contains dangerous API calls
      let timerSeverity = 'HIGH';
      let timerMsg = `${callName}() with string argument — eval equivalent, executes the string as code.`;
      if (firstArg.type === 'Literal' && typeof firstArg.value === 'string') {
        if (/\b(require|import|exec|execSync|spawn|child_process|\.readFile|\.writeFile|process\.env|\.homedir)\b/.test(firstArg.value)) {
          timerSeverity = 'CRITICAL';
          timerMsg = `${callName}() with dangerous API in string: "${firstArg.value.substring(0, 80)}" — eval equivalent code execution.`;
        }
      }
      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity: timerSeverity,
        message: timerMsg,
        file: ctx.relFile
      });
    }
    // BinaryExpression with '+' as first arg = string concatenation for eval via timer
    else if (firstArg.type === 'BinaryExpression' && firstArg.operator === '+') {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity: 'HIGH',
        message: `${callName}() with concatenated string argument — eval equivalent, dynamically built code string.`,
        file: ctx.relFile
      });
    }
    // Identifier arg that was tracked as string value or string concatenation result
    else if (firstArg.type === 'Identifier' &&
             (ctx.stringVarValues?.has(firstArg.name) || ctx.stringBuildVars?.has(firstArg.name))) {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'dangerous_call_eval',
        severity: 'HIGH',
        message: `${callName}() with variable "${firstArg.name}" containing built string — eval equivalent, executes the string as code.`,
        file: ctx.relFile
      });
    }

    // Static timer bomb: setTimeout/setInterval with delay > 1 hour (PhantomRaven 48h delay)
    if (node.arguments.length >= 2) {
      const delayArg = node.arguments[1];
      let delayMs = null;
      if (delayArg.type === 'Literal' && typeof delayArg.value === 'number') {
        delayMs = delayArg.value;
      }
      if (delayMs !== null && delayMs > 3600000) { // > 1 hour
        const hours = (delayMs / 3600000).toFixed(1);
        ctx.threats.push({
          type: 'static_timer_bomb',
          severity: delayMs > 86400000 ? 'HIGH' : 'MEDIUM', // > 24h = HIGH
          message: `${callName}() with ${hours}h delay (${delayMs}ms) — time-bomb evasion: payload activates long after install.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect eval.call(null, code) / eval.apply(null, [code]) / Function.call/apply
  if (node.callee.type === 'MemberExpression' && !node.callee.computed &&
      node.callee.property?.type === 'Identifier' &&
      (node.callee.property.name === 'call' || node.callee.property.name === 'apply')) {
    const obj = node.callee.object;
    if (obj?.type === 'Identifier' && (obj.name === 'eval' || obj.name === 'Function')) {
      ctx.hasEvalInFile = true;
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: obj.name === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
        severity: 'HIGH',
        message: `${obj.name}.${node.callee.property.name}() — indirect execution via call/apply evasion technique.`,
        file: ctx.relFile
      });
    }
    // B2 fix: Function.prototype.call.call(eval, null, code) / X.call.call(eval, ...)
    // Deep MemberExpression: obj is itself a MemberExpression ending in .call/.apply
    if (obj?.type === 'MemberExpression' &&
        obj.property?.type === 'Identifier' &&
        (obj.property.name === 'call' || obj.property.name === 'apply') &&
        node.arguments.length >= 2) {
      const firstArg = node.arguments[0];
      if (firstArg?.type === 'Identifier' && (firstArg.name === 'eval' || firstArg.name === 'Function')) {
        ctx.hasEvalInFile = true;
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: firstArg.name === 'eval' ? 'dangerous_call_eval' : 'dangerous_call_function',
          severity: 'HIGH',
          message: `${firstArg.name} passed to .call.call() — nested call/apply evasion technique.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect array access pattern: [require][0]('child_process') or [eval][0](code)
  if (node.callee.type === 'MemberExpression' && node.callee.computed &&
      node.callee.object?.type === 'ArrayExpression' &&
      node.callee.property?.type === 'Literal' && typeof node.callee.property.value === 'number') {
    const elements = node.callee.object.elements;
    for (const el of elements) {
      if (el?.type === 'Identifier') {
        if (el.name === 'eval') {
          ctx.hasEvalInFile = true;
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'dangerous_call_eval',
            severity: 'HIGH',
            message: '[eval][0]() — array access evasion technique for indirect eval execution.',
            file: ctx.relFile
          });
        } else if (el.name === 'require') {
          ctx.threats.push({
            type: 'dynamic_require',
            severity: 'HIGH',
            message: '[require][0]() — array access evasion technique for indirect require.',
            file: ctx.relFile
          });
        } else if (el.name === 'Function') {
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'dangerous_call_function',
            severity: 'MEDIUM',
            message: '[Function][0]() — array access evasion technique for indirect Function construction.',
            file: ctx.relFile
          });
        }
      }
    }
  }

  // Detect new Proxy(require, handler) — proxy wrapping require to intercept module loading
  if (node.callee.type === 'Identifier' && node.callee.name !== 'Proxy') {
    // handled below in handleNewExpression
  }

  // Detect template literals in exec/execSync: execSync(`${cmd}`)
  if ((execName || memberExec) && node.arguments.length > 0) {
    const arg = node.arguments[0];
    if (arg.type === 'TemplateLiteral' && arg.expressions.length > 0) {
      // Template literal with dynamic expressions in exec — bypass for string matching
      const staticParts = arg.quasis.map(q => q.value.raw).join('');
      if (DANGEROUS_CMD_PATTERNS.some(p => p.test(staticParts))) {
        ctx.threats.push({
          type: 'dangerous_exec',
          severity: 'CRITICAL',
          message: `Dangerous command in template literal exec(): "${staticParts.substring(0, 80)}" — template literal evasion.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Detect indirect eval/Function via computed property
  if (node.callee.type === 'MemberExpression' && node.callee.computed) {
    const prop = node.callee.property;
    if (prop.type === 'Literal' && typeof prop.value === 'string') {
      if (prop.value === 'eval') {
        ctx.hasEvalInFile = true;
        ctx.threats.push({
          type: 'dangerous_call_eval',
          severity: 'HIGH',
          message: 'Indirect eval via computed property access (obj["eval"]) — evasion technique.',
          file: ctx.relFile
        });
      } else if (prop.value === 'Function') {
        ctx.threats.push({
          type: 'dangerous_call_function',
          severity: 'MEDIUM',
          message: 'Indirect Function via computed property access (obj["Function"]) — evasion technique.',
          file: ctx.relFile
        });
      }
    }
    // Detect computed call on globalThis/global alias with variable or expression property
    const obj = node.callee.object;
    if (obj?.type === 'Identifier' &&
        (ctx.globalThisAliases.has(obj.name) || obj.name === 'globalThis' || obj.name === 'global')) {
      if (prop.type === 'Identifier') {
        ctx.hasEvalInFile = true;
        // Resolve variable value via stringVarValues (e.g., const f = 'eval'; globalThis[f]())
        const resolvedValue = ctx.stringVarValues.get(prop.name);
        const isEvalOrFunction = resolvedValue === 'eval' || resolvedValue === 'Function';
        ctx.threats.push({
          type: 'dangerous_call_eval',
          severity: isEvalOrFunction ? 'CRITICAL' : 'HIGH',
          message: isEvalOrFunction
            ? `Resolved indirect ${resolvedValue}() via computed property (${obj.name}[${prop.name}="${resolvedValue}"]) — confirmed eval evasion.`
            : `Dynamic global dispatch via computed property (${obj.name}[${prop.name}]) — likely indirect eval evasion.`,
          file: ctx.relFile
        });
      } else {
        // BinaryExpression, TemplateLiteral, or other computed expression
        // Try to resolve via stringVarValues (e.g., var a='ev',b='al'; globalThis[a+b]())
        const resolvedProp = resolveStringConcatWithVars(prop, ctx.stringVarValues);
        if (resolvedProp === 'eval' || resolvedProp === 'Function') {
          ctx.hasEvalInFile = true;
          ctx.threats.push({
            type: 'dangerous_call_eval',
            severity: 'CRITICAL',
            message: `Resolved indirect ${resolvedProp}() via computed expression (${obj.name}[...="${resolvedProp}"]) — concat evasion.`,
            file: ctx.relFile
          });
        } else if (resolvedProp !== null) {
          ctx.hasEvalInFile = true;
          ctx.threats.push({
            type: 'dangerous_call_eval',
            severity: 'HIGH',
            message: `Dynamic global dispatch via computed expression (${obj.name}[...="${resolvedProp}"]).`,
            file: ctx.relFile
          });
        }
      }
    }
  }

  // Detect indirect eval/Function via sequence expression
  if (node.callee.type === 'SequenceExpression') {
    const exprs = node.callee.expressions;
    const last = exprs[exprs.length - 1];
    if (last && last.type === 'Identifier') {
      if (last.name === 'eval') {
        ctx.hasEvalInFile = true;
        ctx.threats.push({
          type: 'dangerous_call_eval',
          severity: 'HIGH',
          message: 'Indirect eval via sequence expression ((0, eval)) — evasion technique.',
          file: ctx.relFile
        });
      } else if (last.name === 'Function') {
        ctx.threats.push({
          type: 'dangerous_call_function',
          severity: 'MEDIUM',
          message: 'Indirect Function via sequence expression ((0, Function)) — evasion technique.',
          file: ctx.relFile
        });
      }
    }
  }

  // Batch 2: Detect indirect eval/Function via logical expression: (false || eval)(code), (0 || Function)(code)
  if (node.callee.type === 'LogicalExpression' && node.callee.operator === '||') {
    const right = node.callee.right;
    if (right?.type === 'Identifier') {
      if (right.name === 'eval') {
        ctx.hasEvalInFile = true;
        ctx.threats.push({
          type: 'dangerous_call_eval',
          severity: 'HIGH',
          message: 'Indirect eval via logical expression ((false || eval)) — evasion technique.',
          file: ctx.relFile
        });
      } else if (right.name === 'Function') {
        ctx.threats.push({
          type: 'dangerous_call_function',
          severity: 'MEDIUM',
          message: 'Indirect Function via logical expression ((false || Function)) — evasion technique.',
          file: ctx.relFile
        });
      }
    }
  }

  // Detect crypto.createDecipher/createDecipheriv and module._compile
  if (node.callee.type === 'MemberExpression') {
    const prop = node.callee.property;
    const propName = prop.type === 'Identifier' ? prop.name :
                     (prop.type === 'Literal' ? prop.value : null);
    if (propName === 'createDecipher' || propName === 'createDecipheriv') {
      ctx.threats.push({
        type: 'crypto_decipher',
        severity: 'HIGH',
        message: `${propName}() detected — runtime decryption of embedded payload (event-stream/flatmap-stream pattern).`,
        file: ctx.relFile
      });
    }
    if (propName === '_compile') {
      // Context-aware gating: only flag _compile when the Module API is plausibly in scope.
      // Custom class methods (e.g. blessed's Tput.prototype._compile) are not malware.
      const calleeObj = node.callee.object;
      const isThisCall = calleeObj.type === 'ThisExpression';
      const isModuleIdentifier = calleeObj.type === 'Identifier' &&
        (calleeObj.name === 'module' || calleeObj.name === 'Module' || calleeObj.name === 'm');
      const isConstructed = calleeObj.type === 'NewExpression' || calleeObj.type === 'CallExpression';
      const isMemberChain = calleeObj.type === 'MemberExpression';
      // Skip: this._compile() is always a custom instance method, not Node Module API
      // Detect: module/Module/m identifier, new X()._compile(), X()._compile(), X.Y._compile()
      // Other identifiers: only if require('module') or module.constructor is in file
      const shouldDetect = !isThisCall && (
        isModuleIdentifier || isConstructed || isMemberChain ||
        (calleeObj.type === 'Identifier' && ctx.hasModuleImport)
      );
      if (shouldDetect) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'module_compile',
          // P6: Baseline HIGH — single module._compile() in build tools (@babel/core, art-template)
          // is framework behavior. Compound detections (zlib_inflate_eval, fetch_decrypt_exec) stay CRITICAL.
          severity: 'HIGH',
          message: 'module._compile() detected — executes arbitrary code from string in module context (flatmap-stream pattern).',
          file: ctx.relFile
        });
        // SANDWORM_MODE: Module._compile with non-literal argument = dynamic code execution
        if (node.arguments.length >= 1 && !hasOnlyStringLiteralArgs(node)) {
          ctx.threats.push({
            type: 'module_compile_dynamic',
            severity: 'HIGH',
            message: 'In-memory code execution via Module._compile(). Common malware evasion technique.',
            file: ctx.relFile
          });
        }
        // Module._compile counts as temp file exec for write-execute-delete pattern
        ctx.hasTempFileExec = ctx.hasTempFileExec || ctx.hasDevShmInContent;
      }
    }

    // Module._load() — internal module loader bypass (security audit v2)
    if (propName === '_load') {
      const calleeObj = node.callee.object;
      const isModuleIdentifier = calleeObj.type === 'Identifier' &&
        (calleeObj.name === 'Module' || calleeObj.name === 'module' ||
         (ctx.moduleAliases && ctx.moduleAliases.has(calleeObj.name)));
      const isMemberChain = calleeObj.type === 'MemberExpression';
      const isConstructed = calleeObj.type === 'NewExpression' || calleeObj.type === 'CallExpression';
      if (isModuleIdentifier || isMemberChain || isConstructed || ctx.hasModuleImport) {
        ctx.threats.push({
          type: 'module_load_bypass',
          severity: 'CRITICAL',
          message: 'Module._load() detected — internal module loader bypass for dynamic code loading.',
          file: ctx.relFile
        });
      }
    }

    // Audit v3 B3: AsyncFunction/GeneratorFunction constructor via prototype chain
    // Pattern: Object.getPrototypeOf(async function(){}).constructor('code')()
    // or: Reflect.getPrototypeOf(function*(){}).constructor('code')()
    if (propName === 'constructor') {
      const obj = node.callee.object;
      if (obj?.type === 'CallExpression' && obj.callee?.type === 'MemberExpression') {
        const innerObj = obj.callee.object;
        const innerProp = obj.callee.property;
        if (innerObj?.type === 'Identifier' &&
            (innerObj.name === 'Object' || innerObj.name === 'Reflect') &&
            innerProp?.type === 'Identifier' && innerProp.name === 'getPrototypeOf' &&
            obj.arguments?.length >= 1) {
          const arg = obj.arguments[0];
          if (arg.type === 'FunctionExpression' && (arg.async || arg.generator)) {
            const kind = arg.async ? 'AsyncFunction' : 'GeneratorFunction';
            ctx.hasEvalInFile = true;
            ctx.hasDynamicExec = true;
            ctx.threats.push({
              type: 'dangerous_constructor',
              severity: 'CRITICAL',
              message: `${kind} constructor accessed via Object.getPrototypeOf() — prototype chain code execution bypass.`,
              file: ctx.relFile
            });
          }
        }
      }

      // Audit v3 bypass fix: .constructor.constructor('code')() — double constructor chain
      // Any expression.constructor.constructor is traversing to Function constructor
      if (obj?.type === 'MemberExpression') {
        const innerPropName = obj.computed
          ? (obj.property?.type === 'Literal' ? String(obj.property.value) : null)
          : (obj.property?.type === 'Identifier' ? obj.property.name : null);
        if (innerPropName === 'constructor') {
          ctx.hasEvalInFile = true;
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'dangerous_constructor',
            severity: 'CRITICAL',
            message: 'Constructor chain traversal: .constructor.constructor() — accesses Function constructor via prototype chain.',
            file: ctx.relFile
          });
        }
      }

      // B3: (function(){}).constructor('code')() — direct prototype chain Function access
      // Also: [].constructor.constructor, ''.constructor.constructor, (0).constructor.constructor
      if (obj?.type === 'FunctionExpression' || obj?.type === 'ArrowFunctionExpression' ||
          obj?.type === 'ArrayExpression' || obj?.type === 'Literal') {
        if (!hasOnlyStringLiteralArgs(node)) {
          ctx.hasEvalInFile = true;
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'function_prototype_constructor',
            severity: 'CRITICAL',
            message: `Function constructor via prototype chain: (${obj.type === 'FunctionExpression' ? 'function(){}' : obj.type === 'ArrayExpression' ? '[]' : 'literal'}).constructor(code) — bypasses Function/eval detection.`,
            file: ctx.relFile
          });
        }
      }
    }

    // SANDWORM_MODE: Track writeFileSync/writeFile to temp paths
    if (propName === 'writeFileSync' || propName === 'writeFile') {
      const arg = node.arguments && node.arguments[0];
      if (arg) {
        const strVal = extractStringValue(arg);
        if (strVal && /\/dev\/shm\b/.test(strVal)) {
          ctx.hasTempFileWrite = true;
        }
        // Variable reference to /dev/shm path
        if (!strVal && (arg.type === 'Identifier' || arg.type === 'CallExpression' || arg.type === 'MemberExpression')) {
          // Dynamic path — check if file content involves /dev/shm
          ctx.hasTempFileWrite = ctx.hasTempFileWrite || ctx.hasDevShmInContent;
        }
      }
    }

    // SANDWORM_MODE: Track unlinkSync/rmSync (file deletion)
    if (propName === 'unlinkSync' || propName === 'unlink' || propName === 'rmSync') {
      ctx.hasFileDelete = true;
    }
  }

  // SANDWORM_MODE: Track require() of temp path (execution of temp file)
  if (callName === 'require' && node.arguments.length > 0) {
    const arg = node.arguments[0];
    const strVal = extractStringValue(arg);
    if (strVal && /\/dev\/shm\b/.test(strVal)) {
      ctx.hasTempFileExec = true;
    } else if (!strVal && ctx.hasDevShmInContent) {
      // Variable argument in a file that references /dev/shm
      ctx.hasTempFileExec = true;
    }
  }

  // SANDWORM_MODE R7: Detect Object.entries/keys/values(process.env)
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'Object' &&
      node.callee.property?.type === 'Identifier' &&
      ['entries', 'keys', 'values'].includes(node.callee.property.name) &&
      node.arguments.length >= 1) {
    const enumArg = node.arguments[0];
    // Check if argument is process.env
    if (enumArg.type === 'MemberExpression' &&
        enumArg.object?.type === 'Identifier' && enumArg.object.name === 'process' &&
        enumArg.property?.type === 'Identifier' && enumArg.property.name === 'env') {
      ctx.hasEnvEnumeration = true;
    }
  }

  // Audit v3: JSON.stringify(process.env) — bulk env serialization = env enumeration
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'JSON' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'stringify' &&
      node.arguments.length >= 1) {
    const strArg = node.arguments[0];
    if (strArg.type === 'MemberExpression' &&
        strArg.object?.type === 'Identifier' && strArg.object.name === 'process' &&
        strArg.property?.type === 'Identifier' && strArg.property.name === 'env') {
      ctx.hasEnvEnumeration = true;
    }
  }

  // Batch 1: vm.* code execution — vm.runInThisContext, vm.runInNewContext, vm.compileFunction, vm.Script
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const vmMethod = node.callee.property.name;
    if (['runInThisContext', 'runInNewContext', 'compileFunction'].includes(vmMethod)) {
      // Audit v3: elevate to CRITICAL when argument contains dangerous API calls
      let vmSeverity = 'HIGH';
      let vmMsg = `vm.${vmMethod}() — dynamic code execution via Node.js vm module bypasses eval detection.`;
      const vmArg = node.arguments?.[0];
      let vmContent = '';
      if (vmArg?.type === 'Literal' && typeof vmArg.value === 'string') {
        vmContent = vmArg.value;
      } else if (vmArg?.type === 'Identifier' && ctx.stringVarValues?.has(vmArg.name)) {
        vmContent = ctx.stringVarValues.get(vmArg.name);
      }
      if (/\b(require|import|exec|execSync|spawn|child_process|process\.env)\b/.test(vmContent)) {
        vmSeverity = 'CRITICAL';
        ctx.hasDynamicExec = true;
        vmMsg = `vm.${vmMethod}() with dangerous API in code: "${vmContent.substring(0, 80)}" — vm module code execution bypass.`;
      }
      // NOTE: Do NOT set ctx.hasDynamicExec for generic vm.* calls — legitimately used by bundlers
      // (webpack, jest, etc.) and must not trigger compound detections (zlib_inflate_eval,
      // fetch_decrypt_exec) which were designed for eval/Function patterns.
      ctx.threats.push({
        type: 'vm_code_execution',
        severity: vmSeverity,
        message: vmMsg,
        file: ctx.relFile
      });
    }
  }

  // Batch 1: Reflect.construct(Function, [...]) / Reflect.apply(eval, null, [...])
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'Reflect' &&
      node.callee.property?.type === 'Identifier') {
    const reflectMethod = node.callee.property.name;
    if (reflectMethod === 'construct' && node.arguments.length >= 2) {
      const target = node.arguments[0];
      if (target.type === 'Identifier' && target.name === 'Function') {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'reflect_code_execution',
          severity: 'CRITICAL',
          message: 'Reflect.construct(Function, [...]) — indirect Function construction bypasses new Function() detection.',
          file: ctx.relFile
        });
      }
    } else if (reflectMethod === 'apply' && node.arguments.length >= 3) {
      const target = node.arguments[0];
      if (target.type === 'Identifier' && (target.name === 'eval' || target.name === 'Function')) {
        ctx.hasDynamicExec = true;
        ctx.threats.push({
          type: 'reflect_code_execution',
          severity: 'CRITICAL',
          message: `Reflect.apply(${target.name}, ...) — indirect ${target.name} invocation bypasses direct call detection.`,
          file: ctx.relFile
        });
      }
      // Bypass fix: Reflect.apply(Function.prototype.bind/call/apply, Function, [...])
      if (target.type === 'MemberExpression') {
        const methodProp = target.property;
        const methodName = methodProp?.type === 'Identifier' ? methodProp.name :
                           (methodProp?.type === 'Literal' ? String(methodProp.value) : null);
        if (methodName === 'bind' || methodName === 'call' || methodName === 'apply') {
          const thisArg = node.arguments[1];
          if (thisArg?.type === 'Identifier' &&
              (thisArg.name === 'Function' || thisArg.name === 'eval' ||
               ctx.evalAliases?.has(thisArg.name))) {
            ctx.hasDynamicExec = true;
            ctx.threats.push({
              type: 'reflect_bind_code_execution',
              severity: 'CRITICAL',
              message: `Reflect.apply(*.${methodName}, ${thisArg.name}, [...]) — indirect ${thisArg.name} invocation via prototype method, bypasses Reflect.apply(${thisArg.name}) detection.`,
              file: ctx.relFile
            });
          }
        }
      }
      // B1: Reflect.apply(require, null, ['child_process']) — bypasses require() call detection
      if (target.type === 'Identifier' && target.name === 'require') {
        const argsArray = node.arguments[2];
        let modName = null;
        if (argsArray?.type === 'ArrayExpression' && argsArray.elements.length > 0) {
          modName = extractStringValueDeep(argsArray.elements[0]);
        }
        const severity = modName && ['child_process', 'fs', 'net', 'dns', 'http', 'https'].includes(modName)
          ? 'CRITICAL' : 'HIGH';
        ctx.threats.push({
          type: 'reflect_apply_require',
          severity,
          message: `Reflect.apply(require, null, [${modName ? "'" + modName + "'" : '...'}]) — indirect require() bypasses static call detection.`,
          file: ctx.relFile
        });
      }
    }
  }

  // B4: __defineGetter__ / __defineSetter__ — prototype pollution via legacy API
  if (node.callee.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' &&
      (node.callee.property.name === '__defineGetter__' || node.callee.property.name === '__defineSetter__')) {
    ctx.threats.push({
      type: 'prototype_pollution',
      severity: 'HIGH',
      message: `${node.callee.property.name}() called — legacy prototype pollution API can hijack property access on any object.`,
      file: ctx.relFile
    });
  }

  // Batch 1: process.binding('spawn_sync'/'fs') / process._linkedBinding(...)
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'process' &&
      node.callee.property?.type === 'Identifier' &&
      (node.callee.property.name === 'binding' || node.callee.property.name === '_linkedBinding') &&
      node.arguments.length >= 1) {
    const bindArg = node.arguments[0];
    const bindStr = bindArg?.type === 'Literal' && typeof bindArg.value === 'string' ? bindArg.value : null;
    const dangerousBindings = ['spawn_sync', 'fs', 'pipe_wrap', 'tcp_wrap', 'tls_wrap', 'udp_wrap', 'process_wrap'];
    if (bindStr && dangerousBindings.includes(bindStr)) {
      ctx.threats.push({
        type: 'process_binding_abuse',
        severity: 'CRITICAL',
        message: `process.${node.callee.property.name}('${bindStr}') — direct V8 binding access bypasses child_process/fs module detection.`,
        file: ctx.relFile
      });
    } else if (!bindStr) {
      // Dynamic binding argument — suspicious
      ctx.threats.push({
        type: 'process_binding_abuse',
        severity: 'HIGH',
        message: `process.${node.callee.property.name}() with dynamic argument — potential V8 binding abuse.`,
        file: ctx.relFile
      });
    }
  }

  // Blue Team v8: process.dlopen() — direct native module loading bypass
  if (node.callee.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'process' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'dlopen' &&
      node.arguments.length >= 1) {
    ctx.threats.push({
      type: 'process_binding_abuse',
      severity: 'CRITICAL',
      message: 'process.dlopen() — direct native module loading bypasses require() and all module system checks.',
      file: ctx.relFile
    });
  }

  // Blue Team v8: dgram.createSocket() / socket.send() — UDP exfiltration tracking
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const dgramMethod = node.callee.property.name;
    if (dgramMethod === 'createSocket' && ctx.hasDgramImport) {
      ctx.hasDgramSend = true; // createSocket implies intent to use UDP
    }
    if (dgramMethod === 'send' && ctx.hasDgramImport) {
      ctx.hasDgramSend = true;
    }
  }

  // Blue Team v8: Crontab/cron write detection — fs.writeFileSync to cron paths
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const cronWriteMethod = node.callee.property.name;
    if (['writeFileSync', 'writeFile', 'appendFileSync'].includes(cronWriteMethod) && node.arguments.length >= 1) {
      const cronPathArg = node.arguments[0];
      let cronPathStr = extractStringValueDeep(cronPathArg);
      if (!cronPathStr && cronPathArg?.type === 'Identifier' && ctx.stringVarValues?.has(cronPathArg.name)) {
        cronPathStr = ctx.stringVarValues.get(cronPathArg.name);
      }
      if (cronPathStr && (/\/etc\/cron/i.test(cronPathStr) || /crontab/i.test(cronPathStr) ||
          /\/var\/spool\/cron/i.test(cronPathStr))) {
        ctx.hasCrontabWrite = true;
        ctx.threats.push({
          type: 'crontab_systemd_write',
          severity: 'CRITICAL',
          message: `${cronWriteMethod}() writes to cron path: "${cronPathStr.substring(0, 80)}" — scheduled task persistence.`,
          file: ctx.relFile
        });
      }
    }
  }

  // Blue Team v8: .replace() chain detection — 3+ chained .replace() calls for string mutation obfuscation
  // Pattern: 'l33t'.replace(/3/g, 'e').replace(/1/g, 'i') to reconstruct dangerous strings
  if (node.callee.type === 'MemberExpression' && node.callee.property?.type === 'Identifier' &&
      node.callee.property.name === 'replace' && node.arguments.length >= 2) {
    // Walk up the chain to count .replace() depth and try to resolve
    let depth = 1;
    let baseNode = node.callee.object;
    while (baseNode?.type === 'CallExpression' &&
           baseNode.callee?.type === 'MemberExpression' &&
           baseNode.callee.property?.type === 'Identifier' &&
           baseNode.callee.property.name === 'replace' &&
           baseNode.arguments?.length >= 2) {
      depth++;
      baseNode = baseNode.callee.object;
    }
    if (depth >= 3) {
      // Try to statically resolve the chain
      let resolved = null;
      if (baseNode?.type === 'Literal' && typeof baseNode.value === 'string') {
        resolved = baseNode.value;
      } else if (baseNode?.type === 'Identifier' && ctx.stringVarValues?.has(baseNode.name)) {
        resolved = ctx.stringVarValues.get(baseNode.name);
      }
      if (resolved !== null) {
        // Apply each .replace() in order (walk the chain from inner to outer)
        const replaceCalls = [];
        let currentNode = node;
        while (currentNode?.type === 'CallExpression' &&
               currentNode.callee?.type === 'MemberExpression' &&
               currentNode.callee.property?.name === 'replace') {
          replaceCalls.unshift(currentNode.arguments);
          currentNode = currentNode.callee.object;
        }
        for (const args of replaceCalls) {
          if (args.length >= 2) {
            let pattern = null;
            let replacement = null;
            // Extract regex or string pattern
            if (args[0].type === 'Literal' && args[0].regex) {
              try { pattern = new RegExp(args[0].regex.pattern, args[0].regex.flags); } catch { /* skip */ }
            } else if (args[0].type === 'Literal' && typeof args[0].value === 'string') {
              pattern = args[0].value;
            }
            if (args[1].type === 'Literal' && typeof args[1].value === 'string') {
              replacement = args[1].value;
            }
            if (pattern !== null && replacement !== null) {
              resolved = resolved.replace(pattern, replacement);
            } else {
              resolved = null;
              break;
            }
          }
        }
      }
      const DANGEROUS_REPLACE_KEYWORDS = /\b(child_process|eval|exec|spawn|Function|http|net|dns|require|process)\b/;
      if (resolved && DANGEROUS_REPLACE_KEYWORDS.test(resolved)) {
        ctx.threats.push({
          type: 'string_mutation_obfuscation',
          severity: 'HIGH',
          message: `String mutation via ${depth} chained .replace() calls resolves to "${resolved.substring(0, 80)}" — leet-speak/substitution evasion.`,
          file: ctx.relFile
        });
      } else if (depth >= 4) {
        // 4+ replace chains without resolution is still suspicious
        ctx.threats.push({
          type: 'string_mutation_obfuscation',
          severity: 'MEDIUM',
          message: `${depth} chained .replace() calls detected — potential string mutation obfuscation (could not fully resolve).`,
          file: ctx.relFile
        });
      }
    }
  }

  // Blue Team v8b (A1): X.apply(require, null, [...]) — indirect require via Reflect.apply
  // Detect Reflect.apply(require, ...) or anyVar.apply(require, ...) pattern
  // This is an evasion where the attacker uses reflection to invoke require dynamically
  if (node.callee?.type === 'MemberExpression' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'apply' &&
      node.arguments.length >= 2) {
    const firstArg = node.arguments[0];
    if (firstArg?.type === 'Identifier' && firstArg.name === 'require') {
      ctx.threats.push({
        type: 'dynamic_require',
        severity: 'CRITICAL',
        message: '.apply(require, ...) — indirect require() invocation via Reflect.apply or Function.prototype.apply. Evasion technique to dynamically load modules.',
        file: ctx.relFile
      });
    }
  }

  // Audit v3 bypass fix: process.on('uncaughtException'/'unhandledRejection', handler)
  // Error handler hijacking for silent credential exfiltration
  if (node.callee?.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'process' &&
      node.callee.property?.type === 'Identifier' && node.callee.property.name === 'on' &&
      node.arguments.length >= 2) {
    const eventArg = node.arguments[0];
    if (eventArg?.type === 'Literal' &&
        (eventArg.value === 'uncaughtException' || eventArg.value === 'unhandledRejection')) {
      ctx.hasUncaughtExceptionHandler = true;
    }
  }

  // SANDWORM_MODE R8: dns.resolve detection moved to walk.ancestor() in ast.js (FIX 5)

  // Blue Team v8b (A7): JSON.parse with reviver that checks __proto__
  // JSON.parse(str, function(key, value) { if (key === '__proto__') ... })
  // Note: getCallName returns 'parse' (property only), so check object.name === 'JSON'
  if (callName === 'parse' && node.callee?.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier' && node.callee.object.name === 'JSON' &&
      node.arguments.length >= 2) {
    const reviver = node.arguments[1];
    if (reviver && (reviver.type === 'FunctionExpression' || reviver.type === 'ArrowFunctionExpression')) {
      // Check if reviver body contains __proto__ reference
      const reviverSrc = reviver.start !== undefined && reviver.end !== undefined
        ? ctx._sourceCode?.slice(reviver.start, reviver.end) : '';
      if (reviverSrc && /__proto__|prototype\s*[.[]/.test(reviverSrc)) {
        ctx.hasJsonReviverProto = true;
        const hasRequireInReviver = /\brequire\s*\(/.test(reviverSrc);
        const hasProtoAssign = /Object\.prototype\s*\./.test(reviverSrc) || /\.__proto__\s*=/.test(reviverSrc);
        ctx.threats.push({
          type: 'json_reviver_pollution',
          severity: (hasRequireInReviver || hasProtoAssign) ? 'CRITICAL' : 'HIGH',
          message: (hasRequireInReviver || hasProtoAssign)
            ? 'JSON.parse reviver accesses __proto__/prototype with require() or prototype assignment — prototype pollution for code injection.'
            : 'JSON.parse reviver accesses __proto__/prototype — potential prototype pollution via untrusted JSON input.',
          file: ctx.relFile
        });
      }
    }
  }

  // Blue Team v8b (C2): vm.runInContext/runInNewContext/compileFunction with dynamic code
  // Detect when the code argument is built from Buffer.from/base64/concat, not a string literal
  if (node.callee?.type === 'MemberExpression' && node.callee.property?.type === 'Identifier') {
    const vmMethods = ['runInContext', 'runInNewContext', 'runInThisContext', 'compileFunction'];
    if (vmMethods.includes(node.callee.property.name) && node.arguments.length > 0) {
      const codeArg = node.arguments[0];
      // Dynamic code: not a string literal, could be variable, concat, Buffer.from, etc.
      if (codeArg && codeArg.type !== 'Literal') {
        const isDynamic = codeArg.type === 'Identifier' || codeArg.type === 'BinaryExpression' ||
          codeArg.type === 'CallExpression' || codeArg.type === 'TemplateLiteral';
        if (isDynamic) {
          ctx.hasVmDynamicExec = true;
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'vm_dynamic_code',
            severity: 'CRITICAL',
            message: `vm.${node.callee.property.name}() with dynamically constructed code — vm sandbox escape via runtime-built code string.`,
            file: ctx.relFile
          });
        }
      }
    }
  }

  // Blue Team v8b (C2): vm.createContext() with custom require injection + sensitive modules
  // Detects sandbox setup that provides module access to untrusted code
  if (callName === 'createContext' && node.callee?.type === 'MemberExpression' &&
      node.callee.object?.type === 'Identifier') {
    const src = ctx._sourceCode || '';
    // Check if the same file defines a custom require for the sandbox
    const hasRequireInjection = /\.require\s*=\s*(?:\(|function\b)/.test(src) ||
      /require\s*:\s*(?:\(|function\b)/.test(src);
    const hasSensitiveModules = /require\s*\(\s*['"](?:fs|http|https|net|child_process)['"]/.test(src);
    if (hasRequireInjection && hasSensitiveModules) {
      ctx.hasDynamicExec = true;
      ctx.threats.push({
        type: 'vm_dynamic_code',
        severity: 'CRITICAL',
        message: 'vm.createContext() with custom require() injection and access to sensitive modules (fs/http/net) — sandbox that enables untrusted code execution with elevated privileges.',
        file: ctx.relFile
      });
    }
  }

  // Blue Team v8b (B7): fs.readFileSync on image/binary files (stego pattern)
  if (node.callee?.type === 'MemberExpression' && node.callee.property?.type === 'Identifier' &&
      ['readFileSync', 'readFile'].includes(node.callee.property.name)) {
    const fileArg = node.arguments?.[0];
    let filePath = '';
    if (fileArg?.type === 'Literal' && typeof fileArg.value === 'string') {
      filePath = fileArg.value;
    } else if (fileArg?.type === 'Identifier' && ctx.stringVarValues?.has(fileArg.name)) {
      filePath = ctx.stringVarValues.get(fileArg.name);
    }
    if (/\.(png|jpg|jpeg|gif|bmp|ico|svg)$/i.test(filePath)) {
      ctx.hasBinaryFileRead = true;
    }
  }

  // Blue Team v8b (C10): execSync/exec inside .on('message') or .on('data') callback
  if (node.callee?.type === 'MemberExpression' && node.callee.property?.type === 'Identifier' &&
      node.callee.property.name === 'on' && node.arguments.length >= 2) {
    const eventArg = node.arguments[0];
    if (eventArg?.type === 'Literal' && ['message', 'data'].includes(eventArg.value)) {
      const callback = node.arguments[1];
      if (callback && (callback.type === 'FunctionExpression' || callback.type === 'ArrowFunctionExpression')) {
        const cbSrc = callback.start !== undefined && callback.end !== undefined
          ? ctx._sourceCode?.slice(callback.start, callback.end) : '';
        if (cbSrc && /\b(execSync|exec|spawn|spawnSync)\s*\(/.test(cbSrc) &&
            /\brequire\s*\(\s*['"]child_process['"]\s*\)/.test(cbSrc)) {
          ctx.hasCallbackExec = true;
          ctx.hasDynamicExec = true;
          ctx.threats.push({
            type: 'callback_exec_rce',
            severity: 'CRITICAL',
            message: `exec/spawn inside .on('${eventArg.value}') callback with require('child_process') — remote command execution from network input.`,
            file: ctx.relFile
          });
        }
      }
    }
  }
}


module.exports = { handleCallExpression };
