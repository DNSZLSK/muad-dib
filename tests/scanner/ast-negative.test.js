const fs = require('fs');
const os = require('os');
const path = require('path');
const { asyncTest, assert, runScanDirect, cleanupTemp } = require('../test-utils');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-neg-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-neg-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}

function threatTypes(result) {
  return (result.threats || []).map(t => t.type);
}

async function runAstNegativeTests() {
  console.log('\n=== AST NEGATIVE TESTS ===\n');

  await asyncTest('NEG: Clean utility module triggers 0 threats', async () => {
    const tmp = makeTempPkg(`
function add(a, b) { return a + b; }
function multiply(a, b) { return a * b; }
module.exports = { add, multiply };
`);
    try {
      const result = await runScanDirect(tmp);
      assert(result.threats.length === 0, `Expected 0 threats, got ${result.threats.length}: ${JSON.stringify(result.threats.map(t => t.type))}`);
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('NEG: process.env.PORT/HOST/NODE_ENV not flagged as env_access', async () => {
    const tmp = makeTempPkg(`
const port = process.env.PORT || 3000;
const host = process.env.HOST || 'localhost';
const env = process.env.NODE_ENV || 'development';
module.exports = { port, host, env };
`);
    try {
      const result = await runScanDirect(tmp);
      const types = threatTypes(result);
      assert(!types.includes('env_access'), `Standard env vars should not trigger env_access, got: ${types.join(', ')}`);
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('NEG: process.env.npm_package_* not flagged as env_access', async () => {
    const tmp = makeTempPkg(`
const name = process.env.npm_package_name;
const version = process.env.npm_package_version;
console.log(name, version);
`);
    try {
      const result = await runScanDirect(tmp);
      const types = threatTypes(result);
      assert(!types.includes('env_access'), `npm_package_* env vars should not trigger env_access, got: ${types.join(', ')}`);
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('NEG: fs.readFileSync("package.json") not flagged as suspicious_dataflow', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
console.log(pkg.name);
`);
    try {
      const result = await runScanDirect(tmp);
      const types = threatTypes(result);
      assert(!types.includes('suspicious_dataflow'), `Reading package.json should not trigger suspicious_dataflow, got: ${types.join(', ')}`);
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('NEG: fs.readFileSync("README.md") not flagged as sensitive_file_read', async () => {
    const tmp = makeTempPkg(`
const fs = require('fs');
const readme = fs.readFileSync('README.md', 'utf8');
console.log(readme);
`);
    try {
      const result = await runScanDirect(tmp);
      const types = threatTypes(result);
      assert(!types.includes('sensitive_file_read'), `Reading README.md should not trigger sensitive_file_read, got: ${types.join(', ')}`);
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('NEG: Static require("./utils") not flagged as dynamic_require', async () => {
    const tmp = makeTempPkg(`
const utils = require('./utils');
module.exports = utils;
`);
    // Create the utils file so it exists
    fs.writeFileSync(path.join(tmp, 'utils.js'), 'module.exports = {};');
    try {
      const result = await runScanDirect(tmp);
      const types = threatTypes(result);
      assert(!types.includes('dynamic_require'), `Static require should not trigger dynamic_require, got: ${types.join(', ')}`);
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('NEG: crypto.createHash("sha256") not flagged as crypto_decipher', async () => {
    const tmp = makeTempPkg(`
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update('data').digest('hex');
console.log(hash);
`);
    try {
      const result = await runScanDirect(tmp);
      const types = threatTypes(result);
      assert(!types.includes('crypto_decipher'), `createHash should not trigger crypto_decipher, got: ${types.join(', ')}`);
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('NEG: execSync("npm install") not flagged as dangerous_exec', async () => {
    const tmp = makeTempPkg(`
const { execSync } = require('child_process');
execSync('npm install', { stdio: 'inherit' });
`);
    try {
      const result = await runScanDirect(tmp);
      const types = threatTypes(result);
      assert(!types.includes('dangerous_exec'), `npm install should not trigger dangerous_exec, got: ${types.join(', ')}`);
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('NEG: exec("eslint src/") not flagged as dangerous_exec', async () => {
    const tmp = makeTempPkg(`
const { exec } = require('child_process');
exec('eslint src/', (err, stdout) => console.log(stdout));
`);
    try {
      const result = await runScanDirect(tmp);
      const types = threatTypes(result);
      assert(!types.includes('dangerous_exec'), `eslint exec should not trigger dangerous_exec, got: ${types.join(', ')}`);
    } finally {
      cleanupTemp(tmp);
    }
  });

  await asyncTest('NEG: Express middleware res.json override not flagged as prototype_hook', async () => {
    const tmp = makeTempPkg(`
function middleware(req, res, next) {
  res.json = function(data) {
    return res.send(JSON.stringify(data));
  };
  next();
}
module.exports = middleware;
`);
    try {
      const result = await runScanDirect(tmp);
      const types = threatTypes(result);
      assert(!types.includes('prototype_hook'), `Express middleware should not trigger prototype_hook, got: ${types.join(', ')}`);
    } finally {
      cleanupTemp(tmp);
    }
  });
}

module.exports = { runAstNegativeTests };
