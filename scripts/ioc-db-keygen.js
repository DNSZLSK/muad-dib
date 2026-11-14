#!/usr/bin/env node
'use strict';

/*
 * One-time (or rotation) setup of the ioc-db signing key. Run by the maintainer:
 *
 *   node scripts/ioc-db-keygen.js
 *
 * 1. creates the `ioc-db` GitHub Environment restricted to the master branch (gh api);
 * 2. generates an Ed25519 key pair in memory;
 * 3. sends the PRIVATE key straight to `gh secret set IOC_DB_SIGNING_KEY --env ioc-db` on
 *    stdin: it is never written to disk nor printed;
 * 4. writes the PUBLIC key into src/ioc/ioc-db-public-key.js (commit that file).
 *
 * Needs an authenticated `gh` with admin rights on the repository.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

function gh(args, input) {
  return execFileSync('gh', args, { input, stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'inherit'] }).toString();
}

const repo = gh(['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner']).trim();
if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) { console.error('Cannot resolve the repository: ' + repo); process.exit(1); }

// Environment limited to protected/custom branches, then the master branch policy.
gh(['api', '-X', 'PUT', `repos/${repo}/environments/ioc-db`, '--input', '-'],
  JSON.stringify({ deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } }));
try {
  gh(['api', '-X', 'POST', `repos/${repo}/environments/ioc-db/deployment-branch-policies`, '-f', 'name=master', '-f', 'type=branch']);
} catch { /* policy already present */ }

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString().trim();

gh(['secret', 'set', 'IOC_DB_SIGNING_KEY', '--env', 'ioc-db', '--repo', repo], privPem);

const target = path.join(__dirname, '..', 'src', 'ioc', 'ioc-db-public-key.js');
const src = fs.readFileSync(target, 'utf8');
const next = src.replace(/const IOC_DB_PUBLIC_KEY = [\s\S]*?;\n/, 'const IOC_DB_PUBLIC_KEY = ' + JSON.stringify(pubPem) + ';\n');
if (next === src) { console.error('Could not update ' + target); process.exit(1); }
fs.writeFileSync(target, next);

console.log('ioc-db environment ready (master only), secret IOC_DB_SIGNING_KEY set.');
console.log('Public key written to src/ioc/ioc-db-public-key.js:');
console.log(pubPem);
