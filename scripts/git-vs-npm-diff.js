#!/usr/bin/env node
'use strict';

// ── git vs npm tarball diff — manual verification tool ──
//
// For a given package@version, downloads the npm tarball AND the matching
// GitHub source archive, then compares the SHA-256 of each .js/.cjs/.mjs/.ts
// file. Files that exist in npm but NOT in git, or that have different hashes,
// are flagged as `injected` — the smoking-gun signature of a publish-time
// compromise (Axios npm 2026-03 was exactly this: token theft, then publish
// of tampered tarballs that did not match the git repo).
//
// USAGE:
//   node scripts/git-vs-npm-diff.js <package> <version>
//   node scripts/git-vs-npm-diff.js axios 1.14.1
//   node scripts/git-vs-npm-diff.js @scope/pkg 2.0.0
//
// Requires network access. No side effects beyond writing diff report to stdout.
// Exit code 0 = identical, 1 = differences found, 2 = could not verify.

const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const zlib = require('zlib');
const { execSync } = require('child_process');

const COMPARABLE_EXT = ['.js', '.cjs', '.mjs', '.ts', '.tsx', '.json'];
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB per file cap for hashing

function fetch(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method: 'GET', headers: { 'User-Agent': 'muaddib-git-diff' }, ...opts }, (res) => {
      // Handle redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const next = new URL(res.headers.location, url).toString();
        res.resume();
        return fetch(next, opts).then(resolve, reject);
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(new Error('timeout')); });
    req.end();
  });
}

async function fetchJson(url) {
  const r = await fetch(url);
  if (r.status !== 200) throw new Error(`HTTP ${r.status} on ${url}`);
  return JSON.parse(r.body.toString('utf8'));
}

async function fetchPackageMeta(name, version) {
  const encName = encodeURIComponent(name).replace(/^%40/, '@');
  const meta = await fetchJson(`https://registry.npmjs.org/${encName}/${encodeURIComponent(version)}`);
  return meta;
}

function parseGitHubFromRepo(repoField) {
  if (!repoField) return null;
  let url = typeof repoField === 'string' ? repoField : repoField.url;
  if (!url) return null;
  url = url.replace(/^git\+/, '').replace(/\.git$/, '').replace(/^git:\/\//, 'https://');
  const m = url.match(/github\.com[/:]([^/]+)\/([^/?#]+)/i);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

async function downloadAndExtract(tarballUrl, destDir) {
  const r = await fetch(tarballUrl);
  if (r.status !== 200) throw new Error(`HTTP ${r.status} on ${tarballUrl}`);
  const tgzPath = path.join(destDir, 'archive.tgz');
  fs.writeFileSync(tgzPath, r.body);
  // Use system tar; portable across Linux + macOS + WSL + git-bash on Windows.
  // The fixture tarball directory layout is npm-style (`package/`) for npm
  // tarballs, and `repo-version/` for GitHub source tarballs. Extract into
  // destDir/extracted/ to keep the layout uniform.
  const extractDir = path.join(destDir, 'extracted');
  fs.mkdirSync(extractDir, { recursive: true });
  try {
    execSync(`tar -xzf "${tgzPath}" -C "${extractDir}"`, { stdio: 'pipe' });
  } catch (e) {
    throw new Error('tar extraction failed: ' + e.message);
  }
  return extractDir;
}

function walk(dir, base = dir) {
  const out = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'test' || e.name === 'tests') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...walk(full, base));
    } else if (e.isFile()) {
      const ext = path.extname(e.name).toLowerCase();
      if (!COMPARABLE_EXT.includes(ext)) continue;
      out.push(path.relative(base, full).replace(/\\/g, '/'));
    }
  }
  return out;
}

function hashFile(p) {
  try {
    const stat = fs.statSync(p);
    if (stat.size > MAX_FILE_BYTES) return null;
    const buf = fs.readFileSync(p);
    return crypto.createHash('sha256').update(buf).digest('hex');
  } catch { return null; }
}

function buildHashMap(rootDir, stripPrefix) {
  const startDir = stripPrefix ? path.join(rootDir, stripPrefix) : rootDir;
  const files = walk(startDir, startDir);
  const map = new Map();
  for (const rel of files) {
    const full = path.join(startDir, rel);
    const h = hashFile(full);
    if (h) map.set(rel, h);
  }
  return map;
}

function findFirstSubdir(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true }).filter(e => e.isDirectory());
  return entries.length === 1 ? entries[0].name : null;
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length < 2 || argv.includes('--help')) {
    console.log('Usage: node scripts/git-vs-npm-diff.js <package> <version>');
    process.exit(2);
  }
  const [pkg, version] = argv;
  console.log(`[GIT-DIFF] ${pkg}@${version}`);

  let meta;
  try { meta = await fetchPackageMeta(pkg, version); }
  catch (e) { console.error('[GIT-DIFF] Could not fetch npm metadata: ' + e.message); process.exit(2); }

  const tarballUrl = meta.dist && meta.dist.tarball;
  if (!tarballUrl) { console.error('[GIT-DIFF] No tarball URL in npm metadata'); process.exit(2); }
  const repo = parseGitHubFromRepo(meta.repository);
  if (!repo) { console.error('[GIT-DIFF] No GitHub repository URL in package.json — cannot diff'); process.exit(2); }
  const ghTarballCandidates = [
    `https://codeload.github.com/${repo.owner}/${repo.repo}/tar.gz/refs/tags/v${version}`,
    `https://codeload.github.com/${repo.owner}/${repo.repo}/tar.gz/refs/tags/${version}`,
    `https://codeload.github.com/${repo.owner}/${repo.repo}/tar.gz/refs/tags/${pkg}@${version}`
  ];

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-gitdiff-'));
  const npmDir = path.join(tmpRoot, 'npm');
  const ghDir = path.join(tmpRoot, 'gh');
  fs.mkdirSync(npmDir, { recursive: true });
  fs.mkdirSync(ghDir, { recursive: true });

  console.log('[GIT-DIFF] Downloading npm tarball...');
  let npmExtracted;
  try { npmExtracted = await downloadAndExtract(tarballUrl, npmDir); }
  catch (e) { console.error('[GIT-DIFF] npm tarball failed: ' + e.message); process.exit(2); }

  console.log('[GIT-DIFF] Downloading GitHub source archive...');
  let ghExtracted = null;
  for (const url of ghTarballCandidates) {
    try {
      console.log('[GIT-DIFF]   Trying tag: ' + url.split('/').pop());
      ghExtracted = await downloadAndExtract(url, ghDir);
      console.log('[GIT-DIFF]   Got it.');
      break;
    } catch (e) { /* try next */ }
  }
  if (!ghExtracted) {
    console.error('[GIT-DIFF] Could not find GitHub source archive for any tag candidate. Possible publish-time compromise (no matching git tag).');
    process.exit(1);
  }

  // npm tarballs always extract to `package/`. GitHub source tarballs extract to `repo-version/`.
  const npmSub = findFirstSubdir(npmExtracted);
  const ghSub = findFirstSubdir(ghExtracted);

  console.log('[GIT-DIFF] Hashing npm files...');
  const npmHashes = buildHashMap(npmExtracted, npmSub);
  console.log('[GIT-DIFF] Hashing GitHub files...');
  const ghHashes = buildHashMap(ghExtracted, ghSub);

  // Compare
  const npmOnly = [];
  const differs = [];
  for (const [rel, h] of npmHashes) {
    if (!ghHashes.has(rel)) npmOnly.push(rel);
    else if (ghHashes.get(rel) !== h) differs.push(rel);
  }

  console.log('');
  console.log(`[GIT-DIFF] npm files (comparable):    ${npmHashes.size}`);
  console.log(`[GIT-DIFF] GitHub files (comparable): ${ghHashes.size}`);
  console.log(`[GIT-DIFF] npm-only files (injected): ${npmOnly.length}`);
  console.log(`[GIT-DIFF] hash-differs files:        ${differs.length}`);

  if (npmOnly.length === 0 && differs.length === 0) {
    console.log('[GIT-DIFF] OK: npm tarball matches GitHub source.');
    process.exit(0);
  }
  console.log('');
  if (npmOnly.length > 0) {
    console.log('[GIT-DIFF] INJECTED FILES (npm only — strong signal of publish-time compromise):');
    for (const f of npmOnly.slice(0, 50)) console.log('  + ' + f);
    if (npmOnly.length > 50) console.log('  ... and ' + (npmOnly.length - 50) + ' more');
  }
  if (differs.length > 0) {
    console.log('');
    console.log('[GIT-DIFF] HASH-DIFFERS FILES (npm content does not match GitHub source):');
    for (const f of differs.slice(0, 50)) console.log('  ! ' + f);
    if (differs.length > 50) console.log('  ... and ' + (differs.length - 50) + ' more');
  }
  console.log('');
  console.log('[GIT-DIFF] Cleanup tmp: ' + tmpRoot);
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* ignore */ }
  process.exit(1);
}

main().catch(e => { console.error('[GIT-DIFF] Fatal:', e.message); process.exit(2); });
