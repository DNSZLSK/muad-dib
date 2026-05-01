'use strict';

// ── Stub package detector (closes ltidi chain attack gap) ──
//
// Catches the documented ltidi pattern (project_detection_gap_ltidi_chain
// memory entry, 2026): a package whose main file is essentially empty (a
// dozen lines of boilerplate) and whose `dependencies` field declares an
// external HTTPS URL or git URL. The malicious payload lives in the
// resolved external dep, NOT in the published tarball — so the normal
// scanners see clean code and the package scores ~10, well below
// ADR_THRESHOLD=20.
//
// Trigger conditions (all of):
//   1. package.json declares >= 1 dependency whose version is a non-npm
//      reference: `https?://...`, `git+https?://...`, `git://...`,
//      `file:...`, `link:...` (direct URL pull, not a registry range)
//   2. The main file (or index.js / lib/index.js / dist/index.js) has
//      < STUB_BYTES_THRESHOLD bytes of meaningful code (comments and
//      blank lines stripped). Default 500 bytes.
//   3. Package has at least one of: lifecycle hook (preinstall/install/
//      postinstall) OR no real entrypoint at all (bare manifest).
//
// All three together: CRITICAL +50.
// Conditions 1 + 2 alone (no lifecycle):  HIGH +30 — still suspicious because
//   a real lib that pulls a payload via URL would not have a stub main
//   (it would re-export the dep).

const fs = require('fs');
const path = require('path');

const STUB_BYTES_THRESHOLD = 500;

// External (non-npm-registry) version specs that PULL CODE FROM ELSEWHERE.
// Excluded: `link:`, `workspace:`, `file:` paths to local directories — these
// are local references, not network pulls, so they don't fit the ltidi chain
// model. We accept `file:./*.tgz` only if it points at a tarball (rare in
// real workflows). Bare `file:` paths to dirs are treated as local linking.
const EXTERNAL_DEP_RE = /^(?:https?:\/\/|git[+@]|github:|gitlab:|bitbucket:)/i;

function readMeaningfulSize(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    // Strip line comments, block comments, and blank lines.
    const stripped = raw
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '')
      .replace(/^\s*$\n/gm, '')
      .trim();
    return stripped.length;
  } catch {
    return -1;
  }
}

function findMainFile(pkgDir, pkgJson) {
  const candidates = [];
  if (pkgJson && typeof pkgJson.main === 'string') candidates.push(pkgJson.main);
  candidates.push('index.js', 'index.cjs', 'index.mjs', 'lib/index.js', 'src/index.js', 'dist/index.js');
  for (const c of candidates) {
    const full = path.join(pkgDir, c);
    if (fs.existsSync(full) && fs.statSync(full).isFile()) return full;
  }
  return null;
}

function hasLifecycleHook(pkgJson) {
  if (!pkgJson || !pkgJson.scripts || typeof pkgJson.scripts !== 'object') return false;
  return ['preinstall', 'install', 'postinstall'].some(k => typeof pkgJson.scripts[k] === 'string');
}

function externalDepCount(pkgJson) {
  let count = 0;
  const externals = [];
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const obj = pkgJson && pkgJson[field];
    if (!obj || typeof obj !== 'object') continue;
    for (const [name, spec] of Object.entries(obj)) {
      if (typeof spec === 'string' && EXTERNAL_DEP_RE.test(spec)) {
        count++;
        externals.push(name + '@' + spec);
      }
    }
  }
  return { count, externals };
}

function analyzePackageDir(pkgDir) {
  const manifestPath = path.join(pkgDir, 'package.json');
  if (!fs.existsSync(manifestPath)) return null;
  let pkgJson;
  try {
    pkgJson = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch {
    return null;
  }

  const ext = externalDepCount(pkgJson);
  if (ext.count === 0) return null; // not a stub-pull pattern

  // Size of main file
  const mainPath = findMainFile(pkgDir, pkgJson);
  let mainBytes = -1;
  if (mainPath) mainBytes = readMeaningfulSize(mainPath);
  // No main at all → treat as stub (size = 0)
  if (mainBytes === -1) mainBytes = 0;

  if (mainBytes >= STUB_BYTES_THRESHOLD) return null; // not a stub

  const lifecycle = hasLifecycleHook(pkgJson);
  return {
    manifestPath,
    mainPath,
    mainBytes,
    externals: ext.externals,
    lifecycle,
    name: pkgJson.name || path.basename(pkgDir)
  };
}

async function scanStubPackage(targetPath) {
  const threats = [];
  if (!fs.existsSync(targetPath)) return threats;

  // Always check the host package
  const hostResult = analyzePackageDir(targetPath);
  if (hostResult) threats.push(buildThreat(targetPath, hostResult, 'package.json'));

  // Walk one level into node_modules (each direct dep is a separate package
  // that may itself be a stub-pull — common in chain attacks where the
  // outer dep is a clean wrapper around 7 stubs).
  const nodeModulesPath = path.join(targetPath, 'node_modules');
  if (fs.existsSync(nodeModulesPath)) {
    let entries;
    try { entries = fs.readdirSync(nodeModulesPath); } catch { entries = []; }
    for (const entry of entries) {
      if (entry.startsWith('.')) continue;
      const sub = path.join(nodeModulesPath, entry);
      let stat;
      try { stat = fs.statSync(sub); } catch { continue; }
      if (!stat.isDirectory()) continue;
      // Scoped packages: walk into each org/sub
      if (entry.startsWith('@')) {
        let scoped;
        try { scoped = fs.readdirSync(sub); } catch { scoped = []; }
        for (const subEntry of scoped) {
          const scopedDir = path.join(sub, subEntry);
          const r = analyzePackageDir(scopedDir);
          if (r) threats.push(buildThreat(targetPath, r, path.join('node_modules', entry, subEntry, 'package.json')));
        }
        continue;
      }
      const r = analyzePackageDir(sub);
      if (r) threats.push(buildThreat(targetPath, r, path.join('node_modules', entry, 'package.json')));
    }
  }
  return threats;
}

function buildThreat(targetPath, result, fileLabel) {
  const baseDetail = `Stub package (main=${result.mainBytes} bytes) declares ${result.externals.length} external URL dependency(ies): ${result.externals.slice(0, 3).join(', ')}${result.externals.length > 3 ? ' …' : ''}`;
  if (result.lifecycle) {
    return {
      type: 'stub_package_external_payload',
      severity: 'CRITICAL',
      message: `${baseDetail}. Lifecycle hook present — payload likely fetched + executed at install (ltidi chain pattern).`,
      file: fileLabel,
      evidence: result.externals.join('|')
    };
  }
  return {
    type: 'stub_package_external_dep',
    severity: 'HIGH',
    message: `${baseDetail}. No lifecycle hook (lib pattern) but stub main + external URL dep is unusual — manual review.`,
    file: fileLabel,
    evidence: result.externals.join('|')
  };
}

module.exports = { scanStubPackage, analyzePackageDir, STUB_BYTES_THRESHOLD, EXTERNAL_DEP_RE };
