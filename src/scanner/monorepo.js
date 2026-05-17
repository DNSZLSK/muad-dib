'use strict';

/**
 * Monorepo Detection Scanner (audit 2026-05 MR-C1)
 *
 * Detects when the scan target is a monorepo root (Yarn/npm workspaces, pnpm,
 * Lerna, Turbo). Emits ONE informational MEDIUM threat `monorepo_detected`
 * so the user knows the score reflects an aggregated perimeter rather than a
 * single package, and that per-workspace scanning is the correct strategy
 * until full workspace-aware scoring lands (backlog v2.13).
 *
 * Detection precedence (manager priority on first match):
 *   1. pnpm-workspace.yaml         → manager='pnpm'
 *   2. lerna.json                  → manager='lerna'
 *   3. turbo.json + pkg.workspaces → manager='turbo'
 *   4. pkg.workspaces (array or {packages: [...]}) → manager='yarn' (also npm 8+)
 *
 * @param {string} targetPath
 * @returns {Array} threats — empty if not a monorepo, one entry otherwise.
 */

const fs = require('fs');
const path = require('path');

function readJsonSafe(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function countYamlListEntries(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const matches = content.match(/^\s*-\s+\S/gm);
    return matches ? matches.length : 0;
  } catch {
    return 0;
  }
}

function workspacesCount(workspaces) {
  if (Array.isArray(workspaces)) return workspaces.length;
  if (workspaces && typeof workspaces === 'object' && Array.isArray(workspaces.packages)) {
    return workspaces.packages.length;
  }
  return 0;
}

function scanMonorepo(targetPath) {
  const threats = [];

  const pnpmWs = path.join(targetPath, 'pnpm-workspace.yaml');
  const lernaJson = path.join(targetPath, 'lerna.json');
  const turboJson = path.join(targetPath, 'turbo.json');
  const pkgJson = path.join(targetPath, 'package.json');

  let manager = null;
  let manifest = 'package.json';
  let workspaceCount = 0;

  if (fs.existsSync(pnpmWs)) {
    manager = 'pnpm';
    manifest = 'pnpm-workspace.yaml';
    workspaceCount = countYamlListEntries(pnpmWs);
  } else if (fs.existsSync(lernaJson)) {
    manager = 'lerna';
    manifest = 'lerna.json';
    const lerna = readJsonSafe(lernaJson);
    workspaceCount = lerna && Array.isArray(lerna.packages) ? lerna.packages.length : 0;
    if (workspaceCount === 0 && lerna && lerna.workspaces) {
      workspaceCount = workspacesCount(lerna.workspaces);
    }
  } else {
    const pkg = fs.existsSync(pkgJson) ? readJsonSafe(pkgJson) : null;
    const wsCount = pkg && pkg.workspaces ? workspacesCount(pkg.workspaces) : 0;
    if (fs.existsSync(turboJson) && wsCount > 0) {
      manager = 'turbo';
      manifest = 'turbo.json';
      workspaceCount = wsCount;
    } else if (wsCount > 0) {
      manager = 'yarn';
      manifest = 'package.json';
      workspaceCount = wsCount;
    }
  }

  if (!manager) return threats;

  threats.push({
    type: 'monorepo_detected',
    severity: 'MEDIUM',
    message: `Monorepo ${manager} detecte (${workspaceCount} workspace${workspaceCount > 1 ? 's' : ''}). Perimetre elargi — scanner chaque package independamment pour un verdict per-workspace.`,
    file: manifest,
    line: 0,
    manager,
    workspaceCount
  });

  return threats;
}

module.exports = { scanMonorepo };
