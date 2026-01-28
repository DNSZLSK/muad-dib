#!/usr/bin/env node
/**
 * MUAD'DIB Husky Integration
 *
 * Usage with husky v8+:
 *   npx husky add .husky/pre-commit "node node_modules/muaddib-scanner/hooks/husky.js"
 *
 * Or manually add to .husky/pre-commit:
 *   #!/bin/sh
 *   . "$(dirname "$0")/_/husky.sh"
 *   npx muaddib scan . --fail-on high
 */

const { execSync } = require('child_process');
const path = require('path');

const args = process.argv.slice(2);
const mode = args[0] || 'scan'; // 'scan' or 'diff'
const failLevel = args[1] || 'high';

console.log('[MUADDIB] Running security check before commit...\n');

try {
  let command;

  if (mode === 'diff') {
    // Only check for NEW threats compared to HEAD
    command = `node "${path.join(__dirname, '..', 'bin', 'muaddib.js')}" diff HEAD --fail-on ${failLevel}`;
  } else {
    // Full scan
    command = `node "${path.join(__dirname, '..', 'bin', 'muaddib.js')}" scan . --fail-on ${failLevel}`;
  }

  execSync(command, { stdio: 'inherit' });

  console.log('\n[MUADDIB] Security check passed. Proceeding with commit.');
  process.exit(0);

} catch (error) {
  if (error.status) {
    console.log('\n[MUADDIB] Commit blocked: security threats detected!');
    console.log('[MUADDIB] Fix the issues above or use git commit --no-verify to bypass.');
    process.exit(1);
  }

  // Unexpected error
  console.error('[MUADDIB] Error running security check:', error.message);
  process.exit(1);
}
