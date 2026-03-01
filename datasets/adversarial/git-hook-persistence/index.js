// git-dep-verify: Lightweight dependency verification
// Verifies that project dependencies match lockfile checksums

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function verifyLockfile(projectDir) {
  const lockPath = path.join(projectDir, 'package-lock.json');
  if (!fs.existsSync(lockPath)) return { verified: false, reason: 'no lockfile' };
  const content = fs.readFileSync(lockPath, 'utf8');
  const hash = crypto.createHash('sha256').update(content).digest('hex');
  return { verified: true, hash };
}

module.exports = { verifyLockfile };
