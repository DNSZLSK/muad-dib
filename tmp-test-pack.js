const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const testDir = path.join(__dirname, '.muaddib-cache', 'benign-tarballs', '_test_express');
fs.mkdirSync(testDir, { recursive: true });

// Step 1: npm pack with cwd
console.log('Step 1: npm pack express (cwd)...');
try {
  const out = execSync('npm pack express', { cwd: testDir, encoding: 'utf8', timeout: 30000 });
  const tgzFile = out.trim().split('\n').pop().trim();
  console.log('  OK:', tgzFile);

  // Step 2: extract with native Node.js
  const tgzPath = path.join(testDir, tgzFile);
  console.log('Step 2: native extraction...');
  extractTgz(tgzPath, testDir);

  const pkgDir = path.join(testDir, 'package');
  const files = fs.readdirSync(pkgDir);
  console.log('  Extracted files:', files.join(', '));
  console.log('  SUCCESS');
} catch (e) {
  console.log('  FAIL:', e.message.slice(0, 300));
}

// Cleanup
fs.rmSync(testDir, { recursive: true, force: true });

/**
 * Extract a .tgz file using Node.js built-in zlib + minimal tar parser.
 * Only extracts regular files (type '0' or NUL).
 */
function extractTgz(tgzPath, destDir) {
  const compressed = fs.readFileSync(tgzPath);
  const tarData = zlib.gunzipSync(compressed);

  let offset = 0;
  while (offset + 512 <= tarData.length) {
    const header = tarData.subarray(offset, offset + 512);

    // Check for end-of-archive (two zero blocks)
    if (header.every(b => b === 0)) break;

    // Parse tar header
    const name = header.subarray(0, 100).toString('utf8').replace(/\0+$/, '');
    const sizeOctal = header.subarray(124, 136).toString('utf8').replace(/\0+$/, '').trim();
    const size = parseInt(sizeOctal, 8) || 0;
    const typeFlag = String.fromCharCode(header[156]);

    offset += 512; // move past header

    if (name && (typeFlag === '0' || typeFlag === '\0') && size > 0) {
      // Regular file — extract it
      const filePath = path.join(destDir, name);
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      const fileData = tarData.subarray(offset, offset + size);
      fs.writeFileSync(filePath, fileData);
    }

    // Advance past data blocks (512-byte aligned)
    offset += Math.ceil(size / 512) * 512;
  }
}
