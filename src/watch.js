const fs = require('fs');
const path = require('path');
const { run } = require('./index.js');

function watch(targetPath) {
  let debounceTimer = null;

  console.log(`[MUADDIB] Surveillance de ${targetPath}\n`);
  console.log('[INFO] Ctrl+C pour arreter\n');

  // Scan initial
  run(targetPath, { json: false }).catch(err => console.error('[ERROR]', err.message));

  // Surveille les changements
  const watchPaths = [
    path.join(targetPath, 'package.json'),
    path.join(targetPath, 'package-lock.json'),
    path.join(targetPath, 'node_modules')
  ];

  for (const watchPath of watchPaths) {
    if (fs.existsSync(watchPath)) {
      // Note: recursive option only works on macOS and Windows.
      // On Linux, only top-level changes in watchPath are detected.
      if (process.platform === 'linux' && watchPath.includes('node_modules')) {
        console.log(`[WARN] recursive watch not supported on Linux for ${watchPath}`);
      }
      fs.watch(watchPath, { recursive: true }, (eventType, filename) => {
        if (debounceTimer) clearTimeout(debounceTimer);

        debounceTimer = setTimeout(() => {
          console.log(`\n[CHANGE] ${filename || 'unknown file'} modifie`);
          console.log('[MUADDIB] Re-scan...\n');
          run(targetPath, { json: false }).catch(err => console.error('[ERROR]', err.message));
        }, 1000);
      });
      console.log(`[WATCH] ${watchPath}`);
    }
  }
}

module.exports = { watch };