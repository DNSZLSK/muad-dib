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
      fs.watch(watchPath, { recursive: true }, (eventType, filename) => {
        if (debounceTimer) clearTimeout(debounceTimer);

        debounceTimer = setTimeout(() => {
          console.log(`\n[CHANGE] ${filename} modifie`);
          console.log('[MUADDIB] Re-scan...\n');
          run(targetPath, { json: false }).catch(err => console.error('[ERROR]', err.message));
        }, 1000);
      });
      console.log(`[WATCH] ${watchPath}`);
    }
  }
}

module.exports = { watch };