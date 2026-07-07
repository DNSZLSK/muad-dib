/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

const fs = require('fs');
const path = require('path');
const { run } = require('../index.js');

function watch(targetPath) {
  let debounceTimer = null;
  const watchers = [];

  console.log(`[MUADDIB] Watching ${targetPath}\n`);
  console.log('[INFO] Press Ctrl+C to stop\n');

  // Initial scan
  run(targetPath, { json: false }).catch(err => console.error('[ERROR]', err.message));

  // Watch for changes
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
      const watcher = fs.watch(watchPath, { recursive: true }, (eventType, filename) => {
        if (debounceTimer) clearTimeout(debounceTimer);

        debounceTimer = setTimeout(() => {
          console.log(`\n[CHANGE] ${filename || 'unknown file'} modified`);
          console.log('[MUADDIB] Re-scan...\n');
          run(targetPath, { json: false }).catch(err => console.error('[ERROR]', err.message));
        }, 1000);
      });
      watcher.on('error', (err) => {
        console.error(`[WARN] Watcher error on ${watchPath}: ${err.message}`);
      });
      watchers.push(watcher);
      console.log(`[WATCH] ${watchPath}`);
    }
  }

  // Cleanup on SIGINT
  process.once('SIGINT', () => {
    console.log('\n[MUADDIB] Stopping watch...');
    for (const w of watchers) {
      try { w.close(); } catch { /* ignore */ }
    }
    process.exit(0);
  });
}

module.exports = { watch };
