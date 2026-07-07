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

'use strict';

/**
 * Persistent worker for the extraction pool (src/shared/extract-pool.js).
 *
 * Unlike extract-worker.js (one-shot, used by download.js extractArchiveOffThread),
 * this worker stays alive and serves a request/response loop: one extraction per
 * message, reusing the loaded extractArchive + adm-zip across packages so the pool
 * pays no per-package Worker-spawn cost. All extraction hardening (zip-slip,
 * zip-bomb uncompressed-size cap) lives in extractArchive and runs HERE, off the
 * parent's event loop. Each reply echoes the job id so the pool matches it to the
 * caller. Never throws to the thread — failures come back as { ok:false, error }.
 *
 * Message in:  { id, archivePath, destDir, format? }
 * Message out: { id, ok:true, dir } | { id, ok:false, error }
 */

const { parentPort } = require('worker_threads');
const { extractArchive } = require('./download.js');

parentPort.on('message', (job) => {
  if (!job || typeof job.id === 'undefined') return;
  try {
    const opts = job.format ? { format: job.format } : {};
    const dir = extractArchive(job.archivePath, job.destDir, opts);
    parentPort.postMessage({ id: job.id, ok: true, dir });
  } catch (err) {
    parentPort.postMessage({ id: job.id, ok: false, error: err && err.message ? err.message : String(err) });
  }
});
