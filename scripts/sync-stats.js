'use strict';
/*
 * MUAD'DIB — Supply-chain threat detection for npm & PyPI
 * Copyright (C) 2026 DNSZLSK
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * sync-stats.js — inject stats.json into the docs so a count is written in ONE place (code)
 * and propagates everywhere. Two mechanisms:
 *   1. MARKERS  — `<!--stat:KEY-->VALUE<!--/stat:KEY-->` in prose/tables. HTML comments are
 *                 invisible on GitHub/npm, so the reader only sees VALUE. Only the value between
 *                 the markers is ever rewritten — prose, phrasing and translations are untouched.
 *   2. RAW_SITES — a few numbers live inside fenced ``` ``` ASCII diagrams where an HTML comment
 *                 would render literally. Those are matched by an explicit, file-scoped regex.
 *
 *   node scripts/sync-stats.js          rewrite docs in place from stats.json
 *   node scripts/sync-stats.js --check  exit 1 if any doc is out of date (CI gate); writes nothing
 *
 * Historical docs (CHANGELOG.md, docs/CARNET_DE_BORD_MUADDIB.md) are intentionally absent from
 * DOC_FILES: they record point-in-time truth and must never be rewritten.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const stats = JSON.parse(fs.readFileSync(path.join(ROOT, 'stats.json'), 'utf8'));

function need(key) {
  if (stats[key] === undefined || stats[key] === null) {
    throw new Error(`sync-stats: stats.json is missing "${key}" — run \`npm run docs:stats -- --with-tests\``);
  }
  return String(stats[key]);
}

// Files that carry current-state counts. Files without markers/raw-sites are simply skipped.
const DOC_FILES = [
  'README.md',
  'docs/README.fr.md',
  'ARCHITECTURE.md',
  'SECURITY.md',
  'docs/INDEX.md',
  'docs/threat-model.md',
  'docs/EVALUATION_METHODOLOGY.md',
  'docs/index.html',
  'vscode-extension/README.md',
  'CLAUDE.md',
];

// Numbers trapped inside fenced ASCII diagrams. Each regex must match exactly one line in its file.
const RAW_SITES = [
  { file: 'ARCHITECTURE.md', find: /\d+ parallel scanners \(Promise\.allSettled\)/,
    build: () => `${need('scanners')} parallel scanners (Promise.allSettled)` },
  { file: 'ARCHITECTURE.md', find: /Rule enrichment \(src\/rules\/index\.js — \d+ rules\)/,
    build: () => `Rule enrichment (src/rules/index.js — ${need('rulesTotal')} rules)` },
  { file: 'docs/README.fr.md', find: /MUAD'DIB \d+\.\d+\.\d+ Scanner/,
    build: () => `MUAD'DIB ${need('version')} Scanner` },
  { file: 'docs/README.fr.md', find: /\d+ Scanners Parallèles \(\d+ règles\)/,
    build: () => `${need('scanners')} Scanners Parallèles (${need('rulesTotal')} règles)` },
  { file: 'docs/INDEX.md', find: /executor \(\d+ scanners\)/,
    build: () => `executor (${need('scanners')} scanners)` },
  { file: 'docs/INDEX.md', find: /# \d+ parallel scanners \+ 2 pre-analysis/,
    build: () => `# ${need('scanners')} parallel scanners + 2 pre-analysis` },
  { file: 'docs/INDEX.md', find: /# \d+ threat rules \(\d+ RULES \+ 5 PARANOID/,
    build: () => `# ${need('rulesTotal')} threat rules (${need('rulesCore')} RULES + 5 PARANOID` },
  { file: 'CLAUDE.md', find: /custom framework, \d+ tests across \d+ files/,
    build: () => `custom framework, ${need('tests')} tests across ${need('testFiles')} files` },
  { file: 'docs/INDEX.md', find: /# AST-based detection \(acorn\) — \d+ rules/,
    build: () => `# AST-based detection (acorn) — ${need('astRules')} rules` },
];

const MARKER = /<!--stat:(\w+)-->(.*?)<!--\/stat:\1-->/g;
const isCheck = process.argv.includes('--check');
const stale = [];
const unknownKeys = [];
let changedFiles = 0;

for (const rel of DOC_FILES) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) continue;
  const src = fs.readFileSync(abs, 'utf8');
  let out = src;

  out = out.replace(MARKER, (full, key, cur) => {
    if (stats[key] === undefined || stats[key] === null) { unknownKeys.push(`${rel}: marker key "${key}" is not a known stat`); return full; }
    const val = String(stats[key]);
    if (cur !== val) { stale.push(`${rel}: [marker] ${key} "${cur}" → "${val}"`); return `<!--stat:${key}-->${val}<!--/stat:${key}-->`; }
    return full;
  });

  for (const site of RAW_SITES.filter(s => s.file === rel)) {
    const m = out.match(site.find);
    if (!m) { stale.push(`${rel}: [raw] pattern ${site.find} not found`); continue; }
    const want = site.build();
    if (m[0] !== want) { stale.push(`${rel}: [raw] "${m[0]}" → "${want}"`); out = out.replace(site.find, want); }
  }

  if (out !== src && !isCheck) { fs.writeFileSync(abs, out); changedFiles++; }
}

if (unknownKeys.length) {
  console.error('[sync-stats] unknown marker key(s) — fix the typo or add the stat to collect-stats.js:');
  for (const u of unknownKeys) console.error('    ' + u);
  process.exit(1);
}
if (isCheck) {
  if (stale.length) {
    console.error('[sync-stats] docs are STALE vs stats.json — run `npm run docs:stats`:');
    for (const s of stale) console.error('    ' + s);
    process.exit(1);
  }
  console.log('[sync-stats] all doc markers + raw sites match stats.json. OK');
} else {
  console.log(`[sync-stats] applied ${stale.length} update(s) across ${changedFiles} file(s).`);
}
