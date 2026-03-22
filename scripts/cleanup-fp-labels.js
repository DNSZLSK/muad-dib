#!/usr/bin/env node
'use strict';

/**
 * cleanup-fp-labels.js — One-shot script to convert contaminated 'fp' labels to 'unconfirmed'.
 *
 * Context: During 3 months of monitoring, sandbox score === 0 was automatically relabeled
 * as 'fp' (false positive). Without honey tokens, sandbox clean ≠ false positive.
 * This script converts all automated 'fp' labels to 'unconfirmed' so they are excluded
 * from ML training (neither positive nor negative).
 *
 * Usage:
 *   node scripts/cleanup-fp-labels.js                # Dry-run (default)
 *   node scripts/cleanup-fp-labels.js --apply        # Write changes
 *   node scripts/cleanup-fp-labels.js --file path    # Custom JSONL path
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_FILE = path.join(__dirname, '..', 'data', 'ml-training.jsonl');

function main() {
  const args = process.argv.slice(2);
  const apply = args.includes('--apply');
  const fileIdx = args.indexOf('--file');
  const filePath = fileIdx >= 0 && args[fileIdx + 1] ? args[fileIdx + 1] : DEFAULT_FILE;

  if (!fs.existsSync(filePath)) {
    console.log(`[CLEANUP] File not found: ${filePath}`);
    process.exit(1);
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');

  let totalRecords = 0;
  let fpCount = 0;
  let convertedLines = [];

  for (const line of lines) {
    if (!line.trim()) {
      convertedLines.push(line);
      continue;
    }

    try {
      const record = JSON.parse(line);
      totalRecords++;

      if (record.label === 'fp') {
        fpCount++;
        if (apply) {
          record.label = 'unconfirmed';
          convertedLines.push(JSON.stringify(record));
        } else {
          convertedLines.push(line);
        }
      } else {
        convertedLines.push(line);
      }
    } catch {
      convertedLines.push(line); // Keep malformed lines as-is
    }
  }

  console.log(`[CLEANUP] File: ${filePath}`);
  console.log(`[CLEANUP] Total records: ${totalRecords}`);
  console.log(`[CLEANUP] Records with label 'fp': ${fpCount}`);

  if (apply && fpCount > 0) {
    fs.writeFileSync(filePath, convertedLines.join('\n'), 'utf8');
    console.log(`[CLEANUP] APPLIED: Converted ${fpCount} 'fp' labels to 'unconfirmed'`);
  } else if (!apply && fpCount > 0) {
    console.log(`[CLEANUP] DRY-RUN: Would convert ${fpCount} labels. Use --apply to write.`);
  } else {
    console.log(`[CLEANUP] No 'fp' labels found. Nothing to do.`);
  }
}

main();
