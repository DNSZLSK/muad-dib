#!/usr/bin/env node
'use strict';

/**
 * MUAD'DIB — Benign Candidate Verifier
 *
 * Takes a list of candidate npm packages (from production FP analysis, shadow
 * disagreements, user submissions, etc.) and triages them via the npm registry
 * API into three buckets:
 *
 *   AUTO-APPROVED: verifiable legitimacy — trusted org scope/maintainer, OR
 *                  strong reputation (age >= 365d, DL/w >= 50k, versions >= 10,
 *                  has public repo).
 *   NEEDS-REVIEW:  mixed signals — requires human check before adding to
 *                  the benign training corpus.
 *   REJECTED:      negative signals — removed from npm, very new + low
 *                  downloads, no repo + low downloads, or suspicious name
 *                  pattern with low downloads. DO NOT add without explicit
 *                  per-package verification.
 *
 * This script makes NO automated decision about training usage. It only
 * triages for human review. The human decides what goes into
 * datasets/benign/packages-npm.txt.
 *
 * Usage:
 *   node scripts/verify-benign-candidates.js --input <file>
 *   node scripts/verify-benign-candidates.js --input <file> --output-dir <dir>
 *
 * Input format: one package name per line, # for comments, blank lines ignored.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

// --- CLI args ---
const args = process.argv.slice(2);
function getArg(name) {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : null;
}
const INPUT = getArg('--input');
const OUTPUT_DIR = getArg('--output-dir') || path.resolve(__dirname, '..', '.muaddib-cache');

if (!INPUT) {
  console.error('Usage: node scripts/verify-benign-candidates.js --input <file> [--output-dir <dir>]');
  process.exit(1);
}
if (!fs.existsSync(INPUT)) {
  console.error(`ERROR: input file not found: ${INPUT}`);
  process.exit(1);
}

// --- Trusted orgs (allowlist) ---
// Maintainers (npm account handles) known to belong to verified orgs.
// These bypass reputation thresholds — a package maintained by 'facebook'
// is auto-approved even if it's new or low-download (e.g., internal tooling).
const TRUSTED_MAINTAINERS = new Set([
  // Microsoft
  'microsoft', 'microsoft1es', 'microsoft-bot', 'playwrightteam', 'playwright-bot',
  'vscode-bot', 'typescript-bot',
  // Meta / Facebook / React
  'facebook', 'fb', 'reactjs', 'react-native-bot', 'relay-bot',
  // Google / Angular / Firebase
  'google', 'google-wombot', 'angular', 'angular-bot', 'firebase-bot',
  // Vercel / Next.js
  'vercel', 'vercel-release-bot', 'next',
  // Cloudflare
  'cloudflare', 'cloudflare-workers-bot',
  // Shopify
  'shopify', 'shopify-engineering',
  // Salesforce / Ionic / Stencil
  'salesforce', 'ionic-team', 'stencil-team', 'oclif',
  // Spotify / Backstage
  'spotify', 'backstage-service',
  // Apollo GraphQL
  'apollographql', 'apollo-bot',
  // Vue / Svelte
  'yyx990803', 'vuejs', 'sveltejs',
  // Webpack / Babel / Rollup / ESLint / Jest
  'webpack-bot', 'babel-bot', 'rollup-bot', 'eslint-bot', 'jest-bot',
  // Cypress / Playwright / Storybook
  'cypress-io', 'storybook-bot', 'storybookjs',
  // Remix
  'remix-run',
  // Node / npm
  'npm-robot', 'nodejs-bot', 'nodejs-foundation',
  // Strapi / Stripe / Twilio
  'strapi-bot', 'stripe', 'twilio',
  // AWS / Mongo / Docker
  'aws-sdk-bot', 'mongodb', 'docker',
  // Prisma / TypeORM / Drizzle
  'prisma-bot', 'typeorm-team',
  // Well-known verified companies
  'uploadcare', 'equinor', 'octokit', 'github', 'elastic-machine', 'sentry-bot',
  'datadog-ci', 'azure-pipelines-bot', 'parse-community',
]);

// Scopes where all packages are auto-approved (org holds the scope on npm).
// This is a HARDER signal than maintainer: npm verifies scope ownership.
const TRUSTED_SCOPES = new Set([
  // Platforms
  '@microsoft', '@playwright', '@vscode', '@types',
  '@facebook', '@react-native', '@reactjs', '@relay',
  '@google', '@google-cloud', '@googleapis', '@firebase', '@angular',
  '@vercel', '@next',
  '@cloudflare',
  '@shopify',
  '@salesforce', '@stencil', '@ionic', '@oclif',
  '@apollo', '@apollographql',
  '@backstage', '@spotify',
  '@storybook',
  '@vue', '@vueuse',
  '@sveltejs', '@svelte',
  // Build tools
  '@webpack', '@babel', '@rollup', '@eslint', '@biomejs',
  '@swc', '@vitest',
  // Testing
  '@jest', '@testing-library', '@cypress',
  // Remix
  '@remix-run',
  // Node frameworks
  '@nestjs', '@nrwl', '@nx',
  // Node / npm
  '@npmcli', '@types',
  // DB / ORM
  '@prisma', '@drizzle-team', '@typeorm',
  // Services
  '@strapi', '@stripe', '@twilio',
  '@aws-sdk', '@aws-amplify', '@aws-cdk',
  '@mongodb', '@mongodb-js',
  '@docker',
  // Monitoring / observability
  '@sentry', '@datadog', '@opentelemetry', '@elastic', '@elastic-cloud',
  // Cloud
  '@azure',
  // Verified companies
  '@uploadcare', '@equinor', '@octokit',
  // Popular libraries
  '@reduxjs', '@tanstack', '@trpc', '@inquirer',
]);

// Name patterns that suggest typosquat / impersonation / random garbage
const SUSPICIOUS_NAME_PATTERNS = [
  /^0[a-z]/i,                   // starts with 0 (l33t-speak)
  /^[a-z0-9]{1,3}$/i,           // 1-3 char bare name
  /^.*(\w)\1{3,}.*$/,           // 4+ repeated chars anywhere
  /[0-9]{4,}/,                  // 4+ consecutive digits
  /[xyz]{3,}/i,                 // "xxxx", "zzzz"
];

// --- HTTP helpers ---
function httpGetJson(url, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      timeout: timeoutMs,
      headers: { 'User-Agent': 'muaddib-benign-verifier/1.0' }
    }, (res) => {
      if (res.statusCode === 404) {
        res.resume();
        return resolve({ _404: true });
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch (e) { reject(e); }
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

async function fetchPackageMeta(name) {
  const encoded = name.replace(/\//g, '%2F');
  const data = await httpGetJson(`https://registry.npmjs.org/${encoded}`);
  if (data._404) return { status: 'removed' };

  const created = data.time && data.time.created;
  const modified = data.time && data.time.modified;
  const latest = data['dist-tags'] && data['dist-tags'].latest;
  const versions = data.versions ? Object.keys(data.versions) : [];
  const maintainers = (data.maintainers || []).map(m => (m && m.name) || m).filter(Boolean);
  const description = data.description || '';
  const repoRaw = data.repository && (data.repository.url || data.repository);
  const repository = typeof repoRaw === 'string' ? repoRaw : null;

  // Security takedown signal
  if (latest === '0.0.1-security') {
    return { status: 'security_takedown', latestVersion: latest };
  }

  return {
    status: 'alive',
    created,
    modified,
    latestVersion: latest,
    versionCount: versions.length,
    maintainers,
    description,
    repository,
  };
}

async function fetchWeeklyDownloads(name) {
  const encoded = name.replace(/\//g, '%2F');
  try {
    const data = await httpGetJson(`https://api.npmjs.org/downloads/point/last-week/${encoded}`);
    return (data && typeof data.downloads === 'number') ? data.downloads : 0;
  } catch {
    return null;
  }
}

// --- Classification ---
function getScope(pkgName) {
  return pkgName.startsWith('@') ? pkgName.split('/')[0] : null;
}

function ageInDays(dateStr) {
  if (!dateStr) return 0;
  return Math.floor((Date.now() - new Date(dateStr).getTime()) / 86400000);
}

function basename(pkgName) {
  return pkgName.startsWith('@') ? (pkgName.split('/')[1] || '') : pkgName;
}

function nameIsSuspicious(pkgName) {
  const base = basename(pkgName);
  return SUSPICIOUS_NAME_PATTERNS.some(re => re.test(base));
}

function classifyPackage(name, meta, downloads) {
  if (!meta || meta.status === 'removed') {
    return { verdict: 'REJECTED', reason: 'REMOVED from npm registry (npm 404)' };
  }
  if (meta.status === 'security_takedown') {
    return { verdict: 'REJECTED', reason: 'npm SECURITY TAKEDOWN (0.0.1-security)' };
  }

  const scope = getScope(name);
  const ageD = ageInDays(meta.created);
  const dl = downloads || 0;
  const trustedScope = scope && TRUSTED_SCOPES.has(scope);
  const trustedMaintainer = meta.maintainers.some(m => TRUSTED_MAINTAINERS.has(m));

  // --- AUTO-APPROVE paths (trusted overrides always win) ---
  if (trustedScope) {
    return { verdict: 'AUTO-APPROVED', reason: `trusted scope ${scope}` };
  }
  if (trustedMaintainer) {
    const who = meta.maintainers.find(m => TRUSTED_MAINTAINERS.has(m));
    return { verdict: 'AUTO-APPROVED', reason: `trusted maintainer (${who})` };
  }
  if (ageD >= 365 && dl >= 50000 && meta.versionCount >= 10 && meta.repository) {
    return {
      verdict: 'AUTO-APPROVED',
      reason: `strong reputation: age=${ageD}d DL/w=${dl} versions=${meta.versionCount} repo=yes`
    };
  }

  // --- REJECT paths ---
  // Minimum age: a package < 14d old cannot be verified as legitimate.
  // Even well-known maintainers publishing yesterday lack observation time.
  if (ageD < 14) {
    return {
      verdict: 'REJECTED',
      reason: `too new: age=${ageD}d — need >=14d observation window`
    };
  }
  // Publish velocity: new packages with >1 version/day are typical of
  // automated spam, typosquat flooding, or compromised CI publish loops.
  // Legit projects rarely exceed 1 release/day sustained over weeks.
  const versionsPerDay = meta.versionCount / Math.max(ageD, 1);
  if (ageD < 90 && versionsPerDay > 1.0) {
    return {
      verdict: 'REJECTED',
      reason: `excessive publish velocity: ${meta.versionCount} versions in ${ageD}d (${versionsPerDay.toFixed(1)}/d) — typical of automated spam`
    };
  }
  if (ageD < 60 && dl < 100) {
    return { verdict: 'REJECTED', reason: `new + low DL: age=${ageD}d DL/w=${dl}` };
  }
  if (!meta.repository && dl < 1000) {
    return { verdict: 'REJECTED', reason: `no repo + low DL: DL/w=${dl}` };
  }
  if (nameIsSuspicious(name) && dl < 10000) {
    return { verdict: 'REJECTED', reason: `suspicious name pattern + low DL (DL/w=${dl})` };
  }

  // --- NEEDS-REVIEW (middle tier) ---
  const maintainerList = meta.maintainers.length > 0
    ? meta.maintainers.slice(0, 3).join(',')
    : 'none';
  return {
    verdict: 'NEEDS-REVIEW',
    reason: `age=${ageD}d DL/w=${dl} versions=${meta.versionCount} repo=${meta.repository ? 'yes' : 'no'} maintainer=${maintainerList}`
  };
}

// --- Main ---
async function main() {
  const candidates = fs.readFileSync(INPUT, 'utf8')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  console.log(`[verify] ${candidates.length} candidates in ${INPUT}`);
  console.log(`[verify] Output directory: ${OUTPUT_DIR}`);
  console.log('');

  const results = { 'AUTO-APPROVED': [], 'NEEDS-REVIEW': [], 'REJECTED': [] };
  let errorCount = 0;

  for (let i = 0; i < candidates.length; i++) {
    const name = candidates[i];
    const progress = `[${String(i + 1).padStart(3)}/${candidates.length}]`;

    let meta, downloads, classification;
    try {
      meta = await fetchPackageMeta(name);
      downloads = meta.status === 'alive' ? await fetchWeeklyDownloads(name) : 0;
      classification = classifyPackage(name, meta, downloads);
    } catch (err) {
      errorCount++;
      classification = { verdict: 'NEEDS-REVIEW', reason: `registry error: ${err.message}` };
      meta = { maintainers: [], created: null };
      downloads = 0;
    }

    const tag = classification.verdict === 'AUTO-APPROVED' ? '[OK]   '
              : classification.verdict === 'REJECTED'     ? '[REJ]  '
                                                          : '[REV]  ';
    console.log(`${progress} ${tag}${name}`);
    console.log(`         ${classification.reason}`);

    results[classification.verdict].push({
      name,
      verdict: classification.verdict,
      reason: classification.reason,
      ageD: ageInDays(meta.created),
      downloads: downloads || 0,
      maintainers: meta.maintainers || [],
    });

    // Be polite to npm registry
    await new Promise(r => setTimeout(r, 120));
  }

  // --- Write outputs ---
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  const approvedFile = path.join(OUTPUT_DIR, 'benign-auto-approved.txt');
  const reviewFile = path.join(OUTPUT_DIR, 'benign-needs-review.txt');
  const rejectedFile = path.join(OUTPUT_DIR, 'benign-rejected.txt');

  function writeOutput(file, header, entries) {
    const lines = [header, ''];
    for (const r of entries) {
      lines.push(`# ${r.reason}`);
      lines.push(r.name);
      lines.push('');
    }
    fs.writeFileSync(file, lines.join('\n'));
  }

  writeOutput(approvedFile,
    '# AUTO-APPROVED — trusted scope/maintainer OR strong reputation signals.\n' +
    '# Safe to append to datasets/benign/packages-npm.txt without further review.\n' +
    '# Generated by scripts/verify-benign-candidates.js',
    results['AUTO-APPROVED']);

  writeOutput(reviewFile,
    '# NEEDS-REVIEW — mixed signals. Check each manually before adding:\n' +
    '#   1. Open https://www.npmjs.com/package/<name>\n' +
    '#   2. Verify maintainer + repo + description look legitimate\n' +
    '#   3. Optional: npm view <name> or check GitHub stars/activity\n' +
    '# Generated by scripts/verify-benign-candidates.js',
    results['NEEDS-REVIEW']);

  writeOutput(rejectedFile,
    '# REJECTED — negative signals. DO NOT add to benign list without\n' +
    '# explicit per-package verification (review code, maintainer, history).\n' +
    '# These are candidates where automated signals suggest risk:\n' +
    '#   - removed from npm or security takedown\n' +
    '#   - very new (<60d) with low downloads\n' +
    '#   - no repository URL with low downloads\n' +
    '#   - suspicious name pattern (typosquat/random) with low downloads\n' +
    '# Generated by scripts/verify-benign-candidates.js',
    results['REJECTED']);

  // --- Summary ---
  console.log('');
  console.log('='.repeat(60));
  console.log('TRIAGE SUMMARY');
  console.log('='.repeat(60));
  console.log(`  AUTO-APPROVED:  ${String(results['AUTO-APPROVED'].length).padStart(3)}  -> ${approvedFile}`);
  console.log(`  NEEDS-REVIEW:   ${String(results['NEEDS-REVIEW'].length).padStart(3)}  -> ${reviewFile}`);
  console.log(`  REJECTED:       ${String(results['REJECTED'].length).padStart(3)}  -> ${rejectedFile}`);
  console.log(`  Registry errors: ${errorCount}`);
  console.log('');

  if (results['REJECTED'].length > 0) {
    console.log('Rejected packages:');
    for (const r of results['REJECTED']) {
      console.log(`  ${r.name.padEnd(45)} ${r.reason}`);
    }
    console.log('');
  }

  console.log('Next steps:');
  console.log(`  1. Review ${path.basename(reviewFile)} manually — check each package on npmjs.com`);
  console.log(`  2. Append approved + manually-reviewed entries to datasets/benign/packages-npm.txt`);
  console.log(`  3. Run: node scripts/scan-benign-training.js --resume`);
}

main().catch(err => {
  console.error('[FATAL]', err);
  process.exit(1);
});
