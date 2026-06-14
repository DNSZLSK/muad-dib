const fs = require('fs');
const path = require('path');

// Lazy import: npm-registry transitively requires acorn. Keeping it lazy lets
// pure sync helpers (findTyposquatMatch, levenshteinDistance) load before
// `npm ci` — used by scripts/check-deps-typosquats.js in the publish guard.
let _getPackageMetadata;
function getPackageMetadata(name) {
  if (!_getPackageMetadata) _getPackageMetadata = require('./npm-registry.js').getPackageMetadata;
  return _getPackageMetadata(name);
}

// In-memory cache to avoid re-querying the same package in one scan
const metadataCache = new Map();
const MAX_METADATA_CACHE_SIZE = 500;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Top 100 packages npm les plus populaires (cibles de typosquatting)
const POPULAR_PACKAGES = [
  'lodash', 'express', 'react', 'axios', 'chalk', 'commander', 'moment',
  'request', 'async', 'bluebird', 'underscore', 'uuid', 'debug', 'mkdirp',
  'glob', 'minimist', 'webpack', 'babel-core', 'typescript', 'eslint',
  'prettier', 'jest', 'mocha', 'chai', 'sinon', 'mongoose', 'sequelize',
  'redis', 'mongodb', 'socket.io', 'express-session',
  'body-parser', 'cookie-parser', 'cors', 'helmet', 'morgan', 'dotenv',
  'jsonwebtoken', 'bcrypt', 'passport', 'nodemailer', 'aws-sdk', 'stripe',
  'twilio', 'firebase', 'graphql', 'apollo-server', 'nuxt',
  'gatsby', 'angular', 'svelte', 'electron', 'puppeteer', 'cheerio',
  'sharp', 'jimp', 'canvas', 'pdf-lib', 'exceljs', 'csv-parser', 'xml2js',
  'yaml', 'config', 'yargs', 'colors',
  'winston', 'bunyan', 'pino', 'log4js', 'ramda', 'immutable',
  'mobx', 'redux', 'zustand', 'formik', 'yup', 'ajv', 'validator',
  'date-fns', 'dayjs', 'luxon', 'numeral', 'accounting', 'currency.js',
  'lodash-es', 'core-js', 'regenerator-runtime', 'tslib', 'classnames',
  'prop-types', 'cross-env', 'node-fetch', 'got',
  // RT-C1 (Axios UNC1069 March 2026): crypto-js missing — wrapper packages declared
  // `plain-crypto-js` as sub-dep. Added so dependency boundary-squat catches it.
  'crypto-js'
];

// RT-C1-FPR (audit 2026-05): frameworks dont les packages d'ecosysteme ont la
// convention <framework>-<role>-<extension> (eslint-plugin-react, babel-preset-env,
// gatsby-plugin-mdx, eslint-import-resolver-typescript). Un dep dont le PREMIER
// segment hyphene est dans ce Set est une extension legitime du framework, jamais
// un squat d'un autre package -- quelles que soient les autres segments.
// EXCLUS volontairement : react, vue, angular, svelte, typescript. Leurs packages
// d'ecosysteme ont le framework EN SUFFIXE (eslint-plugin-react), donc la convention
// prefixe ne s'applique pas et conserver la detection de squats `react-token-exfil`
// reste prioritaire.
const ECOSYSTEM_FRAMEWORK_PREFIXES = new Set([
  'eslint', 'babel', 'webpack', 'rollup', 'vite', 'parcel', 'esbuild', 'swc', 'tsup',
  'gatsby', 'next', 'nuxt', 'remix', 'expo', 'metro',
  'jest', 'mocha', 'karma', 'cypress', 'playwright', 'vitest',
  'postcss', 'stylelint', 'prettier', 'typedoc',
  'storybook', 'docusaurus', 'astro'
]);

// RT-C1: Hyphen tokens that legitimately PREFIX or SUFFIX popular package names.
// `<token>-<popular>` or `<popular>-<token>` is considered benign when the extra
// token is in this set (ecosystem qualifiers, framework prefixes, official scopes).
const LEGIT_BOUNDARY_TOKENS = new Set([
  // Frameworks / build tools (also common official sub-packages)
  'react', 'vue', 'angular', 'svelte', 'next', 'nuxt', 'gatsby', 'expo',
  'eslint', 'babel', 'webpack', 'rollup', 'vite', 'parcel', 'esbuild',
  'jest', 'mocha', 'vitest', 'karma', 'cypress', 'playwright',
  'typescript', 'ts', 'tsdx', 'koa', 'fastify', 'express', 'nest',
  'redux', 'mobx', 'apollo', 'graphql', 'rxjs',
  // Build / runtime variants
  'cli', 'core', 'utils', 'plugin', 'loader', 'preset', 'config',
  'common', 'browser', 'node', 'native', 'web', 'mobile',
  'esm', 'cjs', 'umd', 'es', 'types', 'typings',
  // Versions / channels
  'v2', 'v3', 'v4', 'next', 'latest', 'stable', 'lts', 'legacy', 'beta', 'alpha'
]);

// RT-C1-FPR (2026-06, n=61 blind adjudication → boundary-squat measured 100% FP): popular
// packages whose names are GENERIC tech/English words appear as a legitimate TRAILING token
// in countless real packages — class-validator, graphile-config, ansi-colors, sinon-chai,
// react-helmet-async, swagger-ui-express, short-uuid, react-router-redux, openapi-typescript,
// tree-sitter-c-sharp, agent-commander. Suffix boundary-squat on these is unreliable, so they
// are NOT matched. Distinctive brand names (axios, lodash, chalk, crypto-js — incl. the
// plain-crypto-js / secure-axios FN-guards) stay matchable. A genuine `<x>-<generic>` squat is
// caught by its CODE (exfil/RCE + the Track-R malice floor), not by name shape (see below).
const GENERIC_POPULAR_NAMES = new Set([
  'validator', 'config', 'colors', 'async', 'chai', 'typescript', 'request', 'uuid',
  'redux', 'express', 'sharp', 'commander', 'debug', 'glob', 'yaml', 'cors', 'helmet',
  'canvas', 'immutable', 'classnames',
  // Infra/framework brands that are also common legit trailing tokens (rate-limit-redis,
  // connect-redis, shadcn-svelte, authentikt-svelte) — same measured-FP class, same FN floor.
  'redis', 'svelte',
]);

// Packages legitimes courts ou qui ressemblent a des populaires
const WHITELIST = new Set([
  // Packages tres courts legitimes
  'qs', 'pg', 'ms', 'ws', 'ip', 'on', 'is', 'it', 'to', 'or', 'fs', 'os',
  'co', 'q', 'n', 'i', 'a', 'v', 'x', 'y', 'z',
  'ejs', 'nyc', 'ini', 'joi', 'vue', 'npm', 'got', 'ora',
  'vary', 'mime', 'send', 'etag', 'raw', 'tar', 'uid', 'cjs',
  'rxjs', 'yarn', 'pnpm', 'next', 'targz',
  
  // Packages legitimes avec noms similaires
  'acorn', 'acorn-walk', 'js-yaml', 'cross-env', 'node-fetch', 'node-gyp',
  'core-js', 'lodash-es', 'date-fns', 'ts-node', 'ts-jest',
  'css-loader', 'style-loader', 'file-loader', 'url-loader', 'babel-loader',
  'vue-loader', 'react-dom', 'react-router', 'react-redux', 'vue-router',
  'express-session', 'body-parser', 'cookie-parser',
  
  // Packages Express.js communs
  'accepts', 'array-flatten', 'content-disposition', 'content-type',
  'depd', 'destroy', 'encodeurl', 'escape-html', 'fresh', 'merge-descriptors',
  'methods', 'on-finished', 'parseurl', 'path-to-regexp', 'proxy-addr',
  'range-parser', 'safe-buffer', 'safer-buffer', 'setprototypeof',
  'statuses', 'type-is', 'unpipe', 'utils-merge',
  
  // Packages CLI et outils legitimes
  'jest-cli', 'prettier-2', 'prettier-1', 'eslint-cli',
  'inquirer', 'enquirer', 'prompts',
  'mysql2', 'pg-native', 'sqlite3', 'better-sqlite3',
  'node-sass', 'sass', 'less',
  'esbuild', 'rollup', 'parcel', 'vite',
  'husky', 'lint-staged', 'commitlint',
  'nodemon', 'pm2', 'forever', 'concurrently',
  'lerna', 'turbo', 'nx',
  'chalk', 'colors', 'picocolors', 'colorette',
  'commander', 'yargs', 'meow', 'cac',
  'execa', 'shelljs', 'cross-spawn',
  'rimraf', 'del', 'trash-cli',
  'globby', 'fast-glob', 'tiny-glob',
  'chokidar', 'watchpack', 'nsfw',
  'dotenv', 'dotenv-expand', 'env-cmd',

  // Packages Vite et outils associes
  'vitest', 'vitepress',
  'eslint-config-prettier', 'eslint-plugin-prettier',
  'eslint-scope', 'eslint-visitor-keys',
  'esbuild-register',
  'neo-async',

  // Packages with names close to other popular packages (not typosquats)
  'chai',       // resembles chalk (missing_char)
  'pino',       // resembles sinon (missing_char)
  'ioredis',    // resembles redis (extra prefix)
  'bcryptjs',   // resembles bcrypt (suffix)
  'recast',     // resembles react (extra_char)
  'asyncdi',    // resembles async (suffix)
  'redux',      // resembles redis (wrong_char)
  'args',       // resembles yargs (missing_char)
  'oxlint',     // resembles eslint (wrong_char)
  'vasync',     // resembles async (extra prefix)

  // FPR P1: Benign packages falsely flagged as typosquat in evaluation
  'conf',       // resembles config
  'defu',       // resembles debug
  'ohash',      // resembles lodash
  'cors',       // resembles colors
  'meant',      // resembles react
  'whelk',      // resembles chalk
  'tslog',      // resembles tslib
  'mkdist',     // resembles mkdirp
  'jshint',     // resembles eslint
  'dtslint',    // resembles eslint
  'redis',      // resembles redux
  'cypress',    // resembles express
  'colord',     // resembles colors
  'read',       // resembles react
  'ulid',       // resembles uuid
  'tslint',     // resembles eslint
  'jison',      // resembles sinon
  'reds',       // resembles redis
  'docdash',    // resembles lodash
  'yarpm',      // resembles yargs
  'canvg',      // resembles canvas
  'obug',       // internal sub-dependency

  // FPR P4: Benign packages falsely flagged as typosquat in evaluation
  'mocks',      // karma dep, resembles mocha (wrong_char)
  'reactor',    // stencil dep, resembles react (suffix)

  // Audit v3 B3: well-established packages flagged as typosquat of multiple popular packages
  'color',        // resembles colors (18M dl/week, 5385d old)
  'ttypescript',  // resembles typescript (70K dl/week, 3198d old)
  // FPR plan : established alternative utility libraries falsely matched
  // against lodash/express by the wrong_char + similarity heuristic.
  'radash'        // utility library, ~1.5M dl/week — wrong_char vs lodash
]);


// B13: Pair-aware whitelist — only skip comparison with the specific popular package
const WHITELIST_PAIRS = new Map([
  ['chai', 'chalk'], ['pino', 'sinon'], ['ioredis', 'redis'],
  ['bcryptjs', 'bcrypt'], ['recast', 'react'], ['asyncdi', 'async'],
  ['redux', 'redis'], ['args', 'yargs'], ['oxlint', 'eslint'], ['vasync', 'async'],
  ['conf', 'config'], ['defu', 'debug'], ['ohash', 'lodash'], ['cors', 'colors'],
  ['meant', 'react'], ['whelk', 'chalk'], ['tslog', 'tslib'], ['mkdist', 'mkdirp'],
  ['jshint', 'eslint'], ['dtslint', 'eslint'], ['redis', 'redux'],
  ['cypress', 'express'], ['colord', 'colors'], ['read', 'react'],
  ['ulid', 'uuid'], ['tslint', 'eslint'], ['jison', 'sinon'],
  ['reds', 'redis'], ['docdash', 'lodash'], ['yarpm', 'yargs'],
  ['canvg', 'canvas'], ['mocks', 'mocha'], ['reactor', 'react'],
  ['radash', 'lodash']
]);

// Pre-computed lowercase versions for performance
const POPULAR_PACKAGES_LOWER = POPULAR_PACKAGES.map(p => p.toLowerCase());

// Seuil minimum de longueur pour eviter faux positifs
const MIN_PACKAGE_LENGTH = 4;

const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

function maxSeverity(a, b) {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

async function getCachedMetadata(packageName) {
  if (metadataCache.has(packageName)) {
    const entry = metadataCache.get(packageName);
    // TTL check: evict stale entries
    if (Date.now() - entry.ts < CACHE_TTL_MS) {
      return entry.data;
    }
    metadataCache.delete(packageName);
  }
  const result = await getPackageMetadata(packageName);
  // Bounded cache: evict oldest entry if at limit
  if (metadataCache.size >= MAX_METADATA_CACHE_SIZE) {
    const firstKey = metadataCache.keys().next().value;
    metadataCache.delete(firstKey);
  }
  metadataCache.set(packageName, { data: result, ts: Date.now() });
  return result;
}

function scoreMetadata(meta) {
  let score = 0;
  let severity = 'HIGH'; // base severity from Levenshtein match

  if (!meta) {
    // Package not found on npm = suspect
    return { score: 20, severity: 'HIGH', factors: ['not_on_npm'] };
  }

  const factors = [];

  // 1. Age
  if (meta.age_days !== null && meta.age_days < 7) {
    score += 30;
    severity = maxSeverity(severity, 'CRITICAL');
    factors.push('age<7d');
  } else if (meta.age_days !== null && meta.age_days < 30) {
    score += 15;
    severity = maxSeverity(severity, 'HIGH');
    factors.push('age<30d');
  }

  // 2. Downloads
  if (meta.weekly_downloads < 100) {
    score += 25;
    severity = maxSeverity(severity, 'HIGH');
    factors.push('downloads<100');
  } else if (meta.weekly_downloads < 1000) {
    score += 10;
    severity = maxSeverity(severity, 'MEDIUM');
    factors.push('downloads<1000');
  }

  // 3. Author package count
  if (meta.author_package_count <= 1) {
    score += 20;
    severity = maxSeverity(severity, 'HIGH');
    factors.push('single_pkg_author');
  }

  // 4. No README
  if (!meta.has_readme) {
    score += 10;
    severity = maxSeverity(severity, 'MEDIUM');
    factors.push('no_readme');
  }

  // 5. No repository
  if (!meta.has_repository) {
    score += 10;
    severity = maxSeverity(severity, 'MEDIUM');
    factors.push('no_repo');
  }

  return { score, severity, factors };
}

const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Safely merge dependency objects, filtering out prototype pollution keys.
 */
function safeMerge(...objs) {
  const result = {};
  for (const obj of objs) {
    if (!obj || typeof obj !== 'object') continue;
    for (const [key, value] of Object.entries(obj)) {
      if (!PROTO_KEYS.has(key)) {
        result[key] = value;
      }
    }
  }
  return result;
}

async function scanTyposquatting(targetPath) {
  const threats = [];
  metadataCache.clear();
  const packageJsonPath = path.join(targetPath, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    return threats;
  }

  let packageJson;
  try {
    packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  } catch {
    return threats;
  }
  const dependencies = safeMerge(
    packageJson.dependencies,
    packageJson.devDependencies,
    packageJson.peerDependencies,
    packageJson.optionalDependencies
  );

  // Phase 1: Levenshtein matches (synchronous)
  const candidates = [];
  for (const depName of Object.keys(dependencies)) {
    const match = findTyposquatMatch(depName);
    if (match) {
      candidates.push({ depName, match });
    }
  }

  // Phase 2: API enrichment (batched to avoid socket exhaustion)
  const BATCH_SIZE = 10;
  const metadataResults = [];
  for (let i = 0; i < candidates.length; i += BATCH_SIZE) {
    const batch = candidates.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map(c => getCachedMetadata(c.depName))
    );
    metadataResults.push(...batchResults);
  }

  // Phase 3: Composite scoring
  for (let i = 0; i < candidates.length; i++) {
    const { depName, match } = candidates[i];
    const meta = metadataResults[i];
    const mf = scoreMetadata(meta);

    const finalSeverity = maxSeverity('HIGH', mf.severity);

    // Build detail message
    let details;
    if (!meta) {
      details = 'Package not found on npm (suspect).';
    } else {
      details = 'Age: ' + meta.age_days + 'd'
        + ', Downloads: ' + meta.weekly_downloads + '/week'
        + ', Author packages: ' + meta.author_package_count
        + ', No README: ' + String(!meta.has_readme)
        + ', No repo: ' + String(!meta.has_repository);
    }

    const confidence = mf.score >= 40 ? 'CRITICAL'
      : mf.score >= 20 ? 'HIGH'
      : mf.score > 0 ? 'MEDIUM'
      : 'LOW';

    const message = 'Package "' + depName + '" resembles "' + match.original
      + '" (' + match.type + '). ' + details + '. Confidence: ' + confidence;

    threats.push({
      type: 'typosquat_detected',
      severity: finalSeverity,
      message: message,
      file: 'package.json',
      details: {
        suspicious: depName,
        legitimate: match.original,
        technique: match.type,
        distance: match.distance,
        composite_score: mf.score,
        factors: mf.factors,
        metadata: meta
      }
    });
  }

  // ============================================
  // RT-C1: dependency boundary-squat detection (Axios UNC1069 March 2026)
  // ============================================
  // Runs on deps that did NOT match Levenshtein (length filter excludes them).
  // Catches `<prefix>-<popular>` / `<popular>-<suffix>` injections in package.json
  // deps, plus require/import usage cross-check inside the package source.
  const levenshteinMatches = new Set(candidates.map(c => c.depName));
  const RT_C1_MAX_DEPS = 50;
  let depsEvaluated = 0;
  for (const depName of Object.keys(dependencies)) {
    if (depsEvaluated >= RT_C1_MAX_DEPS) break;
    if (levenshteinMatches.has(depName)) continue; // already flagged by Levenshtein path
    const bMatch = findDependencyBoundarySquat(depName);
    if (!bMatch) continue;
    depsEvaluated++;

    const declMsg = 'Dependency "' + depName + '" looks like a boundary-squat of "'
      + bMatch.original + '" (extra token: "' + bMatch.extra + '"). Axios UNC1069 pattern.';
    threats.push({
      type: 'dependency_typosquat',
      // RT-C1-FPR (audit 2026-05): demoted HIGH -> MEDIUM. Boundary-squat alone is
      // a heuristic signal (name resemblance, no execution proof). The compounds
      // typosquat_lifecycle (CRITICAL) and typosquat_dataflow (HIGH) escalate when
      // co-occurring with real execution/exfil signals.
      severity: 'MEDIUM',
      message: declMsg,
      file: 'package.json',
      details: {
        suspicious: depName,
        legitimate: bMatch.original,
        technique: bMatch.type,
        extra: bMatch.extra,
        distance: bMatch.distance
      }
    });

    // Cross-check: scan package source for require/import of this dep name
    const usages = findDependencyUsages(targetPath, depName);
    for (const u of usages) {
      threats.push({
        type: 'dependency_typosquat_used',
        severity: 'MEDIUM',
        message: 'Boundary-squat dep "' + depName + '" is require()/import()d in source code',
        file: u.file,
        line: u.line,
        details: {
          suspicious: depName,
          legitimate: bMatch.original
        }
      });
    }
  }

  return threats;
}

/**
 * RT-C1: Detects "boundary squat" patterns: <prefix>-<popular> or <popular>-<suffix>
 * where the hyphenated tokens fully contain a popular package name and the extra
 * material is NOT in LEGIT_BOUNDARY_TOKENS. This catches Axios UNC1069-style
 * sub-dependency injection like `plain-crypto-js` (resembles `crypto-js`) that
 * the Levenshtein matcher misses because length-diff is too large.
 */
function findDependencyBoundarySquat(name) {
  const lower = name.toLowerCase();
  if (!lower || lower.startsWith('@')) return null;            // skip scoped
  if (lower.length < MIN_PACKAGE_LENGTH) return null;
  if (WHITELIST.has(lower)) return null;
  if (isLegitimateVariant(lower)) return null;
  if (!lower.includes('-')) return null;                       // need a boundary
  // If it's an exact match to a popular package, not a squat
  if (POPULAR_PACKAGES_LOWER.indexOf(lower) !== -1) return null;

  for (let i = 0; i < POPULAR_PACKAGES.length; i++) {
    const popular = POPULAR_PACKAGES_LOWER[i];
    if (popular.length < MIN_PACKAGE_LENGTH) continue;
    if (lower === popular) continue;

    if (popular.includes('-')) {
      // Multi-token popular (e.g. crypto-js): a squat PREPENDS a deceptive qualifier
      // (plain-crypto-js → endsWith). The reverse `<popular>-<suffix>` (date-fns-tz,
      // aws-sdk-client-mock, core-js-compat) is the popular package's OWN ecosystem extension —
      // never a squat — so the prefix-position match is dropped (2026-06 FPR fix, 100% FP).
      if (!lower.endsWith('-' + popular)) continue;
      const extra = lower.slice(0, lower.length - popular.length - 1);
      if (extra.length === 0) continue;
      // Reject if extra is a legit boundary token (single token only)
      if (!extra.includes('-') && LEGIT_BOUNDARY_TOKENS.has(extra)) continue;
      return { original: POPULAR_PACKAGES[i], type: 'boundary_squat', distance: extra.length, extra };
    } else {
      // Single-token popular. A SQUAT impersonates by putting the popular name as the
      // TRAILING token (`<deceptive-prefix>-<popular>`, e.g. evil-lodash). The
      // npm-dominant `<popular>-<feature>` convention (react-native-gesture-handler,
      // redux-thunk, glob-parent, async-mutex) is legitimate and must NOT be flagged.
      // FPR audit (2026-06, 200-pkg adjudication): matching the popular token in PREFIX
      // or MIDDLE position made dependency_typosquat ~100% FP on the React-Native and
      // Redux ecosystems — so we only match the SUFFIX position. A genuinely malicious
      // `<popular>-<evil>` is caught by its code (exfil/RCE) + the Track-R malice floor,
      // not by name shape. Supersedes the earlier react-prefix heuristic.
      const tokens = lower.split('-');
      if (tokens.length === 1) continue;
      if (tokens[tokens.length - 1] !== popular) continue;     // popular must be the trailing token
      // Generic-word popular (validator/config/colors/async/chai/typescript/...) is a common
      // legitimate trailing token (class-validator, graphile-config, ansi-colors) — 100% FP in
      // the 2026-06 measurement. Distinctive brands (axios → secure-axios FN-guard) still match.
      if (GENERIC_POPULAR_NAMES.has(popular)) continue;
      const siblings = tokens.slice(0, -1);
      // Benign ecosystem variant if every prefix token is a legit qualifier (ts-jest, babel-jest).
      if (siblings.every(t => LEGIT_BOUNDARY_TOKENS.has(t) || isLegitimateVariant(t))) continue;
      const extra = siblings.join('-');
      return { original: POPULAR_PACKAGES[i], type: 'boundary_squat', distance: extra.length, extra };
    }
  }
  return null;
}

// RT-C1: Bounded scan of the package source for require/import of a given dep name.
// Returns array of { file, line } usage sites. Bounds: 200 files, 256KB per file.
const _DEP_USE_MAX_FILES = 200;
const _DEP_USE_MAX_FILE_BYTES = 256 * 1024;
function findDependencyUsages(targetPath, depName) {
  const out = [];
  if (!depName) return out;

  let files;
  try {
    // Use a local require to avoid a circular import surface — utils.js is stable.
    const { findFiles } = require('../utils.js');
    files = findFiles(targetPath, { extensions: ['.js', '.mjs', '.cjs'], maxFiles: _DEP_USE_MAX_FILES });
  } catch {
    return out;
  }
  if (!files || files.length === 0) return out;

  // Pre-build matchers — escape regex metacharacters in dep name
  const escaped = depName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const reRequire = new RegExp(`require\\s*\\(\\s*['"]${escaped}['"]\\s*\\)`);
  const reFrom = new RegExp(`from\\s+['"]${escaped}['"]`);
  const reDynamic = new RegExp(`import\\s*\\(\\s*['"]${escaped}['"]\\s*\\)`);

  for (const abs of files) {
    let stat;
    try { stat = fs.statSync(abs); } catch { continue; }
    if (!stat.isFile() || stat.size > _DEP_USE_MAX_FILE_BYTES) continue;
    let content;
    try { content = fs.readFileSync(abs, 'utf8'); } catch { continue; }
    // Fast-path early bail
    if (!content.includes(depName)) continue;
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i];
      if (reRequire.test(ln) || reFrom.test(ln) || reDynamic.test(ln)) {
        out.push({ file: path.relative(targetPath, abs), line: i + 1 });
        break; // one match per file is enough — keeps signal density honest
      }
    }
  }
  return out;
}

function findTyposquatMatch(name) {
  const nameLower = name.toLowerCase();
  
  // Ignore les packages whitelistes (B13: only skip entirely if not in pair-aware map)
  if (WHITELIST.has(nameLower) && !WHITELIST_PAIRS.has(nameLower)) return null;

  // Ignore les packages scoped (@org/package)
  if (name.startsWith('@')) return null;

  // Ignore les packages tres courts (trop de faux positifs)
  if (name.length < MIN_PACKAGE_LENGTH) return null;

  // Ignore les packages avec suffixes legitimes courants
  if (isLegitimateVariant(nameLower)) return null;

  // B13: Get the specific popular package this whitelisted name is paired with
  const pairedTarget = WHITELIST_PAIRS.get(nameLower);

  for (let i = 0; i < POPULAR_PACKAGES.length; i++) {
    const popularLower = POPULAR_PACKAGES_LOWER[i];
    const popular = POPULAR_PACKAGES[i];

    // Ignore si c'est exactement le meme
    if (nameLower === popularLower) continue;

    // B13: Skip only the intended pair for whitelisted packages
    if (pairedTarget && pairedTarget === popularLower) continue;

    // Ignore si le package populaire est trop court
    if (popular.length < MIN_PACKAGE_LENGTH) continue;

    // Length pre-filter: Levenshtein distance >= |len(a) - len(b)|
    if (Math.abs(nameLower.length - popularLower.length) > 2) continue;

    const distance = levenshteinDistance(nameLower, popularLower);

    // Distance de 1 = tres suspect (une seule lettre de difference)
    if (distance === 1) {
      return {
        original: popular,
        type: detectTyposquatType(name, popular),
        distance: distance
      };
    }

    // Distance de 2 seulement si le package est assez long (>= 5 chars)
    if (distance === 2 && popular.length >= 5) {
      return {
        original: popular,
        type: detectTyposquatType(name, popular),
        distance: distance
      };
    }
  }

  return null;
}

function isLegitimateVariant(name) {
  // RT-C1-FPR (audit 2026-05): ecosystem framework prefix -> legitimate extension.
  // Ex: eslint-import-resolver-typescript, babel-loader-svelte, gatsby-source-fs.
  const firstHyphen = name.indexOf('-');
  if (firstHyphen > 0) {
    const prefix = name.slice(0, firstHyphen);
    if (ECOSYSTEM_FRAMEWORK_PREFIXES.has(prefix)) return true;
  }

  // Suffixes legitimes qui ne sont PAS du typosquatting
  const legitimateSuffixes = [
    '-cli', '-core', '-utils', '-plugin', '-loader', '-webpack',
    '-react', '-vue', '-angular', '-node', '-browser',
    '-esm', '-cjs', '-umd', '-vite',
    '-types', '-typings',
    '2', '3', '4', '5', // versions majeures (mysql2, etc)
    '-v2', '-v3', '-next', '-latest', '-stable', '-lts'
  ];
  
  for (const suffix of legitimateSuffixes) {
    if (name.endsWith(suffix)) return true;
  }
  
  // Prefixes legitimes
  const legitimatePrefixes = [
    '@types/', '@babel/', '@jest/', '@testing-library/',
    'eslint-plugin-', 'eslint-config-',
    'babel-plugin-', 'babel-preset-',
    'webpack-plugin-', 'rollup-plugin-', 'vite-plugin-'
  ];
  
  for (const prefix of legitimatePrefixes) {
    if (name.startsWith(prefix)) return true;
  }
  
  return false;
}

function detectTyposquatType(typo, original) {
  if (typo.length === original.length - 1) return 'missing_char';
  if (typo.length === original.length + 1) return 'extra_char';
  if (typo.length === original.length) {
    // Check for adjacent character swap
    for (let i = 0; i < typo.length - 1; i++) {
      if (typo[i] === original[i + 1] && typo[i + 1] === original[i]) {
        // Verify remaining chars match
        const before = typo.slice(0, i) === original.slice(0, i);
        const after = typo.slice(i + 2) === original.slice(i + 2);
        if (before && after) return 'swapped_chars';
      }
    }
    return 'wrong_char';
  }
  return 'unknown';
}

function levenshteinDistance(a, b) {
  // Two-row optimization: O(min(m,n)) space instead of O(m*n)
  if (a.length < b.length) { const t = a; a = b; b = t; }
  let prev = new Array(b.length + 1);
  let curr = new Array(b.length + 1);

  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      if (a.charAt(i - 1) === b.charAt(j - 1)) {
        curr[j] = prev[j - 1];
      } else {
        curr[j] = Math.min(prev[j - 1] + 1, curr[j - 1] + 1, prev[j] + 1);
      }
    }
    const tmp = prev; prev = curr; curr = tmp;
  }

  return prev[b.length];
}

function clearMetadataCache() {
  metadataCache.clear();
}

// ============================================
// PyPI TYPOSQUATTING
// ============================================

// Top 50 PyPI packages les plus populaires (cibles de typosquatting)
const POPULAR_PYPI_PACKAGES = [
  'requests', 'flask', 'django', 'numpy', 'pandas', 'scipy', 'matplotlib',
  'pillow', 'boto3', 'setuptools', 'pip', 'wheel', 'urllib3', 'certifi',
  'six', 'python-dateutil', 'pyyaml', 'cryptography', 'jinja2', 'markupsafe',
  'click', 'sqlalchemy', 'beautifulsoup4', 'lxml', 'pytest', 'coverage',
  'tox', 'black', 'mypy', 'pylint', 'fastapi', 'uvicorn', 'gunicorn',
  'celery', 'redis', 'psycopg2', 'pymongo', 'httpx', 'aiohttp', 'tornado',
  'scrapy', 'selenium', 'paramiko', 'fabric', 'ansible', 'tensorflow',
  'torch', 'scikit-learn', 'keras', 'transformers'
];

// PEP 503 normalization: case-insensitive, hyphens/underscores/dots equivalent
function normalizePyPI(name) {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

// Pre-computed normalized versions for O(n) comparison
const POPULAR_PYPI_NORMALIZED = POPULAR_PYPI_PACKAGES.map(normalizePyPI);

// Set for O(1) exact-match check (skip popular packages themselves)
const POPULAR_PYPI_SET = new Set(POPULAR_PYPI_NORMALIZED);

// Legitimate PyPI packages that look like typosquats but are not
const PYPI_WHITELIST = new Set([
  'boto',              // legitimate AWS SDK predecessor of boto3
  'torchvision',       // legitimate PyTorch ecosystem
  'torchaudio',        // legitimate PyTorch ecosystem
  'tensorflow-gpu',    // legitimate TF variant
  'scikit-image',      // legitimate scikit ecosystem
  'scikit-optimize',   // legitimate scikit ecosystem
  'paramiko2',         // fork of paramiko
]);

const MIN_PYPI_LENGTH = 4;

/**
 * Find a PyPI typosquat match using PEP 503 normalization + Levenshtein.
 * No npm-registry-style API scoring — just distance-based detection.
 *
 * @param {string} name - PyPI package name from dependency file
 * @returns {{original: string, type: string, distance: number}|null}
 */
function findPyPITyposquatMatch(name) {
  const normalized = normalizePyPI(name);

  // Skip if it IS a popular package (exact match after normalization)
  if (POPULAR_PYPI_SET.has(normalized)) return null;

  // Skip whitelisted
  if (PYPI_WHITELIST.has(normalized)) return null;

  // Skip very short names (too many false positives)
  if (normalized.length < MIN_PYPI_LENGTH) return null;

  for (let i = 0; i < POPULAR_PYPI_PACKAGES.length; i++) {
    const popularNorm = POPULAR_PYPI_NORMALIZED[i];
    const popular = POPULAR_PYPI_PACKAGES[i];

    // Skip exact match (after normalization)
    if (normalized === popularNorm) continue;

    // Skip short popular packages
    if (popularNorm.length < MIN_PYPI_LENGTH) continue;

    // Length pre-filter: Levenshtein distance >= |len(a) - len(b)|
    if (Math.abs(normalized.length - popularNorm.length) > 2) continue;

    const distance = levenshteinDistance(normalized, popularNorm);

    // Distance 1 = very suspect (one char difference)
    if (distance === 1) {
      return {
        original: popular,
        type: detectTyposquatType(normalized, popularNorm),
        distance: distance
      };
    }

    // Distance 2 only for longer packages (>= 5 chars)
    if (distance === 2 && popularNorm.length >= 5) {
      return {
        original: popular,
        type: detectTyposquatType(normalized, popularNorm),
        distance: distance
      };
    }
  }

  return null;
}

// ============================================
// crates.io (Rust) TYPOSQUATTING — Phase 4
// ============================================
// Pre-alert enrichment ONLY: flags when an incoming crate name (from the GHSA rust
// malware feed) typosquats a popular crate. No crates ingestion / build.rs / scan-time
// Cargo parsing (non-goal). Mirrors the PyPI block above.

// Top crates.io packages by downloads (typosquat targets). Hardcoded snapshot.
const POPULAR_CRATES = [
  'serde', 'serde_json', 'serde_derive', 'serde_yaml', 'syn', 'quote', 'proc-macro2',
  'libc', 'rand', 'rand_core', 'log', 'cfg-if', 'bitflags', 'itertools', 'once_cell',
  'lazy_static', 'regex', 'regex-syntax', 'aho-corasick', 'base64', 'num-traits',
  'unicode-ident', 'tokio', 'tokio-util', 'futures', 'futures-util', 'bytes',
  'hashbrown', 'smallvec', 'parking_lot', 'anyhow', 'thiserror', 'indexmap', 'memchr',
  'chrono', 'semver', 'getrandom', 'clap', 'time', 'uuid', 'hyper', 'reqwest',
  'async-trait', 'tracing', 'tracing-core', 'tracing-subscriber', 'url',
  'percent-encoding', 'idna', 'socket2', 'httparse', 'tower', 'rayon', 'num_cpus',
  'either', 'toml', 'winapi', 'windows-sys', 'env_logger', 'generic-array', 'digest',
  'sha2', 'typenum', 'subtle', 'rustls', 'ring', 'openssl', 'flate2', 'miniz_oxide',
  'crc32fast', 'walkdir', 'tempfile', 'dirs', 'nix', 'backtrace', 'scopeguard',
  'pin-project', 'pin-project-lite', 'slab', 'lock_api', 'crossbeam-utils',
  'crossbeam-channel', 'crossbeam-epoch', 'ahash', 'fnv', 'mio', 'h2', 'http'
];

// crates.io treats '-' and '_' as equivalent and is case-insensitive for name
// uniqueness; normalize the same way for typosquat comparison.
function normalizeCrate(name) {
  return name.toLowerCase().replace(/[-_]+/g, '-');
}

const POPULAR_CRATES_NORMALIZED = POPULAR_CRATES.map(normalizeCrate);
const POPULAR_CRATES_SET = new Set(POPULAR_CRATES_NORMALIZED);

// Legitimate crates within edit-distance of a popular crate but not squats.
const CRATES_WHITELIST = new Set([
  'mime',         // distance 1 from 'time' — both real & popular
  'rand-chacha',  // rand ecosystem sibling (normalized)
  'serde-with',   // serde ecosystem sibling
  'futures-core',
]);

const MIN_CRATE_LENGTH = 4;

/**
 * Find a crates.io typosquat match (Levenshtein over the popular-crate list).
 * Pure + IOC-independent. Used by the GHSA rust pre-alert to enrich the embed.
 *
 * @param {string} name - crate name
 * @returns {{original: string, type: string, distance: number}|null}
 */
function findCratesTyposquatMatch(name) {
  if (typeof name !== 'string' || !name) return null;
  const normalized = normalizeCrate(name);

  if (POPULAR_CRATES_SET.has(normalized)) return null; // it IS a popular crate
  if (CRATES_WHITELIST.has(normalized)) return null;
  if (normalized.length < MIN_CRATE_LENGTH) return null;

  for (let i = 0; i < POPULAR_CRATES.length; i++) {
    const popularNorm = POPULAR_CRATES_NORMALIZED[i];
    const popular = POPULAR_CRATES[i];
    if (normalized === popularNorm) continue;
    if (popularNorm.length < MIN_CRATE_LENGTH) continue;
    if (Math.abs(normalized.length - popularNorm.length) > 2) continue;

    const distance = levenshteinDistance(normalized, popularNorm);
    if (distance === 1) {
      return { original: popular, type: detectTyposquatType(normalized, popularNorm), distance };
    }
    if (distance === 2 && popularNorm.length >= 5) {
      return { original: popular, type: detectTyposquatType(normalized, popularNorm), distance };
    }
  }
  return null;
}

module.exports = { scanTyposquatting, levenshteinDistance, clearMetadataCache, findPyPITyposquatMatch, findCratesTyposquatMatch, findTyposquatMatch };