const fs = require('fs');
const path = require('path');

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
  'prop-types', 'cross-env', 'node-fetch', 'got'
];

// Packages legitimes courts ou qui ressemblent a des populaires
const WHITELIST = [
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
  'neo-async'
];


// Pre-computed lowercase versions for performance
const POPULAR_PACKAGES_LOWER = POPULAR_PACKAGES.map(p => p.toLowerCase());

// Seuil minimum de longueur pour eviter faux positifs
const MIN_PACKAGE_LENGTH = 4;

async function scanTyposquatting(targetPath) {
  const threats = [];
  const packageJsonPath = path.join(targetPath, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    return threats;
  }

  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const dependencies = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
    ...packageJson.peerDependencies,
    ...packageJson.optionalDependencies
  };

  for (const depName of Object.keys(dependencies)) {
    const match = findTyposquatMatch(depName);
    if (match) {
      threats.push({
        type: 'typosquat_detected',
        severity: 'HIGH',
        message: `Package "${depName}" ressemble a "${match.original}" (${match.type}). Possible typosquatting.`,
        file: 'package.json',
        details: {
          suspicious: depName,
          legitimate: match.original,
          technique: match.type,
          distance: match.distance
        }
      });
    }
  }

  return threats;
}

function findTyposquatMatch(name) {
  const nameLower = name.toLowerCase();
  
  // Ignore les packages whitelistes
  if (WHITELIST.includes(nameLower)) return null;
  
  // Ignore les packages scoped (@org/package)
  if (name.startsWith('@')) return null;

  // Ignore les packages tres courts (trop de faux positifs)
  if (name.length < MIN_PACKAGE_LENGTH) return null;

  // Ignore les packages avec suffixes legitimes courants
  if (isLegitimateVariant(nameLower)) return null;

  for (let i = 0; i < POPULAR_PACKAGES.length; i++) {
    const popularLower = POPULAR_PACKAGES_LOWER[i];
    const popular = POPULAR_PACKAGES[i];

    // Ignore si c'est exactement le meme
    if (nameLower === popularLower) continue;

    // Ignore si le package populaire est trop court
    if (popular.length < MIN_PACKAGE_LENGTH) continue;

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
    let diffs = 0;
    for (let i = 0; i < typo.length; i++) {
      if (typo[i] !== original[i]) diffs++;
    }
    if (diffs === 2) return 'swapped_chars';
    return 'wrong_char';
  }
  return 'unknown';
}

function levenshteinDistance(a, b) {
  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

module.exports = { scanTyposquatting, levenshteinDistance };