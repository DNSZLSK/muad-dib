const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const acorn = require('acorn');
const walk = require('acorn-walk');
const { findJsFiles, forEachSafeFile, debugLog } = require('./utils.js');
const { fetchPackageMetadata, getLatestVersions } = require('./temporal-analysis.js');
const { downloadToFile, extractTarGz, sanitizePackageName } = require('./shared/download.js');

const { MAX_FILE_SIZE, getMaxFileSize, ACORN_OPTIONS, safeParse } = require('./shared/constants.js');

const REGISTRY_URL = 'https://registry.npmjs.org';
const METADATA_TIMEOUT = 10_000;

const SENSITIVE_PATHS = [
  '/etc/passwd', '/etc/shadow', '.env', '.npmrc', '.ssh',
  '.aws/credentials', '.bash_history', '.gitconfig'
];

// Severity mapping for each pattern
const PATTERN_SEVERITY = {
  child_process: 'CRITICAL',
  eval: 'CRITICAL',
  Function: 'CRITICAL',
  'net.connect': 'CRITICAL',
  'process.env': 'HIGH',
  fetch: 'HIGH',
  http_request: 'HIGH',
  https_request: 'HIGH',
  'dns.lookup': 'MEDIUM',
  'fs.readFile_sensitive': 'MEDIUM'
};

// --- HTTP helpers ---

/**
 * Fetch version-specific metadata from npm registry.
 * @param {string} packageName
 * @param {string} version
 * @returns {Promise<object>}
 */
function fetchVersionMetadata(packageName, version) {
  const encodedName = encodeURIComponent(packageName).replace('%40', '@');
  const url = `${REGISTRY_URL}/${encodedName}/${encodeURIComponent(version)}`;
  const urlObj = new URL(url);

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'GET',
      headers: { 'User-Agent': 'MUADDIB-Scanner/3.0', 'Accept': 'application/json' }
    }, (res) => {
      if (res.statusCode === 404) {
        res.resume();
        return reject(new Error(`Version ${version} not found for package ${packageName}`));
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        res.resume();
        return reject(new Error(`Registry returned HTTP ${res.statusCode} for ${packageName}@${version}`));
      }
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error(`Invalid JSON for ${packageName}@${version}: ${e.message}`)); }
      });
    });
    req.on('error', err => reject(new Error(`Network error fetching ${packageName}@${version}: ${err.message}`)));
    req.setTimeout(METADATA_TIMEOUT, () => {
      req.destroy();
      reject(new Error(`Timeout fetching metadata for ${packageName}@${version}`));
    });
    req.end();
  });
}

// --- Core functions ---

/**
 * Fetch and extract a specific version of an npm package.
 * @param {string} packageName - npm package name (scoped or unscoped)
 * @param {string} version - Exact version string (e.g. "4.17.21")
 * @returns {Promise<{dir: string, cleanup: Function}>}
 */
async function fetchPackageTarball(packageName, version) {
  const meta = await fetchVersionMetadata(packageName, version);
  const tarballUrl = meta.dist && meta.dist.tarball;
  if (!tarballUrl) {
    throw new Error(`No tarball URL found for ${packageName}@${version}`);
  }

  const safeName = sanitizePackageName(packageName);
  const tmpBase = path.join(os.tmpdir(), 'muaddib-ast-diff');
  if (!fs.existsSync(tmpBase)) fs.mkdirSync(tmpBase, { recursive: true });
  const tmpDir = fs.mkdtempSync(path.join(tmpBase, `${safeName}-${version}-`));

  let extractedDir;
  try {
    const tgzPath = path.join(tmpDir, 'package.tar.gz');
    await downloadToFile(tarballUrl, tgzPath);
    extractedDir = extractTarGz(tgzPath, tmpDir);
  } catch (err) {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { debugLog('tmpDir cleanup failed:', e.message); }
    throw err;
  }

  const cleanup = () => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { debugLog('tmpDir cleanup failed:', e.message); }
  };

  return { dir: extractedDir, cleanup };
}

/**
 * Extract dangerous AST patterns from all .js files in a directory.
 * @param {string} directory - Path to the extracted package
 * @returns {Set<string>} Set of pattern names found
 */
function extractDangerousPatterns(directory) {
  const patterns = new Set();
  const files = findJsFiles(directory);
  forEachSafeFile(files, (file, content) => {
    extractPatternsFromSource(content, patterns);
  });
  return patterns;
}

/**
 * Parse a single JS source string and add detected pattern names to the set.
 * @param {string} source - JS source code
 * @param {Set<string>} patterns - Accumulator set
 */
function extractPatternsFromSource(source, patterns) {
  let ast = safeParse(source);
  if (!ast) return;

  walk.simple(ast, {
    CallExpression(node) {
      // eval()
      if (node.callee.type === 'Identifier' && node.callee.name === 'eval') {
        patterns.add('eval');
      }
      // Function() as a call
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
        patterns.add('Function');
      }
      // require('module')
      if (node.callee.type === 'Identifier' && node.callee.name === 'require' &&
          node.arguments.length > 0 && node.arguments[0].type === 'Literal') {
        const mod = node.arguments[0].value;
        if (mod === 'child_process') patterns.add('child_process');
        if (mod === 'http') patterns.add('http_request');
        if (mod === 'https') patterns.add('https_request');
        if (mod === 'dns') patterns.add('dns.lookup');
        if (mod === 'net') patterns.add('net.connect');
      }
      // fetch()
      if (node.callee.type === 'Identifier' && node.callee.name === 'fetch') {
        patterns.add('fetch');
      }
      // dns.lookup(), dns.resolve(), etc.
      if (node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' && node.callee.object.name === 'dns') {
        patterns.add('dns.lookup');
      }
      // net.connect(), net.createConnection()
      if (node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' && node.callee.object.name === 'net') {
        patterns.add('net.connect');
      }
      // http.request(), http.get(), https.request(), https.get()
      if (node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier') {
        if (node.callee.object.name === 'http') patterns.add('http_request');
        if (node.callee.object.name === 'https') patterns.add('https_request');
      }
      // fs.readFile/readFileSync on sensitive paths
      if (node.callee.type === 'MemberExpression' &&
          node.callee.object.type === 'Identifier' && node.callee.object.name === 'fs' &&
          node.callee.property &&
          (node.callee.property.name === 'readFile' || node.callee.property.name === 'readFileSync')) {
        if (node.arguments.length > 0 && node.arguments[0].type === 'Literal' &&
            typeof node.arguments[0].value === 'string') {
          const filePath = node.arguments[0].value;
          if (SENSITIVE_PATHS.some(s => filePath.includes(s))) {
            patterns.add('fs.readFile_sensitive');
          }
        }
      }
    },

    NewExpression(node) {
      // new Function()
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
        patterns.add('Function');
      }
    },

    MemberExpression(node) {
      // process.env
      if (node.object.type === 'Identifier' && node.object.name === 'process' &&
          node.property && node.property.name === 'env') {
        patterns.add('process.env');
      }
    },

    ImportDeclaration(node) {
      // import ... from 'child_process'
      if (node.source && node.source.type === 'Literal') {
        const mod = node.source.value;
        if (mod === 'child_process') patterns.add('child_process');
        if (mod === 'http') patterns.add('http_request');
        if (mod === 'https') patterns.add('https_request');
        if (mod === 'dns') patterns.add('dns.lookup');
        if (mod === 'net') patterns.add('net.connect');
      }
    }
  });
}

/**
 * Compare AST patterns between two versions of a package.
 * @param {string} packageName - npm package name
 * @param {string} versionA - Older version
 * @param {string} versionB - Newer version
 * @returns {Promise<{added: string[], removed: string[]}>}
 *   added   = patterns in versionB but NOT in versionA (new dangerous capabilities)
 *   removed = patterns in versionA but NOT in versionB
 */
async function compareAstPatterns(packageName, versionA, versionB) {
  let cleanupA = null;
  let cleanupB = null;

  try {
    const [resultA, resultB] = await Promise.all([
      fetchPackageTarball(packageName, versionA),
      fetchPackageTarball(packageName, versionB)
    ]);
    cleanupA = resultA.cleanup;
    cleanupB = resultB.cleanup;

    const patternsA = extractDangerousPatterns(resultA.dir);
    const patternsB = extractDangerousPatterns(resultB.dir);

    const added = [...patternsB].filter(p => !patternsA.has(p));
    const removed = [...patternsA].filter(p => !patternsB.has(p));

    return { added, removed };
  } finally {
    if (cleanupA) cleanupA();
    if (cleanupB) cleanupB();
  }
}

/**
 * Detect sudden dangerous API additions between the two most recent versions.
 * @param {string} packageName - npm package name
 * @returns {Promise<object>} Detection result
 */
async function detectSuddenAstChanges(packageName) {
  const metadata = await fetchPackageMetadata(packageName);
  const latest = getLatestVersions(metadata, 2);

  if (latest.length < 2) {
    return {
      packageName,
      latestVersion: latest.length > 0 ? latest[0].version : null,
      previousVersion: null,
      suspicious: false,
      findings: [],
      metadata: {
        latestPublishedAt: latest.length > 0 ? latest[0].publishedAt : null,
        previousPublishedAt: null
      }
    };
  }

  const [newestEntry, previousEntry] = latest;
  const diff = await compareAstPatterns(packageName, previousEntry.version, newestEntry.version);

  const findings = [];
  for (const pattern of diff.added) {
    const severity = PATTERN_SEVERITY[pattern] || 'MEDIUM';
    findings.push({
      type: 'dangerous_api_added',
      pattern,
      severity,
      description: `Package now uses ${pattern} (not present in previous version)`
    });
  }

  return {
    packageName,
    latestVersion: newestEntry.version,
    previousVersion: previousEntry.version,
    suspicious: findings.length > 0,
    findings,
    metadata: {
      latestPublishedAt: newestEntry.publishedAt,
      previousPublishedAt: previousEntry.publishedAt
    }
  };
}

module.exports = {
  fetchPackageTarball,
  extractDangerousPatterns,
  compareAstPatterns,
  detectSuddenAstChanges,
  // Exported for testing
  extractPatternsFromSource,
  fetchVersionMetadata,
  SENSITIVE_PATHS,
  PATTERN_SEVERITY
};
