const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');
const { loadCachedIOCs } = require('../ioc/updater.js');

// Cache des hashes: filePath -> { hash, mtime }
const hashCache = new Map();

// Limite de profondeur pour eviter recursion infinie
const MAX_DEPTH = 50;

async function scanHashes(targetPath) {
  const threats = [];
  const iocs = loadCachedIOCs();

  // Utilise Set pour lookup O(1) si disponible, sinon cree un Set
  const knownHashes = iocs.hashesSet instanceof Set
    ? iocs.hashesSet
    : new Set(iocs.hashes || []);

  if (knownHashes.size === 0) {
    return threats;
  }

  const nodeModulesPath = path.join(targetPath, 'node_modules');

  if (!fs.existsSync(nodeModulesPath)) {
    return threats;
  }

  // Set pour tracker les inodes visites (evite boucles symlinks)
  const visitedInodes = new Set();

  const jsFiles = findAllJsFiles(nodeModulesPath, [], visitedInodes, 0);

  for (const file of jsFiles) {
    const hash = computeHashCached(file);

    if (hash && knownHashes.has(hash)) {
      threats.push({
        type: 'known_malicious_hash',
        severity: 'CRITICAL',
        message: `Hash malveillant detecte: ${hash.substring(0, 16)}...`,
        file: path.relative(targetPath, file)
      });
    }
  }

  return threats;
}

/**
 * Calcule le hash SHA256 d'un fichier avec mise en cache
 * Le cache est invalide si le mtime du fichier change
 * @param {string} filePath - Chemin du fichier
 * @returns {string|null} Hash SHA256 ou null en cas d'erreur
 */
function computeHashCached(filePath) {
  try {
    const stat = fs.statSync(filePath);
    const mtime = stat.mtimeMs;

    // Verifier le cache
    const cached = hashCache.get(filePath);
    if (cached && cached.mtime === mtime) {
      return cached.hash;
    }

    // Calculer le hash
    const hash = computeHash(filePath);

    // Mettre en cache
    hashCache.set(filePath, { hash, mtime });

    return hash;
  } catch {
    return null;
  }
}

/**
 * Calcule le hash SHA256 d'un fichier
 * @param {string} filePath - Chemin du fichier
 * @returns {string} Hash SHA256
 */
function computeHash(filePath) {
  const content = fs.readFileSync(filePath);
  return nodeCrypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Recherche recursive de fichiers JS avec protection contre les symlinks
 * @param {string} dir - Repertoire a scanner
 * @param {string[]} results - Tableau accumulateur
 * @param {Set<number>} visitedInodes - Inodes deja visites
 * @param {number} depth - Profondeur actuelle
 * @returns {string[]} Liste des fichiers .js
 */
function findAllJsFiles(dir, results = [], visitedInodes = new Set(), depth = 0) {
  // Protection contre recursion infinie
  if (depth > MAX_DEPTH) {
    return results;
  }

  if (!fs.existsSync(dir)) return results;

  try {
    const items = fs.readdirSync(dir);

    for (const item of items) {
      const fullPath = path.join(dir, item);

      try {
        // Utiliser lstatSync pour detecter les symlinks SANS les suivre
        const lstat = fs.lstatSync(fullPath);

        // Verifier si c'est un symlink
        if (lstat.isSymbolicLink()) {
          // Resoudre le symlink et verifier la cible
          try {
            const realPath = fs.realpathSync(fullPath);
            const realStat = fs.statSync(realPath);

            // Verifier si on a deja visite cet inode (evite boucles)
            if (visitedInodes.has(realStat.ino)) {
              continue; // Boucle detectee, skip
            }

            // Si c'est un repertoire, le parcourir
            if (realStat.isDirectory()) {
              visitedInodes.add(realStat.ino);
              findAllJsFiles(realPath, results, visitedInodes, depth + 1);
            } else if (item.endsWith('.js')) {
              visitedInodes.add(realStat.ino);
              results.push(realPath);
            }
          } catch {
            // Symlink casse ou inaccessible, ignorer
          }
          continue;
        }

        // Marquer l'inode comme visite
        visitedInodes.add(lstat.ino);

        if (lstat.isDirectory()) {
          findAllJsFiles(fullPath, results, visitedInodes, depth + 1);
        } else if (item.endsWith('.js')) {
          results.push(fullPath);
        }
      } catch {
        // Ignore les erreurs de permission
      }
    }
  } catch {
    // Ignore les erreurs de lecture du repertoire
  }

  return results;
}

/**
 * Vide le cache des hashes (utile pour les tests)
 */
function clearHashCache() {
  hashCache.clear();
}

/**
 * Retourne la taille du cache (utile pour debug/monitoring)
 * @returns {number}
 */
function getHashCacheSize() {
  return hashCache.size;
}

module.exports = {
  scanHashes,
  computeHash,
  computeHashCached,
  clearHashCache,
  getHashCacheSize
};
