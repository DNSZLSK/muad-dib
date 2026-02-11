const fs = require('fs');
const path = require('path');

/**
 * Scan a project for Python dependencies.
 * Parses requirements.txt, setup.py, and pyproject.toml.
 * @param {string} targetPath - Project root path
 * @returns {Array<{name: string, version: string, source: string}>}
 */
function scanPython(targetPath) {
  const deps = [];

  // 1. requirements.txt
  const reqPath = path.join(targetPath, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const content = fs.readFileSync(reqPath, 'utf8');
      deps.push(...parseRequirementsTxt(content));
    } catch { /* ignore */ }
  }

  // 2. setup.py
  const setupPath = path.join(targetPath, 'setup.py');
  if (fs.existsSync(setupPath)) {
    try {
      const content = fs.readFileSync(setupPath, 'utf8');
      deps.push(...parseSetupPy(content));
    } catch { /* ignore */ }
  }

  // 3. pyproject.toml
  const pyprojectPath = path.join(targetPath, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath)) {
    try {
      const content = fs.readFileSync(pyprojectPath, 'utf8');
      deps.push(...parsePyprojectToml(content));
    } catch { /* ignore */ }
  }

  // Deduplicate by normalized name
  const seen = new Set();
  return deps.filter(d => {
    const key = normalizePyPI(d.name);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * PEP 503 normalization: lowercase, replace [-_.] with single dash
 */
function normalizePyPI(name) {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

/**
 * Parse requirements.txt format.
 * Handles: name==version, name>=version, name~=version, name (no version), comments, -r includes
 */
function parseRequirementsTxt(content) {
  const deps = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;

    // Match: name[extras] operator version ; markers
    const match = trimmed.match(/^([a-zA-Z0-9][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*(?:([=!<>~]=?)\s*([^\s;,]+))?/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[3] || '*',
        source: 'requirements.txt'
      });
    }
  }
  return deps;
}

/**
 * Parse setup.py install_requires=[...] pattern.
 */
function parseSetupPy(content) {
  const deps = [];
  const match = content.match(/install_requires\s*=\s*\[([\s\S]*?)\]/);
  if (match) {
    const items = match[1].match(/['"]([^'"]+)['"]/g);
    if (items) {
      for (const item of items) {
        const clean = item.replace(/['"]/g, '').trim();
        const nameMatch = clean.match(/^([a-zA-Z0-9][a-zA-Z0-9._-]*)/);
        if (nameMatch) {
          const versionMatch = clean.match(/[=!<>~]=\s*(.+)/);
          deps.push({
            name: nameMatch[1],
            version: versionMatch ? versionMatch[1].trim() : '*',
            source: 'setup.py'
          });
        }
      }
    }
  }
  return deps;
}

/**
 * Parse pyproject.toml [project] dependencies=[...] pattern.
 */
function parsePyprojectToml(content) {
  const deps = [];
  const sectionMatch = content.match(/\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
  if (sectionMatch) {
    const items = sectionMatch[1].match(/['"]([^'"]+)['"]/g);
    if (items) {
      for (const item of items) {
        const clean = item.replace(/['"]/g, '').trim();
        const nameMatch = clean.match(/^([a-zA-Z0-9][a-zA-Z0-9._-]*)/);
        if (nameMatch) {
          const versionMatch = clean.match(/[=!<>~]=\s*(.+)/);
          deps.push({
            name: nameMatch[1],
            version: versionMatch ? versionMatch[1].trim() : '*',
            source: 'pyproject.toml'
          });
        }
      }
    }
  }
  return deps;
}

module.exports = { scanPython, normalizePyPI };
