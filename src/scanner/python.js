const fs = require('fs');
const path = require('path');

// ============================================
// REQUIREMENTS.TXT PARSER
// ============================================

/**
 * Parse a requirements.txt file into dependency objects.
 * Supports: pinned (==), minimum (>=), compatible (~=), no version, extras ([extra]),
 * comments (#), blank lines, and recursive includes (-r file.txt).
 *
 * @param {string} filePath - Absolute path to requirements.txt
 * @param {Set} [visited] - Already-visited files (cycle protection)
 * @returns {Array<{name: string, version: string, file: string}>}
 */
function parseRequirementsTxt(filePath, visited) {
  if (!fs.existsSync(filePath)) return [];

  if (!visited) visited = new Set();
  const resolved = path.resolve(filePath);
  if (visited.has(resolved)) return [];
  visited.add(resolved);

  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);
  const deps = [];
  const relFile = filePath;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip blanks and comments
    if (!line || line.startsWith('#')) continue;

    // Recursive include: -r other.txt or --requirement other.txt
    const includeMatch = line.match(/^(?:-r|--requirement)\s+(.+)$/);
    if (includeMatch) {
      const includePath = path.resolve(path.dirname(filePath), includeMatch[1].trim());
      // Path traversal guard: ensure included file stays within the directory tree
      // Use case-insensitive comparison on Windows (PY-01)
      const baseDir = path.resolve(path.dirname(filePath));
      const isWithin = process.platform === 'win32'
        ? includePath.toLowerCase().startsWith(baseDir.toLowerCase())
        : includePath.startsWith(baseDir);
      if (!isWithin) continue;
      const included = parseRequirementsTxt(includePath, visited);
      deps.push(...included);
      continue;
    }

    // Skip options lines (-i, --index-url, -f, --find-links, -e, etc.)
    if (line.startsWith('-')) continue;

    // Parse dependency line
    const parsed = parseRequirementLine(line);
    if (parsed) {
      deps.push({ name: parsed.name, version: parsed.version, file: relFile });
    }
  }

  return deps;
}

/**
 * Parse a single requirements line into name + version.
 * Handles: package==1.0, package>=1.0, package~=1.0, package!=1.0,
 *          package<=1.0, package<1.0, package>1.0, package[extra]==1.0,
 *          package (no version), inline comments (# ...), environment markers (; ...)
 *
 * @param {string} line - A single requirement line
 * @returns {{name: string, version: string}|null}
 */
function parseRequirementLine(line) {
  // Strip inline comments
  let clean = line.split('#')[0].trim();
  if (!clean) return null;

  // Strip environment markers (e.g. ; python_version >= "3.6")
  clean = clean.split(';')[0].trim();
  if (!clean) return null;

  // Match: name[extras] operator version
  // Operators: ==, >=, <=, ~=, !=, >, <
  const match = clean.match(/^([a-zA-Z0-9_][a-zA-Z0-9._-]*)(?:\[([^\]]*)\])?\s*(==|>=|<=|~=|!=|>|<)\s*([^\s,;]+)/);
  if (match) {
    return {
      name: normalizePythonName(match[1]),
      version: match[3] + match[4]
    };
  }

  // No version specified: just a package name (possibly with extras)
  const nameMatch = clean.match(/^([a-zA-Z0-9_][a-zA-Z0-9._-]*)(?:\[([^\]]*)\])?$/);
  if (nameMatch) {
    return {
      name: normalizePythonName(nameMatch[1]),
      version: '*'
    };
  }

  return null;
}

// ============================================
// SETUP.PY PARSER
// ============================================

/**
 * Parse a setup.py file to extract install_requires dependencies.
 * Uses regex-based extraction (not full Python AST).
 *
 * @param {string} filePath - Absolute path to setup.py
 * @returns {Array<{name: string, version: string, file: string}>}
 */
function parseSetupPy(filePath) {
  if (!fs.existsSync(filePath)) return [];

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }
  const deps = [];

  // Match install_requires=[...] — handles multiline lists
  const installRequiresMatch = content.match(/install_requires\s*=\s*\[([^\]]*)\]/s);
  if (installRequiresMatch) {
    const listContent = installRequiresMatch[1];
    const items = extractStringItems(listContent);
    for (const item of items) {
      const parsed = parseRequirementLine(item);
      if (parsed) {
        deps.push({ name: parsed.name, version: parsed.version, file: filePath });
      }
    }
  }

  // Also check setup_requires
  const setupRequiresMatch = content.match(/setup_requires\s*=\s*\[([^\]]*)\]/s);
  if (setupRequiresMatch) {
    const items = extractStringItems(setupRequiresMatch[1]);
    for (const item of items) {
      const parsed = parseRequirementLine(item);
      if (parsed) {
        deps.push({ name: parsed.name, version: parsed.version, file: filePath });
      }
    }
  }

  return deps;
}

/**
 * Extract string literals from a Python list body.
 * Handles both single-quoted and double-quoted strings.
 * @param {string} listBody - Content between [ and ]
 * @returns {string[]}
 */
function extractStringItems(listBody) {
  const items = [];
  const regex = /(?:'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)")/g;
  let match;
  while ((match = regex.exec(listBody)) !== null) {
    const value = (match[1] !== undefined ? match[1] : match[2]).trim();
    if (value) items.push(value);
  }
  return items;
}

// ============================================
// PYPROJECT.TOML PARSER
// ============================================

/**
 * Parse a pyproject.toml file to extract dependencies.
 * Handles both PEP 621 ([project].dependencies) and Poetry ([tool.poetry.dependencies]).
 * Uses a lightweight TOML parser (no external dependency).
 *
 * @param {string} filePath - Absolute path to pyproject.toml
 * @returns {Array<{name: string, version: string, file: string}>}
 */
function parsePyprojectToml(filePath) {
  if (!fs.existsSync(filePath)) return [];

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }
  const deps = [];

  // --- PEP 621: [project] dependencies = [...] ---
  const projectDeps = extractTomlArray(content, 'project', 'dependencies');
  for (const item of projectDeps) {
    const parsed = parseRequirementLine(item);
    if (parsed) {
      deps.push({ name: parsed.name, version: parsed.version, file: filePath });
    }
  }

  // --- Poetry: [tool.poetry.dependencies] ---
  const poetryDeps = extractTomlTable(content, 'tool.poetry.dependencies');
  for (const [name, value] of poetryDeps) {
    // Skip python itself
    if (name === 'python') continue;
    const version = parsePoetryVersion(value);
    deps.push({
      name: normalizePythonName(name),
      version: version,
      file: filePath
    });
  }

  return deps;
}

/**
 * Extract an array value from a TOML section.
 * e.g., [project] dependencies = ["flask>=2.0", "requests"]
 *
 * @param {string} content - Full TOML content
 * @param {string} section - Section name (e.g., "project")
 * @param {string} key - Key name (e.g., "dependencies")
 * @returns {string[]}
 */
function extractTomlArray(content, section, key) {
  const lines = content.split(/\r?\n/);
  let inSection = false;
  let collecting = false;
  let buffer = '';

  for (const line of lines) {
    const trimmed = line.trim();

    // Detect section headers (both [section] and [[section]])
    const sectionMatch = trimmed.match(/^\[{1,2}([^\]]+)\]{1,2}$/);
    if (sectionMatch) {
      if (collecting) break; // Finished collecting if we hit a new section
      inSection = (sectionMatch[1].trim() === section);
      continue;
    }

    if (!inSection) continue;

    // Look for key = [...]
    if (!collecting) {
      const keyMatch = trimmed.match(new RegExp('^' + escapeRegex(key) + '\\s*=\\s*(.*)$'));
      if (keyMatch) {
        buffer = keyMatch[1].trim();
        if (buffer.startsWith('[')) {
          collecting = true;
          if (buffer.includes(']')) {
            // Single-line array
            return extractStringItems(buffer);
          }
        }
      }
    } else {
      buffer += ' ' + trimmed;
      if (trimmed.includes(']')) {
        return extractStringItems(buffer);
      }
    }
  }

  if (collecting) {
    return extractStringItems(buffer);
  }

  return [];
}

/**
 * Extract key-value pairs from a TOML table section.
 * e.g., [tool.poetry.dependencies]
 *        flask = "^2.0"
 *        requests = {version = "^2.28", optional = true}
 *
 * @param {string} content - Full TOML content
 * @param {string} section - Dotted section name
 * @returns {Array<[string, string]>}  Array of [name, versionSpec] pairs
 */
function extractTomlTable(content, section) {
  const lines = content.split(/\r?\n/);
  let inSection = false;
  const pairs = [];

  for (const line of lines) {
    const trimmed = line.trim();

    // Detect section headers (both [section] and [[section]])
    const sectionMatch = trimmed.match(/^\[{1,2}([^\]]+)\]{1,2}$/);
    if (sectionMatch) {
      const sectionName = sectionMatch[1].trim();
      if (sectionName === section) {
        inSection = true;
        continue;
      } else if (inSection) {
        break; // New section, stop
      }
      continue;
    }

    if (!inSection) continue;
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Parse key = value (extended to support dots in package names)
    const kvMatch = trimmed.match(/^([a-zA-Z0-9_.][a-zA-Z0-9_.-]*)\s*=\s*(.+)$/);
    if (kvMatch) {
      pairs.push([kvMatch[1].trim(), kvMatch[2].trim()]);
    }
  }

  return pairs;
}

/**
 * Parse a Poetry version specifier from TOML value.
 * Handles: "^2.0", {version = "^2.0", optional = true}, ">=1.0,<2.0"
 *
 * @param {string} value - TOML value string
 * @returns {string} Version spec or '*'
 */
function parsePoetryVersion(value) {
  // Simple string: "^2.0" or ">=1.0"
  const simpleMatch = value.match(/^["']([^"']+)["']$/);
  if (simpleMatch) {
    const ver = simpleMatch[1].trim();
    return ver === '*' ? '*' : ver;
  }

  // Inline table: {version = "^2.0", ...}
  const tableMatch = value.match(/version\s*=\s*["']([^"']+)["']/);
  if (tableMatch) {
    const ver = tableMatch[1].trim();
    return ver === '*' ? '*' : ver;
  }

  return '*';
}

// ============================================
// MAIN DETECTION FUNCTION
// ============================================

/**
 * Detect a Python project and parse all dependency files.
 * Searches for: requirements.txt, requirements/*.txt, setup.py, pyproject.toml
 *
 * @param {string} targetPath - Path to the project root
 * @returns {Array<{name: string, version: string, file: string}>} Deduplicated dependencies
 */
function detectPythonProject(targetPath) {
  const deps = [];

  // 1. requirements.txt at root
  const reqTxt = path.join(targetPath, 'requirements.txt');
  if (fs.existsSync(reqTxt)) {
    deps.push(...parseRequirementsTxt(reqTxt));
  }

  // 2. requirements/*.txt (common pattern: requirements/dev.txt, requirements/prod.txt)
  const reqDir = path.join(targetPath, 'requirements');
  if (fs.existsSync(reqDir) && fs.statSync(reqDir).isDirectory()) {
    const files = fs.readdirSync(reqDir);
    for (const file of files) {
      if (file.endsWith('.txt')) {
        const reqFile = path.join(reqDir, file);
        deps.push(...parseRequirementsTxt(reqFile));
      }
    }
  }

  // 3. setup.py
  const setupPy = path.join(targetPath, 'setup.py');
  if (fs.existsSync(setupPy)) {
    deps.push(...parseSetupPy(setupPy));
  }

  // 4. pyproject.toml
  const pyproject = path.join(targetPath, 'pyproject.toml');
  if (fs.existsSync(pyproject)) {
    deps.push(...parsePyprojectToml(pyproject));
  }

  // Deduplicate by name (keep first occurrence, which has highest priority file)
  return deduplicateDeps(deps);
}

/**
 * Deduplicate dependencies by name, keeping the first occurrence.
 * @param {Array<{name: string, version: string, file: string}>} deps
 * @returns {Array<{name: string, version: string, file: string}>}
 */
function deduplicateDeps(deps) {
  const seen = new Set();
  const result = [];
  for (const dep of deps) {
    if (!seen.has(dep.name)) {
      seen.add(dep.name);
      result.push(dep);
    }
  }
  return result;
}

// ============================================
// UTILITIES
// ============================================

/**
 * Normalize a Python package name.
 * PEP 503: all comparisons should be case-insensitive, with hyphens/underscores/periods equivalent.
 * @param {string} name
 * @returns {string}
 */
function normalizePythonName(name) {
  return name.toLowerCase().replace(/[-_.]+/g, '-');
}

/**
 * Escape special regex characters in a string.
 * @param {string} str
 * @returns {string}
 */
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

module.exports = {
  parseRequirementsTxt,
  parseSetupPy,
  parsePyprojectToml,
  detectPythonProject,
  normalizePythonName
};
