const fs = require('fs');
const path = require('path');
const walk = require('acorn-walk');
const { PARANOID_RULES } = require('../rules/index.js');
const { getMaxFileSize, safeParse } = require('../shared/constants.js');
const { getExtraExcludes, debugLog } = require('../utils.js');

// Paranoid mode scanner
function scanParanoid(targetPath) {
  const threats = [];

  // AST-based paranoid detection patterns
  const PARANOID_AST_DETECTORS = {
    network_access: {
      callNames: new Set(['fetch', 'axios']),
      memberPatterns: [
        { obj: 'http', prop: 'request' }, { obj: 'http', prop: 'get' },
        { obj: 'https', prop: 'request' }, { obj: 'https', prop: 'get' },
        { obj: 'net', prop: 'connect' }
      ],
      newNames: new Set(['XMLHttpRequest'])
    },
    sensitive_file_access: {
      sensitiveStrings: ['.env', '.npmrc', '.ssh', '.git', 'id_rsa', 'credentials', 'secrets']
    },
    dynamic_execution: {
      callNames: new Set(['eval']),
      newNames: new Set(['Function']),
      memberPatterns: [
        { obj: 'vm', prop: 'runInContext' }, { obj: 'vm', prop: 'runInNewContext' },
        { obj: 'vm', prop: 'runInThisContext' }
      ]
    },
    subprocess: {
      callNames: new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync']),
      memberPatterns: [
        { obj: 'child_process', prop: 'exec' }, { obj: 'child_process', prop: 'execSync' },
        { obj: 'child_process', prop: 'spawn' }, { obj: 'child_process', prop: 'fork' }
      ]
    },
    env_access: {
      memberPatterns: [{ obj: 'process', prop: 'env' }]
    }
  };

  function scanFileAST(filePath) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > getMaxFileSize()) return;
      const content = fs.readFileSync(filePath, 'utf8');
      const relFile = path.relative(targetPath, filePath);

      const ast = safeParse(content);
      if (!ast) {
        // Parse failed — fall back to content matching for this file
        scanFileContent(filePath, content, relFile);
        return;
      }

      const found = new Set(); // deduplicate: one finding per rule per file

      // v2.6.5: Track aliases of eval, Function, require for bypass detection
      // e.g., const e = eval; e(code) — or — const F = Function; new F(code)
      const ALIAS_TARGETS = new Set(['eval', 'Function', 'require']);
      const aliases = new Map(); // aliasName → originalName

      walk.simple(ast, {
        VariableDeclarator(node) {
          // const e = eval / const F = Function / const r = require
          if (node.id?.type === 'Identifier' && node.init?.type === 'Identifier' &&
              ALIAS_TARGETS.has(node.init.name)) {
            aliases.set(node.id.name, node.init.name);
          }
        },
        CallExpression(node) {
          // Direct calls: eval(), exec(), fetch(), etc.
          if (node.callee.type === 'Identifier') {
            // Resolve alias to original name if applicable
            const name = aliases.get(node.callee.name) || node.callee.name;
            for (const [ruleKey, detector] of Object.entries(PARANOID_AST_DETECTORS)) {
              if (detector.callNames && detector.callNames.has(name) && !found.has(ruleKey)) {
                found.add(ruleKey);
                const rule = PARANOID_RULES[ruleKey];
                threats.push({
                  type: rule.id, severity: rule.severity.toUpperCase(),
                  message: `${rule.message}: "${node.callee.name}"${aliases.has(node.callee.name) ? ` (alias of ${name})` : ''}`,
                  file: relFile, mitre: rule.mitre
                });
              }
            }
          }
          // Member calls: http.request(), child_process.exec(), etc.
          if (node.callee.type === 'MemberExpression' &&
              node.callee.object?.type === 'Identifier' &&
              node.callee.property?.type === 'Identifier') {
            const obj = node.callee.object.name;
            const prop = node.callee.property.name;
            for (const [ruleKey, detector] of Object.entries(PARANOID_AST_DETECTORS)) {
              if (detector.memberPatterns &&
                  detector.memberPatterns.some(m => m.obj === obj && m.prop === prop) &&
                  !found.has(ruleKey)) {
                found.add(ruleKey);
                const rule = PARANOID_RULES[ruleKey];
                threats.push({
                  type: rule.id, severity: rule.severity.toUpperCase(),
                  message: `${rule.message}: "${obj}.${prop}"`, file: relFile, mitre: rule.mitre
                });
              }
            }
          }
        },
        NewExpression(node) {
          if (node.callee.type === 'Identifier') {
            // Resolve alias: const F = Function; new F(code)
            const name = aliases.get(node.callee.name) || node.callee.name;
            for (const [ruleKey, detector] of Object.entries(PARANOID_AST_DETECTORS)) {
              if (detector.newNames && detector.newNames.has(name) && !found.has(ruleKey)) {
                found.add(ruleKey);
                const rule = PARANOID_RULES[ruleKey];
                threats.push({
                  type: rule.id, severity: rule.severity.toUpperCase(),
                  message: `${rule.message}: "new ${node.callee.name}"${aliases.has(node.callee.name) ? ` (alias of ${name})` : ''}`,
                  file: relFile, mitre: rule.mitre
                });
              }
            }
          }
        },
        MemberExpression(node) {
          // process.env access
          if (node.object?.type === 'Identifier' && node.object.name === 'process' &&
              node.property?.type === 'Identifier' && node.property.name === 'env' &&
              !found.has('env_access')) {
            found.add('env_access');
            const rule = PARANOID_RULES.env_access;
            threats.push({
              type: rule.id, severity: rule.severity.toUpperCase(),
              message: `${rule.message}: "process.env"`, file: relFile, mitre: rule.mitre
            });
          }
        },
        Literal(node) {
          // Sensitive file string literals
          if (typeof node.value === 'string' && !found.has('sensitive_file_access')) {
            const detector = PARANOID_AST_DETECTORS.sensitive_file_access;
            for (const s of detector.sensitiveStrings) {
              if (node.value.includes(s)) {
                found.add('sensitive_file_access');
                const rule = PARANOID_RULES.sensitive_file_access;
                threats.push({
                  type: rule.id, severity: rule.severity.toUpperCase(),
                  message: `${rule.message}: "${s}"`, file: relFile, mitre: rule.mitre
                });
                break;
              }
            }
          }
        }
      });
    } catch (e) {
      debugLog('[PARANOID] AST parse error:', e?.message);
    }
  }

  // Content-based fallback for non-JS files or parse failures
  function scanFileContent(filePath, content, relFile) {
    const contentWithoutUrls = content.replace(/https?:\/\/[^\s"']+/g, '');
    for (const [, rule] of Object.entries(PARANOID_RULES)) {
      for (const pattern of rule.patterns) {
        if (contentWithoutUrls.includes(pattern)) {
          threats.push({
            type: rule.id, severity: rule.severity.toUpperCase(),
            message: `${rule.message}: "${pattern}"`, file: relFile, mitre: rule.mitre
          });
        }
      }
    }
  }

  function scanFile(filePath) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > getMaxFileSize()) return;
      const ext = path.extname(filePath);
      if (ext === '.js' || ext === '.mjs' || ext === '.cjs') {
        scanFileAST(filePath);
      } else {
        const content = fs.readFileSync(filePath, 'utf8');
        const relFile = path.relative(targetPath, filePath);
        scanFileContent(filePath, content, relFile);
      }
    } catch (e) {
      debugLog('[PARANOID] file read error:', e?.message);
    }
  }

  function walkDir(dir, depth) {
    if (depth > 50) return; // Max depth guard (IDX-06)
    const excluded = ['node_modules', '.git', '.muaddib-cache', ...getExtraExcludes()];
    try {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const fullPath = path.join(dir, file);
        // Use lstatSync to avoid following symlinks
        const stat = fs.lstatSync(fullPath);

        if (stat.isSymbolicLink()) continue;

        if (stat.isDirectory()) {
          const rel = path.relative(targetPath, fullPath).replace(/\\/g, '/');
          const isExcluded = excluded.includes(file) ||
            excluded.some(ex => rel === ex || rel.startsWith(ex + '/'));
          if (!isExcluded) {
            walkDir(fullPath, depth + 1);
          }
        } else if (file.endsWith('.js') || file.endsWith('.mjs') || file.endsWith('.cjs') ||
                   file.endsWith('.json') || file.endsWith('.sh')) {
          scanFile(fullPath);
        }
      }
    } catch (e) {
      debugLog('[PARANOID] walkDir error:', e?.message);
    }
  }

  walkDir(targetPath, 0);
  return threats;
}

module.exports = { scanParanoid };
