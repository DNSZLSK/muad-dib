const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');
const { ACORN_OPTIONS } = require('../shared/constants.js');
const { analyzeWithDeobfuscation } = require('../shared/analyze-helper.js');
const {
  handleVariableDeclarator,
  handleCallExpression,
  handleImportExpression,
  handleNewExpression,
  handleLiteral,
  handleAssignmentExpression,
  handleMemberExpression,
  handlePostWalk
} = require('./ast-detectors.js');

const EXCLUDED_FILES = [
  'src/scanner/ast.js',
  'src/scanner/shell.js',
  'src/scanner/package.js',
  'src/response/playbooks.js'
];

async function analyzeAST(targetPath, options = {}) {
  return analyzeWithDeobfuscation(targetPath, analyzeFile, {
    deobfuscate: options.deobfuscate,
    excludedFiles: EXCLUDED_FILES
  });
}

function analyzeFile(content, filePath, basePath) {
  const threats = [];
  let ast;

  try {
    ast = acorn.parse(content, ACORN_OPTIONS);
  } catch {
    // AST parse failed — apply regex fallback for known dangerous patterns

    // Workflow manipulation: reads + writes to .github/workflows
    if (/\.github/.test(content) && /workflows/.test(content) &&
        /writeFileSync|writeFile/.test(content) &&
        /readdirSync|readFileSync/.test(content)) {
      threats.push({
        type: 'workflow_write',
        severity: 'CRITICAL',
        message: 'File reads and modifies .github/workflows — GitHub Actions injection (regex fallback).',
        file: path.relative(basePath, filePath)
      });
    }

    if (content.length > 1000 && content.split(/\r?\n/).length < 10) {
      threats.push({
        type: 'possible_obfuscation',
        severity: 'MEDIUM',
        message: 'File difficult to parse, possibly obfuscated.',
        file: path.relative(basePath, filePath)
      });
    }
    return threats;
  }

  // Shared detection context
  const ctx = {
    threats,
    relFile: path.relative(basePath, filePath),
    dynamicRequireVars: new Set(),
    dangerousCmdVars: new Map(),
    workflowPathVars: new Set(),
    execPathVars: new Map(),
    globalThisAliases: new Set(),
    hasFromCharCode: content.includes('fromCharCode'),
    hasJsReverseShell: /\bnet\.Socket\b/.test(content) &&
      /\.connect\s*\(/.test(content) &&
      /\.pipe\b/.test(content) &&
      (/\bspawn\b/.test(content) || /\bstdin\b/.test(content) || /\bstdout\b/.test(content)),
    hasBinaryFileLiteral: /\.(png|jpg|jpeg|gif|bmp|ico|wasm)\b/i.test(content),
    hasEvalInFile: false
  };

  walk.simple(ast, {
    VariableDeclarator(node) { handleVariableDeclarator(node, ctx); },
    CallExpression(node) { handleCallExpression(node, ctx); },
    ImportExpression(node) { handleImportExpression(node, ctx); },
    NewExpression(node) { handleNewExpression(node, ctx); },
    Literal(node) { handleLiteral(node, ctx); },
    AssignmentExpression(node) { handleAssignmentExpression(node, ctx); },
    MemberExpression(node) { handleMemberExpression(node, ctx); }
  });

  handlePostWalk(ctx);

  return threats;
}

module.exports = { analyzeAST };
