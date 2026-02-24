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
    hasEvalInFile: false,
    // SANDWORM_MODE: zlib inflate + base64 + eval co-occurrence
    hasZlibInflate: /\brequire\s*\(\s*['"]zlib['"]\s*\)/.test(content) || /\bzlib\s*\.\s*inflate/.test(content),
    hasBase64Decode: /Buffer\.from\s*\([^)]*,\s*['"]base64['"]/.test(content),
    hasDynamicExec: false,  // set in handleCallExpression for eval/Function/Module._compile
    // SANDWORM_MODE: write + execute + delete anti-forensics
    hasTempFileWrite: false,
    hasTempFileExec: false,
    hasFileDelete: false,
    hasTmpdirInContent: /\btmpdir\b|\/dev\/shm\b|\/tmp\b/i.test(content),
    // SANDWORM_MODE P2: env harvesting co-occurrence
    hasEnvEnumeration: false,  // Object.entries/keys/values(process.env)
    hasEnvHarvestPattern: /\b(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|NPM|AWS|SSH|WEBHOOK)\b/.test(content),
    // SANDWORM_MODE P2: DNS exfiltration co-occurrence
    hasDnsRequire: /\brequire\s*\(\s*['"]dns['"]\s*\)/.test(content) || /\bdns\s*\.\s*resolve/.test(content),
    hasBase64Encode: /\.toString\s*\(\s*['"]base64(url)?['"]\s*\)/.test(content),
    hasDnsLoop: false,  // set when dns call inside loop context detected
    // SANDWORM_MODE P2: LLM API key harvesting
    llmApiKeyCount: 0
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
