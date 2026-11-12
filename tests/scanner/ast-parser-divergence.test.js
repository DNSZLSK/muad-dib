const fs = require('fs');
const os = require('os');
const path = require('path');
const { asyncTest, test, assert, runScanDirect, cleanupTemp } = require('../test-utils');
const { safeParse, clearASTCache } = require('../../src/shared/constants.js');
const { nodeAcceptsSyntax, resetNodeSyntaxBudget, MAX_CHECKS_PER_SCAN } = require('../../src/shared/node-syntax-check.js');

function makeTempPkg(jsContent, fileName = 'index.js') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pdiv-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ name: 'test-pdiv-pkg', version: '1.0.0' }));
  fs.writeFileSync(path.join(tmp, fileName), jsContent);
  return tmp;
}
const types = r => (r.threats || []).map(t => t.type);

// Valid for Node 24 (`node --check`), rejected by acorn 8.18 at any ecmaVersion:
// source phase imports. Used as the residual divergence vector.
const SOURCE_PHASE = 'import source wasmMod from "./payload.wasm";\n';
// Valid for Node (CommonJS wrapper), rejected by safeParse before the ecmaVersion /
// allowReturnOutsideFunction fix: a single top-level return at the end of the file.
const VM_PAYLOAD = `
const vm = require('vm');
const payload = Buffer.from('Y29uc29sZS5sb2coImV4ZWMiKQ==', 'base64').toString();
vm.runInThisContext(payload);
`;

async function runAstParserDivergenceTests() {
  console.log('\n=== AST PARSER DIVERGENCE TESTS ===\n');

  // --- oracle ---
  test('PDIV: oracle accepts valid ESM and valid CommonJS with top-level return', () => {
    resetNodeSyntaxBudget();
    assert(nodeAcceptsSyntax('import a from "b";\nexport const x = a;\n') === true, 'valid ESM must be accepted');
    assert(nodeAcceptsSyntax('module.exports = 1;\nreturn;\n') === true, 'CJS top-level return must be accepted');
  });

  test('PDIV: oracle rejects ESM-looking garbage (the node --check <file.js> trap)', () => {
    resetNodeSyntaxBudget();
    assert(nodeAcceptsSyntax('import a from "b";\nfoo(\n') === false, 'broken ESM must be rejected');
    assert(nodeAcceptsSyntax('const x = <div className="a"/>;\n') === false, 'JSX must be rejected');
  });

  test('PDIV: oracle budget is bounded per scan', () => {
    resetNodeSyntaxBudget();
    for (let i = 0; i < MAX_CHECKS_PER_SCAN; i++) nodeAcceptsSyntax('}');
    assert(nodeAcceptsSyntax('const ok = 1;') === null, 'budget exhausted must return null, not spawn');
    resetNodeSyntaxBudget();
    assert(nodeAcceptsSyntax('const ok = 1;') === true, 'reset restores the budget');
  });

  // --- root cause: safeParse sees modern syntax and top-level return ---
  test('PDIV: safeParse parses ES2025/2026 syntax and CommonJS top-level return', () => {
    clearASTCache();
    for (const [name, code] of Object.entries({
      importAttributes: 'import d from "./x.json" with { type: "json" };\n',
      usingDecl: '{ using r = getRes(); }\n',
      regexpModifiers: 'const r = /(?i:abc)def/;\n',
      dupNamedGroups: 'const r = /(?<y>a)|(?<y>b)/;\n',
      topLevelReturn: 'module.exports = 1;\nreturn;\n'
    })) assert(safeParse(code) !== null, name + ' must parse');
  });

  // --- positive end to end ---
  await asyncTest('PDIV-POS: payload followed by a top-level return is analyzed (vm_code_execution)', async () => {
    const tmp = makeTempPkg(VM_PAYLOAD + 'return;\n');
    try {
      const t = types(await runScanDirect(tmp));
      assert(t.includes('vm_code_execution'), 'top-level return must not blind the AST scanner, got: ' + t.join(','));
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PDIV-POS: file Node accepts but acorn rejects -> parser_divergence', async () => {
    const tmp = makeTempPkg(SOURCE_PHASE + VM_PAYLOAD, 'index.mjs');
    try {
      const r = await runScanDirect(tmp);
      const hit = (r.threats || []).find(t => t.type === 'parser_divergence');
      assert(hit, 'parser_divergence expected, got: ' + types(r).join(','));
      assert(hit.severity === 'MEDIUM', 'severity MEDIUM expected, got ' + hit.severity);
      assert(hit.file === 'index.mjs', 'file must be index.mjs, got ' + hit.file);
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PDIV-POS: one deeply nested padding line (acorn stack overflow) -> parser_divergence', async () => {
    // Parser-null audit 2026-11-05: this single line drops a 100-score payload to 2 on master.
    const pad = 'const pad = ' + Array.from({ length: 10000 }, () => "'a'").join(' + ') + ';\n';
    const tmp = makeTempPkg(VM_PAYLOAD + pad);
    try {
      const t = types(await runScanDirect(tmp));
      assert(t.includes('parser_divergence'), 'nesting overflow must raise parser_divergence, got: ' + t.join(','));
    } finally { cleanupTemp(tmp); }
  });

  // --- benign ---
  await asyncTest('PDIV-NEG: JSX in a .js file (rejected by acorn AND Node) -> no parser_divergence', async () => {
    const tmp = makeTempPkg('import React from "react";\nexport const A = () => (<div className="x">hi</div>);\n');
    try {
      const t = types(await runScanDirect(tmp));
      assert(!t.includes('parser_divergence'), 'JSX must not raise parser_divergence, got: ' + t.join(','));
    } finally { cleanupTemp(tmp); }
  });

  await asyncTest('PDIV-NEG: ES2025 import attributes (benign corpus class, 179 files) -> no parser_divergence', async () => {
    const tmp = makeTempPkg('import cfg from "./config.json" with { type: "json" };\nexport default cfg.name;\n', 'index.mjs');
    fs.writeFileSync(path.join(tmp, 'config.json'), '{"name":"x"}');
    try {
      const t = types(await runScanDirect(tmp));
      assert(!t.includes('parser_divergence'), 'import attributes must parse, got: ' + t.join(','));
    } finally { cleanupTemp(tmp); }
  });
}

module.exports = { runAstParserDivergenceTests };
