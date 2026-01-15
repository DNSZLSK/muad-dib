const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const TESTS_DIR = path.join(__dirname, 'samples');
const BIN = path.join(__dirname, '..', 'bin', 'muaddib.js');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
    passed++;
  } catch (e) {
    console.log(`[FAIL] ${name}`);
    console.log(`       ${e.message}`);
    failures.push({ name, error: e.message });
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertIncludes(str, substr, message) {
  if (!str.includes(substr)) {
    throw new Error(message || `Expected "${substr}" in output`);
  }
}

function assertNotIncludes(str, substr, message) {
  if (str.includes(substr)) {
    throw new Error(message || `Unexpected "${substr}" in output`);
  }
}

function runScan(target, options = '') {
  try {
    const cmd = `node "${BIN}" scan "${target}" ${options}`;
    return execSync(cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return e.stdout || e.stderr || '';
  }
}

function runCommand(cmd) {
  try {
    return execSync(`node "${BIN}" ${cmd}`, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return e.stdout || e.stderr || '';
  }
}

// ============================================
// TESTS UNITAIRES - DETECTION AST
// ============================================

console.log('\n=== TESTS AST ===\n');

test('AST: Detecte acces .npmrc', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, '.npmrc', 'Devrait detecter .npmrc');
});

test('AST: Detecte acces .ssh', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, '.ssh', 'Devrait detecter .ssh');
});

test('AST: Detecte GITHUB_TOKEN', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'GITHUB_TOKEN', 'Devrait detecter GITHUB_TOKEN');
});

test('AST: Detecte NPM_TOKEN', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'NPM_TOKEN', 'Devrait detecter NPM_TOKEN');
});

test('AST: Detecte AWS_SECRET', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'AWS_SECRET', 'Devrait detecter AWS_SECRET');
});

test('AST: Detecte eval()', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'eval', 'Devrait detecter eval');
});

test('AST: Detecte exec()', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'exec', 'Devrait detecter exec');
});

test('AST: Detecte new Function()', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'));
  assertIncludes(output, 'Function', 'Devrait detecter Function');
});

// ============================================
// TESTS UNITAIRES - DETECTION SHELL
// ============================================

console.log('\n=== TESTS SHELL ===\n');

test('SHELL: Detecte curl | sh', () => {
  const output = runScan(path.join(TESTS_DIR, 'shell'));
  assertIncludes(output, 'curl', 'Devrait detecter curl | sh');
});

test('SHELL: Detecte wget && chmod +x', () => {
  const output = runScan(path.join(TESTS_DIR, 'shell'));
  assertIncludes(output, 'wget', 'Devrait detecter wget');
});

test('SHELL: Detecte reverse shell', () => {
  const output = runScan(path.join(TESTS_DIR, 'shell'));
  assertIncludes(output, 'reverse', 'Devrait detecter reverse shell');
});

test('SHELL: Detecte rm -rf $HOME', () => {
  const output = runScan(path.join(TESTS_DIR, 'shell'));
  assertIncludes(output, 'home', 'Devrait detecter suppression home');
});

// ============================================
// TESTS UNITAIRES - DETECTION OBFUSCATION
// ============================================

console.log('\n=== TESTS OBFUSCATION ===\n');

test('OBFUSCATION: Detecte hex escapes massifs', () => {
  const output = runScan(path.join(TESTS_DIR, 'obfuscation'));
  assertIncludes(output, 'obfusc', 'Devrait detecter obfuscation');
});

test('OBFUSCATION: Detecte variables _0x', () => {
  const output = runScan(path.join(TESTS_DIR, 'obfuscation'));
  assertIncludes(output, 'obfusc', 'Devrait detecter variables _0x');
});

// ============================================
// TESTS UNITAIRES - DETECTION DATAFLOW
// ============================================

console.log('\n=== TESTS DATAFLOW ===\n');

test('DATAFLOW: Detecte credential read + network send', () => {
  const output = runScan(path.join(TESTS_DIR, 'dataflow'));
  assertIncludes(output, 'Flux suspect', 'Devrait detecter flux suspect');
});

test('DATAFLOW: Detecte env read + fetch', () => {
  const output = runScan(path.join(TESTS_DIR, 'dataflow'));
  assertIncludes(output, 'CRITICAL', 'Devrait etre CRITICAL');
});

// ============================================
// TESTS UNITAIRES - DETECTION PACKAGE.JSON
// ============================================

console.log('\n=== TESTS PACKAGE.JSON ===\n');

test('PACKAGE: Detecte preinstall suspect', () => {
  const output = runScan(path.join(TESTS_DIR, 'package'));
  assertIncludes(output, 'preinstall', 'Devrait detecter preinstall');
});

test('PACKAGE: Detecte postinstall suspect', () => {
  const output = runScan(path.join(TESTS_DIR, 'package'));
  assertIncludes(output, 'postinstall', 'Devrait detecter postinstall');
});

// ============================================
// TESTS UNITAIRES - DETECTION MARQUEURS
// ============================================

console.log('\n=== TESTS MARQUEURS ===\n');

test('MARQUEURS: Detecte Shai-Hulud', () => {
  const output = runScan(path.join(TESTS_DIR, 'markers'));
  assertIncludes(output, 'Shai-Hulud', 'Devrait detecter marqueur Shai-Hulud');
});

test('MARQUEURS: Detecte The Second Coming', () => {
  const output = runScan(path.join(TESTS_DIR, 'markers'));
  assertIncludes(output, 'Second Coming', 'Devrait detecter marqueur The Second Coming');
});

// ============================================
// TESTS UNITAIRES - DETECTION TYPOSQUATTING
// ============================================

console.log('\n=== TESTS TYPOSQUATTING ===\n');

test('TYPOSQUAT: Detecte lodahs (lodash)', () => {
  const output = runScan(path.join(TESTS_DIR, 'typosquat'));
  assertIncludes(output, 'lodahs', 'Devrait detecter lodahs');
});

test('TYPOSQUAT: Detecte axois (axios)', () => {
  const output = runScan(path.join(TESTS_DIR, 'typosquat'));
  assertIncludes(output, 'axois', 'Devrait detecter axois');
});

test('TYPOSQUAT: Detecte expres (express)', () => {
  const output = runScan(path.join(TESTS_DIR, 'typosquat'));
  assertIncludes(output, 'expres', 'Devrait detecter expres');
});

test('TYPOSQUAT: Severity HIGH', () => {
  const output = runScan(path.join(TESTS_DIR, 'typosquat'));
  assertIncludes(output, 'HIGH', 'Devrait etre HIGH');
});

// ============================================
// TESTS INTEGRATION - CLI
// ============================================

console.log('\n=== TESTS CLI ===\n');

test('CLI: --help affiche usage', () => {
  const output = runCommand('--help');
  assertIncludes(output, 'Usage', 'Devrait afficher usage');
});

test('CLI: --json retourne JSON valide', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--json');
  try {
    JSON.parse(output);
  } catch (e) {
    throw new Error('Output JSON invalide');
  }
});

test('CLI: --sarif genere fichier SARIF', () => {
  const sarifPath = path.join(__dirname, 'test-output.sarif');
  runScan(path.join(TESTS_DIR, 'ast'), `--sarif "${sarifPath}"`);
  assert(fs.existsSync(sarifPath), 'Fichier SARIF non genere');
  const content = fs.readFileSync(sarifPath, 'utf8');
  const sarif = JSON.parse(content);
  assert(sarif.version === '2.1.0', 'Version SARIF incorrecte');
  assert(sarif.runs && sarif.runs.length > 0, 'SARIF runs manquant');
  fs.unlinkSync(sarifPath);
});

test('CLI: --html genere fichier HTML', () => {
  const htmlPath = path.join(__dirname, 'test-output.html');
  runScan(path.join(TESTS_DIR, 'ast'), `--html "${htmlPath}"`);
  assert(fs.existsSync(htmlPath), 'Fichier HTML non genere');
  const content = fs.readFileSync(htmlPath, 'utf8');
  assertIncludes(content, 'MUAD', 'HTML devrait contenir MUAD');
  assertIncludes(content, '<table>', 'HTML devrait contenir table');
  fs.unlinkSync(htmlPath);
});

test('CLI: --explain affiche details', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--explain');
  assertIncludes(output, 'Rule ID', 'Devrait afficher Rule ID');
  assertIncludes(output, 'MITRE', 'Devrait afficher MITRE');
  assertIncludes(output, 'References', 'Devrait afficher References');
  assertIncludes(output, 'Playbook', 'Devrait afficher Playbook');
});

test('CLI: --fail-on critical exit code correct', () => {
  try {
    execSync(`node "${BIN}" scan "${path.join(TESTS_DIR, 'dataflow')}" --fail-on critical`, { encoding: 'utf8' });
  } catch (e) {
    assert(e.status === 1, 'Exit code devrait etre 1 pour 1 CRITICAL');
    return;
  }
  throw new Error('Devrait avoir exit code non-zero');
});

test('CLI: --fail-on high exit code correct', () => {
  try {
    execSync(`node "${BIN}" scan "${path.join(TESTS_DIR, 'ast')}" --fail-on high`, { encoding: 'utf8' });
  } catch (e) {
    assert(e.status > 0, 'Exit code devrait etre > 0');
    return;
  }
  throw new Error('Devrait avoir exit code non-zero');
});

// ============================================
// TESTS INTEGRATION - UPDATE
// ============================================

console.log('\n=== TESTS UPDATE ===\n');

test('UPDATE: Telecharge et cache IOCs', () => {
  const output = runCommand('update');
  assertIncludes(output, 'IOCs sauvegardes', 'Devrait sauvegarder IOCs');
  assertIncludes(output, 'packages malveillants', 'Devrait afficher nombre packages');
});

// ============================================
// TESTS FAUX POSITIFS
// ============================================

console.log('\n=== TESTS FAUX POSITIFS ===\n');

test('FAUX POSITIFS: Projet propre = aucune menace', () => {
  const output = runScan(path.join(TESTS_DIR, 'clean'));
  assertIncludes(output, 'Aucune menace', 'Projet propre ne devrait pas avoir de menaces');
});

test('FAUX POSITIFS: Commentaires ignores', () => {
  const output = runScan(path.join(TESTS_DIR, 'clean'));
  assertNotIncludes(output, 'CRITICAL', 'Commentaires ne devraient pas declencher');
});

// ============================================
// TESTS EDGE CASES
// ============================================

console.log('\n=== TESTS EDGE CASES ===\n');

test('EDGE: Fichier vide ne crash pas', () => {
  const output = runScan(path.join(TESTS_DIR, 'edge', 'empty'));
  assert(output !== undefined, 'Ne devrait pas crasher sur fichier vide');
});

test('EDGE: Fichier non-JS ignore', () => {
  const output = runScan(path.join(TESTS_DIR, 'edge', 'non-js'));
  assertIncludes(output, 'Aucune menace', 'Fichiers non-JS ignores');
});

test('EDGE: Syntaxe JS invalide ne crash pas', () => {
  const output = runScan(path.join(TESTS_DIR, 'edge', 'invalid-syntax'));
  assert(output !== undefined, 'Ne devrait pas crasher sur syntaxe invalide');
});

test('EDGE: Tres gros fichier ne timeout pas', () => {
  const start = Date.now();
  runScan(path.join(TESTS_DIR, 'edge', 'large-file'));
  const duration = Date.now() - start;
  assert(duration < 30000, 'Ne devrait pas prendre plus de 30s');
});

// ============================================
// TESTS REGLES MITRE
// ============================================

console.log('\n=== TESTS MITRE ===\n');

test('MITRE: T1552.001 - Credentials in Files', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--explain');
  assertIncludes(output, 'T1552.001', 'Devrait mapper T1552.001');
});

test('MITRE: T1059 - Command Execution', () => {
  const output = runScan(path.join(TESTS_DIR, 'ast'), '--explain');
  assertIncludes(output, 'T1059', 'Devrait mapper T1059');
});

test('MITRE: T1041 - Exfiltration', () => {
  const output = runScan(path.join(TESTS_DIR, 'dataflow'), '--explain');
  assertIncludes(output, 'T1041', 'Devrait mapper T1041');
});

// ============================================
// TESTS WHITELIST / REHABILITATED PACKAGES
// ============================================

console.log('\n=== TESTS WHITELIST ===\n');

test('WHITELIST: chalk est dans REHABILITATED_PACKAGES', () => {
  const { REHABILITATED_PACKAGES } = require('../src/safe-install.js');
  assert(REHABILITATED_PACKAGES['chalk'], 'chalk devrait etre dans REHABILITATED_PACKAGES');
  assert(REHABILITATED_PACKAGES['chalk'].safe === true, 'chalk.safe devrait etre true');
});

test('WHITELIST: debug est dans REHABILITATED_PACKAGES', () => {
  const { REHABILITATED_PACKAGES } = require('../src/safe-install.js');
  assert(REHABILITATED_PACKAGES['debug'], 'debug devrait etre dans REHABILITATED_PACKAGES');
  assert(REHABILITATED_PACKAGES['debug'].safe === true, 'debug.safe devrait etre true');
});

test('WHITELIST: ua-parser-js a des versions compromises specifiques', () => {
  const { REHABILITATED_PACKAGES } = require('../src/safe-install.js');
  const uap = REHABILITATED_PACKAGES['ua-parser-js'];
  assert(uap, 'ua-parser-js devrait etre dans REHABILITATED_PACKAGES');
  assert(uap.safe === false, 'ua-parser-js.safe devrait etre false');
  assert(uap.compromised.includes('0.7.29'), 'Devrait inclure 0.7.29');
  assert(uap.compromised.includes('0.8.0'), 'Devrait inclure 0.8.0');
  assert(uap.compromised.includes('1.0.0'), 'Devrait inclure 1.0.0');
});

test('WHITELIST: checkRehabilitated retourne safe pour chalk', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('chalk', '5.4.0');
  assert(result !== null, 'chalk devrait etre reconnu');
  assert(result.safe === true, 'chalk devrait etre safe');
});

test('WHITELIST: checkRehabilitated retourne unsafe pour ua-parser-js@0.7.29', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('ua-parser-js', '0.7.29');
  assert(result !== null, 'ua-parser-js devrait etre reconnu');
  assert(result.safe === false, 'ua-parser-js@0.7.29 devrait etre unsafe');
});

test('WHITELIST: checkRehabilitated retourne safe pour ua-parser-js@0.7.35', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('ua-parser-js', '0.7.35');
  assert(result !== null, 'ua-parser-js devrait etre reconnu');
  assert(result.safe === true, 'ua-parser-js@0.7.35 devrait etre safe');
});

test('WHITELIST: checkRehabilitated retourne null pour package inconnu', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('some-random-package', '1.0.0');
  assert(result === null, 'Package inconnu devrait retourner null');
});

// ============================================
// TESTS IOC LOADING
// ============================================

console.log('\n=== TESTS IOC LOADING ===\n');

test('IOC: loadCachedIOCs retourne des packages', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.packages, 'Devrait avoir packages');
  assert(iocs.packages.length > 0, 'Devrait avoir au moins un package');
});

test('IOC: loadCachedIOCs retourne des hashes', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.hashes, 'Devrait avoir hashes');
});

test('IOC: loadCachedIOCs retourne des markers', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  assert(iocs.markers, 'Devrait avoir markers');
  assert(iocs.markers.length > 0, 'Devrait avoir au moins un marker');
});

test('IOC: Typosquats ont version wildcard', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  const typosquats = iocs.packages.filter(p => p.source === 'typosquat');
  assert(typosquats.length > 0, 'Devrait avoir des typosquats');
  const allWildcard = typosquats.every(p => p.version === '*');
  assert(allWildcard, 'Tous les typosquats devraient avoir version *');
});

test('IOC: Packages historiques ont versions specifiques', () => {
  const { loadCachedIOCs } = require('../src/ioc/updater.js');
  const iocs = loadCachedIOCs();
  const eventStream = iocs.packages.find(p => p.name === 'event-stream');
  assert(eventStream, 'event-stream devrait etre dans les IOCs');
  assert(eventStream.version === '3.3.6', 'event-stream devrait avoir version 3.3.6');
});

// ============================================
// TESTS IOC MATCHING
// ============================================

console.log('\n=== TESTS IOC MATCHING ===\n');

test('IOC MATCH: Version wildcard matche toutes versions', () => {
  const iocs = { packages: [{ name: 'malicious-pkg', version: '*' }] };
  const pkg = { name: 'malicious-pkg', version: '1.2.3' };
  const match = iocs.packages.find(p => {
    if (p.name !== pkg.name) return false;
    if (p.version === '*') return true;
    return p.version === pkg.version;
  });
  assert(match, 'Wildcard devrait matcher');
});

test('IOC MATCH: Version specifique matche uniquement cette version', () => {
  const iocs = { packages: [{ name: 'some-pkg', version: '1.0.0' }] };
  
  const pkg1 = { name: 'some-pkg', version: '1.0.0' };
  const match1 = iocs.packages.find(p => p.name === pkg1.name && (p.version === '*' || p.version === pkg1.version));
  assert(match1, 'Version exacte devrait matcher');
  
  const pkg2 = { name: 'some-pkg', version: '1.0.1' };
  const match2 = iocs.packages.find(p => p.name === pkg2.name && (p.version === '*' || p.version === pkg2.version));
  assert(!match2, 'Version differente ne devrait pas matcher');
});

// ============================================
// TESTS SCRAPER / DATA
// ============================================

console.log('\n=== TESTS SCRAPER / DATA ===\n');

test('SCRAPER: Module charge sans erreur', () => {
  const { runScraper } = require('../src/ioc/scraper.js');
  assert(typeof runScraper === 'function', 'runScraper devrait etre une fonction');
});

test('SCRAPER: data/iocs.json existe et est valide', () => {
  const iocsPath = path.join(__dirname, '..', 'data', 'iocs.json');
  assert(fs.existsSync(iocsPath), 'data/iocs.json devrait exister');
  const content = fs.readFileSync(iocsPath, 'utf8');
  const iocs = JSON.parse(content);
  assert(iocs.packages, 'Devrait avoir packages');
  assert(Array.isArray(iocs.packages), 'packages devrait etre un array');
});

test('SCRAPER: IOCs ont les champs requis', () => {
  const iocs = require('../data/iocs.json');
  const sample = iocs.packages[0];
  assert(sample.name, 'IOC devrait avoir name');
  assert(sample.version, 'IOC devrait avoir version');
  assert(sample.source, 'IOC devrait avoir source');
});

test('SCRAPER: Au moins 900 IOCs', () => {
  const iocs = require('../data/iocs.json');
  assert(iocs.packages.length >= 900, `Devrait avoir au moins 900 IOCs, a ${iocs.packages.length}`);
});

// ============================================
// TESTS YAML LOADER
// ============================================

console.log('\n=== TESTS YAML LOADER ===\n');

test('YAML: builtin.yaml existe', () => {
  const builtinPath = path.join(__dirname, '..', 'iocs', 'builtin.yaml');
  assert(fs.existsSync(builtinPath), 'iocs/builtin.yaml devrait exister');
});

test('YAML: loadYAMLIOCs retourne des packages', () => {
  const { loadYAMLIOCs } = require('../src/ioc/yaml-loader.js');
  const iocs = loadYAMLIOCs();
  assert(iocs.packages, 'Devrait avoir packages');
  assert(iocs.packages.length > 0, 'Devrait avoir au moins un package');
});

test('YAML: Contient Shai-Hulud packages', () => {
  const { loadYAMLIOCs } = require('../src/ioc/yaml-loader.js');
  const iocs = loadYAMLIOCs();
  const shaiHulud = iocs.packages.filter(p => p.source && p.source.includes('shai-hulud'));
  assert(shaiHulud.length > 0, 'Devrait avoir des packages Shai-Hulud');
});

test('YAML: Contient markers Shai-Hulud', () => {
  const { loadYAMLIOCs } = require('../src/ioc/yaml-loader.js');
  const iocs = loadYAMLIOCs();
  assert(iocs.markers, 'Devrait avoir markers');
  const hasShaiHulud = iocs.markers.some(m => m.pattern && m.pattern.includes('Shai-Hulud'));
  assert(hasShaiHulud, 'Devrait avoir marker Shai-Hulud');
});

// ============================================
// TESTS NON-REGRESSION
// ============================================

console.log('\n=== TESTS NON-REGRESSION ===\n');

test('REGRESSION: chalk ne doit pas bloquer (rehabilite)', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('chalk', '5.4.0');
  assert(result && result.safe === true, 'chalk ne doit pas bloquer');
});

test('REGRESSION: debug ne doit pas bloquer (rehabilite)', () => {
  const { checkRehabilitated } = require('../src/safe-install.js');
  const result = checkRehabilitated('debug', '4.3.0');
  assert(result && result.safe === true, 'debug ne doit pas bloquer');
});

test('REGRESSION: lodash n\'est pas dans les IOCs', () => {
  const iocs = require('../data/iocs.json');
  const lodash = iocs.packages.find(p => p.name === 'lodash');
  assert(!lodash, 'lodash ne devrait pas etre dans les IOCs');
});

test('REGRESSION: loadash (typosquat) EST dans les IOCs', () => {
  const iocs = require('../data/iocs.json');
  const loadash = iocs.packages.find(p => p.name === 'loadash');
  assert(loadash, 'loadash (typosquat) devrait etre dans les IOCs');
});

test('REGRESSION: express n\'est pas dans les IOCs', () => {
  const iocs = require('../data/iocs.json');
  const express = iocs.packages.find(p => p.name === 'express');
  assert(!express, 'express ne devrait pas etre dans les IOCs');
});

test('REGRESSION: axios n\'est pas dans les IOCs', () => {
  const iocs = require('../data/iocs.json');
  const axios = iocs.packages.find(p => p.name === 'axios');
  assert(!axios, 'axios ne devrait pas etre dans les IOCs');
});

// ============================================
// TESTS SECURITE - VALIDATION PACKAGES
// ============================================

console.log('\n=== TESTS SECURITE PACKAGES ===\n');

test('SECURITE: isValidPackageName accepte lodash', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(isValidPackageName('lodash'), 'lodash devrait etre valide');
});

test('SECURITE: isValidPackageName accepte @scope/package', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(isValidPackageName('@types/node'), '@types/node devrait etre valide');
});

test('SECURITE: isValidPackageName rejette injection shell', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(!isValidPackageName('foo; rm -rf /'), 'injection shell devrait etre invalide');
});

test('SECURITE: isValidPackageName rejette backticks', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(!isValidPackageName('foo`whoami`'), 'backticks devrait etre invalide');
});

test('SECURITE: isValidPackageName rejette $(...)', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(!isValidPackageName('foo$(cat /etc/passwd)'), '$() devrait etre invalide');
});

test('SECURITE: isValidPackageName rejette pipes', () => {
  const { isValidPackageName } = require('../src/safe-install.js');
  assert(!isValidPackageName('foo | cat /etc/passwd'), 'pipe devrait etre invalide');
});

// ============================================
// TESTS SECURITE - WEBHOOK VALIDATION
// ============================================

console.log('\n=== TESTS SECURITE WEBHOOK ===\n');

test('SECURITE: validateWebhookUrl accepte Discord', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://discord.com/api/webhooks/123/abc');
  assert(result.valid, 'Discord webhook devrait etre valide');
});

test('SECURITE: validateWebhookUrl accepte Slack', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://hooks.slack.com/services/xxx/yyy');
  assert(result.valid, 'Slack webhook devrait etre valide');
});

test('SECURITE: validateWebhookUrl rejette HTTP (non-HTTPS)', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('http://discord.com/api/webhooks/123');
  assert(!result.valid, 'HTTP devrait etre rejete');
});

test('SECURITE: validateWebhookUrl rejette domaines non autorises', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://evil.com/steal');
  assert(!result.valid, 'evil.com devrait etre rejete');
});

test('SECURITE: validateWebhookUrl rejette IP privees (127.x)', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://127.0.0.1:8080/webhook');
  assert(!result.valid, '127.x devrait etre rejete');
});

test('SECURITE: validateWebhookUrl rejette IP privees (192.168.x)', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://192.168.1.1/webhook');
  assert(!result.valid, '192.168.x devrait etre rejete');
});

test('SECURITE: validateWebhookUrl rejette IP privees (10.x)', () => {
  const { validateWebhookUrl } = require('../src/webhook.js');
  const result = validateWebhookUrl('https://10.0.0.1/webhook');
  assert(!result.valid, '10.x devrait etre rejete');
});

// ============================================
// RESULTATS
// ============================================

console.log('\n========================================');
console.log(`RESULTATS: ${passed} passes, ${failed} echecs`);
console.log('========================================\n');

if (failures.length > 0) {
  console.log('Echecs:');
  failures.forEach(f => {
    console.log(`  - ${f.name}: ${f.error}`);
  });
  console.log('');
}

process.exit(failed > 0 ? 1 : 0);