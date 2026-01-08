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