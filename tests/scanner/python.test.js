const fs = require('fs');
const path = require('path');
const os = require('os');
const { test, asyncTest, assert, assertIncludes, runScanDirect } = require('../test-utils');
const { parseRequirementsTxt, parseSetupPy, parsePyprojectToml, detectPythonProject, normalizePythonName } = require('../../src/scanner/python.js');
const { findPyPITyposquatMatch } = require('../../src/scanner/typosquat.js');

async function runPythonTests() {
  // --- Python parser tests ---
  console.log('\n=== PYTHON PARSER TESTS ===\n');

  test('PYTHON: normalizePythonName lowercases and normalizes separators', () => {
    assert(normalizePythonName('Flask') === 'flask', 'Should lowercase');
    assert(normalizePythonName('my_package') === 'my-package', 'Should replace underscores');
    assert(normalizePythonName('My.Package') === 'my-package', 'Should replace dots');
    assert(normalizePythonName('My-Package') === 'my-package', 'Should lowercase hyphens');
    assert(normalizePythonName('some__pkg') === 'some-pkg', 'Should collapse multiple separators');
  });

  test('PYTHON: parseRequirementsTxt parses pinned versions', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, 'flask==2.3.0\nrequests==2.31.0\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 2, 'Should have 2 deps');
    assert(deps[0].name === 'flask', 'First should be flask');
    assert(deps[0].version === '==2.3.0', 'Should have pinned version');
    assert(deps[1].name === 'requests', 'Second should be requests');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles various version specs', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, [
      'flask>=2.0', 'django~=4.2', 'requests<=2.31.0', 'numpy>1.20',
      'pandas!=1.5.0', 'scipy<2.0', 'simplepkg',
    ].join('\n'));
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 7, 'Should have 7 deps, got ' + deps.length);
    assert(deps[0].version === '>=2.0', 'flask version');
    assert(deps[1].version === '~=4.2', 'django version');
    assert(deps[2].version === '<=2.31.0', 'requests version');
    assert(deps[3].version === '>1.20', 'numpy version');
    assert(deps[4].version === '!=1.5.0', 'pandas version');
    assert(deps[5].version === '<2.0', 'scipy version');
    assert(deps[6].version === '*', 'simplepkg no version');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt ignores comments and blanks', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, '# This is a comment\n\nflask==2.0\n   # Another comment\n\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 1, 'Should have 1 dep');
    assert(deps[0].name === 'flask', 'Should be flask');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles extras', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, 'requests[security]==2.31.0\ncelery[redis,auth]>=5.0\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 2, 'Should have 2 deps');
    assert(deps[0].name === 'requests', 'Should strip extras from name');
    assert(deps[0].version === '==2.31.0', 'Should keep version');
    assert(deps[1].name === 'celery', 'Should strip multiple extras');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles recursive includes', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const baseFile = path.join(tmpDir, 'requirements.txt');
    const extraFile = path.join(tmpDir, 'requirements-dev.txt');
    fs.writeFileSync(extraFile, 'pytest==7.0\nblack==23.0\n');
    fs.writeFileSync(baseFile, 'flask==2.0\n-r requirements-dev.txt\nrequests==2.31\n');
    const deps = parseRequirementsTxt(baseFile);
    assert(deps.length === 4, 'Should have 4 deps, got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should have flask');
    assert(names.includes('pytest'), 'Should have pytest from included file');
    assert(names.includes('black'), 'Should have black from included file');
    assert(names.includes('requests'), 'Should have requests');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles circular includes', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const fileA = path.join(tmpDir, 'a.txt');
    const fileB = path.join(tmpDir, 'b.txt');
    fs.writeFileSync(fileA, 'flask==2.0\n-r b.txt\n');
    fs.writeFileSync(fileB, 'requests==2.31\n-r a.txt\n');
    const deps = parseRequirementsTxt(fileA);
    assert(deps.length === 2, 'Should not loop infinitely');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt skips option lines', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, '--index-url https://pypi.org/simple\n-i https://pypi.org/simple\nflask==2.0\n-e git+https://github.com/foo/bar.git\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 1, 'Should only have flask');
    assert(deps[0].name === 'flask', 'Should be flask');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseRequirementsTxt handles env markers', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqFile = path.join(tmpDir, 'requirements.txt');
    fs.writeFileSync(reqFile, 'pywin32>=300; sys_platform == "win32"\ncolorama>=0.4; os_name == "nt"\n');
    const deps = parseRequirementsTxt(reqFile);
    assert(deps.length === 2, 'Should parse both deps');
    assert(deps[0].name === 'pywin32', 'Should strip env marker');
    assert(deps[0].version === '>=300', 'Should keep version');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseSetupPy extracts install_requires', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const setupFile = path.join(tmpDir, 'setup.py');
    fs.writeFileSync(setupFile, [
      'from setuptools import setup', '',
      'setup(', '    name="myproject",', '    version="1.0.0",',
      '    install_requires=[', '        "flask>=2.0",', '        "requests==2.31.0",',
      '        "click",', '    ],', ')',
    ].join('\n'));
    const deps = parseSetupPy(setupFile);
    assert(deps.length === 3, 'Should have 3 deps, got ' + deps.length);
    assert(deps[0].name === 'flask', 'First should be flask');
    assert(deps[0].version === '>=2.0', 'flask version');
    assert(deps[1].name === 'requests', 'Second should be requests');
    assert(deps[2].name === 'click', 'Third should be click');
    assert(deps[2].version === '*', 'click no version');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseSetupPy handles single-line install_requires', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const setupFile = path.join(tmpDir, 'setup.py');
    fs.writeFileSync(setupFile, 'setup(install_requires=["flask>=2.0", "requests"])');
    const deps = parseSetupPy(setupFile);
    assert(deps.length === 2, 'Should have 2 deps');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parseSetupPy also extracts setup_requires', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const setupFile = path.join(tmpDir, 'setup.py');
    fs.writeFileSync(setupFile, [
      'setup(', '    install_requires=["flask>=2.0"],',
      '    setup_requires=["setuptools-scm"],', ')',
    ].join('\n'));
    const deps = parseSetupPy(setupFile);
    assert(deps.length === 2, 'Should have 2 deps, got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should have flask');
    assert(names.includes('setuptools-scm'), 'Should have setuptools-scm');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parsePyprojectToml extracts PEP 621 dependencies', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const tomlFile = path.join(tmpDir, 'pyproject.toml');
    fs.writeFileSync(tomlFile, [
      '[project]', 'name = "myproject"', 'version = "1.0.0"',
      'dependencies = [', '    "flask>=2.0",', '    "requests==2.31.0",', '    "click",', ']',
    ].join('\n'));
    const deps = parsePyprojectToml(tomlFile);
    assert(deps.length === 3, 'Should have 3 deps, got ' + deps.length);
    assert(deps[0].name === 'flask', 'First should be flask');
    assert(deps[0].version === '>=2.0', 'flask version');
    assert(deps[1].name === 'requests', 'Second should be requests');
    assert(deps[2].name === 'click', 'Third should be click');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parsePyprojectToml extracts Poetry dependencies', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const tomlFile = path.join(tmpDir, 'pyproject.toml');
    fs.writeFileSync(tomlFile, [
      '[tool.poetry]', 'name = "myproject"', '',
      '[tool.poetry.dependencies]', 'python = "^3.8"', 'flask = "^2.3"',
      'requests = {version = "^2.31", optional = true}', 'click = "*"',
    ].join('\n'));
    const deps = parsePyprojectToml(tomlFile);
    assert(deps.length === 3, 'Should have 3 deps (python skipped), got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(!names.includes('python'), 'Should skip python');
    assert(names.includes('flask'), 'Should have flask');
    assert(names.includes('requests'), 'Should have requests');
    assert(names.includes('click'), 'Should have click');
    const flask = deps.find(function(d) { return d.name === 'flask'; });
    assert(flask.version === '^2.3', 'flask version');
    const req = deps.find(function(d) { return d.name === 'requests'; });
    assert(req.version === '^2.31', 'requests version from inline table');
    const click = deps.find(function(d) { return d.name === 'click'; });
    assert(click.version === '*', 'click wildcard');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: parsePyprojectToml handles both PEP 621 and Poetry', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const tomlFile = path.join(tmpDir, 'pyproject.toml');
    fs.writeFileSync(tomlFile, [
      '[project]', 'dependencies = [', '    "flask>=2.0",', ']', '',
      '[tool.poetry.dependencies]', 'python = "^3.8"', 'django = "^4.2"',
    ].join('\n'));
    const deps = parsePyprojectToml(tomlFile);
    assert(deps.length === 2, 'Should have 2 deps, got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should have flask from PEP 621');
    assert(names.includes('django'), 'Should have django from Poetry');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: detectPythonProject finds all dependency files', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\nrequests==2.31.0\n');
    fs.writeFileSync(path.join(tmpDir, 'setup.py'), 'setup(install_requires=["click>=7.0", "gunicorn==20.0"])');
    fs.writeFileSync(path.join(tmpDir, 'pyproject.toml'), '[project]\ndependencies = ["sqlalchemy>=2.0"]\n');
    const deps = detectPythonProject(tmpDir);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should find flask from requirements.txt');
    assert(names.includes('requests'), 'Should find requests from requirements.txt');
    assert(names.includes('click'), 'Should find click from setup.py');
    assert(names.includes('gunicorn'), 'Should find gunicorn from setup.py');
    assert(names.includes('sqlalchemy'), 'Should find sqlalchemy from pyproject.toml');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: detectPythonProject deduplicates by name', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\n');
    fs.writeFileSync(path.join(tmpDir, 'setup.py'), 'setup(install_requires=["flask>=2.0"])');
    const deps = detectPythonProject(tmpDir);
    const flasks = deps.filter(function(d) { return d.name === 'flask'; });
    assert(flasks.length === 1, 'Should deduplicate flask');
    assert(flasks[0].version === '==2.3.0', 'Should keep first occurrence (requirements.txt)');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: detectPythonProject scans requirements/ directory', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const reqDir = path.join(tmpDir, 'requirements');
    fs.mkdirSync(reqDir);
    fs.writeFileSync(path.join(reqDir, 'prod.txt'), 'flask==2.3.0\n');
    fs.writeFileSync(path.join(reqDir, 'dev.txt'), 'pytest==7.0\n');
    const deps = detectPythonProject(tmpDir);
    assert(deps.length === 2, 'Should have 2 deps, got ' + deps.length);
    const names = deps.map(function(d) { return d.name; });
    assert(names.includes('flask'), 'Should have flask from prod.txt');
    assert(names.includes('pytest'), 'Should have pytest from dev.txt');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: detectPythonProject returns empty for non-Python project', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    const deps = detectPythonProject(tmpDir);
    assert(deps.length === 0, 'Should return empty array');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('PYTHON: PEP 503 name normalization in dedup', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytest-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'Flask==2.3.0\nflask==2.0\n');
    const deps = detectPythonProject(tmpDir);
    const flasks = deps.filter(function(d) { return d.name === 'flask'; });
    assert(flasks.length === 1, 'Should deduplicate Flask/flask');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // --- Python scan integration tests ---

  console.log('\n=== PYTHON SCAN INTEGRATION TESTS ===\n');

  const { getRule: getRuleForPypi } = require('../../src/rules/index.js');
  const { getPlaybook: getPlaybookForPypi } = require('../../src/response/playbooks.js');

  test('PYTHON-SCAN: Rule pypi_malicious_package exists', () => {
    const rule = getRuleForPypi('pypi_malicious_package');
    assert(rule.id === 'MUADDIB-PYPI-001', 'Rule ID should be MUADDIB-PYPI-001, got ' + rule.id);
    assert(rule.name === 'Malicious PyPI Package', 'Rule name');
    assert(rule.severity === 'CRITICAL', 'Rule severity');
    assert(rule.confidence === 'high', 'Rule confidence');
    assert(rule.mitre === 'T1195.002', 'Rule MITRE');
  });

  test('PYTHON-SCAN: Playbook pypi_malicious_package exists', () => {
    const playbook = getPlaybookForPypi('pypi_malicious_package');
    assert(playbook.includes('pip uninstall'), 'Playbook should mention pip uninstall, got: ' + playbook);
  });

  await asyncTest('PYTHON-SCAN: JSON output includes python field', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyscan-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\nrequests==2.31.0\ndjango>=4.0\n');
    try {
      const result = await runScanDirect(tmpDir);
      assert(result.python !== null && result.python !== undefined, 'Should have python field');
      assert(result.python.dependencies === 3, 'Should have 3 dependencies, got ' + result.python.dependencies);
      assert(Array.isArray(result.python.files), 'Should have files array');
      assert(result.python.files.length > 0, 'Should have at least 1 file');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('PYTHON-SCAN: python field is null for non-Python project', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyscan-'));
    fs.writeFileSync(path.join(tmpDir, 'package.json'), '{"name":"test","version":"1.0.0"}');
    try {
      const result = await runScanDirect(tmpDir);
      assert(result.python === null, 'python field should be null for non-Python project');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('PYTHON-SCAN: Detects all Python file types', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pyscan-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\n');
    fs.writeFileSync(path.join(tmpDir, 'setup.py'), 'setup(install_requires=["click>=7.0"])');
    fs.writeFileSync(path.join(tmpDir, 'pyproject.toml'), '[project]\ndependencies = ["sqlalchemy>=2.0"]\n');
    try {
      const result = await runScanDirect(tmpDir);
      assert(result.python.dependencies === 3, 'Should have 3 deduplicated deps, got ' + result.python.dependencies);
      assert(result.python.files.length === 3, 'Should reference 3 files, got ' + result.python.files.length);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // --- PyPI typosquatting tests ---

  console.log('\n=== PYPI TYPOSQUATTING TESTS ===\n');

  test('PYPI-TYPOSQUAT: Detects reqeusts (requests)', () => {
    const match = findPyPITyposquatMatch('reqeusts');
    assert(match !== null, 'Should detect reqeusts as typosquat');
    assert(match.original === 'requests', 'Should identify requests as target');
    assert(match.distance <= 2, 'Distance should be <= 2');
  });

  test('PYPI-TYPOSQUAT: Detects numpie (numpy)', () => {
    const match = findPyPITyposquatMatch('numpie');
    assert(match !== null, 'Should detect numpie as typosquat');
    assert(match.original === 'numpy', 'Should identify numpy as target');
  });

  test('PYPI-TYPOSQUAT: Detects flaks (flask)', () => {
    const match = findPyPITyposquatMatch('flaks');
    assert(match !== null, 'Should detect flaks as typosquat');
    assert(match.original === 'flask', 'Should identify flask as target');
  });

  test('PYPI-TYPOSQUAT: Detects djnago (django)', () => {
    const match = findPyPITyposquatMatch('djnago');
    assert(match !== null, 'Should detect djnago as typosquat');
    assert(match.original === 'django', 'Should identify django as target');
  });

  test('PYPI-TYPOSQUAT: Detects pandsa (pandas)', () => {
    const match = findPyPITyposquatMatch('pandsa');
    assert(match !== null, 'Should detect pandsa as typosquat');
    assert(match.original === 'pandas', 'Should identify pandas as target');
  });

  test('PYPI-TYPOSQUAT: Does not flag exact package names', () => {
    assert(findPyPITyposquatMatch('requests') === null, 'requests itself');
    assert(findPyPITyposquatMatch('flask') === null, 'flask itself');
    assert(findPyPITyposquatMatch('numpy') === null, 'numpy itself');
    assert(findPyPITyposquatMatch('django') === null, 'django itself');
  });

  test('PYPI-TYPOSQUAT: PEP 503 normalization — case insensitive', () => {
    assert(findPyPITyposquatMatch('Flask') === null, 'Flask (capitalized) = flask');
    assert(findPyPITyposquatMatch('Django') === null, 'Django (capitalized) = django');
    assert(findPyPITyposquatMatch('NumPy') === null, 'NumPy (mixed case) = numpy');
  });

  test('PYPI-TYPOSQUAT: PEP 503 normalization — underscores/dots/hyphens equivalent', () => {
    assert(findPyPITyposquatMatch('scikit_learn') === null, 'scikit_learn = scikit-learn');
    assert(findPyPITyposquatMatch('scikit.learn') === null, 'scikit.learn = scikit-learn');
    assert(findPyPITyposquatMatch('python_dateutil') === null, 'python_dateutil = python-dateutil');
  });

  test('PYPI-TYPOSQUAT: Skips short names (< 4 chars)', () => {
    assert(findPyPITyposquatMatch('six') === null, 'six is too short');
    assert(findPyPITyposquatMatch('pip') === null, 'pip is too short');
    assert(findPyPITyposquatMatch('tox') === null, 'tox is too short');
  });

  test('PYPI-TYPOSQUAT: Skips whitelisted packages', () => {
    assert(findPyPITyposquatMatch('boto') === null, 'boto is whitelisted');
    assert(findPyPITyposquatMatch('torchvision') === null, 'torchvision is whitelisted');
  });

  test('PYPI-TYPOSQUAT: Severity is HIGH', () => {
    const match = findPyPITyposquatMatch('reqeusts');
    assert(match !== null, 'Should detect reqeusts');
    const rule = getRuleForPypi('pypi_typosquat_detected');
    assert(rule.severity === 'HIGH', 'Rule severity should be HIGH');
  });

  await asyncTest('PYPI-TYPOSQUAT: CLI detects PyPI typosquat in requirements.txt', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytypo-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'reqeusts==2.31.0\nflask==2.3.0\n');
    try {
      const result = await runScanDirect(tmpDir);
      const typosquatThreats = result.threats.filter(function(t) { return t.type === 'pypi_typosquat_detected'; });
      assert(typosquatThreats.length >= 1, 'Should detect at least 1 PyPI typosquat, got ' + typosquatThreats.length);
      assert(typosquatThreats[0].message.includes('reqeusts'), 'Should mention reqeusts');
      assert(typosquatThreats[0].message.includes('requests'), 'Should mention requests as target');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await asyncTest('PYPI-TYPOSQUAT: No false positive for legit Python deps', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-pytypo-'));
    fs.writeFileSync(path.join(tmpDir, 'requirements.txt'), 'flask==2.3.0\nrequests==2.31.0\nnumpy==1.24.0\ndjango>=4.0\n');
    try {
      const result = await runScanDirect(tmpDir);
      const typosquatThreats = result.threats.filter(function(t) { return t.type === 'pypi_typosquat_detected'; });
      assert(typosquatThreats.length === 0, 'Should have 0 PyPI typosquat for legit deps, got ' + typosquatThreats.length);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  test('PYPI-TYPOSQUAT: Playbook exists', () => {
    const playbook = getPlaybookForPypi('pypi_typosquat_detected');
    assert(playbook.includes('package PyPI'), 'Playbook should mention PyPI package');
  });
}

module.exports = { runPythonTests };
