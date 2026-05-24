const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, asyncTest, assert } = require('../test-utils');
const {
  generateCycloneDX,
  saveCycloneDX,
  severityToCycloneDX,
  buildPurl,
  resolveRootComponent,
  SPEC_VERSION
} = require('../../src/output/cyclonedx.js');

function makeTmpPkg(pkg) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-cdx-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify(pkg, null, 2));
  return tmp;
}
function rmrf(p) { try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* ignore */ } }

async function runCyclonedxTests() {
  console.log('\n=== P1b: CYCLONEDX TESTS ===\n');

  // ── Constants & helpers ──
  test('P1b: SPEC_VERSION is "1.5"', () => {
    assert(SPEC_VERSION === '1.5');
  });

  test('P1b: severityToCycloneDX maps muaddib levels correctly', () => {
    assert(severityToCycloneDX('CRITICAL') === 'critical');
    assert(severityToCycloneDX('HIGH') === 'high');
    assert(severityToCycloneDX('MEDIUM') === 'medium');
    assert(severityToCycloneDX('LOW') === 'low');
    assert(severityToCycloneDX(undefined) === 'info');
    assert(severityToCycloneDX('bogus') === 'info');
  });

  test('P1b: buildPurl unscoped npm', () => {
    assert(buildPurl('axios', '1.0.0', true) === 'pkg:npm/axios@1.0.0');
  });

  test('P1b: buildPurl scoped npm encodes @ and /', () => {
    const p = buildPurl('@scope/pkg', '1.0.0', true);
    // @scope → %40scope, / → /, name part also encoded
    assert(p.startsWith('pkg:npm/'));
    assert(p.includes('%40scope'));
    assert(p.endsWith('@1.0.0'));
  });

  test('P1b: buildPurl pre-release version is preserved (encoded)', () => {
    const p = buildPurl('foo', '1.0.0-beta.1+build', true);
    assert(p.startsWith('pkg:npm/foo@'));
    // The + in build metadata must be encoded by encodeURIComponent
    assert(p.includes('%2B') || p.includes('1.0.0-beta.1%2Bbuild'));
  });

  test('P1b: buildPurl falls back to pkg:generic without package.json', () => {
    const p = buildPurl('some-dir', '0.0.0', false);
    assert(p.startsWith('pkg:generic/'));
  });

  // ── resolveRootComponent ──
  await asyncTest('P1b: resolveRootComponent reads package.json', async () => {
    const tmp = makeTmpPkg({ name: 'test-pkg', version: '2.3.4' });
    try {
      const r = resolveRootComponent(tmp);
      assert(r.name === 'test-pkg');
      assert(r.version === '2.3.4');
      assert(r.hasPackageJson === true);
    } finally { rmrf(tmp); }
  });

  await asyncTest('P1b: resolveRootComponent falls back when no package.json', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-cdx-nopkg-'));
    try {
      const r = resolveRootComponent(tmp);
      assert(r.hasPackageJson === false);
      assert(r.version === '0.0.0');
      assert(typeof r.name === 'string' && r.name.length > 0);
    } finally { rmrf(tmp); }
  });

  await asyncTest('P1b: resolveRootComponent tolerates broken package.json', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-cdx-bad-'));
    fs.writeFileSync(path.join(tmp, 'package.json'), '{not valid json');
    try {
      const r = resolveRootComponent(tmp);
      assert(r.hasPackageJson === false);
      assert(r.version === '0.0.0');
    } finally { rmrf(tmp); }
  });

  // ── generateCycloneDX — structure ──
  test('P1b: generateCycloneDX produces required top-level fields', () => {
    const bom = generateCycloneDX({ target: '/tmp/nothing', threats: [] });
    assert(bom.bomFormat === 'CycloneDX');
    assert(bom.specVersion === '1.5');
    assert(typeof bom.serialNumber === 'string' && /^urn:uuid:[0-9a-f-]{36}$/.test(bom.serialNumber),
      'serialNumber must be urn:uuid:<uuid>, got: ' + bom.serialNumber);
    assert(bom.version === 1);
    assert(typeof bom.metadata.timestamp === 'string');
    assert(Array.isArray(bom.metadata.tools) && bom.metadata.tools[0].name === 'muaddib');
    assert(bom.metadata.component['bom-ref'] === 'scanned-package');
    assert(bom.metadata.component.type === 'library');
    assert(typeof bom.metadata.component.purl === 'string' && bom.metadata.component.purl.startsWith('pkg:'));
    assert(Array.isArray(bom.vulnerabilities));
  });

  test('P1b: generateCycloneDX with empty threats yields valid BOM with vulnerabilities=[]', () => {
    const bom = generateCycloneDX({ target: '/tmp/clean', threats: [] });
    assert(Array.isArray(bom.vulnerabilities) && bom.vulnerabilities.length === 0);
    // Must still be a valid SBOM
    assert(bom.bomFormat === 'CycloneDX');
  });

  test('P1b: generateCycloneDX maps a single threat to a vulnerability', () => {
    const bom = generateCycloneDX({
      target: '/tmp/x',
      threats: [{
        type: 'env_access',
        rule_id: 'MUADDIB-AST-002',
        severity: 'HIGH',
        confidence: 'high',
        domain: 'malware',
        mitre: 'T1552.001',
        message: 'access GITHUB_TOKEN',
        file: 'index.js',
        line: 42,
        points: 10
      }]
    });
    assert(bom.vulnerabilities.length === 1);
    const v = bom.vulnerabilities[0];
    assert(v.id === 'MUADDIB-AST-002');
    assert(v['bom-ref'] === 'muaddib-vuln-1');
    assert(v.source.name === 'MUADDIB');
    assert(v.description === 'access GITHUB_TOKEN');
    assert(v.ratings[0].severity === 'high');
    assert(v.ratings[0].score === 10);
    assert(v.ratings[0].source.name === 'MUADDIB');
    assert(v.ratings[0].method === 'other');
    assert(v.affects[0].ref === 'scanned-package');
  });

  test('P1b: vulnerability properties include risk_domain + mitre + confidence + type', () => {
    const bom = generateCycloneDX({
      target: '/tmp/x',
      threats: [{
        type: 'unclaimed_maintainer_email',
        rule_id: 'MUADDIB-MAINTAINER-005',
        severity: 'HIGH',
        confidence: 'medium',
        domain: 'author',
        mitre: 'T1556',
        message: 'no MX',
        file: 'package.json'
      }]
    });
    const props = bom.vulnerabilities[0].properties;
    const byName = Object.fromEntries(props.map(p => [p.name, p.value]));
    assert(byName['muaddib:risk_domain'] === 'author');
    assert(byName['muaddib:type'] === 'unclaimed_maintainer_email');
    assert(byName['muaddib:confidence'] === 'medium');
    assert(byName['muaddib:mitre'] === 'T1556');
    assert(byName['muaddib:file'] === 'package.json');
  });

  test('P1b: vulnerability resolves domain from getRuleDomain when threat.domain missing', () => {
    // The threat lacks `domain` — the formatter must fall back via getRuleDomain
    const bom = generateCycloneDX({
      target: '/tmp/x',
      threats: [{
        type: 'env_access',
        rule_id: 'MUADDIB-AST-002',
        severity: 'HIGH',
        confidence: 'high',
        message: 'm',
        file: 'a.js'
      }]
    });
    const props = bom.vulnerabilities[0].properties;
    const byName = Object.fromEntries(props.map(p => [p.name, p.value]));
    assert(byName['muaddib:risk_domain'] === 'malware', 'env_access must resolve to malware via getRuleDomain');
  });

  test('P1b: severity mapping per threat varies (CRITICAL/HIGH/MEDIUM/LOW)', () => {
    const bom = generateCycloneDX({
      target: '/tmp/x',
      threats: [
        { type: 'a', rule_id: 'r1', severity: 'CRITICAL', confidence: 'high', message: '', file: '' },
        { type: 'b', rule_id: 'r2', severity: 'HIGH', confidence: 'high', message: '', file: '' },
        { type: 'c', rule_id: 'r3', severity: 'MEDIUM', confidence: 'high', message: '', file: '' },
        { type: 'd', rule_id: 'r4', severity: 'LOW', confidence: 'high', message: '', file: '' }
      ]
    });
    assert(bom.vulnerabilities[0].ratings[0].severity === 'critical');
    assert(bom.vulnerabilities[1].ratings[0].severity === 'high');
    assert(bom.vulnerabilities[2].ratings[0].severity === 'medium');
    assert(bom.vulnerabilities[3].ratings[0].severity === 'low');
  });

  test('P1b: bom-ref values are unique across multiple vulnerabilities', () => {
    const bom = generateCycloneDX({
      target: '/tmp/x',
      threats: [
        { type: 'a', rule_id: 'r1', severity: 'HIGH', confidence: 'high', message: '', file: '' },
        { type: 'a', rule_id: 'r1', severity: 'HIGH', confidence: 'high', message: '', file: '' },
        { type: 'b', rule_id: 'r2', severity: 'HIGH', confidence: 'high', message: '', file: '' }
      ]
    });
    const refs = bom.vulnerabilities.map(v => v['bom-ref']);
    const uniq = new Set(refs);
    assert(uniq.size === refs.length, 'bom-ref must be unique per vulnerability');
  });

  // ── Root component identity from package.json ──
  await asyncTest('P1b: root component reflects scanned package.json (unscoped)', async () => {
    const tmp = makeTmpPkg({ name: 'axios', version: '1.7.2' });
    try {
      const bom = generateCycloneDX({ target: tmp, threats: [] });
      assert(bom.metadata.component.name === 'axios');
      assert(bom.metadata.component.version === '1.7.2');
      assert(bom.metadata.component.purl === 'pkg:npm/axios@1.7.2');
    } finally { rmrf(tmp); }
  });

  await asyncTest('P1b: root component reflects scoped package.json', async () => {
    const tmp = makeTmpPkg({ name: '@scope/lib', version: '0.1.0' });
    try {
      const bom = generateCycloneDX({ target: tmp, threats: [] });
      assert(bom.metadata.component.name === '@scope/lib');
      assert(bom.metadata.component.purl.startsWith('pkg:npm/%40scope/'));
    } finally { rmrf(tmp); }
  });

  await asyncTest('P1b: root component falls back to generic without package.json', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-cdx-bare-'));
    try {
      const bom = generateCycloneDX({ target: tmp, threats: [] });
      assert(bom.metadata.component.version === '0.0.0');
      assert(bom.metadata.component.purl.startsWith('pkg:generic/'));
    } finally { rmrf(tmp); }
  });

  // ── Persistence ──
  await asyncTest('P1b: saveCycloneDX writes a parseable file', async () => {
    const tmp = makeTmpPkg({ name: 'sample', version: '1.0.0' });
    const outPath = path.join(tmp, 'bom.cdx.json');
    try {
      const written = saveCycloneDX({
        target: tmp,
        threats: [{
          type: 'env_access', rule_id: 'MUADDIB-AST-002', severity: 'HIGH',
          confidence: 'high', domain: 'malware', message: 'm', file: 'index.js', points: 10
        }]
      }, outPath);
      assert(written === outPath);
      assert(fs.existsSync(outPath));
      const parsed = JSON.parse(fs.readFileSync(outPath, 'utf8'));
      assert(parsed.bomFormat === 'CycloneDX');
      assert(parsed.specVersion === '1.5');
      assert(parsed.vulnerabilities.length === 1);
    } finally { rmrf(tmp); }
  });

  test('P1b: saveCycloneDX rejects invalid output path', () => {
    let threw = false;
    try { saveCycloneDX({ threats: [] }, null); }
    catch (e) { threw = true; assert(e.message.includes('Invalid output path')); }
    assert(threw, 'saveCycloneDX must throw on null path');
  });
}

module.exports = { runCyclonedxTests };
