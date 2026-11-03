const { test, assert } = require('../test-utils');
const {
  applyStringIocCorroboration,
  applySingleFireCriticalFloor,
  calculateRiskScore,
  SINGLE_FIRE_CRITICAL_FLOOR
} = require('../../src/scoring.js');

// Spec (src/scoring.js, "String-IOC corroboration"): a CRITICAL ioc_string_match is
// decisive (single-fire floor, MT-1 bypass) only with independent evidence at
// PACKAGE level: a non-LOW finding of a fixed behavioral type list (or a compound),
// or >= 2 distinct CRITICAL strings of one campaign family. >= 2 unrelated families
// without behavioral evidence = IOC catalog, every string match reported LOW.

const ioc = (evidence, campaign, file = 'index.js', extra = {}) =>
  ({ type: 'ioc_string_match', severity: 'CRITICAL', evidence, campaign, file, message: 'm', ...extra });
const finding = (type, severity, file) => ({ type, severity, file, message: 'm' });

function runStringIocCorroborationTests() {
  console.log('\n=== STRING IOC CORROBORATION TESTS ===\n');

  test('STRIOC-CORR: GT-099 shape (3 CRITICAL strings, one family, no behavior) is corroborated', () => {
    const t = [ioc('cargo-build-helper-2026', 'trapdoor-2026-05', 'a.py'), ioc('ddjidd564.github.io', 'trapdoor-2026-05', 'b.py'),
      ioc('trap-core.js', 'trapdoor-2026-05', 'c.py')];
    const r = applyStringIocCorroboration(t);
    assert(r.outcome === 'corroborated' && r.multiplicity === true, JSON.stringify(r));
    assert(t.every(x => x.severity === 'CRITICAL' && !x.iocUncorroborated && !x.iocCatalog), 'nothing may be downgraded');
  });

  test('STRIOC-CORR: a lone CRITICAL string with no other evidence is uncorroborated, still CRITICAL', () => {
    const t = [ioc('sfrclak.com', 'axios-2026-03', 'sunglasses/patterns.py'), finding('env_access', 'HIGH', 'x.js')];
    const r = applyStringIocCorroboration(t);
    assert(r.outcome === 'uncorroborated', JSON.stringify(r));
    assert(t[0].severity === 'CRITICAL' && t[0].iocUncorroborated === true, JSON.stringify(t[0]));
  });

  test('STRIOC-CORR adversarial: IOC in a.js, exfiltration in b.js stays corroborated', () => {
    const t = [ioc('iseekaigogo.com', 'tensorlake-2026-10', 'lib/config.js'), finding('detached_credential_exfil', 'CRITICAL', 'lib/run.js')];
    const r = applyStringIocCorroboration(t);
    assert(r.outcome === 'corroborated' && r.behavioral === true, JSON.stringify(r));
    assert(!t[0].iocUncorroborated, 'cross-file behavior must corroborate');
  });

  test('STRIOC-CORR adversarial: own IOC padded with 3 other families + behavior stays CRITICAL', () => {
    const t = [ioc('iseekaigogo.com', 'tensorlake-2026-10'), ioc('OrDeR_7077', 'axios-2026-03', 'pad.js'),
      ioc('checkmarx.zone', 'teampcp-2026', 'pad.js'), ioc('ci-artifacts.dev', 'subql-2026-10', 'pad.js'),
      finding('reverse_shell', 'CRITICAL', 'lib/run.js')];
    const r = applyStringIocCorroboration(t);
    assert(r.outcome === 'corroborated', 'padding must not buy a catalog downgrade: ' + JSON.stringify(r));
    assert(t.filter(x => x.type === 'ioc_string_match').every(x => x.severity === 'CRITICAL' && !x.iocCatalog), 'all IOC matches stay CRITICAL');
  });

  test('STRIOC-CORR: two unrelated families without behavior is an IOC catalog (all LOW)', () => {
    // @hasna/shield shape
    const t = [ioc('sfrclak.com', 'axios-2026-03', 'dist/index.js'), ioc('/tmp/ld.py', 'axios-2026-03', 'dist/index.js'),
      ioc('checkmarx.zone', 'teampcp-2026', 'dist/index.js'),
      { ...ioc('ddjidd564', 'trapdoor-2026-05', 'dist/index.js'), severity: 'HIGH' }];
    const r = applyStringIocCorroboration(t);
    assert(r.outcome === 'catalog', JSON.stringify(r));
    assert(t.every(x => x.severity === 'LOW' && x.iocCatalog === true), JSON.stringify(t.map(x => [x.evidence, x.severity])));
  });

  test('STRIOC-CORR: a compound finding blocks the catalog downgrade', () => {
    const t = [ioc('sfrclak.com', 'axios-2026-03'), ioc('checkmarx.zone', 'teampcp-2026'),
      { ...finding('crypto_staged_payload_compound', 'CRITICAL', 'x.js'), compound: true }];
    assert(applyStringIocCorroboration(t).outcome === 'corroborated', 'compound = independent evidence');
    assert(t.slice(0, 2).every(x => x.severity === 'CRITICAL'), 'stays CRITICAL');
  });

  test('STRIOC-CORR: a LOW (downgraded) behavioral finding does not corroborate', () => {
    const t = [ioc('sfrclak.com', 'axios-2026-03'), finding('reverse_shell', 'LOW', 'x.js')];
    assert(applyStringIocCorroboration(t).outcome === 'uncorroborated', 'LOW = already judged benign/unreachable');
  });

  test('STRIOC-CORR: an independent package-name IOC on a dependency corroborates (wizloft shape)', () => {
    const t = [ioc('global.i="A8-', 'polinrider-2026-08', 'dist/index.js', { family: 'dprk-nullreceiver' }),
      finding('dependency_ioc_match', 'HIGH', 'package.json')];
    assert(applyStringIocCorroboration(t).outcome === 'corroborated', 'dependency IOC is independent evidence');
  });

  test('STRIOC-CORR: related campaigns of one lineage are one family, not a catalog', () => {
    const t = [ioc('Shai-Hulud: Here We Go Again', 'shai-hulud-2026-05', 'a.js', { family: 'shai-hulud' }),
      ioc('OhNoWhatsGoingOnWithGitHub', 'mini-shai-hulud-2026-04', 'a.js', { family: 'shai-hulud' })];
    const r = applyStringIocCorroboration(t);
    assert(r.outcome === 'corroborated' && r.multiplicity === true, JSON.stringify(r));
  });

  test('STRIOC-CORR: the family defaults to the campaign id without its date suffix', () => {
    // axios-2026-03 and axios-2026-04 are one family -> multiplicity, not a catalog
    const t = [ioc('OrDeR_7077', 'axios-2026-03'), ioc('rsp_kill', 'axios-2026-04')];
    const r = applyStringIocCorroboration(t);
    assert(r.outcome === 'corroborated' && r.multiplicity === true, JSON.stringify(r));
  });

  test('STRIOC-CORR: two occurrences of the SAME string are not multiplicity', () => {
    const t = [ioc('sfrclak.com', 'axios-2026-03', 'a.js'), ioc('sfrclak.com', 'axios-2026-03', 'b.js')];
    assert(applyStringIocCorroboration(t).outcome === 'uncorroborated', 'distinct strings are required');
  });

  test('STRIOC-CORR: packages without CRITICAL string IOCs are untouched', () => {
    const t = [{ ...ioc('huggingface.co/api/models', 'huggingface-cdn-2026'), severity: 'LOW' }, finding('env_access', 'HIGH', 'x.js')];
    const before = JSON.stringify(t);
    assert(applyStringIocCorroboration(t).outcome === 'none' && JSON.stringify(t) === before, 'no-op expected');
  });

  // ── Effect on the score ──
  const summaryOf = threats => ({ summary: { riskScore: 40, riskLevel: 'MEDIUM' }, threats });

  test('STRIOC-CORR: the single-fire floor ignores an uncorroborated string IOC', () => {
    const t = [ioc('sfrclak.com', 'axios-2026-03')];
    applyStringIocCorroboration(t);
    const res = summaryOf(t);
    const triggers = applySingleFireCriticalFloor(res);
    assert(triggers.length === 0 && res.summary.riskScore === 40, `no floor expected, got ${res.summary.riskScore}`);
  });

  test('STRIOC-CORR: the single-fire floor still applies to a corroborated string IOC', () => {
    const t = [ioc('cargo-build-helper-2026', 'trapdoor-2026-05'), ioc('ddjidd564.github.io', 'trapdoor-2026-05')];
    applyStringIocCorroboration(t);
    const res = summaryOf(t);
    applySingleFireCriticalFloor(res);
    assert(res.summary.riskScore === SINGLE_FIRE_CRITICAL_FLOOR, `floor ${SINGLE_FIRE_CRITICAL_FLOOR} expected, got ${res.summary.riskScore}`);
  });

  test('STRIOC-CORR: an uncorroborated string IOC no longer bypasses the MT-1 no-lifecycle ceiling', () => {
    const lone = [ioc('sfrclak.com', 'axios-2026-03', 'a.py'), ioc('sfrclak.com', 'axios-2026-03', 'b.py'),
      finding('obfuscation_detected', 'CRITICAL', 'a.py')];
    applyStringIocCorroboration(lone);
    assert(lone[0].iocUncorroborated === true, 'precondition');
    const r = calculateRiskScore(lone, null);
    assert(r.riskScore <= 35, `MT-1 ceiling expected (<= 35), got ${r.riskScore}`);
  });

  test('STRIOC-CORR: a corroborated string IOC still bypasses the MT-1 ceiling (GT-099 path)', () => {
    const t = [ioc('cargo-build-helper-2026', 'trapdoor-2026-05', 'a.py'), ioc('ddjidd564.github.io', 'trapdoor-2026-05', 'a.py'),
      ioc('trap-core.js', 'trapdoor-2026-05', 'a.py')];
    applyStringIocCorroboration(t);
    const r = calculateRiskScore(t, null);
    assert(r.riskScore > 35, `bypass expected (> 35), got ${r.riskScore}`);
  });

  // ── IOC data (iocs/string-iocs.yaml via the YAML loader) ──
  const { loadYAMLIOCs } = require('../../src/ioc/yaml-loader.js');
  const strings = loadYAMLIOCs().stringIocs;
  const entry = s => strings.find(x => x.string === s);

  test('STRIOC-DATA: P-2024-001 is no longer a string IOC (benign invoice / document serial)', () => {
    assert(!entry('P-2024-001'), 'P-2024-001 must be removed');
  });

  test('STRIOC-DATA: the two generic strings are LOW (composite-only), not silently CRITICAL', () => {
    assert(entry('huggingface.co/api/models') && entry('huggingface.co/api/models').severity === 'LOW', JSON.stringify(entry('huggingface.co/api/models')));
    assert(entry('getSignaturesForAddress') && entry('getSignaturesForAddress').severity === 'LOW', JSON.stringify(entry('getSignaturesForAddress')));
  });

  test('STRIOC-DATA: lineage families reach the loaded entries', () => {
    assert(entry('OhNoWhatsGoingOnWithGitHub').family === 'shai-hulud', 'mini-shai-hulud -> shai-hulud');
    assert(entry('git-tanstack.com').family === 'shai-hulud', 'shai-hulud-2026-05 -> shai-hulud');
    assert(entry('global.i="A8-').family === 'dprk-nullreceiver', 'polinrider -> dprk-nullreceiver');
    assert(entry('0xa322e5f3d311d3080e6f0121063e9adc2490ef1a').family === 'dprk-nullreceiver', 'nullreceiver -> dprk-nullreceiver');
  });

  test('STRIOC-DATA: GT-099 keeps at least two distinct CRITICAL TrapDoor strings after the removal', () => {
    const trapdoor = strings.filter(x => x.campaign === 'trapdoor-2026-05' && x.severity === 'CRITICAL').map(x => x.string);
    for (const s of ['cargo-build-helper-2026', 'ddjidd564.github.io']) assert(trapdoor.includes(s), 'missing ' + s);
  });
}

module.exports = { runStringIocCorroborationTests };
