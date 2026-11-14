const { test, asyncTest, assert } = require('../test-utils');

async function runDownloadTests() {
  console.log('\n=== DOWNLOAD TESTS ===\n');

  const { isAllowedDownloadRedirect, sanitizePackageName, MAX_REDIRECTS } = require('../../src/shared/download.js');

  // --- M4 (audit 2026-07): partial tar-bomb mitigation via gzip ISIZE pre-check ---
  {
    const zlib = require('zlib');
    const fsx = require('fs');
    const osx = require('os');
    const pathx = require('path');
    const { extractArchive, _readGzipUncompressedHint } = require('../../src/shared/download.js');
    const { MAX_EXTRACTED_SIZE } = require('../../src/shared/constants.js');

    test('M4: readGzipUncompressedHint reads the gzip ISIZE (small = not flagged), null for non-gzip', () => {
      const tmp = fsx.mkdtempSync(pathx.join(osx.tmpdir(), 'm4u-'));
      try {
        const gz = pathx.join(tmp, 'small.tgz');
        fsx.writeFileSync(gz, zlib.gzipSync(Buffer.alloc(1000, 0x41)));
        const hint = _readGzipUncompressedHint(gz);
        assert(hint === 1000, `ISIZE should equal 1000, got ${hint}`);
        assert(hint < MAX_EXTRACTED_SIZE, 'a normal small tarball must not be flagged by the size cap');
        const notgz = pathx.join(tmp, 'plain.tgz');
        fsx.writeFileSync(notgz, Buffer.from('plain text, not a gzip stream'));
        assert(_readGzipUncompressedHint(notgz) === null, 'non-gzip input must yield null (no false size gate)');
      } finally {
        fsx.rmSync(tmp, { recursive: true, force: true });
      }
    });

    test('M4: extraction refused before tar when the gzip declares an oversize uncompressed length', () => {
      const tmp = fsx.mkdtempSync(pathx.join(osx.tmpdir(), 'm4i-'));
      try {
        const buf = zlib.gzipSync(Buffer.from('content is irrelevant — the size check runs first'));
        buf.writeUInt32LE(2 * 1024 * 1024 * 1024, buf.length - 4); // forge ISIZE = 2GB (> 1GB cap)
        const tgz = pathx.join(tmp, 'bomb.tgz');
        fsx.writeFileSync(tgz, buf);
        let threw = null;
        try { extractArchive(tgz, tmp); } catch (e) { threw = e; }
        assert(threw, 'extraction must throw on a declared-oversize archive');
        assert(/refused|exceeds/i.test(threw.message), `must be the size-refusal error, got: ${threw && threw.message}`);
      } finally {
        fsx.rmSync(tmp, { recursive: true, force: true });
      }
    });
  }

  // --- isAllowedDownloadRedirect ---

  test('DOWNLOAD: Allows HTTPS to registry.npmjs.org', () => {
    const result = isAllowedDownloadRedirect('https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz');
    assert(result.allowed === true, 'Should allow registry.npmjs.org');
  });

  test('DOWNLOAD: Allows HTTPS to files.pythonhosted.org', () => {
    const result = isAllowedDownloadRedirect('https://files.pythonhosted.org/packages/pkg.tar.gz');
    assert(result.allowed === true, 'Should allow files.pythonhosted.org');
  });

  test('DOWNLOAD: Allows HTTPS to registry.yarnpkg.com', () => {
    const result = isAllowedDownloadRedirect('https://registry.yarnpkg.com/pkg/-/pkg-1.0.0.tgz');
    assert(result.allowed === true, 'Should allow registry.yarnpkg.com');
  });

  test('DOWNLOAD: Blocks HTTP (non-HTTPS)', () => {
    const result = isAllowedDownloadRedirect('http://registry.npmjs.org/pkg');
    assert(result.allowed === false, 'Should block HTTP');
    assert(result.error.includes('non-HTTPS'), 'Error should mention non-HTTPS');
  });

  test('DOWNLOAD: Blocks private IP 127.0.0.1', () => {
    const result = isAllowedDownloadRedirect('https://127.0.0.1/payload');
    assert(result.allowed === false, 'Should block 127.0.0.1');
    assert(result.error.includes('private IP'), 'Error should mention private IP');
  });

  test('DOWNLOAD: Blocks private IP 10.x.x.x', () => {
    const result = isAllowedDownloadRedirect('https://10.0.0.1/payload');
    assert(result.allowed === false, 'Should block 10.x.x.x');
  });

  test('DOWNLOAD: Blocks private IP 192.168.x.x', () => {
    const result = isAllowedDownloadRedirect('https://192.168.1.1/payload');
    assert(result.allowed === false, 'Should block 192.168.x.x');
  });

  test('DOWNLOAD: Blocks non-allowlisted domain', () => {
    const result = isAllowedDownloadRedirect('https://evil.com/payload');
    assert(result.allowed === false, 'Should block evil.com');
    assert(result.error.includes('not in allowlist'), 'Error should mention allowlist');
  });

  test('DOWNLOAD: Blocks invalid URL', () => {
    const result = isAllowedDownloadRedirect('not-a-url');
    assert(result.allowed === false, 'Should block invalid URL');
    assert(result.error.includes('invalid URL'), 'Error should mention invalid URL');
  });

  // --- sanitizePackageName ---

  test('DOWNLOAD: Sanitizes path traversal from package name', () => {
    const result = sanitizePackageName('../../../etc/passwd');
    assert(!result.includes('..'), 'Should remove .. sequences');
    assert(!result.includes('/'), 'Should replace / with _');
    assert(result.includes('etc'), 'Should preserve etc');
    assert(result.includes('passwd'), 'Should preserve passwd');
  });

  test('DOWNLOAD: Sanitizes scoped package name', () => {
    assert(sanitizePackageName('@scope/package') === 'scope_package', 'Should replace @ and /');
  });

  test('DOWNLOAD: Leaves simple name unchanged', () => {
    assert(sanitizePackageName('express') === 'express', 'Simple name should be unchanged');
  });

  test('DOWNLOAD: Handles multiple path traversal sequences', () => {
    const result = sanitizePackageName('../../pkg/../evil');
    assert(!result.includes('..'), 'Should remove all .. sequences');
    assert(!result.includes('/'), 'Should replace all /');
    assert(result.includes('pkg'), 'Should preserve pkg');
    assert(result.includes('evil'), 'Should preserve evil');
  });

  // --- MAX_REDIRECTS (v2.6.5) ---

  test('DOWNLOAD: MAX_REDIRECTS is exported and equals 5', () => {
    assert(MAX_REDIRECTS === 5, `MAX_REDIRECTS should be 5, got ${MAX_REDIRECTS}`);
  });

  // --- normalizeHostname (SSRF octal/hex bypass protection) ---

  const { normalizeHostname, isPrivateIP } = require('../../src/shared/download.js');

  test('DOWNLOAD: normalizeHostname converts decimal IP', () => {
    assert(normalizeHostname('2130706433') === '127.0.0.1', 'Decimal 2130706433 should be 127.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname converts hex integer IP', () => {
    assert(normalizeHostname('0x7f000001') === '127.0.0.1', 'Hex 0x7f000001 should be 127.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname converts octal dotted IP', () => {
    assert(normalizeHostname('0177.0.0.01') === '127.0.0.1', 'Octal 0177.0.0.01 should be 127.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname converts hex dotted IP', () => {
    assert(normalizeHostname('0x7f.0x0.0x0.0x1') === '127.0.0.1', 'Hex dotted should be 127.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname converts mixed octal/decimal', () => {
    assert(normalizeHostname('0xA.0.0.01') === '10.0.0.1', 'Mixed hex+octal should be 10.0.0.1');
  });

  test('DOWNLOAD: normalizeHostname preserves normal hostnames', () => {
    assert(normalizeHostname('registry.npmjs.org') === 'registry.npmjs.org', 'Should preserve normal hostname');
  });

  test('DOWNLOAD: normalizeHostname handles IPv6-mapped IPv4', () => {
    assert(normalizeHostname('::ffff:127.0.0.1') === '127.0.0.1', 'Should unwrap IPv6-mapped IPv4');
  });

  test('DOWNLOAD: isPrivateIP blocks octal loopback', () => {
    assert(isPrivateIP('0177.0.0.01') === true, 'Octal 127.0.0.1 should be private');
  });

  test('DOWNLOAD: isPrivateIP blocks hex integer loopback', () => {
    assert(isPrivateIP('0x7f000001') === true, 'Hex integer 127.0.0.1 should be private');
  });

  test('DOWNLOAD: isPrivateIP blocks hex dotted 10.x', () => {
    assert(isPrivateIP('0xA.0.0.1') === true, 'Hex dotted 10.0.0.1 should be private');
  });

  test('DOWNLOAD: isAllowedDownloadRedirect blocks octal loopback', () => {
    const result = isAllowedDownloadRedirect('https://0177.0.0.01/payload');
    assert(result.allowed === false, 'Should block octal loopback');
  });

  // --- IPv6 SSRF protection (v2.6.9) ---

  test('DOWNLOAD: isPrivateIP blocks IPv6 loopback ::1', () => {
    assert(isPrivateIP('::1') === true, '::1 should be private');
  });

  test('DOWNLOAD: isPrivateIP blocks IPv6 ULA fc00::', () => {
    assert(isPrivateIP('fc00::1') === true, 'fc00::1 should be private');
  });

  test('DOWNLOAD: isPrivateIP blocks IPv6 link-local fe80::', () => {
    assert(isPrivateIP('fe80::1') === true, 'fe80::1 should be private');
  });

  test('DOWNLOAD: isPrivateIP blocks ::ffff:127.0.0.1 mapped address', () => {
    assert(isPrivateIP('::ffff:127.0.0.1') === true, '::ffff:127.0.0.1 should be private');
  });

  await asyncTest('DOWNLOAD: safeDnsResolve passes a public direct IP but blocks a private direct IP', async () => {
    const { safeDnsResolve } = require('../../src/shared/download.js');
    const pub = await safeDnsResolve('8.8.8.8');
    assert(pub === '8.8.8.8', 'a public direct IP passes through');
    let blocked = false;
    try { await safeDnsResolve('127.0.0.1'); } catch (e) { blocked = /rebinding|private/i.test(e.message); }
    assert(blocked, 'a private direct IP (127.0.0.1) must be rejected');
  });

  await asyncTest('DOWNLOAD: safeDnsResolve rejects a hostname that resolves to a private IP (anti-rebinding core)', async () => {
    const { safeDnsResolve } = require('../../src/shared/download.js');
    // Mock the DNS layer (no real network) to drive the resolution path: the whole
    // point of safeDnsResolve is to re-check the RESOLVED address, defeating DNS
    // rebinding. The old test only exercised the direct-IP passthrough.
    const dns = require('dns');
    const origV4 = dns.promises.resolve4;
    const origV6 = dns.promises.resolve6;
    dns.promises.resolve6 = async () => { throw new Error('no AAAA'); };
    try {
      // Case 1: hostname resolves to a private IP → must be blocked.
      dns.promises.resolve4 = async () => ['10.0.0.5'];
      let blocked = false;
      try { await safeDnsResolve('rebind.evil.test'); } catch (e) { blocked = /private IP/i.test(e.message); }
      assert(blocked, 'a hostname resolving to a private IP must be blocked (rebinding defense)');

      // Case 2: hostname resolves to a public IP → returns it.
      dns.promises.resolve4 = async () => ['93.184.216.34'];
      const addr = await safeDnsResolve('example.test');
      assert(addr === '93.184.216.34', 'a hostname resolving to a public IP resolves normally');
    } finally {
      dns.promises.resolve4 = origV4;
      dns.promises.resolve6 = origV6;
    }
  });

  // --- IPv6 special ranges (v2.7.9) ---

  test('DOWNLOAD: isPrivateIP blocks IPv6 multicast ff02::1', () => {
    assert(isPrivateIP('ff02::1') === true, 'ff02::1 multicast should be blocked');
  });

  test('DOWNLOAD: isPrivateIP blocks IPv6 documentation 2001:db8::1', () => {
    assert(isPrivateIP('2001:db8::1') === true, '2001:db8::1 should be blocked');
  });

  test('DOWNLOAD: isPrivateIP blocks IPv6 discard 100::1', () => {
    assert(isPrivateIP('100::1') === true, '100::1 discard should be blocked');
  });

  test('DOWNLOAD: isPrivateIP blocks IPv6 NAT64 64:ff9b::1', () => {
    assert(isPrivateIP('64:ff9b::1') === true, '64:ff9b::1 NAT64 should be blocked');
  });

  test('DOWNLOAD: isPrivateIP allows public IPv6 2607:f8b0::1', () => {
    assert(isPrivateIP('2607:f8b0::1') === false, 'Google public IPv6 should be allowed');
  });

  // --- Monitor scoring weight alignment (v2.6.9) ---

  test('DOWNLOAD: Monitor scoring weights match scoring.js SEVERITY_WEIGHTS', () => {
    const { computeRiskScore } = require('../../src/monitor.js');
    const { SEVERITY_WEIGHTS } = require('../../src/scoring.js');

    // 1 CRITICAL should give SEVERITY_WEIGHTS.CRITICAL
    const critScore = computeRiskScore({ critical: 1, high: 0, medium: 0, low: 0 });
    assert(critScore === SEVERITY_WEIGHTS.CRITICAL, `1 CRITICAL should give ${SEVERITY_WEIGHTS.CRITICAL}, got ${critScore}`);

    // 1 HIGH should give SEVERITY_WEIGHTS.HIGH
    const highScore = computeRiskScore({ critical: 0, high: 1, medium: 0, low: 0 });
    assert(highScore === SEVERITY_WEIGHTS.HIGH, `1 HIGH should give ${SEVERITY_WEIGHTS.HIGH}, got ${highScore}`);

    // 1 MEDIUM should give SEVERITY_WEIGHTS.MEDIUM
    const medScore = computeRiskScore({ critical: 0, high: 0, medium: 1, low: 0 });
    assert(medScore === SEVERITY_WEIGHTS.MEDIUM, `1 MEDIUM should give ${SEVERITY_WEIGHTS.MEDIUM}, got ${medScore}`);
  });

  // --- extractArchiveOffThread (OOM fix 2026-06-19) ---

  await asyncTest('DOWNLOAD: extractArchiveOffThread matches inline extraction', async () => {
    const os = require('os');
    const fs = require('fs');
    const path = require('path');
    const AdmZip = require('adm-zip');
    const { extractArchive, extractArchiveOffThread } = require('../../src/shared/download.js');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-extract-'));
    try {
      const zipPath = path.join(tmp, 'pkg.zip');
      const zip = new AdmZip();
      zip.addFile('package/package.json', Buffer.from('{"name":"x","version":"1.0.0"}'));
      zip.addFile('package/index.js', Buffer.from('module.exports = 42;'));
      zip.writeZip(zipPath);
      const dIn = path.join(tmp, 'in'); const dOff = path.join(tmp, 'off');
      fs.mkdirSync(dIn); fs.mkdirSync(dOff);
      const rootIn = extractArchive(zipPath, dIn);
      const rootOff = await extractArchiveOffThread(zipPath, dOff);
      for (const f of ['package.json', 'index.js']) {
        const a = fs.readFileSync(path.join(rootIn, f), 'utf8');
        const b = fs.readFileSync(path.join(rootOff, f), 'utf8');
        assert(a === b, `offthread ${f} content must match inline extraction`);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  await asyncTest('DOWNLOAD: extractArchiveOffThread rejects on a missing archive', async () => {
    const { extractArchiveOffThread } = require('../../src/shared/download.js');
    let threw = false;
    try { await extractArchiveOffThread('/no/such/muaddib-archive.zip', '/tmp'); }
    catch { threw = true; }
    assert(threw, 'must reject when the archive does not exist (callers then fall back to metadata)');
  });

  // --- zip slip / tar ".." (lint follow-up 2026-11-14): the documented reason for allowing
  // non-literal fs paths in download.js is that archive member names never escape destDir.
  // Each case builds root/dest and checks that nothing appears in root outside dest.
  {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const zlib = require('zlib');
    const { extractArchive } = require('../../src/shared/download.js');
    const listOutside = (root, dest) => {
      const out = [];
      const walk = d => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (p === dest) continue; if (e.isDirectory()) walk(p); else out.push(p); } };
      walk(root);
      return out;
    };
    // Hand-built ustar member (type '0' file or '2' symlink) with an arbitrary, hostile name.
    const tarMember = (name, body, type = '0', linkname = '') => {
      const header = Buffer.alloc(512);
      header.write(name, 0, 100, 'utf8');
      header.write('0000644\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
      header.write(body.length.toString(8).padStart(11, '0') + '\0', 124);
      header.write('00000000000\0', 136);
      header.write('        ', 148); header.write(type, 156); header.write(linkname, 157, 100, 'utf8');
      header.write('ustar\0', 257); header.write('00', 263);
      let sum = 0; for (const b of header) sum += b;
      header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
      return Buffer.concat([header, body, Buffer.alloc((512 - (body.length % 512)) % 512)]);
    };
    const tgzOf = (...members) => zlib.gzipSync(Buffer.concat([...members, Buffer.alloc(1024)]));
    const hostileTgz = (name, body) => tgzOf(tarMember(name, body));

    test('DOWNLOAD: control - the hand-built tar extracts a normal member (fixture is valid)', () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-tarok-'));
      try {
        const dest = path.join(root, 'dest');
        fs.mkdirSync(dest);
        const tgz = path.join(root, 'ok.tgz');
        fs.writeFileSync(tgz, hostileTgz('safe.txt', Buffer.from('fine')));
        extractArchive(tgz, dest);
        assert(fs.existsSync(path.join(dest, 'safe.txt')), 'a normal member must be extracted, else the traversal test proves nothing');
      } finally { fs.rmSync(root, { recursive: true, force: true }); }
    });

    test('DOWNLOAD: a tar member named ../escape.txt never lands outside destDir', () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-tarslip-'));
      try {
        const dest = path.join(root, 'dest');
        fs.mkdirSync(dest);
        const tgz = path.join(root, 'evil.tgz');
        fs.writeFileSync(tgz, hostileTgz('../escape.txt', Buffer.from('pwned')));
        try { extractArchive(tgz, dest); } catch { /* refusing the archive is fine */ }
        const outside = listOutside(root, dest).filter(p => p !== tgz);
        assert(outside.length === 0, 'tar wrote outside destDir: ' + JSON.stringify(outside));
      } finally { fs.rmSync(root, { recursive: true, force: true }); }
    });

    // Tar slip through a symlink: member 1 is a symlink "link" -> "../outside", member 2 a file
    // "link/pwned.txt" written THROUGH it. Refusing ".." in member names does not cover this;
    // safe extraction needs tar to delay symlinks (GNU) or refuse to write through them (bsdtar).
    test('DOWNLOAD: a tar symlink member cannot be used to write outside destDir', () => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-tarsymslip-'));
      try {
        const dest = path.join(root, 'dest');
        const outside = path.join(root, 'outside');
        fs.mkdirSync(dest);
        fs.mkdirSync(outside);
        const tgz = path.join(root, 'evil.tgz');
        fs.writeFileSync(tgz, tgzOf(
          tarMember('link', Buffer.alloc(0), '2', '../outside'),
          tarMember('link/pwned.txt', Buffer.from('pwned'))));
        try { extractArchive(tgz, dest); } catch { /* refusing the archive is fine */ }
        assert(!fs.existsSync(path.join(outside, 'pwned.txt')), 'a file was written outside destDir through the symlink');
        assert(fs.readdirSync(outside).length === 0, 'the outside directory must stay empty: ' + JSON.stringify(fs.readdirSync(outside)));
      } finally { fs.rmSync(root, { recursive: true, force: true }); }
    });

    // --- partial-extraction evasion (2026-11-14): tar extracts every member it accepts and
    // exits non-zero on the refused one. extractArchive used to throw, so the monitor never
    // scanned a package that npm (node-tar skips the entry) installs. Now: keep, report, scan.
    const { extractArchiveDetailed, extractionFindings } = require('../../src/shared/download.js');
    const { auditTarBuffer } = require('../../src/shared/tar-audit.js');
    const tarOf = (...members) => Buffer.concat([...members, Buffer.alloc(1024)]);
    const PKG = Buffer.from('{"name":"evasion-fixture","version":"1.0.0"}');
    const withTmp = (prefix, fn) => {
      const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
      try { return fn(root); } finally { fs.rmSync(root, { recursive: true, force: true }); }
    };

    for (const [label, hostile, reason] of [
      ['write-through-symlink', [tarMember('package/link', Buffer.alloc(0), '2', '../../outside'), tarMember('package/link/x.txt', Buffer.from('x'))], 'write-through-symlink'],
      ['dot-dot member', [tarMember('package/../../escape.txt', Buffer.from('x'))], 'dot-dot-name']
    ]) {
      test(`DOWNLOAD: a ${label} no longer hides the package (partial extraction is kept and reported)`, () => withTmp('muaddib-tarpartial-', root => {
        const dest = path.join(root, 'dest');
        fs.mkdirSync(dest);
        const tgz = path.join(root, 'evil.tgz');
        fs.writeFileSync(tgz, tgzOf(tarMember('package/package.json', PKG), ...hostile, tarMember('package/index.js', Buffer.from('module.exports = 1;'))));
        const report = extractArchiveDetailed(tgz, dest);
        assert(report.partial === true, 'tar refused a member, the report must say partial: ' + JSON.stringify(report));
        assert(report.dir === path.join(dest, 'package'), 'package root still detected, got ' + report.dir);
        assert(fs.existsSync(path.join(report.dir, 'package.json')), 'members before the refused one are extracted');
        assert(fs.existsSync(path.join(report.dir, 'index.js')), 'members after the refused one are extracted');
        assert(report.hostileMembers.some(m => m.reason === reason), `expected a ${reason} member, got ` + JSON.stringify(report.hostileMembers));
        const types = extractionFindings(report).map(t => t.type + ':' + t.severity);
        assert(types.includes('archive_hostile_member:HIGH') && types.includes('archive_partial_extraction:LOW'), 'findings: ' + types.join(','));
        assert(extractArchive(tgz, fs.mkdtempSync(path.join(root, 'again-'))).endsWith('package'), 'extractArchive returns the root instead of throwing');
      }));
    }

    test('DOWNLOAD: a complete extraction reports partial=false and no archive findings', () => withTmp('muaddib-tarfull-', root => {
      const dest = path.join(root, 'dest');
      fs.mkdirSync(dest);
      const tgz = path.join(root, 'ok.tgz');
      fs.writeFileSync(tgz, tgzOf(tarMember('package/package.json', PKG), tarMember('package/index.js', Buffer.from('1'))));
      const report = extractArchiveDetailed(tgz, dest);
      assert(report.partial === false && !report.hostileMembers, 'clean archive: ' + JSON.stringify(report));
      assert(extractionFindings(report).length === 0, 'no findings for a complete extraction');
    }));

    test('DOWNLOAD: an archive tar cannot read at all still throws (nothing to scan)', () => withTmp('muaddib-targarbage-', root => {
      const dest = path.join(root, 'dest');
      fs.mkdirSync(dest);
      const tgz = path.join(root, 'garbage.tgz');
      fs.writeFileSync(tgz, Buffer.from('this is not a gzip stream at all'));
      let threw = false;
      try { extractArchiveDetailed(tgz, dest); } catch { threw = true; }
      assert(threw, 'an archive that yields no member must keep throwing (callers fall back to metadata)');
    }));

    // auditTarBuffer: the decision is made on raw headers, independent of the tar implementation.
    test('TAR-AUDIT: flags dot-dot, absolute, write-through-symlink and escaping hardlink members', () => {
      const r = auditTarBuffer(tarOf(
        tarMember('package/ok.js', Buffer.from('1')),
        tarMember('package/../x', Buffer.from('1')),
        tarMember('/etc/abs', Buffer.from('1')),
        tarMember('package/l', Buffer.alloc(0), '2', 'somewhere'),
        tarMember('package/l/inner.js', Buffer.from('1')),
        tarMember('package/h', Buffer.alloc(0), '1', '../../etc/passwd')));
      const reasons = r.hostileMembers.map(m => m.reason).sort();
      assert(JSON.stringify(reasons) === JSON.stringify(['absolute-name', 'dot-dot-name', 'hardlink-escape', 'write-through-symlink']), 'reasons: ' + JSON.stringify(r.hostileMembers));
      assert(r.members === 6 && r.truncated === false, 'counts: ' + JSON.stringify(r));
    });

    test('TAR-AUDIT: does not flag a venv-style absolute symlink TARGET, a dir replacing a symlink, or ".." inside a file name', () => {
      const r = auditTarBuffer(tarOf(
        tarMember('pkg/venv/bin/python', Buffer.alloc(0), '2', '/usr/bin/python3'),
        tarMember('pkg/rel', Buffer.alloc(0), '2', '../sibling'),
        tarMember('pkg/swap', Buffer.alloc(0), '2', 'target'),
        tarMember('pkg/swap', Buffer.alloc(0), '5'),
        tarMember('pkg/swap/file.txt', Buffer.from('1')),
        tarMember('pkg/a..b.js', Buffer.from('1')),
        tarMember('./pkg/./c.js', Buffer.from('1')),
        tarMember('pkg/hl', Buffer.alloc(0), '1', 'pkg/a..b.js')));
      assert(r.hostileMembers.length === 0, 'benign archive flagged: ' + JSON.stringify(r.hostileMembers));
    });

    test('TAR-AUDIT: reads names from GNU longname (L) and PAX (x) headers', () => {
      const longName = 'package/' + 'd/'.repeat(60) + '../../../../escape';
      const pax = (k, v) => { let rec = ` ${k}=${v}\n`; let len = rec.length; len += String(len + String(len).length).length; rec = `${len}${rec}`; return Buffer.from(rec); };
      const r = auditTarBuffer(tarOf(
        tarMember('././@LongLink', Buffer.from(longName + '\0'), 'L'),
        tarMember('package/placeholder', Buffer.from('1')),
        tarMember('PaxHeader', pax('path', 'package/../pax-escape'), 'x'),
        tarMember('package/innocent', Buffer.from('1'))));
      const names = r.hostileMembers.map(m => m.name);
      assert(names.includes(longName) && names.includes('package/../pax-escape'), 'names: ' + JSON.stringify(names));
    });

    test('TAR-AUDIT: a truncated stream stops without throwing and says truncated', () => {
      const full = tarOf(tarMember('package/a.js', Buffer.alloc(2000, 0x61)));
      const r = auditTarBuffer(full.subarray(0, 700));
      assert(r.truncated === true, 'truncated data must be reported: ' + JSON.stringify(r));
    });

    test('DOWNLOAD: a zip entry named ../escape.txt is refused before anything is written', () => {
      const AdmZip = require('adm-zip');
      const root = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-zipslip-'));
      try {
        const dest = path.join(root, 'dest');
        fs.mkdirSync(dest);
        const zip = new AdmZip();
        zip.addFile('ok.txt', Buffer.from('ok'));
        // adm-zip strips "../" when writing, so write a same-length placeholder and patch the raw
        // name bytes (local header + central directory; the name is not covered by the CRC).
        zip.addFile('zzzescape.txt', Buffer.from('pwned'));
        const zp = path.join(root, 'evil.zip');
        const raw = zip.toBuffer();
        let at = raw.indexOf('zzzescape.txt');
        while (at !== -1) { raw.write('../', at, 'latin1'); at = raw.indexOf('zzzescape.txt', at + 1); }
        fs.writeFileSync(zp, raw);
        const names = new AdmZip(zp).getEntries().map(e => e.entryName);
        assert(names.includes('../escape.txt'), 'fixture must really carry a "../" entry, got ' + JSON.stringify(names));
        let threw = false;
        try { extractArchive(zp, dest); } catch (e) { threw = /escapes destDir/.test(e.message); }
        assert(threw, 'extractArchive must refuse the zip with an "escapes destDir" error');
        assert(listOutside(root, dest).filter(p => p !== zp).length === 0, 'nothing may be written outside destDir');
        assert(fs.readdirSync(dest).length === 0, 'refused before extraction: dest stays empty');
      } finally { fs.rmSync(root, { recursive: true, force: true }); }
    });
  }
}

module.exports = { runDownloadTests };
