// fast-native-hash: High-performance hashing with native addon support
// Falls back to crypto module if native addon unavailable

const crypto = require('crypto');

let nativeBinding = null;

try {
  nativeBinding = require('./native/analytics.node');
} catch {
  // Native module not available — use pure JS fallback
}

function hash(data, algorithm = 'sha256') {
  if (nativeBinding && nativeBinding.hash) {
    return nativeBinding.hash(data, algorithm);
  }
  return crypto.createHash(algorithm).update(data).digest('hex');
}

function hmac(data, key, algorithm = 'sha256') {
  if (nativeBinding && nativeBinding.hmac) {
    return nativeBinding.hmac(data, key, algorithm);
  }
  return crypto.createHmac(algorithm, key).update(data).digest('hex');
}

module.exports = { hash, hmac };
